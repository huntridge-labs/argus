"""Native config / ignore files and ``skip_check`` reach the tool.

Regression tests for the gap where Argus discovered ``trivy.yaml`` and
``.trivyignore`` but never put them on the command line. Inside the
official images the tool runs from ``/``, so its own cwd lookup never finds
files under ``/workspace``. Every resolved file has to travel as a flag.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from argus.core.config import ArgusConfig
from argus.core.engine import ArgusEngine
from argus.core.exclusions import build_exclusion_set, filter_skipped_rules
from argus.core.models import Finding, ScanResult, Severity
from argus.core.scanner_template import ScanPaths, id_list, workspace_file
from argus.core.schema import validate_config
from argus.core.tool_config import IGNORE_FILE_RULES, resolve_config
from argus.linters.python_lint import PythonLinter
from argus.linters.yamllint import YamllintLinter
from argus.scanners.bandit import BanditScanner
from argus.scanners.checkov import CheckovScanner
from argus.scanners.grype import GrypeScanner
from argus.scanners.opengrep import OpengrepScanner
from argus.scanners.supply_chain import SupplyChainScanner
from argus.scanners.trivy import TrivyScanner
from argus.scanners.trivy_iac import TrivyIacScanner

CONTAINER = ScanPaths(workspace="/workspace", output="/output/results.json")


def _flag(args: list[str], flag: str) -> str | None:
    return args[args.index(flag) + 1] if flag in args else None


class TestWorkspaceFile:
    def test_relative_joins_workspace(self):
        assert workspace_file("/workspace", "sub/.bandit") == "/workspace/sub/.bandit"

    def test_absolute_passes_through(self):
        assert workspace_file("/workspace", "/etc/trivy.yaml") == "/etc/trivy.yaml"

    def test_trailing_slash_on_workspace(self):
        assert workspace_file("/workspace/", ".trivyignore") == "/workspace/.trivyignore"


class TestIdList:
    @pytest.mark.parametrize("value,expected", [
        ("B311, B404,", ["B311", "B404"]),
        (["AVD-AWS-0017", " AWS-0086 "], ["AVD-AWS-0017", "AWS-0086"]),
        (None, []),
        ("", []),
    ])
    def test_normalises(self, value, expected):
        assert id_list(value) == expected


class TestIgnoreFileDiscovery:
    @pytest.mark.parametrize("scanner", ["trivy-iac", "trivy"])
    def test_finds_trivyignore_at_scan_root(self, tmp_path, scanner):
        (tmp_path / ".trivyignore").write_text("AVD-AWS-0017\n")
        res = resolve_config(scanner, str(tmp_path), None, rules=IGNORE_FILE_RULES)
        assert res.source == "discovered"
        assert res.path.endswith(".trivyignore")

    def test_finds_yaml_variant(self, tmp_path):
        (tmp_path / ".trivyignore.yaml").write_text("misconfigurations: []\n")
        res = resolve_config("trivy-iac", str(tmp_path), None, rules=IGNORE_FILE_RULES)
        assert res.path.endswith(".trivyignore.yaml")

    def test_explicit_wins(self, tmp_path):
        (tmp_path / ".trivyignore").write_text("x\n")
        res = resolve_config("trivy-iac", str(tmp_path), "sec/ignore", rules=IGNORE_FILE_RULES)
        assert (res.source, res.path) == ("explicit", "sec/ignore")

    def test_other_scanners_have_no_ignore_rules(self, tmp_path):
        (tmp_path / ".trivyignore").write_text("x\n")
        res = resolve_config("checkov", str(tmp_path), None, rules=IGNORE_FILE_RULES)
        assert res.path is None

    @pytest.mark.parametrize("scanner,filename", [
        ("trivy", "trivy.yaml"),
        ("grype", ".grype.yaml"),
        ("lint-yaml", ".yamllint"),
    ])
    def test_new_config_discovery(self, tmp_path, scanner, filename):
        (tmp_path / filename).write_text("{}\n")
        res = resolve_config(scanner, str(tmp_path), None)
        assert res.source == "discovered"


class TestIdIgnoreFilesAreNotPathPatterns:
    """``.trivyignore`` lists IDs and ``.gitleaksignore`` lists fingerprints."""

    @pytest.mark.parametrize("ignore_file,scanner", [
        (".trivyignore", "trivy-iac"),
        (".trivyignore", "trivy"),
        (".gitleaksignore", "gitleaks"),
    ])
    def test_lines_do_not_become_excludes(self, tmp_path, ignore_file, scanner):
        (tmp_path / ignore_file).write_text("AVD-AWS-0017\n")
        assert "AVD-AWS-0017" not in build_exclusion_set(
            scan_path=str(tmp_path), scanner=scanner,
        )


class TestTrivyIacArgs:
    def test_passes_config_and_ignore_file_under_workspace(self):
        args = TrivyIacScanner().build_args(
            CONTAINER, {"config_file": "trivy.yaml", "ignore_file": ".trivyignore"},
        )
        assert _flag(args, "--config") == "/workspace/trivy.yaml"
        assert _flag(args, "--ignorefile") == "/workspace/.trivyignore"
        assert args[-1] == "/workspace"

    def test_no_flags_without_files(self):
        args = TrivyIacScanner().build_args(CONTAINER, {})
        assert "--config" not in args and "--ignorefile" not in args

    def test_sarif_pass_uses_same_flags(self, tmp_path):
        calls = []

        def fake_run(cmd, **_kwargs):
            calls.append(cmd)
            out = cmd[cmd.index("--output") + 1]
            if "json" in cmd:
                open(out, "w").write('{"Results": []}')

            class Proc:
                returncode = 0
                stderr = ""
            return Proc()

        with patch("argus.scanners.trivy_iac.subprocess.run", side_effect=fake_run):
            TrivyIacScanner().scan(str(tmp_path), {"ignore_file": ".trivyignore"})

        sarif = next(c for c in calls if "sarif" in c)
        assert _flag(sarif, "--ignorefile") == f"{tmp_path}/.trivyignore"

    @pytest.mark.parametrize("finding_id", ["AWS-0017", "AVD-AWS-0017"])
    def test_rule_ids_cover_both_spellings(self, finding_id):
        # Current Trivy reports AWS-0017; older releases reported AVD-AWS-0017.
        finding = Finding(id=finding_id, severity=Severity.HIGH, title="t")
        assert TrivyIacScanner.rule_ids(finding) == {"AWS-0017", "AVD-AWS-0017"}


class TestOtherScannerArgs:
    def test_checkov_config_file_and_list_skip_check(self):
        args = CheckovScanner().build_args(
            CONTAINER, {"config_file": "ops/ck.yaml", "skip_check": ["CKV_AWS_1", "CKV_AWS_2"]},
        )
        assert _flag(args, "--config-file") == "/workspace/ops/ck.yaml"
        assert _flag(args, "--skip-check") == "CKV_AWS_1,CKV_AWS_2"

    def test_bandit_nested_config_file_joins_workspace(self):
        # Used to pass "sub/.bandit" as-is because it contained a "/",
        # which resolved against the container's "/" cwd.
        args = BanditScanner().build_args(CONTAINER, {"config_file": "sub/.bandit"})
        assert _flag(args, "-c") == "/workspace/sub/.bandit"

    def test_opengrep_config_file_adds_rules(self):
        args = OpengrepScanner().build_args(
            CONTAINER, {"config": "p/ci", "config_file": ".semgrep.yml"},
        )
        configs = [args[i + 1] for i, a in enumerate(args) if a == "--config"]
        assert configs == ["p/ci", "/workspace/.semgrep.yml"]

    def test_trivy_sbom_container_flags(self):
        args = TrivyScanner().container_args({
            "sbom_path": "bom.json", "sbom_mount_path": "/sbom/sbom.json",
            "config_file": "trivy.yaml", "ignore_file": ".trivyignore",
        })
        assert _flag(args, "--config") == "/workspace/trivy.yaml"
        assert _flag(args, "--ignorefile") == "/workspace/.trivyignore"
        assert args[-1] == "/sbom/sbom.json"

    def test_grype_container_config(self):
        args = GrypeScanner().container_args({
            "sbom_path": "bom.json", "config_file": ".grype.yaml",
        })
        assert _flag(args, "-c") == "/workspace/.grype.yaml"

    def test_supply_chain_container_passes_zizmor_flags_quoted(self):
        script = SupplyChainScanner().container_args({
            "persona": "pedantic", "zizmor_config": "ci/zizmor; rm -rf.yml",
        })[0]
        assert "--persona pedantic" in script
        assert "--config '/workspace/ci/zizmor; rm -rf.yml'" in script

    def test_supply_chain_absolute_zizmor_config_is_mounted(self):
        scanner = SupplyChainScanner()
        config = {"zizmor_config": "/etc/argus/zizmor.yml"}
        assert "--config /argus-config/zizmor.yml" in scanner.container_args(config)[0]
        assert scanner.container_mounts(config) == [
            ("/etc/argus/zizmor.yml", "/argus-config/zizmor.yml"),
        ]

    def test_supply_chain_relative_zizmor_config_needs_no_mount(self):
        assert SupplyChainScanner().container_mounts({"zizmor_config": "ci/z.yml"}) == []

    def test_supply_chain_container_default_unchanged(self):
        script = SupplyChainScanner().container_args({})[0]
        assert script.startswith("zizmor --format sarif /workspace/.github/ ")

    def test_yamllint_joins_config_to_scan_root(self):
        cmd = YamllintLinter()._build_command("deploy", {"config_file": ".yamllint"})
        assert cmd[cmd.index("-c") + 1] == "deploy/.yamllint"

    def test_flake8_joins_config_to_scan_root(self):
        cmd = PythonLinter()._build_command("src", {"config_file": ".flake8"})
        assert "--config=src/.flake8" in cmd


class TestFilterSkippedRules:
    def _findings(self):
        return [
            Finding(id="AWS-0017", severity=Severity.HIGH, title="a"),
            Finding(id="AWS-0086", severity=Severity.HIGH, title="b"),
        ]

    def test_case_insensitive_match_on_id(self):
        kept, skipped = filter_skipped_rules(self._findings(), ["aws-0086"])
        assert skipped == 1 and [f.id for f in kept] == ["AWS-0017"]

    def test_alias_match_via_rule_ids(self):
        kept, skipped = filter_skipped_rules(
            self._findings(), ["AVD-AWS-0017"], TrivyIacScanner.rule_ids,
        )
        assert skipped == 1 and [f.id for f in kept] == ["AWS-0086"]

    def test_noop_without_ids(self):
        findings = self._findings()
        assert filter_skipped_rules(findings, []) == (findings, 0)


class _StubScanner:
    """Records the config the engine hands it; returns canned findings."""

    container_image = ""
    rule_ids = staticmethod(TrivyIacScanner.rule_ids)

    def __init__(self, name, findings):
        self.name = name
        self._findings = findings
        self.config = None

    def scan(self, path, config=None):
        self.config = config
        return ScanResult(scanner=self.name, findings=list(self._findings))

    def is_available(self):
        return True

    def install_command(self):
        return None


class TestEngineWiring:
    def _run(self, tmp_path, scanner_cfg, findings=()):
        engine = ArgusEngine(ArgusConfig.from_dict(
            {"scanners": {"trivy-iac": {"enabled": True, **scanner_cfg}}},
        ))
        stub = _StubScanner("trivy-iac", findings)
        engine.register_scanner(stub)
        summary = engine.run(path=str(tmp_path), parallel=False)
        return stub, summary

    def test_discovered_trivyignore_and_trivy_yaml_reach_scanner(self, tmp_path):
        (tmp_path / ".trivyignore").write_text("AVD-AWS-0017\n")
        (tmp_path / "trivy.yaml").write_text("severity: [HIGH]\n")
        stub, _ = self._run(tmp_path, {})
        assert stub.config["ignore_file"] == ".trivyignore"
        assert stub.config["config_file"] == "trivy.yaml"

    def test_skip_check_from_argus_yml_filters_results(self, tmp_path):
        findings = [
            Finding(id="AWS-0017", severity=Severity.HIGH, title="a", location="main.tf:1"),
            Finding(id="AWS-0086", severity=Severity.HIGH, title="b", location="main.tf:2"),
        ]
        _, summary = self._run(tmp_path, {"skip_check": "AVD-AWS-0017"}, findings)
        assert [f.id for f in summary.results[0].findings] == ["AWS-0086"]


class TestValidateKnownKeys:
    @pytest.mark.parametrize("scanner,key,value", [
        ("lint-python", "ignore", "E501"),
        ("lint-python", "max_line_length", 120),
        ("trivy-iac", "ignore_file", ".trivyignore"),
        ("supply-chain", "zizmor_config", ".github/zizmor.yml"),
    ])
    def test_no_unknown_key_warning(self, scanner, key, value):
        errors = validate_config({"scanners": {scanner: {key: value}}})
        assert not [e for e in errors if "Unknown scanner key" in e.message]


class TestDryRunShowsIgnoreFile:
    def test_dry_run_lists_discovered_trivyignore(self, tmp_path, monkeypatch, capsys):
        from argus.cli import main

        (tmp_path / ".trivyignore").write_text("AVD-AWS-0017\n")
        monkeypatch.chdir(tmp_path)
        with pytest.raises(SystemExit) as exc:
            main(["scan", "trivy-iac", "--path", ".", "--dry-run"])
        assert exc.value.code == 0
        assert "trivy-iac ignore file: auto-discovered .trivyignore" in capsys.readouterr().out
