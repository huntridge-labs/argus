"""Tests for tool-native ignore files in the container scan.

``containers.trivy_ignore_file`` goes to trivy as ``--ignorefile`` and
``containers.grype_config_file`` to grype as ``-c``. Unlike an OpenVEX
statement, which names only a component PURL, both formats can scope a rule
to one file in the image (trivy ``paths``, grype ``package.location``).

What trivy and grype ignored is read back from their own output (trivy
``--show-suppressed`` -> ``ExperimentalModifiedFindings``, grype
``ignoredMatches``) so reports can show it as ignored, with the reason,
without counting it. The tools are mocked; real-image behaviour is checked
by hand against the CLI image (see the PR).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from argus.container.ignores import (
    grype_config_args,
    parse_grype_ignored,
    parse_trivy_suppressed,
    trivy_ignore_args,
    unmatched_ignore_rules,
)
from argus.container.scanner import (
    ContainerScanResult,
    _run_grype,
    _run_trivy,
    scan_image,
)
from argus.container.discovery import ContainerTarget
from argus.core.models import Finding, Severity

GITLEAKS = "usr/local/bin/gitleaks"

TRIVY_IGNORE = (
    "vulnerabilities:\n"
    "  - id: CVE-2025-68121\n"
    f"    paths: [\"{GITLEAKS}\"]\n"
    "    statement: gitleaks never makes a TLS connection\n"
)

GRYPE_CONFIG = (
    "ignore:\n"
    "  - vulnerability: GO-2026-4337\n"
    "    reason: gitleaks never makes a TLS connection\n"
    "    package:\n"
    "      name: stdlib\n"
    f"      location: /{GITLEAKS}\n"
)


def _trivy_output(source: str, target: str = GITLEAKS) -> dict:
    """Trivy JSON with one open finding and one ignored by an ignore file."""
    return {
        "Results": [
            {
                "Target": target,
                "Class": "lang-pkgs",
                "Type": "gobinary",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-25679",
                        "PkgName": "stdlib",
                        "InstalledVersion": "v1.24.11",
                        "Severity": "HIGH",
                        "PkgIdentifier": {"PURL": "pkg:golang/stdlib@v1.24.11"},
                    }
                ],
                "ExperimentalModifiedFindings": [
                    {
                        "Type": "vulnerability",
                        "Status": "ignored",
                        "Statement": "gitleaks never makes a TLS connection",
                        "Source": source,
                        "Finding": {
                            "VulnerabilityID": "CVE-2025-68121",
                            "PkgName": "stdlib",
                            "InstalledVersion": "v1.24.11",
                            "FixedVersion": "1.24.13",
                            "Severity": "CRITICAL",
                            "PkgIdentifier": {"PURL": "pkg:golang/stdlib@v1.24.11"},
                        },
                    },
                    {
                        "Type": "misconfiguration",
                        "Status": "ignored",
                        "Source": source,
                        "Finding": {"ID": "DS002"},
                    },
                ],
            }
        ]
    }


def _grype_output(rules: list[dict]) -> dict:
    """Grype JSON with one open match and one ignored match."""
    artifact = {
        "name": "stdlib",
        "version": "go1.24.11",
        "purl": "pkg:golang/stdlib@1.24.11",
        "locations": [{"path": f"/{GITLEAKS}"}],
    }
    return {
        "matches": [
            {
                "vulnerability": {"id": "GO-2026-4601", "severity": "High"},
                "artifact": artifact,
            }
        ],
        "ignoredMatches": [
            {
                "vulnerability": {
                    "id": "GO-2026-4337",
                    "severity": "Critical",
                    "fix": {"versions": ["1.24.13"]},
                },
                "artifact": artifact,
                "appliedIgnoreRules": rules,
            }
        ],
    }


def _applied_rule(reason: str = "gitleaks never makes a TLS connection") -> dict:
    """The rule as grype echoes it back (empty strings for unset fields)."""
    return {
        "vulnerability": "GO-2026-4337",
        "reason": reason,
        "namespace": "",
        "package": {"name": "stdlib", "language": "", "location": f"/{GITLEAKS}"},
    }


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _completed(returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout="", stderr="")


def _force_local_binary(monkeypatch):
    monkeypatch.setattr(
        "argus.container.scanner.shutil.which",
        lambda tool: f"/usr/local/bin/{tool}",
    )


@pytest.fixture
def in_tmp_cwd(tmp_path, monkeypatch):
    """Run from tmp_path so configured relative paths resolve there."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


# --------------------------------------------------------------------- #
# Flag + mount construction                                             #
# --------------------------------------------------------------------- #


class TestIgnoreArgs:
    def test_no_config_means_no_flags(self):
        assert trivy_ignore_args(None, use_container=True) == ([], [])
        assert grype_config_args({}, use_container=False) == ([], [])

    def test_missing_file_is_skipped_with_warning(self, tmp_path, caplog):
        cfg = {"trivy_ignore_file": str(tmp_path / "nope.yaml")}
        assert trivy_ignore_args(cfg, use_container=False) == ([], [])
        assert "not found" in caplog.text

    def test_trivy_local_points_at_host_path(self, tmp_path):
        ignore = _write(tmp_path / "ignore.yaml", TRIVY_IGNORE)
        mounts, flags = trivy_ignore_args(
            {"trivy_ignore_file": str(ignore)}, use_container=False,
        )
        assert mounts == []
        assert flags == ["--ignorefile", str(ignore.resolve())]

    def test_trivy_container_mount_keeps_extension(self, tmp_path):
        # trivy picks the YAML parser from the file extension, so the
        # in-container name must keep ``.yaml``.
        ignore = _write(tmp_path / "argus-cli.trivyignore.yaml", TRIVY_IGNORE)
        mounts, flags = trivy_ignore_args(
            {"trivy_ignore_file": str(ignore)}, use_container=True,
        )
        target = "/argus-ignore/argus-cli.trivyignore.yaml"
        assert mounts == ["-v", f"{ignore.resolve()}:{target}:ro"]
        assert flags == ["--ignorefile", target]

    def test_grype_container_uses_dash_c(self, tmp_path):
        config = _write(tmp_path / "argus-cli.grype.yaml", GRYPE_CONFIG)
        mounts, flags = grype_config_args(
            {"grype_config_file": str(config)}, use_container=True,
        )
        target = "/argus-ignore/argus-cli.grype.yaml"
        assert mounts == ["-v", f"{config.resolve()}:{target}:ro"]
        assert flags == ["-c", target]


class TestRunnerWiring:
    def test_run_trivy_passes_ignorefile_and_show_suppressed(self, tmp_path, monkeypatch):
        _force_local_binary(monkeypatch)
        ignore = _write(tmp_path / "ignore.yaml", TRIVY_IGNORE)
        captured = {}

        def fake_run(cmd, *a, **k):
            captured["cmd"] = list(cmd)
            (tmp_path / "trivy-results.json").write_text('{"Results": []}')
            return _completed(0)

        monkeypatch.setattr("subprocess.run", fake_run)
        _run_trivy("img:tag", tmp_path, local=True,
                   config={"trivy_ignore_file": str(ignore)})

        cmd = captured["cmd"]
        assert cmd[cmd.index("--ignorefile") + 1] == str(ignore.resolve())
        assert "--show-suppressed" in cmd
        assert cmd.index("--ignorefile") < cmd.index("img:tag")

    def test_run_trivy_always_shows_suppressed(self, tmp_path, monkeypatch):
        # trivy also drops findings for VEX and an auto-discovered
        # .trivyignore; asking it to say so costs nothing.
        _force_local_binary(monkeypatch)
        captured = {}

        def fake_run(cmd, *a, **k):
            captured["cmd"] = list(cmd)
            (tmp_path / "trivy-results.json").write_text('{"Results": []}')
            return _completed(0)

        monkeypatch.setattr("subprocess.run", fake_run)
        _run_trivy("img:tag", tmp_path, local=True, config={})
        assert "--show-suppressed" in captured["cmd"]
        assert "--ignorefile" not in captured["cmd"]

    def test_run_trivy_container_mounts_ignore_file(self, tmp_path, monkeypatch):
        ignore = _write(tmp_path / "ignore.yaml", TRIVY_IGNORE)
        calls = []

        def fake_run(cmd, *a, **k):
            calls.append(list(cmd))
            (tmp_path / "trivy-results.json").write_text('{"Results": []}')
            return _completed(0)

        monkeypatch.setattr("argus.container.scanner.shutil.which", lambda tool: None)
        monkeypatch.setattr("argus.container_runtime.is_available", lambda: True)
        monkeypatch.setattr("argus.container_runtime.pull_image", lambda image: True)
        monkeypatch.setattr("argus.container_runtime.runtime_cmd", lambda: "docker")
        monkeypatch.setattr("subprocess.run", fake_run)
        _run_trivy("img:tag", tmp_path, local=True,
                   config={"trivy_ignore_file": str(ignore)})

        scan_cmd = calls[-1]
        assert f"{ignore.resolve()}:/argus-ignore/ignore.yaml:ro" in scan_cmd
        assert scan_cmd[scan_cmd.index("--ignorefile") + 1] == "/argus-ignore/ignore.yaml"
        assert "--show-suppressed" in scan_cmd

    def test_run_grype_passes_config(self, tmp_path, monkeypatch):
        _force_local_binary(monkeypatch)
        config = _write(tmp_path / "grype.yaml", GRYPE_CONFIG)
        captured = {}

        def fake_run(cmd, *a, **k):
            captured["cmd"] = list(cmd)
            (tmp_path / "grype-results.json").write_text('{"matches": []}')
            return _completed(0)

        monkeypatch.setattr("subprocess.run", fake_run)
        _run_grype("img:tag", tmp_path, local=True,
                   config={"grype_config_file": str(config)})
        cmd = captured["cmd"]
        assert cmd[cmd.index("-c") + 1] == str(config.resolve())

    def test_run_grype_container_mounts_config(self, tmp_path, monkeypatch):
        config = _write(tmp_path / "grype.yaml", GRYPE_CONFIG)
        calls = []

        def fake_run(cmd, *a, **k):
            calls.append(list(cmd))
            (tmp_path / "grype-results.json").write_text('{"matches": []}')
            return _completed(0)

        monkeypatch.setattr("argus.container.scanner.shutil.which", lambda tool: None)
        monkeypatch.setattr("argus.container_runtime.is_available", lambda: True)
        monkeypatch.setattr("argus.container_runtime.pull_image", lambda image: True)
        monkeypatch.setattr("argus.container_runtime.runtime_cmd", lambda: "docker")
        monkeypatch.setattr("subprocess.run", fake_run)
        _run_grype("img:tag", tmp_path, local=True,
                   config={"grype_config_file": str(config)})

        scan_cmd = calls[-1]
        assert f"{config.resolve()}:/argus-ignore/grype.yaml:ro" in scan_cmd
        assert scan_cmd[scan_cmd.index("-c") + 1] == "/argus-ignore/grype.yaml"


# --------------------------------------------------------------------- #
# Reading back what the tools ignored                                   #
# --------------------------------------------------------------------- #


class TestParseTrivySuppressed:
    def test_ignored_finding_carries_reason_source_and_path(self, in_tmp_cwd):
        ignore = _write(in_tmp_cwd / "ignore.yaml", TRIVY_IGNORE)
        cfg = {"trivy_ignore_file": "ignore.yaml"}
        out = _write(
            in_tmp_cwd / "trivy-results.json",
            json.dumps(_trivy_output("/argus-ignore/ignore.yaml")),
        )

        ignored = parse_trivy_suppressed(out, cfg)

        assert [f.id for f in ignored] == ["CVE-2025-68121"]
        meta = ignored[0].metadata
        assert ignored[0].severity == Severity.CRITICAL
        assert meta["tool"] == "trivy"
        assert meta["ignored"] is True
        assert meta["ignore_status"] == "ignored"
        assert meta["ignore_reason"] == "gitleaks never makes a TLS connection"
        assert meta["ignore_source"] == "ignore.yaml"
        assert meta["ignore_path"] == GITLEAKS
        assert ignore.exists()

    def test_local_source_path_maps_to_configured_name(self, in_tmp_cwd):
        ignore = _write(in_tmp_cwd / "ignore.yaml", TRIVY_IGNORE)
        out = _write(
            in_tmp_cwd / "trivy-results.json",
            json.dumps(_trivy_output(str(ignore.resolve()))),
        )
        ignored = parse_trivy_suppressed(out, {"trivy_ignore_file": "ignore.yaml"})
        assert ignored[0].metadata["ignore_source"] == "ignore.yaml"

    def test_vex_source_maps_back_to_document(self, in_tmp_cwd):
        _write(in_tmp_cwd / "doc.openvex.json", "{}")
        out = _write(
            in_tmp_cwd / "trivy-results.json",
            json.dumps(_trivy_output("/vex/doc0.json")),
        )
        ignored = parse_trivy_suppressed(out, {"vex": "doc.openvex.json"})
        assert ignored[0].metadata["ignore_source"] == "doc.openvex.json"

    def test_missing_or_bad_output_yields_nothing(self, tmp_path):
        assert parse_trivy_suppressed(tmp_path / "absent.json", {}) == []
        bad = _write(tmp_path / "bad.json", "{not json")
        assert parse_trivy_suppressed(bad, {}) == []


class TestParseGrypeIgnored:
    def test_ignored_match_attributed_to_config(self, in_tmp_cwd):
        _write(in_tmp_cwd / "grype.yaml", GRYPE_CONFIG)
        out = _write(
            in_tmp_cwd / "grype-results.json",
            json.dumps(_grype_output([_applied_rule()])),
        )

        ignored = parse_grype_ignored(out, {"grype_config_file": "grype.yaml"})

        assert [f.id for f in ignored] == ["GO-2026-4337"]
        meta = ignored[0].metadata
        assert meta["tool"] == "grype"
        assert meta["ignored"] is True
        assert meta["ignore_reason"] == "gitleaks never makes a TLS connection"
        assert meta["ignore_source"] == "grype.yaml"
        assert meta["ignore_path"] == f"/{GITLEAKS}"

    def test_vex_rule_reports_vex_status(self, tmp_path):
        rule = {"vex-status": "not_affected",
                "vex-justification": "vulnerable_code_not_in_execute_path"}
        out = _write(tmp_path / "g.json", json.dumps(_grype_output([rule])))
        meta = parse_grype_ignored(out, {})[0].metadata
        assert meta["ignore_status"] == "not_affected"
        assert "vulnerable_code_not_in_execute_path" in meta["ignore_reason"]
        assert meta["ignore_source"] == "openvex"

    def test_rule_not_in_config_is_attributed_to_grype(self, in_tmp_cwd):
        # grype ships default rules of its own; those are not ours.
        _write(in_tmp_cwd / "grype.yaml", GRYPE_CONFIG)
        builtin = {"vulnerability": "", "reason": "", "package": {"name": "kernel-headers"}}
        out = _write(in_tmp_cwd / "g.json", json.dumps(_grype_output([builtin])))
        meta = parse_grype_ignored(out, {"grype_config_file": "grype.yaml"})[0].metadata
        assert meta["ignore_source"] == "grype (built-in rule)"

    def test_missing_output_yields_nothing(self, tmp_path):
        assert parse_grype_ignored(tmp_path / "absent.json", {}) == []


# --------------------------------------------------------------------- #
# scan_image: ignored findings ride alongside, never counted            #
# --------------------------------------------------------------------- #


def test_scan_image_records_ignored_findings_without_counting_them(in_tmp_cwd, monkeypatch):
    _write(in_tmp_cwd / "ignore.yaml", TRIVY_IGNORE)
    _write(in_tmp_cwd / "grype.yaml", GRYPE_CONFIG)
    open_finding = Finding(
        id="CVE-2026-25679", severity=Severity.HIGH, title="t",
        cve="CVE-2026-25679", scanner="container", metadata={"tool": "trivy"},
    )

    def fake_trivy(image_ref, tmp_path, local=False, config=None):
        (tmp_path / "trivy-results.json").write_text(
            json.dumps(_trivy_output("/argus-ignore/ignore.yaml")))
        return [open_finding]

    def fake_grype(image_ref, tmp_path, local=False, config=None):
        (tmp_path / "grype-results.json").write_text(
            json.dumps(_grype_output([_applied_rule()])))
        return []

    monkeypatch.setattr("argus.container.scanner._run_trivy", fake_trivy)
    monkeypatch.setattr("argus.container.scanner._run_grype", fake_grype)
    monkeypatch.setattr("argus.container.scanner.is_image_local", lambda ref: True)
    monkeypatch.setattr("argus.container.scanner.get_image_digest", lambda ref: "")

    result = scan_image(
        ContainerTarget(name="cli", image_ref="cli:test"),
        scanners=("trivy", "grype"), sbom=False,
        config={"trivy_ignore_file": "ignore.yaml", "grype_config_file": "grype.yaml"},
    )

    assert sorted(f.id for f in result.ignored_findings) == ["CVE-2025-68121", "GO-2026-4337"]
    assert [f.id for f in result.combined_findings] == ["CVE-2026-25679"]
    assert result.critical_count == 0
    assert result.high_count == 1
    assert result.total_count == 1


def test_result_defaults_to_no_ignored_findings():
    assert ContainerScanResult(name="x", image_ref="x:1").ignored_findings == []


# --------------------------------------------------------------------- #
# Guard: a rule that matched nothing                                     #
# --------------------------------------------------------------------- #


def _ignored(tool: str, vuln: str, source: str, path: str, package: str = "stdlib") -> Finding:
    return Finding(
        id=vuln, severity=Severity.CRITICAL, title=vuln, scanner="container",
        metadata={"tool": tool, "package": package, "ignored": True,
                  "ignore_source": source, "ignore_path": path},
    )


class TestUnmatchedIgnoreRules:
    def test_all_rules_matched(self, in_tmp_cwd):
        _write(in_tmp_cwd / "ignore.yaml", TRIVY_IGNORE)
        _write(in_tmp_cwd / "grype.yaml", GRYPE_CONFIG)
        cfg = {"trivy_ignore_file": "ignore.yaml", "grype_config_file": "grype.yaml"}
        ignored = [
            _ignored("trivy", "CVE-2025-68121", "ignore.yaml", GITLEAKS),
            _ignored("grype", "GO-2026-4337", "grype.yaml", f"/{GITLEAKS}"),
        ]
        assert unmatched_ignore_rules(ignored, cfg) == []

    def test_rule_with_no_ignored_finding_is_reported(self, in_tmp_cwd):
        _write(in_tmp_cwd / "ignore.yaml", TRIVY_IGNORE)
        _write(in_tmp_cwd / "grype.yaml", GRYPE_CONFIG)
        cfg = {"trivy_ignore_file": "ignore.yaml", "grype_config_file": "grype.yaml"}

        misses = unmatched_ignore_rules([], cfg)

        assert {(m.tool, m.vulnerability, m.path, m.source) for m in misses} == {
            ("trivy", "CVE-2025-68121", GITLEAKS, "ignore.yaml"),
            ("grype", "GO-2026-4337", f"/{GITLEAKS}", "grype.yaml"),
        }

    def test_finding_at_another_path_does_not_satisfy_rule(self, in_tmp_cwd):
        _write(in_tmp_cwd / "ignore.yaml", TRIVY_IGNORE)
        ignored = [_ignored("trivy", "CVE-2025-68121", "ignore.yaml",
                            "usr/local/bin/actionlint")]
        misses = unmatched_ignore_rules(ignored, {"trivy_ignore_file": "ignore.yaml"})
        assert [m.vulnerability for m in misses] == ["CVE-2025-68121"]

    def test_finding_from_another_source_does_not_satisfy_rule(self, in_tmp_cwd):
        _write(in_tmp_cwd / "ignore.yaml", TRIVY_IGNORE)
        ignored = [_ignored("trivy", "CVE-2025-68121", "doc.openvex.json", GITLEAKS)]
        misses = unmatched_ignore_rules(ignored, {"trivy_ignore_file": "ignore.yaml"})
        assert len(misses) == 1

    def test_only_tools_that_ran_are_checked(self, in_tmp_cwd):
        _write(in_tmp_cwd / "ignore.yaml", TRIVY_IGNORE)
        _write(in_tmp_cwd / "grype.yaml", GRYPE_CONFIG)
        cfg = {"trivy_ignore_file": "ignore.yaml", "grype_config_file": "grype.yaml"}
        misses = unmatched_ignore_rules([], cfg, tools=("grype",))
        assert [m.tool for m in misses] == ["grype"]

    def test_plain_trivyignore_ids_are_checked(self, in_tmp_cwd):
        _write(in_tmp_cwd / ".trivyignore", "# accepted\nCVE-2025-1 exp:2099-01-01\n\nCVE-2025-2\n")
        ignored = [_ignored("trivy", "CVE-2025-1", ".trivyignore", "app")]
        misses = unmatched_ignore_rules(ignored, {"trivy_ignore_file": ".trivyignore"})
        assert [m.vulnerability for m in misses] == ["CVE-2025-2"]

    def test_no_files_configured(self):
        assert unmatched_ignore_rules([], {}) == []


# --------------------------------------------------------------------- #
# Config + CLI surface                                                   #
# --------------------------------------------------------------------- #


def test_containers_ignore_keys_flow_from_config_file(tmp_path):
    from argus.cli import _load_container_config, build_parser

    cfg = tmp_path / "argus.yml"
    cfg.write_text(
        "containers:\n"
        "  images:\n"
        "    - image: img:tag\n"
        "  trivy_ignore_file: .vex/a.trivyignore.yaml\n"
        "  grype_config_file: .vex/a.grype.yaml\n"
    )
    args = build_parser().parse_args(["scan", "container", "--config", str(cfg)])
    config = _load_container_config(args)
    assert config["trivy_ignore_file"] == ".vex/a.trivyignore.yaml"
    assert config["grype_config_file"] == ".vex/a.grype.yaml"


def test_schema_accepts_container_ignore_keys():
    from argus.core.schema import _CONTAINERS_KEYS

    assert {"trivy_ignore_file", "grype_config_file"} <= _CONTAINERS_KEYS


def test_canonical_metadata_carries_ignored_findings():
    from argus.cli import _canonical_container_metadata

    result = ContainerScanResult(
        name="cli", image_ref="cli:1",
        ignored_findings=[_ignored("trivy", "CVE-2025-68121", "i.yaml", GITLEAKS)],
    )
    meta = _canonical_container_metadata(result)
    assert [f["id"] for f in meta["ignored_findings"]] == ["CVE-2025-68121"]
    assert meta["ignored_findings"][0]["metadata"]["ignore_source"] == "i.yaml"


def test_canonical_metadata_omits_empty_ignored_findings():
    from argus.cli import _canonical_container_metadata

    meta = _canonical_container_metadata(ContainerScanResult(name="x", image_ref="x:1"))
    assert "ignored_findings" not in meta


def test_container_json_reports_ignored_count(tmp_path):
    from argus.cli import _write_container_json
    from argus.container.scanner import ContainerScanSummary

    result = ContainerScanResult(
        name="cli", image_ref="cli:1",
        ignored_findings=[_ignored("trivy", "CVE-2025-68121", "i.yaml", GITLEAKS)],
    )
    _write_container_json(ContainerScanSummary(results=[result]), tmp_path)
    data = json.loads((tmp_path / "container-scan.json").read_text())
    row = data["results"][0]
    assert row["ignored"] == 1
    assert row["total"] == 0


def test_cli_warns_on_unmatched_ignore_rule(in_tmp_cwd, capsys):
    from argus.cli import _warn_unmatched_ignore_rules
    from argus.container.scanner import ContainerScanSummary

    _write(in_tmp_cwd / "ignore.yaml", TRIVY_IGNORE)
    summary = ContainerScanSummary(results=[ContainerScanResult(name="cli", image_ref="cli:1")])
    _warn_unmatched_ignore_rules(summary, {"trivy_ignore_file": "ignore.yaml"})
    err = capsys.readouterr().err
    assert "CVE-2025-68121" in err
    assert "matched nothing" in err


def test_cli_warning_considers_every_image(in_tmp_cwd, capsys):
    # One argus.yml ignore file covers every image; a rule only has to
    # match in one of them.
    from argus.cli import _warn_unmatched_ignore_rules
    from argus.container.scanner import ContainerScanSummary

    _write(in_tmp_cwd / "ignore.yaml", TRIVY_IGNORE)
    hit = ContainerScanResult(
        name="cli", image_ref="cli:1",
        ignored_findings=[_ignored("trivy", "CVE-2025-68121", "ignore.yaml", GITLEAKS)],
    )
    other = ContainerScanResult(name="bandit", image_ref="bandit:1")
    _warn_unmatched_ignore_rules(
        ContainerScanSummary(results=[other, hit]), {"trivy_ignore_file": "ignore.yaml"},
    )
    assert capsys.readouterr().err == ""
