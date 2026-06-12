"""Unit tests for ``argus.scanners.mumps.MumpsScanner``.

These tests cover the scanner protocol surface and the rule registry
shape. They do **not** require the compiled tree-sitter-mumps grammar;
rule-level integration tests live in ``test_mumps_rules.py`` and skip when
the grammar shared library is unavailable.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.core.models import Severity
from argus.scanners import SCANNER_REGISTRY, get_scanner
from argus.scanners.mumps import MumpsScanner
from argus.scanners.mumps.parser import GrammarUnavailable, MumpsParser
from argus.scanners.mumps.rules import RULES


class TestMumpsScannerProtocol:
    """The Scanner protocol surface — names, registry, helpers."""

    def test_registered_in_global_registry(self):
        assert "mumps" in SCANNER_REGISTRY
        assert SCANNER_REGISTRY["mumps"] is MumpsScanner

    def test_get_scanner_returns_instance(self):
        scanner = get_scanner("mumps")
        assert isinstance(scanner, MumpsScanner)

    def test_scanner_metadata(self):
        scanner = MumpsScanner()
        assert scanner.name == "mumps"
        assert scanner.category == "sast"
        assert "mumps" in scanner.languages

    def test_install_command_mentions_extras_or_container(self):
        scanner = MumpsScanner()
        hint = scanner.install_command()
        assert hint is not None
        assert "argus-security[mumps]" in hint or "scanner-mumps" in hint


class TestMumpsScannerScan:
    """``scan()`` boundary behaviours that don't need the grammar."""

    def test_returns_empty_when_path_missing(self, tmp_path):
        scanner = MumpsScanner()
        result = scanner.scan(str(tmp_path / "does-not-exist"))
        assert result.scanner == "mumps"
        assert result.findings == []
        assert "error" in result.metadata

    def test_returns_empty_when_no_m_files(self, tmp_path):
        (tmp_path / "ignore.py").write_text("print('hi')\n")
        (tmp_path / "ignore.txt").write_text("hello\n")
        scanner = MumpsScanner()
        result = scanner.scan(str(tmp_path))
        assert result.findings == []
        assert result.metadata["files_scanned"] == 0

    def test_extension_filter_walks_subdirectories(self, tmp_path):
        nested = tmp_path / "sub" / "deeper"
        nested.mkdir(parents=True)
        m_file = nested / "test.m"
        m_file.write_text("TEST ;empty\n Q\n")

        scanner = MumpsScanner()
        # Locate the file via the iterator without invoking parsing.
        found = list(scanner._iter_sources(tmp_path, (".m",)))
        assert m_file in found

    def test_iter_sources_accepts_single_file_target(self, tmp_path):
        m_file = tmp_path / "one.m"
        m_file.write_text("ONE ; ok\n Q\n")
        non_m = tmp_path / "one.txt"
        non_m.write_text("ignore\n")

        scanner = MumpsScanner()
        assert list(scanner._iter_sources(m_file, (".m",))) == [m_file]
        assert list(scanner._iter_sources(non_m, (".m",))) == []

    def test_is_available_true_when_grammar_present(self, monkeypatch):
        from argus.scanners.mumps import parser as parser_module
        monkeypatch.setattr(parser_module, "tree_sitter_available", lambda: True)
        # MumpsScanner.is_available re-imports via the module, so patch the
        # symbol the scanner pulled at import time too.
        from argus.scanners.mumps import scanner as scanner_module
        monkeypatch.setattr(scanner_module, "tree_sitter_available", lambda: True)
        assert MumpsScanner().is_available() is True


class TestRuleRegistry:
    """Rule registry shape — IDs, severities, distinct identifiers."""

    def test_phase_one_rules_registered(self):
        ids = {rule.id for rule in RULES}
        assert ids == {
            "M001", "M002", "M003", "M004", "M005", "M006", "M007",
            "M101", "M102",
            "M201", "M202", "M203", "M204", "M205", "M206",
            "M207", "M208", "M209", "M210", "M211", "M212", "M213",
            "M214", "M215", "M216", "M217", "M218", "M219",
        }

    def test_rule_ids_are_distinct(self):
        ids = [rule.id for rule in RULES]
        assert len(ids) == len(set(ids)), "duplicate rule IDs"

    def test_security_rules_have_cwes(self):
        cwe_required = {"M001", "M002", "M003", "M004", "M005", "M006", "M007"}
        for rule in RULES:
            if rule.id in cwe_required:
                assert rule.cwe, f"{rule.id} must declare a CWE"

    def test_diagnostic_rules_have_no_cwe(self):
        diagnostic_ids = {
            "M101", "M102",
            "M201", "M202", "M203", "M204", "M205", "M206", "M207", "M208",
            # M212 carries CWE-835 and M211 carries CWE-362, excluded here
            "M209", "M210", "M213",
            "M214", "M215", "M216", "M217", "M218", "M219",
        }
        for rule in RULES:
            if rule.id in diagnostic_ids:
                assert rule.cwe is None


class TestGrammarLoading:
    """Behaviour when the grammar shared library cannot be located."""

    def test_grammar_unavailable_raises_clear_error(self, monkeypatch):
        from argus.scanners.mumps import parser as parser_module
        # Force every grammar lookup path to miss. monkeypatching
        # find_grammar is more robust than setting ARGUS_MUMPS_GRAMMAR
        # since the test harness may have a built grammar in
        # ~/.cache/argus/grammars/mumps.so from a prior local run.
        monkeypatch.setattr(parser_module, "find_grammar", lambda: None)
        monkeypatch.setattr(MumpsParser, "_parser", None)
        monkeypatch.setattr(MumpsParser, "_language", None)
        with pytest.raises(GrammarUnavailable):
            MumpsParser.parse(Path("x.m"), b" ; empty\n")


class TestTreeSitterVersionGating:
    """Dual-path grammar loading across the py-tree-sitter 0.22 API break (#248).

    py-tree-sitter 0.22 dropped the two-arg ``Language(path, name)``
    constructor and ``Parser.set_language``. ``_load_grammar`` selects the
    path by version; CI installs only one tree-sitter, so these tests pin the
    branch *selection* directly. The ≥0.22 ctypes/PyCapsule loader
    (``_grammar_capsule``) is exercised end-to-end against the real grammar
    in test_mumps_rules.py.
    """

    @staticmethod
    def _install_fake_tree_sitter(monkeypatch, calls):
        import sys
        import types

        class _Lang:
            def __init__(self, *args):
                calls["language_args"] = args

        class _Parser:
            def __init__(self, *args):
                calls["parser_args"] = args

            def set_language(self, language):
                calls["set_language"] = language

        module = types.ModuleType("tree_sitter")
        module.Language = _Lang
        module.Parser = _Parser
        monkeypatch.setitem(sys.modules, "tree_sitter", module)

    def test_minor_parses_major_minor(self, monkeypatch):
        from argus.scanners.mumps import parser as pm
        monkeypatch.setattr("importlib.metadata.version", lambda _n: "0.25.2")
        assert pm._tree_sitter_minor() == (0, 25)

    def test_modern_path_uses_capsule_and_parser_ctor(self, monkeypatch):
        from argus.scanners.mumps import parser as pm
        calls: dict = {}
        self._install_fake_tree_sitter(monkeypatch, calls)
        monkeypatch.setattr(pm, "_tree_sitter_minor", lambda: (0, 25))
        capsule = object()
        monkeypatch.setattr(pm, "_grammar_capsule", lambda _g: capsule)

        language, _parser = pm._load_grammar(Path("/x/mumps.so"))

        assert calls["language_args"] == (capsule,)   # Language(<capsule>)
        assert calls["parser_args"] == (language,)    # Parser(language)
        assert "set_language" not in calls            # set_language is gone in ≥0.22

    def test_legacy_path_uses_two_arg_language_and_set_language(self, monkeypatch):
        from argus.scanners.mumps import parser as pm
        calls: dict = {}
        self._install_fake_tree_sitter(monkeypatch, calls)
        monkeypatch.setattr(pm, "_tree_sitter_minor", lambda: (0, 21))

        language, _parser = pm._load_grammar(Path("/x/mumps.so"))

        assert calls["language_args"] == ("/x/mumps.so", "mumps")  # 2-arg form
        assert calls["parser_args"] == ()                          # no-arg ctor
        assert calls["set_language"] is language                   # bound via set_language


class _StubNode:
    """Empty AST node — has no children so walk() yields only itself
    and the call-graph builder finds zero labels / edges."""

    type = "stub_root"
    children: list = []
    is_named = True

    @property
    def parent(self):
        return None

    def child_by_field_name(self, _name):
        return None


class _StubTree:
    def __init__(self):
        self.root_node = _StubNode()


class _StubParsed:
    """Minimal ParsedSource stand-in for tests that mock MumpsParser.parse.

    Tests that drive the scan loop don't need a real tree-sitter tree;
    rules are mocked or stubbed at the loop level. The call-graph
    builder always runs in the new two-phase scan loop, so we give it
    an empty tree to walk (zero routines / edges) instead of None.
    """

    def __init__(self, path: Path):
        self.path = path
        self.source_bytes = b""
        self.source_text = ""
        self.tree = _StubTree()

    def location(self, node):
        return str(self.path)

    def node_text(self, node):
        return ""


class TestScanLoopBehaviour:
    """Drive the scan() loop with MumpsParser.parse mocked.

    These tests cover the path-walking, per-file dispatch, per-rule
    invocation, and the parse-failure / rule-crash recovery branches
    without needing a compiled grammar.
    """

    def _write_m_file(self, dir_path: Path, name: str = "test.m") -> Path:
        path = dir_path / name
        path.write_text("TEST ; stub\n Q\n")
        return path

    def test_scan_invokes_every_rule_per_file(self, tmp_path, monkeypatch):
        from argus.scanners.mumps import scanner as scanner_module
        self._write_m_file(tmp_path)

        captured: list[str] = []

        class _RecordingRule:
            id = "TEST-RULE"
            def analyze(self, parsed, config=None):
                captured.append(parsed.path.name)
                return []

        monkeypatch.setattr(MumpsParser, "parse", lambda p, b: _StubParsed(p))
        monkeypatch.setattr(scanner_module, "RULES", [_RecordingRule()])

        result = MumpsScanner().scan(str(tmp_path))
        assert result.metadata["files_scanned"] == 1
        assert captured == ["test.m"]

    def test_scan_re_raises_grammar_unavailable(self, tmp_path, monkeypatch):
        self._write_m_file(tmp_path)

        def _raise_grammar(p, b):
            raise GrammarUnavailable("no grammar")

        monkeypatch.setattr(MumpsParser, "parse", _raise_grammar)
        with pytest.raises(GrammarUnavailable):
            MumpsScanner().scan(str(tmp_path))

    def test_scan_emits_parse_failure_finding_on_oserror(self, tmp_path, monkeypatch):
        self._write_m_file(tmp_path)

        def _raise_os(p, b):
            raise OSError("disk full")

        monkeypatch.setattr(MumpsParser, "parse", _raise_os)
        result = MumpsScanner().scan(str(tmp_path))
        assert result.metadata["parse_failures"] == 1
        parse_fail = [f for f in result.findings if f.id == "M-PARSE-FAIL"]
        assert len(parse_fail) == 1
        assert "disk full" in parse_fail[0].description

    def test_scan_emits_rule_crash_finding_when_rule_raises(
        self, tmp_path, monkeypatch,
    ):
        from argus.scanners.mumps import scanner as scanner_module
        self._write_m_file(tmp_path)

        class _ExplodingRule:
            id = "BOOM"
            def analyze(self, parsed, config=None):
                raise RuntimeError("rule went sideways")

        monkeypatch.setattr(MumpsParser, "parse", lambda p, b: _StubParsed(p))
        monkeypatch.setattr(scanner_module, "RULES", [_ExplodingRule()])
        result = MumpsScanner().scan(str(tmp_path))
        crashes = [f for f in result.findings if f.id == "M-RULE-CRASH"]
        assert len(crashes) == 1
        assert "BOOM" in crashes[0].title
        assert crashes[0].metadata["rule"] == "BOOM"
        assert crashes[0].metadata["error_type"] == "RuntimeError"

    def test_scan_aggregates_findings_across_rules(self, tmp_path, monkeypatch):
        from argus.core.models import Finding, Severity
        from argus.scanners.mumps import scanner as scanner_module
        self._write_m_file(tmp_path)

        class _Rule:
            def __init__(self, rule_id):
                self.id = rule_id
            def analyze(self, parsed, config=None):
                return [Finding(
                    id=self.id,
                    severity=Severity.INFO,
                    title="stub",
                    location=parsed.location(None),
                    scanner="m",
                )]

        monkeypatch.setattr(MumpsParser, "parse", lambda p, b: _StubParsed(p))
        monkeypatch.setattr(scanner_module, "RULES", [_Rule("A"), _Rule("B")])
        result = MumpsScanner().scan(str(tmp_path))
        ids = sorted(f.id for f in result.findings)
        assert ids == ["A", "B"]

    def test_scan_filters_only_m_extension_files(self, tmp_path, monkeypatch):
        from argus.scanners.mumps import scanner as scanner_module
        (tmp_path / "ignore.txt").write_text("not mumps\n")
        (tmp_path / "code.m").write_text("CODE ; ok\n Q\n")
        seen: list[str] = []

        class _Rule:
            id = "X"
            def analyze(self, parsed, config=None):
                seen.append(parsed.path.name)
                return []

        monkeypatch.setattr(MumpsParser, "parse", lambda p, b: _StubParsed(p))
        monkeypatch.setattr(scanner_module, "RULES", [_Rule()])
        MumpsScanner().scan(str(tmp_path))
        assert seen == ["code.m"]


class TestBuildArgs:
    """``build_args`` shape — the container CLI argv the engine appends
    to the ``scanner-mumps`` image's ENTRYPOINT after stripping argv[0]."""

    def test_returns_argus_scan_mumps_with_path_and_output(self):
        from argus.core.scanner_template import ScanPaths
        args = MumpsScanner().build_args(
            ScanPaths(workspace="/workspace", output="/output/results.json"),
        )
        assert args[0] == "argus"  # sentinel stripped by engine
        assert "scan" in args and "mumps" in args
        assert "--path" in args
        assert args[args.index("--path") + 1] == "/workspace"
        assert "--output-dir" in args
        assert args[args.index("--output-dir") + 1] == "/output"
        assert "--format" in args
        assert args[args.index("--format") + 1] == "json"
        # Flat output so the engine's top-level glob finds argus-results.json.
        assert "--no-timestamp" in args

    def test_extra_args_appended(self):
        from argus.core.scanner_template import ScanPaths
        args = MumpsScanner().build_args(
            ScanPaths(workspace="/w", output="/o/results.json"),
            {"extra_args": ["--verbose", "--rule", "M001"]},
        )
        assert args[-3:] == ["--verbose", "--rule", "M001"]

    def test_handles_missing_output_path(self):
        from argus.core.scanner_template import ScanPaths
        args = MumpsScanner().build_args(ScanPaths(workspace="/w", output=""))
        assert args[args.index("--output-dir") + 1] == "/output"


class TestParseResults:
    """``parse_results`` lifts mumps findings out of a container run's
    nested ``argus-results.json`` report. The container runs ``argus scan
    mumps`` (which emits the standard Argus JSON report); the engine hands
    that file back here to rebuild ``Finding`` objects."""

    def _write_report(self, tmp_path):
        import json
        report = {
            "results": [
                {
                    "scanner": "mumps",
                    "findings": [
                        {
                            "id": "M001",
                            "severity": "high",
                            "title": "XECUTE of tainted expression",
                            "description": "desc",
                            "location": "/workspace/EVIL.m:3:2",
                            "cwe": "CWE-95",
                            "cve": None,
                            "scanner": "mumps",
                            "metadata": {"taint_sources": ["READ"]},
                        },
                        {
                            "id": "B100",
                            "severity": "low",
                            "title": "not a mumps finding",
                            "location": "/workspace/x.py:1",
                            "scanner": "bandit",
                        },
                    ],
                },
            ],
        }
        (tmp_path / "argus-results.json").write_text(json.dumps(report))
        (tmp_path / "argus-audit.json").write_text(
            json.dumps({"argus_version": "x", "scan_id": "y"})
        )

    def test_reconstructs_only_mumps_findings(self, tmp_path):
        self._write_report(tmp_path)
        findings = MumpsScanner().parse_results(tmp_path / "argus-results.json")
        assert len(findings) == 1
        f = findings[0]
        assert f.id == "M001"
        assert f.severity == Severity.HIGH
        assert f.cwe == "CWE-95"
        assert f.scanner == "mumps"
        # The /workspace mount prefix is stripped to a repo-relative path.
        assert f.location == "EVIL.m:3:2"
        assert f.metadata.get("taint_sources") == ["READ"]

    def test_resolves_to_results_when_handed_audit_manifest(self, tmp_path):
        # The engine globs *.json and may hand us argus-audit.json first;
        # parse_results must still read findings from the sibling results
        # file rather than returning nothing.
        self._write_report(tmp_path)
        findings = MumpsScanner().parse_results(tmp_path / "argus-audit.json")
        assert [f.id for f in findings] == ["M001"]


class TestToolVersion:
    """``tool_version()`` reports the py-tree-sitter version when
    installed, ``None`` otherwise. Mock both branches because the test
    environment's tree_sitter presence is not guaranteed."""

    def test_returns_none_when_tree_sitter_missing(self, monkeypatch):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "tree_sitter":
                raise ImportError("not installed in this env")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        assert MumpsScanner().tool_version() is None

    def test_returns_version_when_available(self, monkeypatch):
        import sys
        import types
        fake = types.ModuleType("tree_sitter")
        fake.__version__ = "0.21.3"
        monkeypatch.setitem(sys.modules, "tree_sitter", fake)
        assert MumpsScanner().tool_version() == "0.21.3"
