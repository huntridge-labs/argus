"""Unit tests for ``argus.scanners.m.MScanner``.

These tests cover the scanner protocol surface and the rule registry
shape. They do **not** require the compiled tree-sitter-mumps grammar;
rule-level integration tests live in ``test_m_rules.py`` and skip when
the grammar shared library is unavailable.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.scanners import SCANNER_REGISTRY, get_scanner
from argus.scanners.m import MScanner
from argus.scanners.m.parser import GrammarUnavailable, MParser
from argus.scanners.m.rules import RULES


class TestMScannerProtocol:
    """The Scanner protocol surface — names, registry, helpers."""

    def test_registered_in_global_registry(self):
        assert "m" in SCANNER_REGISTRY
        assert SCANNER_REGISTRY["m"] is MScanner

    def test_get_scanner_returns_instance(self):
        scanner = get_scanner("m")
        assert isinstance(scanner, MScanner)

    def test_scanner_metadata(self):
        scanner = MScanner()
        assert scanner.name == "m"
        assert scanner.category == "sast"
        assert "mumps" in scanner.languages

    def test_install_command_mentions_extras_or_container(self):
        scanner = MScanner()
        hint = scanner.install_command()
        assert hint is not None
        assert "argus-security[m]" in hint or "scanner-m" in hint


class TestMScannerScan:
    """``scan()`` boundary behaviours that don't need the grammar."""

    def test_returns_empty_when_path_missing(self, tmp_path):
        scanner = MScanner()
        result = scanner.scan(str(tmp_path / "does-not-exist"))
        assert result.scanner == "m"
        assert result.findings == []
        assert "error" in result.metadata

    def test_returns_empty_when_no_m_files(self, tmp_path):
        (tmp_path / "ignore.py").write_text("print('hi')\n")
        (tmp_path / "ignore.txt").write_text("hello\n")
        scanner = MScanner()
        result = scanner.scan(str(tmp_path))
        assert result.findings == []
        assert result.metadata["files_scanned"] == 0

    def test_extension_filter_walks_subdirectories(self, tmp_path):
        nested = tmp_path / "sub" / "deeper"
        nested.mkdir(parents=True)
        m_file = nested / "test.m"
        m_file.write_text("TEST ;empty\n Q\n")

        scanner = MScanner()
        # Locate the file via the iterator without invoking parsing.
        found = list(scanner._iter_sources(tmp_path, (".m",)))
        assert m_file in found

    def test_iter_sources_accepts_single_file_target(self, tmp_path):
        m_file = tmp_path / "one.m"
        m_file.write_text("ONE ; ok\n Q\n")
        non_m = tmp_path / "one.txt"
        non_m.write_text("ignore\n")

        scanner = MScanner()
        assert list(scanner._iter_sources(m_file, (".m",))) == [m_file]
        assert list(scanner._iter_sources(non_m, (".m",))) == []

    def test_is_available_true_when_grammar_present(self, monkeypatch):
        from argus.scanners.m import parser as parser_module
        monkeypatch.setattr(parser_module, "tree_sitter_available", lambda: True)
        # MScanner.is_available re-imports via the module, so patch the
        # symbol the scanner pulled at import time too.
        from argus.scanners.m import scanner as scanner_module
        monkeypatch.setattr(scanner_module, "tree_sitter_available", lambda: True)
        assert MScanner().is_available() is True


class TestRuleRegistry:
    """Rule registry shape — IDs, severities, distinct identifiers."""

    def test_four_rules_registered(self):
        ids = {rule.id for rule in RULES}
        assert ids == {"M001", "M002", "M004", "M101"}

    def test_rule_ids_are_distinct(self):
        ids = [rule.id for rule in RULES]
        assert len(ids) == len(set(ids)), "duplicate rule IDs"

    def test_security_rules_have_cwes(self):
        cwe_required = {"M001", "M002", "M004"}
        for rule in RULES:
            if rule.id in cwe_required:
                assert rule.cwe, f"{rule.id} must declare a CWE"

    def test_diagnostic_rules_have_no_cwe(self):
        diagnostic_ids = {"M101"}
        for rule in RULES:
            if rule.id in diagnostic_ids:
                assert rule.cwe is None


class TestGrammarLoading:
    """Behaviour when the grammar shared library cannot be located."""

    def test_grammar_unavailable_raises_clear_error(self, monkeypatch):
        monkeypatch.setenv("ARGUS_M_GRAMMAR", "/nonexistent/path/mumps.so")
        # Bust the parser cache so the env override is picked up.
        monkeypatch.setattr(MParser, "_parser", None)
        monkeypatch.setattr(MParser, "_language", None)
        # Inject a tree_sitter shim if not installed, so the failure
        # path we exercise is "grammar missing", not "py-tree-sitter
        # missing". Both routes raise GrammarUnavailable, but this is
        # the route the test intentionally documents.
        with pytest.raises(GrammarUnavailable):
            MParser.parse(Path("x.m"), b" ; empty\n")


class _StubParsed:
    """Minimal ParsedSource stand-in for tests that mock MParser.parse.

    Tests that drive the scan loop don't need a real tree-sitter tree;
    rules are mocked or stubbed at the loop level. Carries the path
    so any finding constructor that wants ``location`` still works.
    """

    def __init__(self, path: Path):
        self.path = path
        self.source_bytes = b""
        self.tree = None

    def location(self, node):
        return str(self.path)


class TestScanLoopBehaviour:
    """Drive the scan() loop with MParser.parse mocked.

    These tests cover the path-walking, per-file dispatch, per-rule
    invocation, and the parse-failure / rule-crash recovery branches
    without needing a compiled grammar.
    """

    def _write_m_file(self, dir_path: Path, name: str = "test.m") -> Path:
        path = dir_path / name
        path.write_text("TEST ; stub\n Q\n")
        return path

    def test_scan_invokes_every_rule_per_file(self, tmp_path, monkeypatch):
        from argus.scanners.m import scanner as scanner_module
        self._write_m_file(tmp_path)

        captured: list[str] = []

        class _RecordingRule:
            id = "TEST-RULE"
            def analyze(self, parsed):
                captured.append(parsed.path.name)
                return []

        monkeypatch.setattr(MParser, "parse", lambda p, b: _StubParsed(p))
        monkeypatch.setattr(scanner_module, "RULES", [_RecordingRule()])

        result = MScanner().scan(str(tmp_path))
        assert result.metadata["files_scanned"] == 1
        assert captured == ["test.m"]

    def test_scan_re_raises_grammar_unavailable(self, tmp_path, monkeypatch):
        self._write_m_file(tmp_path)

        def _raise_grammar(p, b):
            raise GrammarUnavailable("no grammar")

        monkeypatch.setattr(MParser, "parse", _raise_grammar)
        with pytest.raises(GrammarUnavailable):
            MScanner().scan(str(tmp_path))

    def test_scan_emits_parse_failure_finding_on_oserror(self, tmp_path, monkeypatch):
        self._write_m_file(tmp_path)

        def _raise_os(p, b):
            raise OSError("disk full")

        monkeypatch.setattr(MParser, "parse", _raise_os)
        result = MScanner().scan(str(tmp_path))
        assert result.metadata["parse_failures"] == 1
        parse_fail = [f for f in result.findings if f.id == "M-PARSE-FAIL"]
        assert len(parse_fail) == 1
        assert "disk full" in parse_fail[0].description

    def test_scan_emits_rule_crash_finding_when_rule_raises(
        self, tmp_path, monkeypatch,
    ):
        from argus.scanners.m import scanner as scanner_module
        self._write_m_file(tmp_path)

        class _ExplodingRule:
            id = "BOOM"
            def analyze(self, parsed):
                raise RuntimeError("rule went sideways")

        monkeypatch.setattr(MParser, "parse", lambda p, b: _StubParsed(p))
        monkeypatch.setattr(scanner_module, "RULES", [_ExplodingRule()])
        result = MScanner().scan(str(tmp_path))
        crashes = [f for f in result.findings if f.id == "M-RULE-CRASH"]
        assert len(crashes) == 1
        assert "BOOM" in crashes[0].title
        assert crashes[0].metadata["rule"] == "BOOM"
        assert crashes[0].metadata["error_type"] == "RuntimeError"

    def test_scan_aggregates_findings_across_rules(self, tmp_path, monkeypatch):
        from argus.core.models import Finding, Severity
        from argus.scanners.m import scanner as scanner_module
        self._write_m_file(tmp_path)

        class _Rule:
            def __init__(self, rule_id):
                self.id = rule_id
            def analyze(self, parsed):
                return [Finding(
                    id=self.id,
                    severity=Severity.INFO,
                    title="stub",
                    location=parsed.location(None),
                    scanner="m",
                )]

        monkeypatch.setattr(MParser, "parse", lambda p, b: _StubParsed(p))
        monkeypatch.setattr(scanner_module, "RULES", [_Rule("A"), _Rule("B")])
        result = MScanner().scan(str(tmp_path))
        ids = sorted(f.id for f in result.findings)
        assert ids == ["A", "B"]

    def test_scan_filters_only_m_extension_files(self, tmp_path, monkeypatch):
        from argus.scanners.m import scanner as scanner_module
        (tmp_path / "ignore.txt").write_text("not mumps\n")
        (tmp_path / "code.m").write_text("CODE ; ok\n Q\n")
        seen: list[str] = []

        class _Rule:
            id = "X"
            def analyze(self, parsed):
                seen.append(parsed.path.name)
                return []

        monkeypatch.setattr(MParser, "parse", lambda p, b: _StubParsed(p))
        monkeypatch.setattr(scanner_module, "RULES", [_Rule()])
        MScanner().scan(str(tmp_path))
        assert seen == ["code.m"]


class TestBuildArgs:
    """``build_args`` shape — the container CLI argv the engine appends
    to the ``scanner-m`` image's ENTRYPOINT after stripping argv[0]."""

    def test_returns_argus_scan_m_with_path_and_output(self):
        from argus.core.scanner_template import ScanPaths
        args = MScanner().build_args(
            ScanPaths(workspace="/workspace", output="/output/results.json"),
        )
        assert args[0] == "argus"  # sentinel stripped by engine
        assert "scan" in args and "m" in args
        assert "--path" in args
        assert args[args.index("--path") + 1] == "/workspace"
        assert "--output-dir" in args
        assert args[args.index("--output-dir") + 1] == "/output"
        assert "--format" in args
        assert args[args.index("--format") + 1] == "json"

    def test_extra_args_appended(self):
        from argus.core.scanner_template import ScanPaths
        args = MScanner().build_args(
            ScanPaths(workspace="/w", output="/o/results.json"),
            {"extra_args": ["--verbose", "--rule", "M001"]},
        )
        assert args[-3:] == ["--verbose", "--rule", "M001"]

    def test_handles_missing_output_path(self):
        from argus.core.scanner_template import ScanPaths
        args = MScanner().build_args(ScanPaths(workspace="/w", output=""))
        assert args[args.index("--output-dir") + 1] == "/output"


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
        assert MScanner().tool_version() is None

    def test_returns_version_when_available(self, monkeypatch):
        import sys
        import types
        fake = types.ModuleType("tree_sitter")
        fake.__version__ = "0.21.3"
        monkeypatch.setitem(sys.modules, "tree_sitter", fake)
        assert MScanner().tool_version() == "0.21.3"
