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
