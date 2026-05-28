"""Integration tests for MUMPS scanner rules.

These tests parse real .m fixture files and assert each rule fires (or
does not fire) as documented. They require the compiled
tree-sitter-mumps grammar shared library to be reachable — locally
that's ``scripts/build-m-grammar.sh``; in CI / container execution
it's the ``scanner-m`` image. When the grammar is not installed all
tests in this module skip cleanly so the unit-level coverage in
``test_m_scanner.py`` still runs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.core.models import Severity
from argus.core.redact import REDACTED_PLACEHOLDER
from argus.scanners.m import MScanner
from argus.scanners.m.parser import tree_sitter_available


pytestmark = pytest.mark.skipif(
    not tree_sitter_available(),
    reason=(
        "MUMPS tree-sitter grammar not installed. Run "
        "scripts/build-m-grammar.sh or use the scanner-m container."
    ),
)


@pytest.fixture
def m_fixtures_dir() -> Path:
    return Path(__file__).parent / "m" / "fixtures"


def _scan(path: Path):
    return MScanner().scan(str(path))


def _findings_with_id(result, rule_id: str):
    return [f for f in result.findings if f.id == rule_id]


class TestM001XECUTEInjection:
    def test_fires_on_read_tainted_xecute(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m001_xecute_taint.m")
        hits = _findings_with_id(result, "M001")
        assert hits, "M001 must fire when XECUTE references a READ-tainted var"
        assert all(f.severity == Severity.HIGH for f in hits)
        assert all(f.cwe == "CWE-95" for f in hits)

    def test_clean_xecute_does_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m001_xecute_clean.m")
        assert _findings_with_id(result, "M001") == []


class TestM002IndirectionInjection:
    def test_fires_on_variable_indirection(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m002_indirection.m")
        hits = _findings_with_id(result, "M002")
        assert hits, "M002 must fire on @VAR indirection"
        assert all(f.severity == Severity.HIGH for f in hits)
        assert all(f.cwe == "CWE-94" for f in hits)

    def test_clean_routine_does_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m002_clean.m")
        assert _findings_with_id(result, "M002") == []


class TestM004HardcodedCredentials:
    def test_fires_on_credential_shaped_globals(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m004_hardcoded.m")
        hits = _findings_with_id(result, "M004")
        assert len(hits) >= 2, "M004 must fire on each credential-shaped SET"
        assert all(f.severity == Severity.CRITICAL for f in hits)
        assert all(f.cwe == "CWE-798" for f in hits)

    def test_literal_value_is_redacted(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m004_hardcoded.m")
        hits = _findings_with_id(result, "M004")
        for finding in hits:
            assert "hunter2" not in finding.title
            assert "hunter2" not in finding.description
            assert "hunter2" not in str(finding.metadata)
            assert finding.metadata.get("value") == REDACTED_PLACEHOLDER

    def test_non_credential_globals_do_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m004_clean.m")
        assert _findings_with_id(result, "M004") == []


class TestM101DuplicateLabel:
    def test_fires_on_duplicate_label(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m101_dup_label.m")
        hits = _findings_with_id(result, "M101")
        assert len(hits) == 1, "M101 fires once — on the duplicate, not the first"
        finding = hits[0]
        assert finding.severity == Severity.INFO
        assert finding.metadata.get("label") == "DOTHING"
        assert finding.metadata.get("first_declaration"), (
            "M101 must record the first declaration's location"
        )

    def test_unique_labels_do_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m101_unique_labels.m")
        assert _findings_with_id(result, "M101") == []


class TestScanResultShape:
    def test_metadata_records_files_scanned_and_rules(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m002_indirection.m")
        assert result.metadata["files_scanned"] == 1
        assert "M001" in result.metadata["rules_run"]
        assert "M101" in result.metadata["rules_run"]
