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

    def test_fires_on_zargv_tainted_xecute(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m001_zargv_taint.m")
        hits = _findings_with_id(result, "M001")
        assert hits, "M001 must recognize $ZARGV as a taint source"
        assert all(f.severity == Severity.HIGH for f in hits)

    def test_fires_on_cgi_tainted_xecute(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m001_cgi_taint.m")
        hits = _findings_with_id(result, "M001")
        assert hits, "M001 must recognize ^%CGI(...) as a taint source"
        assert all(f.severity == Severity.HIGH for f in hits)


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


class TestM003OpenUseInjection:
    def test_fires_on_tainted_open_argument(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m003_open_taint.m")
        hits = _findings_with_id(result, "M003")
        assert hits, "M003 must fire when OPEN/USE references a READ-tainted var"
        assert all(f.severity == Severity.HIGH for f in hits)
        assert all(f.cwe == "CWE-78" for f in hits)
        commands = {f.metadata.get("command") for f in hits}
        # Both OPEN and USE in the fixture should trip the rule
        assert "OPEN" in commands or "USE" in commands

    def test_constant_device_does_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m003_open_clean.m")
        assert _findings_with_id(result, "M003") == []

    def test_pipe_device_bumps_to_critical(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m003_pipe_taint.m")
        hits = _findings_with_id(result, "M003")
        assert hits, "M003 must fire on a tainted PIPE-device argument"
        pipe_hits = [f for f in hits if f.metadata.get("device_class") == "PIPE"]
        assert pipe_hits, "PIPE detection must classify the device"
        assert all(f.severity == Severity.CRITICAL for f in pipe_hits), (
            "PIPE-bound OPEN/USE with tainted argument is OS-level RCE, must be CRITICAL"
        )


class TestM005TaintedDispatch:
    def test_fires_on_tainted_do_indirection(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m005_dispatch_taint.m")
        hits = _findings_with_id(result, "M005")
        assert hits, "M005 must fire when DO indirection references a READ-tainted var"
        assert all(f.severity == Severity.CRITICAL for f in hits)
        assert all(f.cwe == "CWE-95" for f in hits)
        # Taint sources should be recorded for downstream triage
        for finding in hits:
            assert finding.metadata.get("taint_sources"), (
                "M005 must record the tainted variable name(s)"
            )

    def test_static_dispatch_does_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m005_dispatch_clean.m")
        assert _findings_with_id(result, "M005") == []


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


class TestM102UnreachableAfterQuit:
    def test_fires_on_unconditional_break(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m102_unreachable.m")
        hits = _findings_with_id(result, "M102")
        assert len(hits) == 2, (
            "M102 must fire once per unconditional break with a following command"
        )
        assert all(f.severity == Severity.INFO for f in hits)
        break_commands = {f.metadata.get("break_command") for f in hits}
        assert "Q" in break_commands or "H" in break_commands

    def test_postconditional_break_does_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m102_postconditional.m")
        # Only the final unconditional Q at end-of-routine could
        # theoretically fire, but it has no following command and so
        # the rule should produce no findings on this fixture.
        assert _findings_with_id(result, "M102") == []


class TestM006ExternalCallInjection:
    def test_fires_on_tainted_external_call(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m006_external_taint.m")
        hits = _findings_with_id(result, "M006")
        assert hits, "M006 must fire when $& call receives a tainted argument"
        assert all(f.severity == Severity.HIGH for f in hits)
        assert all(f.cwe == "CWE-78" for f in hits)
        for finding in hits:
            assert finding.metadata.get("function", "").startswith("$&")

    def test_pure_external_call_does_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m006_external_clean.m")
        assert _findings_with_id(result, "M006") == []


class TestM201UnresolvedLabel:
    def test_fires_on_missing_label_reference(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m201_missing.m")
        hits = _findings_with_id(result, "M201")
        assert hits, "M201 must fire when DO references an undeclared label"
        labels = {f.metadata.get("label") for f in hits}
        assert "MISSING" in labels

    def test_resolved_labels_do_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m201_resolved.m")
        assert _findings_with_id(result, "M201") == []


class TestM202RoutineNameMismatch:
    def test_fires_on_mismatch(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m202mismatch.m")
        hits = _findings_with_id(result, "M202")
        assert hits, "M202 must fire when first label differs from filename stem"
        finding = hits[0]
        assert finding.metadata.get("declared") == "WRONGNAME"
        assert finding.metadata.get("expected") == "M202MISMATCH"

    def test_matching_name_does_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m202clean.m")
        assert _findings_with_id(result, "M202") == []


class TestM205LabelFallthrough:
    def test_fires_on_fallthrough(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m205_fallthrough.m")
        hits = _findings_with_id(result, "M205")
        assert hits, "M205 must fire when a label body falls through"
        finding = hits[0]
        assert finding.metadata.get("preceding_label") == "LABELA"
        assert finding.metadata.get("fallthrough_into") == "LABELB"

    def test_terminated_labels_do_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m205_terminated.m")
        assert _findings_with_id(result, "M205") == []


class TestScanResultShape:
    def test_metadata_records_files_scanned_and_rules(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m002_indirection.m")
        assert result.metadata["files_scanned"] == 1
        assert "M001" in result.metadata["rules_run"]
        assert "M101" in result.metadata["rules_run"]
