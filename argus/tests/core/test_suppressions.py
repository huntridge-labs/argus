"""Unit tests for argus.core.suppressions (Phase 7 — bulk triage + VEX).

UI-free: the VEX builders / merge / ignore-entry formatters are pure; the
writeback is exercised with tmp_path. No Textual, no network.
"""

from __future__ import annotations

import json

from argus.core.suppressions import (
    OPENVEX_CONTEXT,
    STATUS_AFFECTED,
    STATUS_NOT_AFFECTED,
    STATUS_UNDER_INVESTIGATION,
    TriageDecision,
    build_vex_document,
    decision_for,
    gitleaksignore_entries,
    merge_vex_documents,
    to_vex_statement,
    trivyignore_entries,
    write_suppressions,
)


class TestDecisionFor:
    def test_false_positive_maps_to_not_affected(self):
        d = decision_for("false_positive", cve="CVE-1-1", reason="test code")
        assert d.status == STATUS_NOT_AFFECTED
        assert d.justification == "vulnerable_code_not_present"

    def test_accept_risk_is_affected(self):
        d = decision_for("accept_risk", cve="CVE-1-1", reason="mitigated at WAF")
        assert d.status == STATUS_AFFECTED and d.justification == ""

    def test_unknown_action_is_under_investigation(self):
        assert decision_for("???", cve="CVE-1-1").status == STATUS_UNDER_INVESTIGATION


class TestToVexStatement:
    def test_not_affected_carries_justification_and_impact(self):
        d = TriageDecision("CVE-1-1", product="pkg:pypi/x@1", status=STATUS_NOT_AFFECTED,
                           justification="vulnerable_code_not_present", reason="dead path")
        stmt = to_vex_statement(d)
        assert stmt["status"] == STATUS_NOT_AFFECTED
        assert stmt["justification"] == "vulnerable_code_not_present"
        assert stmt["impact_statement"] == "dead path"
        assert stmt["products"] == [{"@id": "pkg:pypi/x@1"}]

    def test_affected_carries_action_statement(self):
        d = TriageDecision("CVE-1-1", status=STATUS_AFFECTED, reason="risk accepted Q3")
        stmt = to_vex_statement(d)
        assert stmt["action_statement"] == "risk accepted Q3"
        assert "products" not in stmt  # no product → omit

    def test_timestamp_passthrough(self):
        d = TriageDecision("CVE-1-1", timestamp="2026-06-13T00:00:00+00:00")
        assert to_vex_statement(d)["timestamp"] == "2026-06-13T00:00:00+00:00"


class TestBuildVexDocument:
    def test_document_shape(self):
        doc = build_vex_document(
            [decision_for("false_positive", cve="CVE-1-1", reason="x")],
            timestamp="2026-06-13T00:00:00+00:00",
        )
        assert doc["@context"] == OPENVEX_CONTEXT
        assert doc["version"] == 1
        assert doc["timestamp"] == "2026-06-13T00:00:00+00:00"
        assert doc["statements"][0]["vulnerability"]["name"] == "CVE-1-1"

    def test_deterministic_id_for_same_decisions(self):
        decisions = [decision_for("false_positive", cve="CVE-1-1", reason="x")]
        a = build_vex_document(decisions, timestamp="T")
        b = build_vex_document(decisions, timestamp="T")
        assert a["@id"] == b["@id"]

    def test_id_changes_with_content(self):
        a = build_vex_document([decision_for("false_positive", cve="CVE-1-1")], timestamp="T")
        b = build_vex_document([decision_for("false_positive", cve="CVE-2-2")], timestamp="T")
        assert a["@id"] != b["@id"]

    def test_skips_decisions_without_cve(self):
        doc = build_vex_document([
            TriageDecision("", product="fp:1", status=STATUS_NOT_AFFECTED),  # secret finding
            decision_for("false_positive", cve="CVE-1-1"),
        ], timestamp="T")
        assert len(doc["statements"]) == 1
        assert doc["statements"][0]["vulnerability"]["name"] == "CVE-1-1"


class TestMergeVexDocuments:
    def test_new_decision_replaces_same_key(self):
        old = build_vex_document(
            [TriageDecision("CVE-1-1", product="pkg:pypi/x@1", status=STATUS_AFFECTED)],
            timestamp="T1",
        )
        new = build_vex_document(
            [TriageDecision("CVE-1-1", product="pkg:pypi/x@1", status=STATUS_NOT_AFFECTED,
                            justification="vulnerable_code_not_present")],
            timestamp="T2",
        )
        merged = merge_vex_documents(old, new)
        assert len(merged["statements"]) == 1
        assert merged["statements"][0]["status"] == STATUS_NOT_AFFECTED
        assert merged["version"] == 2

    def test_distinct_keys_accumulate(self):
        old = build_vex_document([TriageDecision("CVE-1-1", product="a")], timestamp="T")
        new = build_vex_document([TriageDecision("CVE-2-2", product="b")], timestamp="T")
        merged = merge_vex_documents(old, new)
        assert len(merged["statements"]) == 2


class TestIgnoreEntries:
    def test_trivyignore_includes_reason_and_cve(self):
        lines = trivyignore_entries([decision_for("false_positive", cve="CVE-1-1", reason="vendored")])
        assert "# vendored" in lines and "CVE-1-1" in lines

    def test_trivyignore_skips_under_investigation(self):
        assert trivyignore_entries([decision_for("investigating", cve="CVE-1-1")]) == []

    def test_gitleaksignore_uses_fingerprint(self):
        d = TriageDecision("", product="abc123:rule:1", status=STATUS_NOT_AFFECTED, scanner="gitleaks")
        assert "abc123:rule:1" in gitleaksignore_entries([d])

    def test_gitleaksignore_skips_non_gitleaks(self):
        d = TriageDecision("CVE-1-1", product="pkg:pypi/x@1", status=STATUS_NOT_AFFECTED, scanner="trivy")
        assert gitleaksignore_entries([d]) == []


class TestWriteSuppressions:
    def test_writes_vex_and_trivyignore(self, tmp_path):
        decisions = [decision_for("false_positive", cve="CVE-1-1", reason="vendored", scanner="trivy")]
        written = write_suppressions(tmp_path, decisions, timestamp="T")
        assert (tmp_path / "argus-results.openvex.json").is_file()
        assert written["openvex"] == tmp_path / "argus-results.openvex.json"
        assert written["trivyignore"] == tmp_path / ".trivyignore"
        assert "CVE-1-1" in (tmp_path / ".trivyignore").read_text()

    def test_merges_into_existing_vex(self, tmp_path):
        write_suppressions(tmp_path, [decision_for("false_positive", cve="CVE-1-1")], timestamp="T1")
        write_suppressions(tmp_path, [decision_for("false_positive", cve="CVE-2-2")], timestamp="T2")
        doc = json.loads((tmp_path / "argus-results.openvex.json").read_text())
        names = {s["vulnerability"]["name"] for s in doc["statements"]}
        assert names == {"CVE-1-1", "CVE-2-2"}
        assert doc["version"] == 2

    def test_appends_without_clobbering_trivyignore(self, tmp_path):
        (tmp_path / ".trivyignore").write_text("# pre-existing\nCVE-0-0\n")
        write_suppressions(tmp_path, [decision_for("false_positive", cve="CVE-1-1")], timestamp="T")
        text = (tmp_path / ".trivyignore").read_text()
        assert "CVE-0-0" in text and "CVE-1-1" in text

    def test_under_investigation_writes_no_ignore(self, tmp_path):
        written = write_suppressions(tmp_path, [decision_for("investigating", cve="CVE-1-1")], timestamp="T")
        # VEX still records it; no ignore entry though.
        assert "openvex" in written
        assert not (tmp_path / ".trivyignore").exists()
