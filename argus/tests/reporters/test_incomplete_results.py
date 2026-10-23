"""Every reporter shows an incomplete result as incomplete, never clean (#492)."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from argus.core.models import Finding, ScanResult, ScanSummary, Severity
from argus.reporters.json_report import JsonReporter
from argus.reporters.junit import JUnitReporter
from argus.reporters.markdown import MarkdownReporter
from argus.reporters.sarif import SarifReporter
from argus.reporters.terminal import TerminalReporter

REASON = (
    "trivy did not evaluate the SBOM's 3 OS package(s) (amzn-2023); "
    "it read the OS as 'none'."
)


def _summary(threshold=None, findings=None):
    return ScanSummary(
        results=[
            ScanResult(
                scanner="trivy",
                findings=findings or [],
                metadata={"incomplete": True, "incomplete_reason": REASON},
            ),
            ScanResult(scanner="grype"),
        ],
        severity_threshold=threshold,
    )


class TestTerminal:
    def test_status_is_incomplete_not_pass(self, capsys):
        TerminalReporter().report(_summary())
        out = capsys.readouterr().out
        assert "Status: INCOMPLETE" in out
        assert "Status: PASS" not in out
        assert REASON in out

    def test_scanner_row_is_labelled(self, capsys):
        TerminalReporter().report(_summary())
        out = capsys.readouterr().out
        assert "Scanner: trivy (0 findings, incomplete)" in out

    def test_threshold_failure_still_reads_fail(self, capsys):
        finding = Finding(id="CVE-1", severity=Severity.HIGH, title="x")
        TerminalReporter().report(_summary(threshold=Severity.HIGH, findings=[finding]))
        out = capsys.readouterr().out
        assert "Status: FAIL (findings above threshold: high)" in out
        assert REASON in out


class TestMarkdown:
    def test_status_and_health_section(self, tmp_path):
        text = MarkdownReporter().report(_summary(), tmp_path).read_text()
        assert "**Status**: INCOMPLETE" in text
        assert "PASS" not in text.split("## Summary")[0]
        assert "## Scanner Health" in text
        assert f"- `trivy`: {REASON}" in text


class TestSarif:
    def test_incomplete_run_carries_an_error_notification(self, tmp_path):
        sarif = json.loads(SarifReporter().report(_summary(), tmp_path).read_text())
        runs = {r["tool"]["driver"]["name"]: r for r in sarif["runs"]}
        trivy = runs["argus/trivy"]
        assert trivy["properties"]["incomplete"] is True
        invocation = trivy["invocations"][0]
        assert invocation["executionSuccessful"] is True
        note = invocation["toolExecutionNotifications"][0]
        assert note["level"] == "error"
        assert note["message"]["text"] == REASON
        # Complete runs keep their old shape.
        assert "invocations" not in runs["argus/grype"]
        assert "properties" not in runs["argus/grype"]


class TestJunit:
    def test_incomplete_scanner_is_an_error_not_clean(self, tmp_path):
        root = ET.parse(str(JUnitReporter().report(_summary(), tmp_path))).getroot()
        trivy = next(s for s in root.iter("testsuite") if s.get("name") == "trivy")
        names = [c.get("name") for c in trivy.iter("testcase")]
        assert "trivy: clean" not in names
        error = trivy.find("testcase/error")
        assert error.get("type") == "incomplete"
        assert error.get("message") == REASON
        assert trivy.get("errors") == "1"


class TestJson:
    def test_summary_level_fields(self, tmp_path):
        data = json.loads(JsonReporter().report(_summary(), tmp_path).read_text())
        assert data["passed"] is False
        assert data["complete"] is False
        assert data["incomplete_scanners"] == ["trivy"]
