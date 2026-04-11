"""Tests for argus.reporters.terminal — TerminalReporter."""

import pytest

from argus.core.models import Finding, ScanResult, ScanSummary, Severity
from argus.reporters.terminal import TerminalReporter


def _make_summary(threshold=None):
    """Create a ScanSummary with known findings for testing."""
    result = ScanResult(
        scanner="bandit",
        findings=[
            Finding(id="B102", severity=Severity.HIGH, title="Use of exec"),
            Finding(id="B105", severity=Severity.MEDIUM, title="Hardcoded password"),
            Finding(id="B101", severity=Severity.LOW, title="Assert used"),
        ],
    )
    return ScanSummary(
        results=[result],
        severity_threshold=threshold,
    )


class TestTerminalReporter:
    """Test TerminalReporter output."""

    def test_report_prints_header(self, capsys):
        reporter = TerminalReporter()
        summary = _make_summary()
        reporter.report(summary)

        output = capsys.readouterr().out
        assert "Argus Security Scan Results" in output

    def test_report_prints_summary_counts(self, capsys):
        reporter = TerminalReporter()
        summary = _make_summary()
        reporter.report(summary)

        output = capsys.readouterr().out
        assert "Critical" in output
        assert "High" in output
        assert "Medium" in output
        assert "Low" in output
        assert "Total" in output

    def test_report_prints_scanner_name(self, capsys):
        reporter = TerminalReporter()
        summary = _make_summary()
        reporter.report(summary)

        output = capsys.readouterr().out
        assert "bandit" in output

    def test_report_prints_finding_count(self, capsys):
        reporter = TerminalReporter()
        summary = _make_summary()
        reporter.report(summary)

        output = capsys.readouterr().out
        assert "3 findings" in output

    def test_report_pass_status_no_threshold(self, capsys):
        reporter = TerminalReporter()
        summary = _make_summary(threshold=None)
        reporter.report(summary)

        output = capsys.readouterr().out
        assert "PASS" in output

    def test_report_fail_status_with_threshold(self, capsys):
        reporter = TerminalReporter()
        summary = _make_summary(threshold=Severity.MEDIUM)
        reporter.report(summary)

        output = capsys.readouterr().out
        assert "FAIL" in output

    def test_report_empty_results(self, capsys):
        reporter = TerminalReporter()
        summary = ScanSummary()
        reporter.report(summary)

        output = capsys.readouterr().out
        assert "PASS" in output

    def test_report_scanner_with_zero_findings(self, capsys):
        reporter = TerminalReporter()
        result = ScanResult(scanner="gitleaks", findings=[])
        summary = ScanSummary(results=[result])
        reporter.report(summary)

        output = capsys.readouterr().out
        assert "gitleaks" in output
        assert "0 findings" in output
