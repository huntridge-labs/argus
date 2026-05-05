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

    def test_report_warns_on_execution_failure_above_pass_status(self, capsys):
        """Scanners that produced no output (execution_failed=True in
        metadata) get a clear warning in the terminal output so a single
        bad scanner image doesn't quietly slip past the PASS line."""
        reporter = TerminalReporter()
        summary = ScanSummary(
            results=[
                ScanResult(scanner="gitleaks", findings=[]),  # ran fine
                ScanResult(
                    scanner="bandit", findings=[],
                    metadata={
                        "execution_failed": True,
                        "execution_failure_reason": (
                            "no output files (exit=13). stderr: "
                            "cannot open /output/results.json: permission denied"
                        ),
                    },
                ),
                ScanResult(
                    scanner="opengrep", findings=[],
                    metadata={"execution_failed": True},
                ),
            ],
            severity_threshold=None,
        )
        reporter.report(summary)
        output = capsys.readouterr().out

        # Failed scanners are named, count is correct, and the hint
        # points at --fail-on-scanner-error for hard CI gating.
        assert "2 scanner(s) produced no output" in output
        assert "bandit" in output
        assert "opengrep" in output
        assert "--fail-on-scanner-error" in output
        # PASS status still renders below — execution failure is a
        # separate signal from threshold compliance.
        assert "PASS" in output

    def test_report_no_warning_when_all_scanners_produced_output(self, capsys):
        """Successful runs must not get the warning row."""
        reporter = TerminalReporter()
        summary = _make_summary()
        reporter.report(summary)

        output = capsys.readouterr().out
        assert "produced no output" not in output

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
