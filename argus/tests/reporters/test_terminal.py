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

    def test_report_status_pass_degraded_when_any_scanner_failed(self, capsys):
        """Regression: when one scanner fails to execute but the rest
        are clean against threshold, the status line previously read
        ``Status: PASS`` — directly contradicting the warning row above
        it. Status must annotate ``(degraded — some scanners did not
        run)`` so a quick scroll to the bottom doesn't lie. The
        ``passed`` boolean stays True (threshold-only); the degraded
        label is purely a UX cue."""
        reporter = TerminalReporter()
        summary = ScanSummary(
            results=[
                ScanResult(scanner="gitleaks", findings=[]),
                ScanResult(
                    scanner="bandit", findings=[],
                    metadata={"execution_failed": True},
                ),
            ],
            severity_threshold=None,
        )
        reporter.report(summary)
        output = capsys.readouterr().out
        # The threshold check still passes — that's the contract.
        assert summary.passed is True
        # But the displayed status must call out the degraded run so
        # the user doesn't read "Warning: ..." then "PASS" and shrug.
        assert "Status: PASS (degraded" in output
        # And the plain "Status: PASS" string must not appear *as a
        # standalone status line* — only as part of the degraded label.
        # We assert the plain newline-bounded form is absent:
        assert "\nStatus: PASS\n" not in output

    def test_report_status_pass_clean_when_no_failures(self, capsys):
        """Clean runs must still show the unqualified ``Status: PASS``."""
        reporter = TerminalReporter()
        summary = _make_summary(threshold=None)
        reporter.report(summary)
        output = capsys.readouterr().out
        # Clean PASS is the default rendering — no degraded suffix.
        assert "Status: PASS" in output
        assert "degraded" not in output

    def test_report_status_fail_takes_priority_over_degraded(self, capsys):
        """If findings exceed the threshold, the run is FAIL — not
        a degraded PASS — even when other scanners failed to execute.
        Threshold violations dominate the exit policy."""
        reporter = TerminalReporter()
        summary = ScanSummary(
            results=[
                ScanResult(
                    scanner="bandit",
                    findings=[Finding(id="B102", severity=Severity.HIGH, title="t")],
                ),
                ScanResult(
                    scanner="gitleaks", findings=[],
                    metadata={"execution_failed": True},
                ),
            ],
            severity_threshold=Severity.MEDIUM,
        )
        reporter.report(summary)
        output = capsys.readouterr().out
        assert "FAIL" in output
        # Don't display PASS at all when the run is FAIL — even with
        # an executed-but-degraded scanner mixed in.
        assert "Status: PASS" not in output

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
