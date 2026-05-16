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

    def test_report_warns_on_execution_failure_with_per_scanner_reason(self, capsys):
        """Scanners that did not run cleanly get a clear warning row
        with the *actual* scanner-specific reason (not generic 'uid
        mismatch / crashed / wrong entrypoint' boilerplate), so the
        user can act on it without re-running with --verbose."""
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

        # New header text: count + "did not run cleanly".
        assert "2 scanner(s) did not run cleanly" in output
        # Per-scanner reason lines (bullet form). Each scanner name
        # appears with its specific reason, not a generic guess.
        assert "bandit" in output and "permission denied" in output
        assert "opengrep" in output
        # The CTA still points at --fail-on-scanner-error for CI gating.
        assert "--fail-on-scanner-error" in output
        # PASS status still renders below — execution failure is a
        # separate signal from threshold compliance.
        assert "PASS" in output

    def test_report_does_not_emit_generic_failure_guesses(self, capsys):
        """Regression: the old reporter printed canned text guessing at
        causes (uid mismatch / crashed / wrong entrypoint). That was
        misleading for OSV exit-1-with-findings and yamllint
        binary-not-found cases. The reason from the adapter is
        authoritative — generic boilerplate must not appear."""
        reporter = TerminalReporter()
        summary = ScanSummary(
            results=[
                ScanResult(
                    scanner="osv", findings=[],
                    metadata={
                        "execution_failed": True,
                        "execution_failure_reason": "Tool not found: osv-scanner",
                    },
                ),
            ],
            severity_threshold=None,
        )
        reporter.report(summary)
        output = capsys.readouterr().out

        # The actual reason must be visible.
        assert "Tool not found" in output
        # The old generic guesses must NOT appear — they were the
        # exact source of the user's "misleading warning text"
        # complaint after the first patch.
        assert "uid mismatch" not in output
        assert "wrong entrypoint" not in output
        assert "crashed" not in output

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

    def test_report_parse_failed_renders_distinctly_from_execution_failed(self, capsys):
        """A scanner that produced output but couldn't be parsed is a
        third state — not the same as 'didn't run'. The reporter
        renders parse failures in their own warning block so the user
        can tell them apart, and the degraded status label counts
        them separately."""
        reporter = TerminalReporter()
        summary = ScanSummary(
            results=[
                ScanResult(
                    scanner="osv", findings=[],
                    metadata={
                        "parse_failed": True,
                        "parse_failure_reason": (
                            "JSONDecodeError: Expecting value: line 1 column 1. "
                            "output head: 'unexpected text'"
                        ),
                    },
                ),
            ],
            severity_threshold=None,
        )
        reporter.report(summary)
        output = capsys.readouterr().out

        # The dedicated parse-failure block must surface the reason.
        assert "could not be parsed" in output
        assert "osv" in output
        assert "JSONDecodeError" in output
        # Distinct degraded label — separates execution failures from
        # parse failures so the user understands which kind happened.
        assert "Status: PASS (degraded — 1 unparsable)" in output
        # Must not be miscategorized as an execution failure.
        assert "did not run cleanly" not in output

    def test_report_status_label_lists_both_kinds_when_both_present(self, capsys):
        """Mixed-failure runs label the degraded status with both
        counts so the user knows the breakdown without scrolling up."""
        reporter = TerminalReporter()
        summary = ScanSummary(
            results=[
                ScanResult(
                    scanner="bandit", findings=[],
                    metadata={
                        "execution_failed": True,
                        "execution_failure_reason": "Tool not found: bandit",
                    },
                ),
                ScanResult(
                    scanner="osv", findings=[],
                    metadata={
                        "parse_failed": True,
                        "parse_failure_reason": "JSONDecodeError: line 1 col 1",
                    },
                ),
            ],
            severity_threshold=None,
        )
        reporter.report(summary)
        output = capsys.readouterr().out

        assert "Status: PASS (degraded — 1 did not run, 1 unparsable)" in output

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
