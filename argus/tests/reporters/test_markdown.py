"""Tests for argus.reporters.markdown — MarkdownReporter."""

import pytest

from argus.core.models import (
    Finding,
    PhaseResult,
    ScanResult,
    ScanSummary,
    Severity,
)
from argus.reporters.markdown import MarkdownReporter


def _make_summary(threshold=None):
    """Create a ScanSummary with known findings for testing."""
    result = ScanResult(
        scanner="bandit",
        findings=[
            Finding(id="B102", severity=Severity.HIGH, title="Use of exec"),
            Finding(id="B105", severity=Severity.MEDIUM, title="Hardcoded password"),
        ],
    )
    return ScanSummary(
        results=[result],
        severity_threshold=threshold,
    )


class TestMarkdownReporter:
    """Test MarkdownReporter output."""

    def test_report_creates_file(self, tmp_output_dir):
        reporter = MarkdownReporter()
        summary = _make_summary()
        filepath = reporter.report(summary, tmp_output_dir)

        assert filepath.exists()
        assert filepath.name == "argus-summary.md"

    def test_report_contains_header(self, tmp_output_dir):
        reporter = MarkdownReporter()
        summary = _make_summary()
        filepath = reporter.report(summary, tmp_output_dir)

        content = filepath.read_text()
        assert "# Argus Security Scan Results" in content

    def test_report_contains_summary_table(self, tmp_output_dir):
        reporter = MarkdownReporter()
        summary = _make_summary()
        filepath = reporter.report(summary, tmp_output_dir)

        content = filepath.read_text()
        assert "| Severity | Count |" in content
        # All five severity rows must be present so the markdown report
        # math reconciles with the canonical argus-results.json. The Info
        # row was previously missing, which made the breakdown sum less
        # than the printed Total — see issue #168-E.
        for row in ("Critical", "High", "Medium", "Low", "Info"):
            assert row in content, f"missing severity row: {row}"

    def test_report_contains_findings(self, tmp_output_dir):
        reporter = MarkdownReporter()
        summary = _make_summary()
        filepath = reporter.report(summary, tmp_output_dir)

        content = filepath.read_text()
        assert "B102" in content
        assert "Use of exec" in content
        assert "bandit" in content

    def test_report_pass_status(self, tmp_output_dir):
        reporter = MarkdownReporter()
        summary = _make_summary(threshold=None)
        filepath = reporter.report(summary, tmp_output_dir)

        content = filepath.read_text()
        assert "PASS" in content

    def test_report_fail_status(self, tmp_output_dir):
        reporter = MarkdownReporter()
        summary = _make_summary(threshold=Severity.MEDIUM)
        filepath = reporter.report(summary, tmp_output_dir)

        content = filepath.read_text()
        assert "FAIL" in content

    def test_report_creates_output_dir_if_missing(self, tmp_path):
        reporter = MarkdownReporter()
        summary = _make_summary()
        output_dir = tmp_path / "nested" / "output"
        filepath = reporter.report(summary, output_dir)

        assert filepath.exists()

    def test_report_empty_scanner(self, tmp_output_dir):
        reporter = MarkdownReporter()
        result = ScanResult(scanner="gitleaks", findings=[])
        summary = ScanSummary(results=[result])
        filepath = reporter.report(summary, tmp_output_dir)

        content = filepath.read_text()
        assert "gitleaks" in content
        assert "No findings" in content


class TestMarkdownReporterScannerHealth:
    """Covers the ``## Scanner Health`` section emitted when any
    scanner failed to run cleanly, partially failed, or produced
    unparsable output. Pre-issue-#168/#169/#170 the markdown reporter
    had no failure surface at all, so a degraded run produced a
    clean-looking markdown report — directly hiding the same class
    of bug from PR commenters as the terminal reporter had hidden
    from CLI users.
    """

    def test_scanner_health_section_omitted_when_clean(self, tmp_output_dir):
        reporter = MarkdownReporter()
        summary = ScanSummary(
            results=[ScanResult(scanner="bandit", findings=[])],
        )
        content = reporter.report(summary, tmp_output_dir).read_text()
        assert "Scanner Health" not in content

    def test_scanner_health_lists_execution_failure(self, tmp_output_dir):
        reporter = MarkdownReporter()
        summary = ScanSummary(
            results=[
                ScanResult(
                    scanner="bandit", findings=[],
                    metadata={
                        "execution_failed": True,
                        "execution_failure_reason": "permission denied",
                    },
                ),
            ],
        )
        content = reporter.report(summary, tmp_output_dir).read_text()
        assert "## Scanner Health" in content
        assert "1 scanner(s) did not run cleanly" in content
        assert "bandit" in content
        assert "permission denied" in content

    def test_scanner_health_lists_partial_failure_per_phase(self, tmp_output_dir):
        # Per issue #169: partial-phase failures need to appear in the
        # markdown body with phase-level granularity, not just an
        # opaque scanner-level note.
        reporter = MarkdownReporter()
        summary = ScanSummary(
            results=[
                ScanResult(
                    scanner="lint-terraform",
                    findings=[],
                    phase_results=[
                        PhaseResult(phase="terraform-fmt", status="ran"),
                        PhaseResult(
                            phase="terraform-validate",
                            status="failed",
                            error="image pull failed",
                        ),
                    ],
                ),
            ],
        )
        content = reporter.report(summary, tmp_output_dir).read_text()
        assert "## Scanner Health" in content
        assert "1 scanner(s) did not run cleanly" in content
        assert "phase `terraform-validate` failed" in content
        assert "image pull failed" in content

    def test_scanner_health_lists_parse_failure(self, tmp_output_dir):
        reporter = MarkdownReporter()
        summary = ScanSummary(
            results=[
                ScanResult(
                    scanner="opengrep", findings=[],
                    metadata={
                        "parse_failed": True,
                        "parse_failure_reason": "invalid JSON at line 3",
                    },
                ),
            ],
        )
        content = reporter.report(summary, tmp_output_dir).read_text()
        assert "## Scanner Health" in content
        assert "could not be parsed" in content
        assert "opengrep" in content
        assert "invalid JSON" in content

    def test_scanner_health_with_only_parse_failures_skips_did_not_run_block(
        self, tmp_output_dir,
    ):
        # When ``exec_failed`` and ``partial_failed`` are both empty
        # but ``parse_failed`` has entries, the parse section renders
        # without the "did not run cleanly" header above it.
        reporter = MarkdownReporter()
        summary = ScanSummary(
            results=[
                ScanResult(
                    scanner="opengrep", findings=[],
                    metadata={
                        "parse_failed": True,
                        "parse_failure_reason": "schema drift",
                    },
                ),
            ],
        )
        content = reporter.report(summary, tmp_output_dir).read_text()
        assert "## Scanner Health" in content
        assert "did not run cleanly" not in content
        assert "could not be parsed" in content
