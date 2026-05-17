"""Tests for argus.reporters.markdown — MarkdownReporter."""

import pytest

from argus.core.models import Finding, ScanResult, ScanSummary, Severity
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
