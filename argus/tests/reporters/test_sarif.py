"""Tests for argus.reporters.sarif — SarifReporter."""

import json

import pytest

from argus.core.models import Finding, ScanResult, ScanSummary, Severity
from argus.reporters.sarif import SarifReporter


def _make_summary():
    """Create a ScanSummary with known findings for testing."""
    result = ScanResult(
        scanner="bandit",
        findings=[
            Finding(
                id="B102",
                severity=Severity.HIGH,
                title="Dangerous function call",
                description="Unsafe function detected",
                location="app.py:25",
                cwe="CWE-78",
            ),
            Finding(
                id="B105",
                severity=Severity.MEDIUM,
                title="Hardcoded password",
                location="config.py:8",
            ),
        ],
    )
    return ScanSummary(results=[result])


class TestSarifReporter:
    """Test SarifReporter output."""

    def test_report_creates_file(self, tmp_output_dir):
        reporter = SarifReporter()
        summary = _make_summary()
        filepath = reporter.report(summary, tmp_output_dir)

        assert filepath.exists()
        assert filepath.name == "argus-results.sarif"

    def test_report_valid_json(self, tmp_output_dir):
        reporter = SarifReporter()
        summary = _make_summary()
        filepath = reporter.report(summary, tmp_output_dir)

        data = json.loads(filepath.read_text())
        assert isinstance(data, dict)

    def test_sarif_structure(self, tmp_output_dir):
        reporter = SarifReporter()
        summary = _make_summary()
        filepath = reporter.report(summary, tmp_output_dir)

        data = json.loads(filepath.read_text())
        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert "runs" in data
        assert len(data["runs"]) == 1

    def test_sarif_run_structure(self, tmp_output_dir):
        reporter = SarifReporter()
        summary = _make_summary()
        filepath = reporter.report(summary, tmp_output_dir)

        data = json.loads(filepath.read_text())
        run = data["runs"][0]
        assert "tool" in run
        assert "driver" in run["tool"]
        assert run["tool"]["driver"]["name"] == "argus/bandit"
        assert "rules" in run["tool"]["driver"]
        assert "results" in run

    def test_sarif_results_count(self, tmp_output_dir):
        reporter = SarifReporter()
        summary = _make_summary()
        filepath = reporter.report(summary, tmp_output_dir)

        data = json.loads(filepath.read_text())
        results = data["runs"][0]["results"]
        assert len(results) == 2

    def test_sarif_result_has_location(self, tmp_output_dir):
        reporter = SarifReporter()
        summary = _make_summary()
        filepath = reporter.report(summary, tmp_output_dir)

        data = json.loads(filepath.read_text())
        result = data["runs"][0]["results"][0]
        assert "locations" in result
        physical = result["locations"][0]["physicalLocation"]
        assert physical["artifactLocation"]["uri"] == "app.py"
        assert physical["region"]["startLine"] == 25

    def test_sarif_severity_levels(self, tmp_output_dir):
        reporter = SarifReporter()
        summary = _make_summary()
        filepath = reporter.report(summary, tmp_output_dir)

        data = json.loads(filepath.read_text())
        results = data["runs"][0]["results"]
        levels = [r["level"] for r in results]
        assert "error" in levels
        assert "warning" in levels

    def test_report_creates_output_dir_if_missing(self, tmp_path):
        reporter = SarifReporter()
        summary = _make_summary()
        output_dir = tmp_path / "nested" / "output"
        filepath = reporter.report(summary, output_dir)

        assert filepath.exists()
