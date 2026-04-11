"""Tests for argus.reporters.json_report — JsonReporter."""

import json

import pytest

from argus.core.models import Finding, ScanResult, ScanSummary, Severity
from argus.reporters.json_report import JsonReporter


def _make_summary():
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
        severity_threshold=Severity.HIGH,
    )


class TestJsonReporter:
    """Test JsonReporter output."""

    def test_report_creates_file(self, tmp_output_dir):
        reporter = JsonReporter()
        summary = _make_summary()
        filepath = reporter.report(summary, tmp_output_dir)

        assert filepath.exists()
        assert filepath.name == "argus-results.json"

    def test_report_valid_json(self, tmp_output_dir):
        reporter = JsonReporter()
        summary = _make_summary()
        filepath = reporter.report(summary, tmp_output_dir)

        data = json.loads(filepath.read_text())
        assert isinstance(data, dict)

    def test_json_structure(self, tmp_output_dir):
        reporter = JsonReporter()
        summary = _make_summary()
        filepath = reporter.report(summary, tmp_output_dir)

        data = json.loads(filepath.read_text())
        assert "results" in data
        assert "severity_threshold" in data
        assert "critical_count" in data
        assert "high_count" in data
        assert "medium_count" in data
        assert "low_count" in data
        assert "total_count" in data
        assert "passed" in data

    def test_json_counts(self, tmp_output_dir):
        reporter = JsonReporter()
        summary = _make_summary()
        filepath = reporter.report(summary, tmp_output_dir)

        data = json.loads(filepath.read_text())
        assert data["total_count"] == 2
        assert data["high_count"] == 1
        assert data["medium_count"] == 1
        assert data["severity_threshold"] == "high"
        assert data["passed"] is False

    def test_json_findings(self, tmp_output_dir):
        reporter = JsonReporter()
        summary = _make_summary()
        filepath = reporter.report(summary, tmp_output_dir)

        data = json.loads(filepath.read_text())
        results = data["results"]
        assert len(results) == 1
        assert results[0]["scanner"] == "bandit"
        assert len(results[0]["findings"]) == 2

    def test_report_creates_output_dir_if_missing(self, tmp_path):
        reporter = JsonReporter()
        summary = _make_summary()
        output_dir = tmp_path / "nested" / "output"
        filepath = reporter.report(summary, output_dir)

        assert filepath.exists()
