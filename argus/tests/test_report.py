"""Integration tests for argus report subcommand and model roundtrip."""

import argparse
import json
from pathlib import Path

import pytest

from argus.cli import cmd_report, EXIT_SUCCESS, EXIT_ERROR
from argus.core.models import (
    Finding,
    ScanResult,
    ScanSummary,
    Severity,
)


def _make_summary() -> ScanSummary:
    """Build a realistic ScanSummary for testing."""
    return ScanSummary(
        results=[
            ScanResult(
                scanner="bandit",
                findings=[
                    Finding(
                        id="B101",
                        severity=Severity.HIGH,
                        title="Use of assert detected",
                        location="app.py:42",
                        cwe="CWE-703",
                    ),
                    Finding(
                        id="B105",
                        severity=Severity.MEDIUM,
                        title="Hardcoded password",
                        location="config.py:10",
                    ),
                    Finding(
                        id="B311",
                        severity=Severity.LOW,
                        title="Random not for crypto",
                        location="utils.py:5",
                    ),
                ],
            ),
            ScanResult(scanner="gitleaks", findings=[]),
        ],
        severity_threshold=Severity.HIGH,
    )


def _write_results_json(directory: Path, summary: ScanSummary) -> Path:
    """Write argus-results.json to a directory."""
    directory.mkdir(parents=True, exist_ok=True)
    json_file = directory / "argus-results.json"
    json_file.write_text(
        json.dumps(summary.to_dict(), indent=2),
        encoding="utf-8",
    )
    return json_file


def _make_report_args(**overrides) -> argparse.Namespace:
    """Build an argparse Namespace for cmd_report."""
    defaults = {
        "format": "markdown",
        "results_dir": "./argus-results",
        "output_dir": None,
        "verbose": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# ── Model roundtrip tests ──────────────────────────────────


class TestScanResultFromDict:
    """Test ScanResult.from_dict() deserialization."""

    def test_roundtrip_preserves_findings(self):
        original = ScanResult(
            scanner="bandit",
            findings=[
                Finding(id="B101", severity=Severity.HIGH, title="assert"),
                Finding(id="B105", severity=Severity.MEDIUM, title="password"),
            ],
        )
        restored = ScanResult.from_dict(original.to_dict())
        assert restored.scanner == "bandit"
        assert len(restored.findings) == 2
        assert restored.findings[0].id == "B101"
        assert restored.findings[1].severity == Severity.MEDIUM

    def test_roundtrip_preserves_metadata(self):
        original = ScanResult(
            scanner="test",
            findings=[],
            metadata={"execution": "container", "image": "img:1.0"},
        )
        restored = ScanResult.from_dict(original.to_dict())
        assert restored.metadata["execution"] == "container"
        assert restored.metadata["image"] == "img:1.0"

    def test_empty_findings(self):
        original = ScanResult(scanner="gitleaks", findings=[])
        restored = ScanResult.from_dict(original.to_dict())
        assert restored.scanner == "gitleaks"
        assert restored.findings == []

    def test_finding_fields_preserved(self):
        finding = Finding(
            id="B101",
            severity=Severity.CRITICAL,
            title="Critical issue",
            description="Detailed description",
            location="src/main.py:99",
            cwe="CWE-89",
            cve="CVE-2024-1234",
            scanner="bandit",
            metadata={"confidence": "HIGH"},
        )
        data = ScanResult(scanner="bandit", findings=[finding]).to_dict()
        restored = ScanResult.from_dict(data)
        f = restored.findings[0]
        assert f.id == "B101"
        assert f.severity == Severity.CRITICAL
        assert f.title == "Critical issue"
        assert f.description == "Detailed description"
        assert f.location == "src/main.py:99"
        assert f.cwe == "CWE-89"
        assert f.cve == "CVE-2024-1234"


class TestScanSummaryFromDict:
    """Test ScanSummary.from_dict() deserialization."""

    def test_roundtrip_preserves_structure(self):
        original = _make_summary()
        data = original.to_dict()
        restored = ScanSummary.from_dict(data)

        assert len(restored.results) == 2
        assert restored.results[0].scanner == "bandit"
        assert restored.results[1].scanner == "gitleaks"
        assert restored.total_count == 3
        assert restored.high_count == 1

    def test_roundtrip_preserves_threshold(self):
        original = ScanSummary(
            results=[],
            severity_threshold=Severity.MEDIUM,
        )
        restored = ScanSummary.from_dict(original.to_dict())
        assert restored.severity_threshold == Severity.MEDIUM

    def test_none_threshold(self):
        original = ScanSummary(results=[], severity_threshold=None)
        restored = ScanSummary.from_dict(original.to_dict())
        assert restored.severity_threshold is None

    def test_passed_flag_preserved(self):
        passing = ScanSummary(results=[], severity_threshold=Severity.HIGH)
        assert ScanSummary.from_dict(passing.to_dict()).passed is True

        failing = _make_summary()  # has HIGH finding with HIGH threshold
        assert ScanSummary.from_dict(failing.to_dict()).passed is False

    def test_severity_counts_match(self):
        original = _make_summary()
        restored = ScanSummary.from_dict(original.to_dict())
        assert restored.critical_count == original.critical_count
        assert restored.high_count == original.high_count
        assert restored.medium_count == original.medium_count
        assert restored.low_count == original.low_count


# ── cmd_report integration tests ───────────────────────────


class TestCmdReport:
    """Integration tests for the report subcommand."""

    def test_markdown_report_generated(self, tmp_path):
        summary = _make_summary()
        results_dir = tmp_path / "results"
        _write_results_json(results_dir, summary)

        args = _make_report_args(
            format="markdown",
            results_dir=str(results_dir),
            output_dir=str(tmp_path / "output"),
        )
        exit_code = cmd_report(args)

        assert exit_code == EXIT_SUCCESS
        md_file = tmp_path / "output" / "argus-summary.md"
        assert md_file.exists()
        content = md_file.read_text()
        assert "bandit" in content
        assert "B101" in content

    def test_json_report_generated(self, tmp_path):
        summary = _make_summary()
        results_dir = tmp_path / "results"
        _write_results_json(results_dir, summary)

        args = _make_report_args(
            format="json",
            results_dir=str(results_dir),
            output_dir=str(tmp_path / "output"),
        )
        exit_code = cmd_report(args)

        assert exit_code == EXIT_SUCCESS
        json_file = tmp_path / "output" / "argus-results.json"
        assert json_file.exists()
        data = json.loads(json_file.read_text())
        assert data["total_count"] == 3

    def test_sarif_report_generated(self, tmp_path):
        summary = _make_summary()
        results_dir = tmp_path / "results"
        _write_results_json(results_dir, summary)

        args = _make_report_args(
            format="sarif",
            results_dir=str(results_dir),
            output_dir=str(tmp_path / "output"),
        )
        exit_code = cmd_report(args)

        assert exit_code == EXIT_SUCCESS
        sarif_file = tmp_path / "output" / "argus-results.sarif"
        assert sarif_file.exists()
        data = json.loads(sarif_file.read_text())
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 2

    def test_terminal_report(self, tmp_path, capsys):
        summary = _make_summary()
        results_dir = tmp_path / "results"
        _write_results_json(results_dir, summary)

        args = _make_report_args(
            format="terminal",
            results_dir=str(results_dir),
        )
        exit_code = cmd_report(args)

        assert exit_code == EXIT_SUCCESS
        output = capsys.readouterr().out
        assert "bandit" in output.lower() or "3" in output

    def test_missing_results_dir(self):
        args = _make_report_args(results_dir="/nonexistent/path")
        exit_code = cmd_report(args)
        assert exit_code == EXIT_ERROR

    def test_missing_json_file(self, tmp_path):
        results_dir = tmp_path / "empty"
        results_dir.mkdir()
        args = _make_report_args(results_dir=str(results_dir))
        exit_code = cmd_report(args)
        assert exit_code == EXIT_ERROR

    def test_output_dir_defaults_to_results_dir(self, tmp_path):
        summary = _make_summary()
        results_dir = tmp_path / "results"
        _write_results_json(results_dir, summary)

        args = _make_report_args(
            format="markdown",
            results_dir=str(results_dir),
            output_dir=None,
        )
        exit_code = cmd_report(args)

        assert exit_code == EXIT_SUCCESS
        assert (results_dir / "argus-summary.md").exists()

    def test_report_from_zero_findings(self, tmp_path):
        empty = ScanSummary(results=[
            ScanResult(scanner="bandit", findings=[]),
        ])
        results_dir = tmp_path / "results"
        _write_results_json(results_dir, empty)

        args = _make_report_args(
            format="markdown",
            results_dir=str(results_dir),
            output_dir=str(tmp_path / "output"),
        )
        exit_code = cmd_report(args)

        assert exit_code == EXIT_SUCCESS
        content = (tmp_path / "output" / "argus-summary.md").read_text()
        assert "No findings" in content or "0" in content
