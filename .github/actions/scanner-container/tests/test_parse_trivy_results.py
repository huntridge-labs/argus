#!/usr/bin/env python3
"""Unit tests for parse_trivy_results.py using pytest.

Uses in-process imports instead of subprocess for fast execution.
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit


# Get the scripts directory
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
PARSER_SCRIPT = SCRIPTS_DIR / "parse_trivy_results.py"

# Load module in-process via importlib
spec = importlib.util.spec_from_file_location(
    "parse_trivy_results", PARSER_SCRIPT,
)
parse_trivy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_trivy)

# Get fixtures directory
FIXTURES_DIR = (
    Path(__file__).parent.parent.parent.parent.parent
    / "tests" / "fixtures" / "scanner-outputs" / "trivy"
)


class TestParseTrivyResults:
    """Test suite for parse_trivy_results.py functionality."""

    # ====== Tests for 'counts' command ======

    def test_counts_zero_findings(self):
        """Test counts command with zero findings."""
        result = parse_trivy.get_counts(str(FIXTURES_DIR / "results-zero-findings.json"))
        assert result == "0 0 0 0"

    def test_counts_with_findings(self):
        """Test counts command with mixed severities."""
        result = parse_trivy.get_counts(str(FIXTURES_DIR / "results-with-findings.json"))
        assert result == "1 1 1 1"

    def test_counts_with_errors(self, tmp_path):
        """Test counts with various error conditions (nonexistent, empty, invalid JSON)."""
        # Nonexistent file
        result = parse_trivy.get_counts("/nonexistent/file.json")
        assert result == "0 0 0 0"

        # Empty file
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("")
        result = parse_trivy.get_counts(str(empty_file))
        assert result == "0 0 0 0"

        # Invalid JSON
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{invalid json")
        result = parse_trivy.get_counts(str(bad_file))
        assert result == "0 0 0 0"

    # ====== Tests for 'total' command ======

    def test_total_zero_findings(self):
        """Test total command with zero findings."""
        result = parse_trivy.get_total(str(FIXTURES_DIR / "results-zero-findings.json"))
        assert result == "0"

    def test_total_with_findings(self):
        """Test total command with findings and nonexistent file."""
        result = parse_trivy.get_total(str(FIXTURES_DIR / "results-with-findings.json"))
        assert result == "4"

        result = parse_trivy.get_total("/nonexistent/file.json")
        assert result == "0"

    # ====== Tests for 'unique' command ======

    def test_unique_zero_findings(self):
        """Test unique command with zero findings."""
        result = parse_trivy.get_unique(str(FIXTURES_DIR / "results-zero-findings.json"))
        assert result == "0"

    def test_unique_with_findings_and_duplicates(self, tmp_path):
        """Test unique command with findings (including duplicates)."""
        result = parse_trivy.get_unique(str(FIXTURES_DIR / "results-with-findings.json"))
        assert result == "4"

        # With duplicate CVE IDs (dedup should work)
        json_file = tmp_path / "duplicates.json"
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2023-1111", "Severity": "HIGH"},
                        {"VulnerabilityID": "CVE-2023-1111", "Severity": "HIGH"},
                        {"VulnerabilityID": "CVE-2023-2222", "Severity": "MEDIUM"},
                    ]
                }
            ]
        }
        json_file.write_text(json.dumps(data))
        result = parse_trivy.get_unique(str(json_file))
        assert result == "2"

    # ====== Tests for 'unique-by-severity' command ======

    def test_unique_by_severity_zero_findings(self):
        """Test unique-by-severity with zero findings."""
        result = parse_trivy.get_unique_by_severity(
            str(FIXTURES_DIR / "results-zero-findings.json"),
        )
        assert result == "0 0 0 0"

    def test_unique_by_severity_with_findings(self):
        """Test unique-by-severity with findings."""
        result = parse_trivy.get_unique_by_severity(
            str(FIXTURES_DIR / "results-with-findings.json"),
        )
        assert result == "1 1 1 1"

    # ====== Tests for 'cves' command ======

    def test_cves_zero_findings(self):
        """Test cves command with zero findings."""
        result = parse_trivy.get_cves(str(FIXTURES_DIR / "results-zero-findings.json"))
        assert result == ""

    def test_cves_with_findings(self):
        """Test cves command returns CVE IDs."""
        result = parse_trivy.get_cves(str(FIXTURES_DIR / "results-with-findings.json"))
        lines = result.split("\n")
        assert len(lines) == 4
        assert "CVE-2023-1234" in result
        assert "CVE-2023-5678" in result

    def test_cves_sorted_and_unique(self, tmp_path):
        """Test that cves output is sorted and unique."""
        json_file = tmp_path / "cves.json"
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2023-3333"},
                        {"VulnerabilityID": "CVE-2023-1111"},
                        {"VulnerabilityID": "CVE-2023-3333"},
                        {"VulnerabilityID": "CVE-2023-2222"},
                    ]
                }
            ]
        }
        json_file.write_text(json.dumps(data))
        result = parse_trivy.get_cves(str(json_file))
        lines = result.split("\n")
        assert len(lines) == 3
        assert lines == sorted(lines)

    # ====== Tests for 'cves-by-severity' command ======

    def test_cves_by_severity_multiple_levels(self):
        """Test cves-by-severity filters by severity level."""
        fixture = str(FIXTURES_DIR / "results-with-findings.json")

        result = parse_trivy.get_cves_by_severity(fixture, "CRITICAL")
        assert "CVE-2023-1234" in result

        result = parse_trivy.get_cves_by_severity(fixture, "HIGH")
        assert "CVE-2023-5678" in result

        result = parse_trivy.get_cves_by_severity(fixture, "MEDIUM")
        assert "CVE-2023-9012" in result

        result = parse_trivy.get_cves_by_severity(fixture, "LOW")
        assert "CVE-2024-0001" in result

        # Unknown severity returns empty
        result = parse_trivy.get_cves_by_severity(fixture, "UNKNOWN")
        assert result == ""

    def test_cves_by_severity_missing_flag(self):
        """Test cves-by-severity without severity flag (CLI validation)."""
        cmd = [
            sys.executable, str(PARSER_SCRIPT),
            "cves-by-severity",
            str(FIXTURES_DIR / "results-with-findings.json"),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        assert result.returncode != 0

    # ====== Tests for 'table' command ======

    def test_table_zero_findings(self):
        """Test table command with zero findings."""
        result = parse_trivy.get_table(str(FIXTURES_DIR / "results-zero-findings.json"))
        assert "No data" in result

    def test_table_with_findings_limit_and_emoji(self):
        """Test table command generates markdown with findings, limit, and emojis."""
        fixture = str(FIXTURES_DIR / "results-with-findings.json")

        # With findings
        result = parse_trivy.get_table(fixture)
        assert "|" in result
        assert "CVE-2023-1234" in result or "CVE-" in result

        # With limit
        result = parse_trivy.get_table(fixture, limit=2)
        lines = [line for line in result.split("\n") if "|" in line and "CVE" in line]
        assert len(lines) <= 2

        # Check for severity emojis
        result = parse_trivy.get_table(fixture)
        assert any(emoji in result for emoji in ["🚨", "⚠️", "🟡", "🔵"])

    # ====== Tests for 'digest' command ======

    def test_digest_with_findings(self):
        """Test digest extraction from various inputs."""
        result = parse_trivy.get_digest(str(FIXTURES_DIR / "results-with-findings.json"))
        assert result != "unknown"
        assert "sha256:" in result or len(result) > 10

        result = parse_trivy.get_digest(str(FIXTURES_DIR / "results-zero-findings.json"))
        assert result != "unknown"

        result = parse_trivy.get_digest("/nonexistent/file.json")
        assert result == "unknown"

    # ====== Tests for 'image' command ======

    def test_image_extraction_various_inputs(self):
        """Test image ref extraction from various inputs."""
        result = parse_trivy.get_image_ref(str(FIXTURES_DIR / "results-with-findings.json"))
        assert result != "unknown"
        assert ":" in result

        result = parse_trivy.get_image_ref(str(FIXTURES_DIR / "results-zero-findings.json"))
        assert result != "unknown"
        assert "alpine" in result.lower()

        result = parse_trivy.get_image_ref("/nonexistent/file.json")
        assert result == "unknown"

    # ====== Integration tests ======

    def test_malformed_results_structure(self, tmp_path):
        """Test with malformed Results structure."""
        json_file = tmp_path / "malformed.json"
        data = {"Results": "not a list"}
        json_file.write_text(json.dumps(data))
        result = parse_trivy.get_counts(str(json_file))
        assert result == "0 0 0 0"

    def test_missing_fields(self, tmp_path):
        """Test with missing expected fields."""
        json_file = tmp_path / "missing_fields.json"
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2023-1111"},
                    ]
                }
            ]
        }
        json_file.write_text(json.dumps(data))
        result = parse_trivy.get_counts(str(json_file))
        # Missing Severity defaults to LOW
        assert result == "0 0 0 1"

    def test_empty_results(self, tmp_path):
        """Test with empty Results array."""
        json_file = tmp_path / "empty_results.json"
        data = {"Results": []}
        json_file.write_text(json.dumps(data))
        result = parse_trivy.get_counts(str(json_file))
        assert result == "0 0 0 0"

    def test_multiple_result_entries(self, tmp_path):
        """Test aggregation across multiple Result entries."""
        json_file = tmp_path / "multi_result.json"
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2023-1111", "Severity": "CRITICAL"},
                    ]
                },
                {
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2023-2222", "Severity": "HIGH"},
                    ]
                },
            ]
        }
        json_file.write_text(json.dumps(data))
        result = parse_trivy.get_counts(str(json_file))
        assert result == "1 1 0 0"

    def test_help_command(self):
        """Test help flag (CLI validation)."""
        cmd = [sys.executable, str(PARSER_SCRIPT), "--help"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0
        assert "counts" in result.stdout

    def test_unknown_command(self):
        """Test unknown command (CLI validation)."""
        cmd = [
            sys.executable, str(PARSER_SCRIPT),
            "unknown",
            str(FIXTURES_DIR / "results-zero-findings.json"),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        assert result.returncode != 0
        assert "Unknown command" in result.stderr
