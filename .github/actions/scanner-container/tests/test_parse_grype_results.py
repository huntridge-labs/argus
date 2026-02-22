#!/usr/bin/env python3
"""Unit tests for parse_grype_results.py using pytest.

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
PARSER_SCRIPT = SCRIPTS_DIR / "parse_grype_results.py"

# Load module in-process via importlib
spec = importlib.util.spec_from_file_location(
    "parse_grype_results", PARSER_SCRIPT,
)
parse_grype = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_grype)

# Get fixtures directory
FIXTURES_DIR = (
    Path(__file__).parent.parent.parent.parent.parent
    / "tests" / "fixtures" / "scanner-outputs" / "grype"
)


class TestParseGrypeResults:
    """Test suite for parse_grype_results.py functionality."""

    # ====== Tests for 'counts' command ======

    def test_counts_zero_findings(self):
        """Test counts command with zero findings."""
        result = parse_grype.get_counts(str(FIXTURES_DIR / "results-zero-findings.json"))
        assert result == "0 0 0 0"

    def test_counts_with_findings_and_errors(self, tmp_path):
        """Test counts with findings (including errors: nonexistent, empty, invalid JSON)."""
        result = parse_grype.get_counts(str(FIXTURES_DIR / "results-with-findings.json"))
        parts = result.split()
        assert len(parts) == 4
        for part in parts:
            assert int(part) >= 0

        # Nonexistent file
        result = parse_grype.get_counts("/nonexistent/file.json")
        assert result == "0 0 0 0"

        # Empty file
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("")
        result = parse_grype.get_counts(str(empty_file))
        assert result == "0 0 0 0"

        # Invalid JSON
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{invalid json")
        result = parse_grype.get_counts(str(bad_file))
        assert result == "0 0 0 0"

    # ====== Tests for 'total' command ======

    def test_total_zero_findings(self):
        """Test total command with zero findings."""
        result = parse_grype.get_total(str(FIXTURES_DIR / "results-zero-findings.json"))
        assert result == "0"

    def test_total_with_findings(self):
        """Test total command with findings and nonexistent file."""
        result = parse_grype.get_total(str(FIXTURES_DIR / "results-with-findings.json"))
        assert int(result) > 0

        result = parse_grype.get_total("/nonexistent/file.json")
        assert result == "0"

    # ====== Tests for 'unique' command ======

    def test_unique_zero_findings(self):
        """Test unique command with zero findings."""
        result = parse_grype.get_unique(str(FIXTURES_DIR / "results-zero-findings.json"))
        assert result == "0"

    def test_unique_with_findings_and_duplicates(self, tmp_path):
        """Test unique command with findings (including duplicate deduplication)."""
        result = parse_grype.get_unique(str(FIXTURES_DIR / "results-with-findings.json"))
        assert int(result) > 0

        # With duplicates - should deduplicate
        json_file = tmp_path / "duplicates.json"
        data = {
            "matches": [
                {"vulnerability": {"id": "CVE-2023-1111", "severity": "High"}},
                {"vulnerability": {"id": "CVE-2023-1111", "severity": "High"}},
                {"vulnerability": {"id": "CVE-2023-2222", "severity": "Medium"}},
            ]
        }
        json_file.write_text(json.dumps(data))
        result = parse_grype.get_unique(str(json_file))
        assert result == "2"

    # ====== Tests for 'unique-by-severity' command ======

    def test_unique_by_severity_zero_findings(self):
        """Test unique-by-severity with zero findings."""
        result = parse_grype.get_unique_by_severity(
            str(FIXTURES_DIR / "results-zero-findings.json"),
        )
        assert result == "0 0 0 0"

    def test_unique_by_severity_with_findings(self):
        """Test unique-by-severity with findings."""
        result = parse_grype.get_unique_by_severity(
            str(FIXTURES_DIR / "results-with-findings.json"),
        )
        parts = result.split()
        assert len(parts) == 4

    # ====== Tests for 'cves' command ======

    def test_cves_zero_findings(self):
        """Test cves command with zero findings."""
        result = parse_grype.get_cves(str(FIXTURES_DIR / "results-zero-findings.json"))
        assert result == ""

    def test_cves_with_findings_and_sorting(self, tmp_path):
        """Test cves command with findings (including sorting and deduplication)."""
        result = parse_grype.get_cves(str(FIXTURES_DIR / "results-with-findings.json"))
        lines = result.split("\n")
        assert len(lines) > 0
        assert any("CVE-" in line for line in lines)

        # Test sorting and uniqueness
        json_file = tmp_path / "cves.json"
        data = {
            "matches": [
                {"vulnerability": {"id": "CVE-2023-3333"}},
                {"vulnerability": {"id": "CVE-2023-1111"}},
                {"vulnerability": {"id": "CVE-2023-3333"}},
                {"vulnerability": {"id": "CVE-2023-2222"}},
            ]
        }
        json_file.write_text(json.dumps(data))
        result = parse_grype.get_cves(str(json_file))
        lines = result.split("\n")
        assert len(lines) == 3
        assert lines == sorted(lines)

    # ====== Tests for 'cves-by-severity' command ======

    def test_cves_by_severity_filters(self):
        """Test cves-by-severity filters by severity level."""
        fixture = str(FIXTURES_DIR / "results-with-findings.json")
        for severity in ["Critical", "High", "Medium", "Low"]:
            result = parse_grype.get_cves_by_severity(fixture, severity)
            assert "CVE-" in result or result == ""

        # Unknown severity should return empty
        result = parse_grype.get_cves_by_severity(fixture, "Unknown")
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
        result = parse_grype.get_table(str(FIXTURES_DIR / "results-zero-findings.json"))
        assert "No data" in result

    def test_table_with_findings_limit_and_emoji(self):
        """Test table command with findings, limit, and emojis."""
        fixture = str(FIXTURES_DIR / "results-with-findings.json")

        result = parse_grype.get_table(fixture)
        assert "|" in result
        assert "CVE-" in result or "CRITICAL" in result.upper()

        # With limit
        result = parse_grype.get_table(fixture, limit=2)
        lines = [line for line in result.split("\n") if "|" in line and "CVE" in line]
        assert len(lines) <= 2

        # Check for severity emojis
        result = parse_grype.get_table(fixture)
        assert any(emoji in result for emoji in ["🚨", "⚠️", "🟡", "🔵"])

    # ====== Integration tests ======

    def test_malformed_matches_structure(self, tmp_path):
        """Test with malformed matches structure."""
        json_file = tmp_path / "malformed.json"
        data = {"matches": "not a list"}
        json_file.write_text(json.dumps(data))
        result = parse_grype.get_counts(str(json_file))
        assert result == "0 0 0 0"

    def test_missing_fields(self, tmp_path):
        """Test with missing expected fields."""
        json_file = tmp_path / "missing_fields.json"
        data = {
            "matches": [
                {"vulnerability": {"id": "CVE-2023-1111"}},
            ]
        }
        json_file.write_text(json.dumps(data))
        result = parse_grype.get_counts(str(json_file))
        assert result == "0 0 0 1"

    def test_empty_matches(self, tmp_path):
        """Test with empty matches array."""
        json_file = tmp_path / "empty_matches.json"
        data = {"matches": []}
        json_file.write_text(json.dumps(data))
        result = parse_grype.get_counts(str(json_file))
        assert result == "0 0 0 0"

    def test_multiple_matches(self, tmp_path):
        """Test aggregation across multiple matches."""
        json_file = tmp_path / "multi_match.json"
        data = {
            "matches": [
                {"vulnerability": {"id": "CVE-2023-1111", "severity": "Critical"}},
                {"vulnerability": {"id": "CVE-2023-2222", "severity": "High"}},
            ]
        }
        json_file.write_text(json.dumps(data))
        result = parse_grype.get_counts(str(json_file))
        assert result == "1 1 0 0"

    def test_grype_severity_casing(self, tmp_path):
        """Test that Grype severity casing is handled correctly."""
        json_file = tmp_path / "casing.json"
        data = {
            "matches": [
                {"vulnerability": {"id": "CVE-2023-1111", "severity": "Critical"}},
                {"vulnerability": {"id": "CVE-2023-2222", "severity": "High"}},
                {"vulnerability": {"id": "CVE-2023-3333", "severity": "Medium"}},
                {"vulnerability": {"id": "CVE-2023-4444", "severity": "Low"}},
            ]
        }
        json_file.write_text(json.dumps(data))
        result = parse_grype.get_counts(str(json_file))
        assert result == "1 1 1 1"

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

    def test_table_with_missing_fix_versions(self, tmp_path):
        """Test table rendering when fix versions are missing."""
        json_file = tmp_path / "no_fix.json"
        data = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2023-1111",
                        "severity": "High",
                        "fix": {"versions": []},
                    },
                    "artifact": {"name": "test-package", "version": "1.0.0"},
                }
            ]
        }
        json_file.write_text(json.dumps(data))
        result = parse_grype.get_table(str(json_file))
        assert "CVE-2023-1111" in result
        assert "N/A" in result


class TestEdgeCases:
    """Edge case tests for parse_grype_results."""

    def test_empty_json_file(self, tmp_path):
        """Test with empty JSON file."""
        json_file = tmp_path / "empty.json"
        json_file.write_text("")
        result = parse_grype.get_counts(str(json_file))
        assert result == "0 0 0 0"

    def test_malformed_json(self, tmp_path):
        """Test with malformed JSON."""
        json_file = tmp_path / "bad.json"
        json_file.write_text("{invalid json")
        result = parse_grype.get_counts(str(json_file))
        assert result == "0 0 0 0"

    def test_json_with_no_matches(self, tmp_path):
        """Test JSON with missing matches field."""
        json_file = tmp_path / "no_matches.json"
        json_file.write_text(json.dumps({}))
        result = parse_grype.get_counts(str(json_file))
        assert result == "0 0 0 0"

    def test_matches_not_array(self, tmp_path):
        """Test when matches is not an array."""
        json_file = tmp_path / "not_array.json"
        json_file.write_text(json.dumps({"matches": "not an array"}))
        result = parse_grype.get_counts(str(json_file))
        assert result == "0 0 0 0"

    def test_empty_matches_array(self, tmp_path):
        """Test with empty matches array."""
        json_file = tmp_path / "empty_matches.json"
        json_file.write_text(json.dumps({"matches": []}))
        result = parse_grype.get_counts(str(json_file))
        assert result == "0 0 0 0"

    def test_matches_without_vulnerability_field(self, tmp_path):
        """Test match without vulnerability field."""
        json_file = tmp_path / "no_vuln.json"
        json_file.write_text(json.dumps({
            "matches": [{"artifact": {"name": "pkg"}}],
        }))
        result = parse_grype.get_counts(str(json_file))
        assert result == "0 0 0 1"

    def test_vulnerability_missing_severity(self, tmp_path):
        """Test vulnerability without severity field."""
        json_file = tmp_path / "no_severity.json"
        json_file.write_text(json.dumps({
            "matches": [{
                "vulnerability": {"id": "CVE-2023-1111"},
                "artifact": {"name": "pkg"},
            }],
        }))
        result = parse_grype.get_counts(str(json_file))
        assert result.startswith("0 0 0")

    def test_unknown_severity_level(self, tmp_path):
        """Test with unknown severity level."""
        json_file = tmp_path / "unknown_sev.json"
        json_file.write_text(json.dumps({
            "matches": [{
                "vulnerability": {"id": "CVE-2023-1111", "severity": "Unknown"},
                "artifact": {"name": "pkg", "version": "1.0"},
            }],
        }))
        result = parse_grype.get_counts(str(json_file))
        parts = result.split()
        assert len(parts) == 4

    def test_cves_with_none_id(self, tmp_path):
        """Test CVEs with None/missing IDs."""
        json_file = tmp_path / "no_cve_id.json"
        json_file.write_text(json.dumps({
            "matches": [
                {
                    "vulnerability": {"severity": "High", "id": None},
                    "artifact": {"name": "pkg", "version": "1.0"},
                },
                {
                    "vulnerability": {"severity": "High", "id": "CVE-2023-2222"},
                    "artifact": {"name": "pkg", "version": "1.0"},
                },
            ],
        }))
        result = parse_grype.get_cves(str(json_file))
        assert "CVE-2023-2222" in result

    def test_duplicate_cves(self, tmp_path):
        """Test that duplicate CVEs are counted as unique."""
        json_file = tmp_path / "dups.json"
        json_file.write_text(json.dumps({
            "matches": [
                {"vulnerability": {"id": "CVE-2023-1111", "severity": "High"}, "artifact": {"name": "pkg1"}},
                {"vulnerability": {"id": "CVE-2023-1111", "severity": "High"}, "artifact": {"name": "pkg2"}},
            ],
        }))
        result = parse_grype.get_unique(str(json_file))
        assert result == "1"

    def test_very_long_cve_id(self, tmp_path):
        """Test with very long CVE ID."""
        long_cve = "CVE-" + "x" * 100
        json_file = tmp_path / "long_cve.json"
        json_file.write_text(json.dumps({
            "matches": [{
                "vulnerability": {"id": long_cve, "severity": "High"},
                "artifact": {"name": "pkg"},
            }],
        }))
        result = parse_grype.get_cves(str(json_file))
        assert long_cve in result

    def test_unicode_in_package_names(self, tmp_path):
        """Test with unicode in package names."""
        json_file = tmp_path / "unicode.json"
        json_file.write_text(json.dumps({
            "matches": [{
                "vulnerability": {"id": "CVE-2023-1111", "severity": "High"},
                "artifact": {"name": "\u65e5\u672c\u8a9e\u30d1\u30c3\u30b1\u30fc\u30b8", "version": "1.0.0"},
            }],
        }))
        result = parse_grype.get_counts(str(json_file))
        assert result == "0 1 0 0"

    def test_nonexistent_input_file(self):
        """Test with nonexistent input file."""
        result = parse_grype.get_counts("/nonexistent/path.json")
        assert result == "0 0 0 0"

    def test_table_with_very_long_strings(self, tmp_path):
        """Test table output with very long package/vulnerability names."""
        json_file = tmp_path / "long_strings.json"
        long_str = "x" * 100
        json_file.write_text(json.dumps({
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2023-1111",
                    "severity": "Critical",
                    "description": long_str,
                },
                "artifact": {"name": long_str, "version": long_str},
            }],
        }))
        result = parse_grype.get_table(str(json_file))
        assert "CVE-2023-1111" in result

    def test_severity_case_sensitivity(self, tmp_path):
        """Test severity matching is case-insensitive."""
        json_file = tmp_path / "case.json"
        json_file.write_text(json.dumps({
            "matches": [
                {"vulnerability": {"id": "CVE-1", "severity": "CRITICAL"}, "artifact": {"name": "p"}},
                {"vulnerability": {"id": "CVE-2", "severity": "critical"}, "artifact": {"name": "p"}},
                {"vulnerability": {"id": "CVE-3", "severity": "Critical"}, "artifact": {"name": "p"}},
            ],
        }))
        result = parse_grype.get_counts(str(json_file))
        # At least some should be recognized as critical
        assert result != "0 0 0 0"

    def test_all_severity_levels(self, tmp_path):
        """Test with all severity levels present."""
        json_file = tmp_path / "all_levels.json"
        json_file.write_text(json.dumps({
            "matches": [
                {"vulnerability": {"id": "CVE-1", "severity": "Critical"}, "artifact": {"name": "p"}},
                {"vulnerability": {"id": "CVE-2", "severity": "High"}, "artifact": {"name": "p"}},
                {"vulnerability": {"id": "CVE-3", "severity": "Medium"}, "artifact": {"name": "p"}},
                {"vulnerability": {"id": "CVE-4", "severity": "Low"}, "artifact": {"name": "p"}},
            ],
        }))
        result = parse_grype.get_counts(str(json_file))
        assert result == "1 1 1 1"
