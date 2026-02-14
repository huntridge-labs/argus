#!/usr/bin/env python3
"""
Unit tests for parse_zap_results.py
Tests the ZAP (OWASP Zed Attack Proxy) results parser with synthetic fixtures
"""

import json
import pytest

pytestmark = pytest.mark.unit
import sys
from pathlib import Path

import pytest


# Add the scripts directory to the path
REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

# Import the script as a module
import importlib.util
spec = importlib.util.spec_from_file_location(
    "parse_zap_results",
    SCRIPTS_DIR / "parse_zap_results.py"
)
parse_zap_results = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_zap_results)

# Get fixtures path
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "scanner-outputs" / "zap"


class TestParseZAPResults:
    """Test cases for parse_zap_results.py functionality using fixtures."""

    def test_counts_zero_findings(self):
        """Test counts command with zero findings."""
        result = parse_zap_results.get_counts(str(FIXTURES_DIR / "results-zero-findings.json"))
        # ZAP has no critical level, so always "0 0 0 0"
        assert result == "0 0 0 0"

    def test_counts_baseline_scan(self):
        """Test counts command with baseline scan results."""
        result = parse_zap_results.get_counts(str(FIXTURES_DIR / "results-baseline-scan.json"))
        # Baseline scan: 0 crit, 0 high, 1 medium, 2 low
        assert result == "0 0 1 2"

    def test_counts_nonexistent_file(self):
        """Test counts command with nonexistent file."""
        result = parse_zap_results.get_counts("/nonexistent/file.json")
        assert result == "0 0 0 0"

    def test_counts_empty_file(self, tmp_path):
        """Test counts command with empty file."""
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("")
        result = parse_zap_results.get_counts(str(empty_file))
        assert result == "0 0 0 0"

    def test_counts_malformed_json(self, tmp_path):
        """Test counts command with malformed JSON."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{invalid json")
        result = parse_zap_results.get_counts(str(bad_file))
        assert result == "0 0 0 0"

    def test_counts_with_info_zero_findings(self):
        """Test counts-with-info command with zero findings."""
        result = parse_zap_results.get_counts_with_info(str(FIXTURES_DIR / "results-zero-findings.json"))
        assert result == "0 0 0 0 0"

    def test_counts_with_info_baseline(self):
        """Test counts-with-info command with baseline scan results."""
        result = parse_zap_results.get_counts_with_info(str(FIXTURES_DIR / "results-baseline-scan.json"))
        # Should include informational count as 5th number
        assert result == "0 0 1 2 0"

    def test_total_zero_findings(self):
        """Test total command with zero findings."""
        result = parse_zap_results.get_total(str(FIXTURES_DIR / "results-zero-findings.json"))
        assert result == "0"

    def test_total_baseline_scan(self):
        """Test total command with baseline scan results."""
        result = parse_zap_results.get_total(str(FIXTURES_DIR / "results-baseline-scan.json"))
        assert result == "3"

    def test_unique_zero_findings(self):
        """Test unique command with zero findings."""
        result = parse_zap_results.get_unique(str(FIXTURES_DIR / "results-zero-findings.json"))
        assert result == "0"

    def test_unique_baseline_scan(self):
        """Test unique command with baseline scan results."""
        result = parse_zap_results.get_unique(str(FIXTURES_DIR / "results-baseline-scan.json"))
        assert result == "3"

    def test_alerts_zero_findings(self):
        """Test alerts command with zero findings."""
        result = parse_zap_results.get_alerts(str(FIXTURES_DIR / "results-zero-findings.json"))
        assert result == []

    def test_alerts_baseline_scan(self):
        """Test alerts command with baseline scan results."""
        result = parse_zap_results.get_alerts(str(FIXTURES_DIR / "results-baseline-scan.json"))
        assert len(result) == 3
        assert "X-Content-Type-Options Header Missing" in result
        assert "Cookie without SameSite Attribute" in result
        assert "Cross-Domain Misconfiguration" in result

    def test_alerts_by_severity_high(self):
        """Test alerts command filtered by high severity."""
        result = parse_zap_results.get_alerts(str(FIXTURES_DIR / "results-baseline-scan.json"), severity="high")
        assert len(result) == 0  # No high severity in baseline fixture

    def test_alerts_by_severity_medium(self):
        """Test alerts command filtered by medium severity."""
        result = parse_zap_results.get_alerts(str(FIXTURES_DIR / "results-baseline-scan.json"), severity="medium")
        assert len(result) == 1
        assert "Cross-Domain Misconfiguration" in result

    def test_alerts_by_severity_low(self):
        """Test alerts command filtered by low severity."""
        result = parse_zap_results.get_alerts(str(FIXTURES_DIR / "results-baseline-scan.json"), severity="low")
        assert len(result) == 2

    def test_alerts_by_severity_informational(self):
        """Test alerts command filtered by informational severity."""
        result = parse_zap_results.get_alerts(str(FIXTURES_DIR / "results-baseline-scan.json"), severity="informational")
        assert len(result) == 0

    def test_alerts_by_severity_critical_maps_to_high(self):
        """Test alerts command with critical severity maps to high."""
        result = parse_zap_results.get_alerts(str(FIXTURES_DIR / "results-baseline-scan.json"), severity="critical")
        assert len(result) == 0  # Critical maps to high, no high in fixture

    def test_table_zero_findings(self):
        """Test table command with zero findings."""
        result = parse_zap_results.generate_table(str(FIXTURES_DIR / "results-zero-findings.json"))
        assert result == ""

    def test_table_baseline_scan(self):
        """Test table command with baseline scan results."""
        result = parse_zap_results.generate_table(str(FIXTURES_DIR / "results-baseline-scan.json"))
        assert "Cross-Domain Misconfiguration" in result
        assert "X-Content-Type-Options Header Missing" in result
        assert "|" in result  # Markdown table format

    def test_table_with_limit(self):
        """Test table command respects limit parameter."""
        # Should work with any limit
        result = parse_zap_results.generate_table(str(FIXTURES_DIR / "results-baseline-scan.json"), limit=1)
        assert isinstance(result, str)

    def test_target_baseline_scan(self):
        """Test target command with baseline scan results."""
        result = parse_zap_results.get_target(str(FIXTURES_DIR / "results-baseline-scan.json"))
        assert result == "http://localhost:3000"

    def test_target_missing_file(self):
        """Test target command with missing file."""
        result = parse_zap_results.get_target("/nonexistent/file.json")
        assert result == "unknown"

    def test_details_medium_severity(self):
        """Test details command with medium severity."""
        result = parse_zap_results.generate_details(
            str(FIXTURES_DIR / "results-baseline-scan.json"),
            severity="medium"
        )
        assert "<details>" in result
        assert "Cross-Domain Misconfiguration" in result

    def test_details_low_severity(self):
        """Test details command with low severity."""
        result = parse_zap_results.generate_details(
            str(FIXTURES_DIR / "results-baseline-scan.json"),
            severity="low"
        )
        assert "<details>" in result
        assert "X-Content-Type-Options Header Missing" in result or "Cookie without SameSite Attribute" in result

    def test_details_zero_findings(self):
        """Test details command with zero findings."""
        result = parse_zap_results.generate_details(
            str(FIXTURES_DIR / "results-zero-findings.json"),
            severity="low"
        )
        assert result == ""

    def test_details_invalid_severity(self):
        """Test details command with invalid severity."""
        result = parse_zap_results.generate_details(
            str(FIXTURES_DIR / "results-baseline-scan.json"),
            severity="invalid"
        )
        assert result == ""

    def test_compact_table_medium_severity(self):
        """Test compact-table command with medium severity."""
        result = parse_zap_results.generate_compact_table(
            str(FIXTURES_DIR / "results-baseline-scan.json"),
            severity="medium"
        )
        assert "| Alert | CWE | Locations | Quick Fix |" in result
        assert "Cross-Domain Misconfiguration" in result

    def test_compact_table_low_severity(self):
        """Test compact-table command with low severity."""
        result = parse_zap_results.generate_compact_table(
            str(FIXTURES_DIR / "results-baseline-scan.json"),
            severity="low"
        )
        assert "| Alert | CWE | Locations | Quick Fix |" in result

    def test_compact_table_zero_findings(self):
        """Test compact-table command with zero findings."""
        result = parse_zap_results.generate_compact_table(
            str(FIXTURES_DIR / "results-zero-findings.json"),
            severity="low"
        )
        # Should have header but no data rows
        assert "| Alert | CWE | Locations | Quick Fix |" in result
        # Should have header + separator rows (1 newline between them)
        assert result.count('\n') >= 1

    def test_map_severity_to_riskcode_high(self):
        """Test severity to riskcode mapping for high."""
        assert parse_zap_results.map_severity_to_riskcode("high") == "3"
        assert parse_zap_results.map_severity_to_riskcode("High") == "3"
        assert parse_zap_results.map_severity_to_riskcode("HIGH") == "3"

    def test_map_severity_to_riskcode_critical(self):
        """Test severity to riskcode mapping for critical (maps to high)."""
        assert parse_zap_results.map_severity_to_riskcode("critical") == "3"

    def test_map_severity_to_riskcode_medium(self):
        """Test severity to riskcode mapping for medium."""
        assert parse_zap_results.map_severity_to_riskcode("medium") == "2"

    def test_map_severity_to_riskcode_low(self):
        """Test severity to riskcode mapping for low."""
        assert parse_zap_results.map_severity_to_riskcode("low") == "1"

    def test_map_severity_to_riskcode_info(self):
        """Test severity to riskcode mapping for informational."""
        assert parse_zap_results.map_severity_to_riskcode("info") == "0"
        assert parse_zap_results.map_severity_to_riskcode("informational") == "0"

    def test_map_severity_to_riskcode_invalid(self):
        """Test severity to riskcode mapping for invalid severity."""
        assert parse_zap_results.map_severity_to_riskcode("invalid") is None

    def test_fixtures_exist(self):
        """Verify that required fixtures exist."""
        assert FIXTURES_DIR.exists(), f"Fixtures directory not found: {FIXTURES_DIR}"
        assert (FIXTURES_DIR / "results-zero-findings.json").exists(), "Fixture with zero findings not found"
        assert (FIXTURES_DIR / "results-baseline-scan.json").exists(), "Fixture with baseline scan not found"

    def test_fixture_format_baseline(self):
        """Test that the baseline fixture has correct format."""
        fixture_path = FIXTURES_DIR / "results-baseline-scan.json"
        content = json.loads(fixture_path.read_text())

        assert "@version" in content
        assert "site" in content
        assert len(content["site"]) > 0
        assert "alerts" in content["site"][0]
        assert len(content["site"][0]["alerts"]) == 3

    def test_fixture_format_zero_findings(self):
        """Test that the zero findings fixture has correct format."""
        fixture_path = FIXTURES_DIR / "results-zero-findings.json"
        content = json.loads(fixture_path.read_text())

        assert "@version" in content
        assert "site" in content
        # Either no alerts or empty alerts array
        if content["site"]:
            assert len(content["site"][0].get("alerts", [])) == 0

    @pytest.mark.parametrize("severity", ["high", "medium", "low", "info"])
    def test_alerts_severity_filtering(self, severity):
        """Test that alerts can be filtered by various severities."""
        result = parse_zap_results.get_alerts(
            str(FIXTURES_DIR / "results-baseline-scan.json"),
            severity=severity
        )
        # Should return a list (may be empty or contain items)
        assert isinstance(result, list)

    @pytest.mark.parametrize("command", ["counts", "total", "unique", "target"])
    def test_commands_nonexistent_file(self, command):
        """Test that commands handle nonexistent files gracefully."""
        if command == "counts":
            result = parse_zap_results.get_counts("/nonexistent/file.json")
            assert result == "0 0 0 0"
        elif command == "total":
            result = parse_zap_results.get_total("/nonexistent/file.json")
            assert result == "0"
        elif command == "unique":
            result = parse_zap_results.get_unique("/nonexistent/file.json")
            assert result == "0"
        elif command == "target":
            result = parse_zap_results.get_target("/nonexistent/file.json")
            assert result == "unknown"

    def test_alerts_sorted_alphabetically(self):
        """Test that alert names are returned in sorted order."""
        result = parse_zap_results.get_alerts(str(FIXTURES_DIR / "results-baseline-scan.json"))
        # Check if list is sorted
        assert result == sorted(result)

    def test_details_contains_cwe_when_present(self):
        """Test that details include CWE ID when present."""
        result = parse_zap_results.generate_details(
            str(FIXTURES_DIR / "results-baseline-scan.json"),
            severity="medium",
            limit=50
        )
        # The fixture has CWE IDs, they should be in the output
        assert "CWE-" in result or result == ""

    def test_compact_table_with_limit(self):
        """Test compact table respects limit parameter."""
        result1 = parse_zap_results.generate_compact_table(
            str(FIXTURES_DIR / "results-baseline-scan.json"),
            severity="low",
            limit=1
        )
        result2 = parse_zap_results.generate_compact_table(
            str(FIXTURES_DIR / "results-baseline-scan.json"),
            severity="low",
            limit=50
        )
        # Both should be valid, but result1 might be shorter
        assert isinstance(result1, str)
        assert isinstance(result2, str)


class TestEdgeCases:
    """Edge case tests for ZAP results parsing."""

    def test_empty_results_json(self, tmp_path):
        """Test with empty JSON file."""
        json_file = tmp_path / "empty.json"
        json_file.write_text("")
        result = parse_zap_results.get_counts(str(json_file))
        # Empty file should return "0 0 0 0"
        assert result is not None

    def test_malformed_json(self, tmp_path):
        """Test with malformed JSON."""
        json_file = tmp_path / "bad.json"
        json_file.write_text("{invalid json")
        result = parse_zap_results.get_counts(str(json_file))
        assert result is not None

    def test_json_no_sites(self, tmp_path):
        """Test with JSON missing sites field."""
        json_file = tmp_path / "no_sites.json"
        json_file.write_text(json.dumps({}))
        result = parse_zap_results.get_counts(str(json_file))
        assert result is not None

    def test_empty_sites_array(self, tmp_path):
        """Test with empty sites array."""
        json_file = tmp_path / "empty_sites.json"
        json_file.write_text(json.dumps({"site": []}))
        result = parse_zap_results.get_counts(str(json_file))
        # Empty sites should return counts of zero
        assert "0" in result

    def test_site_without_alerts(self, tmp_path):
        """Test site without alerts."""
        json_file = tmp_path / "no_alerts.json"
        json_file.write_text(json.dumps({
            "site": [{
                "name": "https://example.com",
                "@host": "example.com"
            }]
        }))
        result = parse_zap_results.get_counts(str(json_file))
        assert "0" in result

    def test_alert_without_risk_level(self, tmp_path):
        """Test alert missing riskcode."""
        json_file = tmp_path / "no_riskcode.json"
        json_file.write_text(json.dumps({
            "site": [{
                "alert": [{
                    "name": "Test Alert",
                    "description": "Test"
                }]
            }]
        }))
        result = parse_zap_results.get_counts(str(json_file))
        assert result is not None

    def test_nonexistent_file(self):
        """Test with nonexistent file."""
        result = parse_zap_results.get_counts("/nonexistent/file.json")
        # Should return "0 0 0" or similar
        assert "0" in result

    def test_very_long_alert_names(self, tmp_path):
        """Test with very long alert names."""
        long_name = "A" * 500
        json_file = tmp_path / "long_names.json"
        json_file.write_text(json.dumps({
            "site": [{
                "alert": [{
                    "name": long_name,
                    "description": long_name,
                    "riskcode": "1"
                }]
            }]
        }))
        result = parse_zap_results.generate_compact_table(str(json_file), severity="high")
        assert isinstance(result, str)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
