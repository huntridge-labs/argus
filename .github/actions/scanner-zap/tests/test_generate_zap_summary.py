#!/usr/bin/env python3
"""
Unit tests for generate_zap_summary.py
Tests markdown generation for ZAP DAST scan results
"""

import json
import pytest

pytestmark = pytest.mark.unit
import os
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
    "generate_zap_summary",
    SCRIPTS_DIR / "generate_zap_summary.py"
)
generate_zap_summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generate_zap_summary)

# Get fixtures path
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "scanner-outputs" / "zap"
PARSER_PATH = SCRIPTS_DIR / "parse_zap_results.py"


class TestGenerateZAPSummary:
    """Test cases for generate_zap_summary.py functionality."""

    def test_format_scan_type_baseline(self):
        """Test format_scan_type with baseline."""
        result = generate_zap_summary.format_scan_type(scan_type="baseline")
        assert " - Baseline" in result

    def test_format_scan_type_full(self):
        """Test format_scan_type with full."""
        result = generate_zap_summary.format_scan_type(scan_type="full")
        assert " - Full Scan" in result

    def test_format_scan_type_api(self):
        """Test format_scan_type with api."""
        result = generate_zap_summary.format_scan_type(scan_type="api")
        assert " - API Scan" in result

    def test_format_scan_type_with_mode(self):
        """Test format_scan_type with scan mode."""
        result = generate_zap_summary.format_scan_type(scan_type="baseline", scan_mode="docker-run")
        assert " - Baseline" in result
        assert "docker-run" in result

    def test_format_scan_type_empty(self):
        """Test format_scan_type with empty values."""
        result = generate_zap_summary.format_scan_type(scan_type="", scan_mode="")
        assert result == ""

    def test_get_counts_baseline_fixture(self):
        """Test get_counts with baseline fixture."""
        parser_path = str(PARSER_PATH)
        report_path = str(FIXTURES_DIR / "results-baseline-scan.json")
        crit, high, med, low = generate_zap_summary.get_counts(parser_path, report_path)
        assert crit == 0
        assert high == 0
        assert med == 1
        assert low == 2

    def test_get_counts_zero_findings_fixture(self):
        """Test get_counts with zero findings fixture."""
        parser_path = str(PARSER_PATH)
        report_path = str(FIXTURES_DIR / "results-zero-findings.json")
        crit, high, med, low = generate_zap_summary.get_counts(parser_path, report_path)
        assert crit == 0
        assert high == 0
        assert med == 0
        assert low == 0

    def test_get_counts_with_info_baseline_fixture(self):
        """Test get_counts_with_info with baseline fixture."""
        parser_path = str(PARSER_PATH)
        report_path = str(FIXTURES_DIR / "results-baseline-scan.json")
        crit, high, med, low, info = generate_zap_summary.get_counts_with_info(parser_path, report_path)
        assert crit == 0
        assert high == 0
        assert med == 1
        assert low == 2
        assert info == 0

    def test_get_total_baseline_fixture(self):
        """Test get_total with baseline fixture."""
        parser_path = str(PARSER_PATH)
        report_path = str(FIXTURES_DIR / "results-baseline-scan.json")
        total = generate_zap_summary.get_total(parser_path, report_path)
        assert total == 3

    def test_get_unique_baseline_fixture(self):
        """Test get_unique with baseline fixture."""
        parser_path = str(PARSER_PATH)
        report_path = str(FIXTURES_DIR / "results-baseline-scan.json")
        unique = generate_zap_summary.get_unique(parser_path, report_path)
        assert unique == 3

    def test_get_target_baseline_fixture(self):
        """Test get_target with baseline fixture."""
        parser_path = str(PARSER_PATH)
        report_path = str(FIXTURES_DIR / "results-baseline-scan.json")
        target = generate_zap_summary.get_target(parser_path, report_path)
        assert target == "http://localhost:3000"

    def test_find_reports_no_directory(self, tmp_path, monkeypatch):
        """Test find_reports when directory doesn't exist."""
        monkeypatch.chdir(tmp_path)
        reports = generate_zap_summary.find_reports()
        assert reports == []

    def test_find_reports_empty_directory(self, tmp_path, monkeypatch):
        """Test find_reports with empty zap-downloads directory."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "zap-downloads").mkdir()
        reports = generate_zap_summary.find_reports()
        assert reports == []

    def test_find_reports_single_report(self, tmp_path, monkeypatch):
        """Test find_reports with single report file."""
        monkeypatch.chdir(tmp_path)
        zap_downloads = tmp_path / "zap-downloads"
        zap_downloads.mkdir()

        # Copy fixture
        report_file = zap_downloads / "report_json.json"
        report_file.write_text((FIXTURES_DIR / "results-baseline-scan.json").read_text())

        reports = generate_zap_summary.find_reports()
        assert len(reports) == 1
        assert reports[0].name == "report_json.json"

    def test_find_reports_multiple_reports(self, tmp_path, monkeypatch):
        """Test find_reports with multiple report files."""
        monkeypatch.chdir(tmp_path)
        zap_downloads = tmp_path / "zap-downloads"
        zap_downloads.mkdir()

        # Create subdirectories with reports
        sub1 = zap_downloads / "zap-reports-baseline-abc123"
        sub2 = zap_downloads / "zap-reports-full-def456"
        sub1.mkdir()
        sub2.mkdir()

        # Copy fixture to both
        fixture_content = (FIXTURES_DIR / "results-baseline-scan.json").read_text()
        (sub1 / "report_json.json").write_text(fixture_content)
        (sub2 / "report_json.json").write_text(fixture_content)

        reports = generate_zap_summary.find_reports()
        assert len(reports) == 2

    def test_extract_scan_type_from_artifact_baseline(self):
        """Test extract_scan_type_from_artifact with baseline."""
        artifact_name = "zap-reports-baseline-abc123"
        result = generate_zap_summary.extract_scan_type_from_artifact(artifact_name)
        assert result == "baseline"

    def test_extract_scan_type_from_artifact_full(self):
        """Test extract_scan_type_from_artifact with full."""
        artifact_name = "zap-reports-full-def456"
        result = generate_zap_summary.extract_scan_type_from_artifact(artifact_name)
        assert result == "full"

    def test_extract_scan_type_from_artifact_api(self):
        """Test extract_scan_type_from_artifact with api."""
        artifact_name = "zap-reports-api-ghi789"
        result = generate_zap_summary.extract_scan_type_from_artifact(artifact_name)
        assert result == "api"

    def test_extract_scan_type_from_artifact_complex(self):
        """Test extract_scan_type_from_artifact with complex format."""
        artifact_name = "zap-reports-a1b2c3-baseline-d4e5f6"
        result = generate_zap_summary.extract_scan_type_from_artifact(artifact_name)
        assert result == "baseline"

    def test_extract_scan_type_from_artifact_unknown(self):
        """Test extract_scan_type_from_artifact with unknown format."""
        artifact_name = "zap-reports-unknown"
        result = generate_zap_summary.extract_scan_type_from_artifact(artifact_name)
        assert result == "unknown"

    def test_write_summary_header_zap_md(self, tmp_path):
        """Test write_summary_header creates correct format for zap.md."""
        output_file = tmp_path / "zap.md"
        generate_zap_summary.write_summary_header(output_file, " - Baseline")

        content = output_file.read_text()
        assert "<details>" in content
        assert "🕷️ ZAP (DAST) - Baseline" in content
        assert "✅ Completed" in content

    def test_write_summary_header_step_summary(self, tmp_path):
        """Test write_summary_header creates correct format for step summary."""
        output_file = tmp_path / "GITHUB_STEP_SUMMARY"
        generate_zap_summary.write_summary_header(output_file, " - Full Scan")

        content = output_file.read_text()
        assert "## 🕷️ ZAP DAST Summary - Full Scan" in content
        assert "<details>" not in content

    def test_write_skipped_summary(self, tmp_path, monkeypatch):
        """Test write_skipped_summary creates correct output."""
        monkeypatch.chdir(tmp_path)
        generate_zap_summary.write_skipped_summary(" - Baseline")

        summary_file = tmp_path / "scanner-summaries" / "zap.md"
        assert summary_file.exists()
        content = summary_file.read_text()
        assert "⏭️ Skipped" in content
        assert "🕷️ ZAP (DAST) - Baseline" in content

    def test_append_to_file_creates_file(self, tmp_path):
        """Test append_to_file creates file if it doesn't exist."""
        test_file = tmp_path / "test.txt"
        generate_zap_summary.append_to_file(str(test_file), "Hello World")

        assert test_file.exists()
        assert test_file.read_text() == "Hello World"

    def test_append_to_file_appends_content(self, tmp_path):
        """Test append_to_file appends to existing file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello ")
        generate_zap_summary.append_to_file(str(test_file), "World")

        assert test_file.read_text() == "Hello World"

    def test_run_details_command(self):
        """Test run_details_command executes parser correctly."""
        parser_path = str(PARSER_PATH)
        report_path = str(FIXTURES_DIR / "results-baseline-scan.json")

        result = generate_zap_summary.run_details_command(
            parser_path,
            report_path,
            severity="medium",
            limit=50
        )
        assert isinstance(result, str)
        assert "Cross-Domain Misconfiguration" in result or result == ""

    def test_run_compact_table_command(self):
        """Test run_compact_table_command executes parser correctly."""
        parser_path = str(PARSER_PATH)
        report_path = str(FIXTURES_DIR / "results-baseline-scan.json")

        result = generate_zap_summary.run_compact_table_command(
            parser_path,
            report_path,
            severity="low",
            limit=50
        )
        assert isinstance(result, str)
        assert "| Alert | CWE | Locations | Quick Fix |" in result

    def test_get_env_with_value(self, monkeypatch):
        """Test get_env returns environment variable value."""
        monkeypatch.setenv("TEST_VAR", "test_value")
        result = generate_zap_summary.get_env("TEST_VAR")
        assert result == "test_value"

    def test_get_env_with_default(self):
        """Test get_env returns default when variable not set."""
        result = generate_zap_summary.get_env("NONEXISTENT_VAR_12345", "default_value")
        assert result == "default_value"

    def test_ensure_parser_present(self, monkeypatch):
        """Test ensure_parser when ZAP_PARSER is set."""
        monkeypatch.setenv("ZAP_PARSER", "/path/to/parser.py")
        result = generate_zap_summary.ensure_parser()
        assert result == "/path/to/parser.py"

    def test_ensure_parser_missing(self, monkeypatch):
        """Test ensure_parser raises error when ZAP_PARSER not set."""
        monkeypatch.delenv("ZAP_PARSER", raising=False)
        with pytest.raises(RuntimeError) as exc_info:
            generate_zap_summary.ensure_parser()
        assert "ZAP_PARSER must be set" in str(exc_info.value)

    def test_main_no_reports(self, tmp_path, monkeypatch, capsys):
        """Test main function with no reports."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("ZAP_PARSER", str(PARSER_PATH))

        generate_zap_summary.main()

        captured = capsys.readouterr()
        assert "No ZAP scan results found" in captured.out
        assert (tmp_path / "scanner-summaries" / "zap.md").exists()

    def test_main_single_report(self, tmp_path, monkeypatch, capsys):
        """Test main function with single report."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("ZAP_PARSER", str(PARSER_PATH))
        monkeypatch.setenv("ZAP_SCAN_TYPE", "baseline")

        zap_downloads = tmp_path / "zap-downloads"
        zap_downloads.mkdir()
        fixture_content = (FIXTURES_DIR / "results-baseline-scan.json").read_text()
        (zap_downloads / "report_json.json").write_text(fixture_content)

        generate_zap_summary.main()

        summary_file = tmp_path / "scanner-summaries" / "zap.md"
        assert summary_file.exists()
        content = summary_file.read_text()
        assert "Overall Findings Summary" in content
        assert "baseline scan" in content

    def test_main_multiple_reports(self, tmp_path, monkeypatch, capsys):
        """Test main function with multiple reports."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("ZAP_PARSER", str(PARSER_PATH))

        zap_downloads = tmp_path / "zap-downloads"
        zap_downloads.mkdir()

        # Create subdirectories with reports
        sub1 = zap_downloads / "zap-reports-baseline-abc123"
        sub2 = zap_downloads / "zap-reports-full-def456"
        sub1.mkdir()
        sub2.mkdir()

        fixture_content = (FIXTURES_DIR / "results-baseline-scan.json").read_text()
        (sub1 / "report_json.json").write_text(fixture_content)
        (sub2 / "report_json.json").write_text(fixture_content)

        generate_zap_summary.main()

        summary_file = tmp_path / "scanner-summaries" / "zap.md"
        assert summary_file.exists()
        content = summary_file.read_text()
        assert "Scan Breakdown" in content
        assert "baseline" in content
        assert "full" in content

    def test_main_with_github_step_summary(self, tmp_path, monkeypatch):
        """Test main function writes to GITHUB_STEP_SUMMARY."""
        monkeypatch.chdir(tmp_path)
        step_summary_file = tmp_path / "STEP_SUMMARY"
        monkeypatch.setenv("ZAP_PARSER", str(PARSER_PATH))
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step_summary_file))

        zap_downloads = tmp_path / "zap-downloads"
        zap_downloads.mkdir()
        fixture_content = (FIXTURES_DIR / "results-baseline-scan.json").read_text()
        (zap_downloads / "report_json.json").write_text(fixture_content)

        generate_zap_summary.main()

        assert step_summary_file.exists()
        content = step_summary_file.read_text()
        assert "ZAP DAST Summary" in content

    def test_main_with_artifact_links(self, tmp_path, monkeypatch):
        """Test main function generates artifact links when GitHub vars set."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("ZAP_PARSER", str(PARSER_PATH))
        monkeypatch.setenv("GITHUB_REPOSITORY", "test/repo")
        monkeypatch.setenv("GITHUB_RUN_ID", "12345")

        zap_downloads = tmp_path / "zap-downloads"
        zap_downloads.mkdir()
        fixture_content = (FIXTURES_DIR / "results-baseline-scan.json").read_text()
        (zap_downloads / "report_json.json").write_text(fixture_content)

        generate_zap_summary.main()

        summary_file = tmp_path / "scanner-summaries" / "zap.md"
        content = summary_file.read_text()
        assert "Artifacts" in content
        assert "12345" in content

    @pytest.mark.parametrize("scan_type,expected_display", [
        ("baseline", " - Baseline"),
        ("full", " - Full Scan"),
        ("api", " - API Scan"),
        ("unknown", " - Unknown"),
    ])
    def test_format_scan_type_variations(self, scan_type, expected_display):
        """Test format_scan_type with various scan types."""
        result = generate_zap_summary.format_scan_type(scan_type=scan_type)
        assert expected_display in result

    def test_main_clean_scan(self, tmp_path, monkeypatch):
        """Test main function with clean scan (zero findings)."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("ZAP_PARSER", str(PARSER_PATH))
        monkeypatch.setenv("ZAP_SCAN_TYPE", "baseline")

        zap_downloads = tmp_path / "zap-downloads"
        zap_downloads.mkdir()
        fixture_content = (FIXTURES_DIR / "results-zero-findings.json").read_text()
        (zap_downloads / "report_json.json").write_text(fixture_content)

        generate_zap_summary.main()

        summary_file = tmp_path / "scanner-summaries" / "zap.md"
        assert summary_file.exists()
        content = summary_file.read_text()
        assert "0" in content  # Should show zero counts


class TestEdgeCases:
    """Edge case tests for ZAP summary generation."""

    def test_missing_zap_downloads_directory(self, tmp_path, monkeypatch):
        """Test when zap-downloads directory doesn't exist."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("ZAP_PARSER", str(PARSER_PATH))
        monkeypatch.setenv("ZAP_SCAN_TYPE", "baseline")
        # Don't create zap-downloads directory
        generate_zap_summary.main()
        summary_file = tmp_path / "scanner-summaries" / "zap.md"
        # Should still create summary
        assert summary_file.exists()

    def test_malformed_json_report(self, tmp_path, monkeypatch):
        """Test with malformed JSON report."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("ZAP_PARSER", str(PARSER_PATH))
        monkeypatch.setenv("ZAP_SCAN_TYPE", "full")

        zap_downloads = tmp_path / "zap-downloads"
        zap_downloads.mkdir()
        (zap_downloads / "report_json.json").write_text("{invalid json")

        generate_zap_summary.main()
        summary_file = tmp_path / "scanner-summaries" / "zap.md"
        assert summary_file.exists()

    def test_empty_json_report(self, tmp_path, monkeypatch):
        """Test with empty JSON report."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("ZAP_PARSER", str(PARSER_PATH))
        monkeypatch.setenv("ZAP_SCAN_TYPE", "baseline")

        zap_downloads = tmp_path / "zap-downloads"
        zap_downloads.mkdir()
        (zap_downloads / "report_json.json").write_text("")

        generate_zap_summary.main()
        summary_file = tmp_path / "scanner-summaries" / "zap.md"
        assert summary_file.exists()

    def test_very_large_finding_counts(self, tmp_path, monkeypatch):
        """Test with very large finding counts."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("ZAP_PARSER", str(PARSER_PATH))
        monkeypatch.setenv("ZAP_SCAN_TYPE", "api")

        zap_downloads = tmp_path / "zap-downloads"
        zap_downloads.mkdir()
        (zap_downloads / "report_json.json").write_text(json.dumps({
            "site": [{
                "alert": [
                    {"riskcode": "3", "name": f"Alert {i}"}
                    for i in range(100)
                ]
            }]
        }))

        generate_zap_summary.main()
        summary_file = tmp_path / "scanner-summaries" / "zap.md"
        assert summary_file.exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
