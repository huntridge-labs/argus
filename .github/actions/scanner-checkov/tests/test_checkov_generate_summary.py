#!/usr/bin/env python3
"""
Unit tests for scanner-checkov/scripts/generate_summary.py
Tests markdown generation for Checkov IaC security scan results

Uses in-process imports instead of subprocess for fast execution.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.unit

# Paths
REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
GENERATOR_SCRIPT = SCRIPTS_DIR / "generate_summary.py"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "scanner-outputs" / "checkov"

# Load module in-process via importlib
spec = importlib.util.spec_from_file_location(
    "checkov_generate_summary", GENERATOR_SCRIPT,
)
gen_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen_mod)


def _run_in_process(
    workspace,
    output_file,
    is_pr_comment="false",
    has_iac="true",
    iac_path="infrastructure",
    critical="0",
    high="0",
    medium="0",
    low="0",
    passed="0",
    total="0",
    repo_url="https://github.com/test/repo/blob/main",
    github_server_url="https://github.com",
    github_repo="test/repo",
    github_run_id="12345",
):
    """Run generate_checkov_summary in-process, returning a result-like object."""
    original_dir = os.getcwd()
    try:
        os.chdir(workspace)
        gen_mod.generate_checkov_summary(
            output_file,
            is_pr_comment,
            has_iac,
            iac_path,
            critical,
            high,
            medium,
            low,
            passed,
            total,
            repo_url,
            github_server_url,
            github_repo,
            github_run_id,
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    except SystemExit as e:
        return SimpleNamespace(returncode=e.code or 1, stdout="", stderr="")
    except Exception as e:
        return SimpleNamespace(returncode=1, stdout="", stderr=str(e))
    finally:
        os.chdir(original_dir)


class TestCheckovGenerateSummary:
    """Test cases for scanner-checkov generate_summary.py"""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up test workspace for each test."""
        self.workspace = tmp_path
        self.checkov_reports = tmp_path / "checkov-reports"
        self.checkov_reports.mkdir(parents=True)
        self.output_file = tmp_path / "summary.md"

    def run_generator(self, **kwargs):
        """Helper to run the generator in-process."""
        kwargs.setdefault("output_file", str(self.output_file))
        return _run_in_process(self.workspace, **kwargs)

    def test_script_and_fixtures_exist(self):
        """Verify generator script and fixtures exist."""
        assert GENERATOR_SCRIPT.exists(), f"Script not found: {GENERATOR_SCRIPT}"
        assert FIXTURES_DIR.exists(), f"Fixtures not found: {FIXTURES_DIR}"
        assert (FIXTURES_DIR / "results-with-findings.json").exists()
        assert (FIXTURES_DIR / "results-zero-findings.json").exists()

    def test_missing_output_file_argument(self):
        """Test error when output file argument is missing (CLI validation)."""
        result = subprocess.run(
            [sys.executable, str(GENERATOR_SCRIPT)],
            capture_output=True,
            text=True,
            cwd=self.workspace,
            timeout=10,
        )
        assert result.returncode != 0
        assert "required: output_file" in result.stderr or "the following arguments are required: output_file" in result.stderr

    def test_generates_summary_with_findings(self):
        """Test generating summary with findings (tests finding aggregation, formatting, framework info)."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.json",
            self.checkov_reports / "checkov-results.json",
        )

        result = self.run_generator(
            has_iac="true",
            critical="0",
            high="2",
            medium="2",
            low="1",
            passed="8",
            total="5",
            is_pr_comment="false",
        )

        assert result.returncode == 0, f"Script failed: {result.stderr}"
        assert self.output_file.exists(), "Output file not created"

        content = self.output_file.read_text()

        assert "Checkov IaC Security" in content
        assert "Check Summary" in content
        assert "| **0** | **2** | **2** | **1** | **5** | **8** |" in content
        assert "Framework:" in content
        assert "## " in content
        assert "Checkov IaC Security Scan Summary" in content
        assert "HIGH Severity" in content
        assert "MEDIUM Severity" in content

    def test_generates_summary_zero_findings(self):
        """Test generating summary with zero findings."""
        shutil.copy(
            FIXTURES_DIR / "results-zero-findings.json",
            self.checkov_reports / "checkov-results.json",
        )

        result = self.run_generator(
            has_iac="true",
            critical="0",
            high="0",
            medium="0",
            low="0",
            passed="12",
            total="0",
        )

        assert result.returncode == 0
        assert self.output_file.exists()

        content = self.output_file.read_text()
        assert "All 12 security checks passed" in content

    def test_skipped_no_iac_directory(self):
        """Test skipped status when no IaC directory."""
        result = self.run_generator(has_iac="false", iac_path="")

        assert result.returncode == 0
        assert self.output_file.exists()

        content = self.output_file.read_text()
        assert "Skipped" in content
        assert "no IaC directory" in content

    def test_pr_comment_format_collapsible(self):
        """Test PR comment format uses collapsible sections."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.json",
            self.checkov_reports / "checkov-results.json",
        )

        result = self.run_generator(
            is_pr_comment="true",
            has_iac="true",
            high="2",
            medium="2",
            low="1",
            passed="8",
            total="5",
        )

        assert result.returncode == 0
        content = self.output_file.read_text()

        assert "<details>" in content
        assert "<summary>" in content
        assert "</details>" in content

    def test_critical_severity_priority_message(self):
        """Test CRITICAL severity priority message appears."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.json",
            self.checkov_reports / "checkov-results.json",
        )

        result = self.run_generator(
            has_iac="true",
            critical="3",
            high="2",
            medium="0",
            low="0",
            passed="8",
            total="5",
        )

        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "CRITICAL" in content
        assert "3 critical severity issues" in content

    def test_failed_checks_details_section(self):
        """Test failed checks details section is present."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.json",
            self.checkov_reports / "checkov-results.json",
        )

        result = self.run_generator(
            has_iac="true",
            high="2",
            medium="2",
            low="1",
            passed="8",
            total="5",
        )

        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "Failed Check Details" in content
        assert "Check ID" in content
        assert "Check Name" in content

    def test_artifact_link_present(self):
        """Test artifact link is present in output."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.json",
            self.checkov_reports / "checkov-results.json",
        )

        result = self.run_generator(
            has_iac="true",
            github_repo="test/repo",
            github_run_id="12345",
            total="5",
        )

        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "https://github.com/test/repo/actions/runs/12345" in content

    def test_handles_missing_json_file(self):
        """Test handles missing JSON file gracefully."""
        result = self.run_generator(has_iac="true")

        assert result.returncode == 0
        assert self.output_file.exists()

        content = self.output_file.read_text()
        assert "No results" in content or "No Checkov results" in content


class TestEdgeCases:
    """Edge case tests for scanner-checkov summary generation."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up test workspace for each test."""
        self.workspace = tmp_path
        self.checkov_reports = tmp_path / "checkov-reports"
        self.checkov_reports.mkdir(parents=True)
        self.output_file = tmp_path / "summary.md"

    def run_generator(self, **kwargs):
        """Helper to run the generator in-process."""
        kwargs.setdefault("output_file", str(self.output_file))
        return _run_in_process(self.workspace, **kwargs)

    def test_malformed_json_file(self):
        """Test with malformed JSON in results file."""
        bad_json = self.checkov_reports / "checkov-results.json"
        bad_json.write_text("{invalid json content")

        result = self.run_generator(has_iac="true", total="5")
        assert result.returncode == 0
        assert self.output_file.exists()

    def test_json_file_with_empty_object(self):
        """Test with JSON containing empty results object."""
        json_file = self.checkov_reports / "checkov-results.json"
        json_file.write_text(json.dumps({}))

        result = self.run_generator(has_iac="true", total="0")
        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "Checkov" in content

    def test_json_file_missing_results_field(self):
        """Test with JSON missing 'results' field."""
        json_file = self.checkov_reports / "checkov-results.json"
        json_file.write_text(json.dumps({"check_type": "terraform"}))

        result = self.run_generator(has_iac="true", total="0")
        assert result.returncode == 0
        assert self.output_file.exists()

    def test_null_severity_field(self):
        """Test with null severity field in checks."""
        json_file = self.checkov_reports / "checkov-results.json"
        json_file.write_text(json.dumps({
            "check_type": "terraform",
            "results": {
                "failed_checks": [{
                    "check_id": "CKV-001",
                    "check_name": "Check",
                    "resource": "resource",
                    "file_path": "main.tf",
                    "severity": None,
                }]
            }
        }))

        result = self.run_generator(has_iac="true", total="1")
        assert result.returncode == 0

    def test_missing_file_line_range(self):
        """Test with missing file_line_range field."""
        json_file = self.checkov_reports / "checkov-results.json"
        json_file.write_text(json.dumps({
            "check_type": "terraform",
            "results": {
                "failed_checks": [{
                    "check_id": "CKV-001",
                    "check_name": "Check",
                    "resource": "resource",
                    "file_path": "main.tf",
                }]
            }
        }))

        result = self.run_generator(has_iac="true", total="1")
        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "#L1-L1" in content or "main.tf" in content

    def test_empty_failed_checks_array(self):
        """Test with empty failed_checks array."""
        json_file = self.checkov_reports / "checkov-results.json"
        json_file.write_text(json.dumps({
            "check_type": "terraform",
            "results": {
                "failed_checks": []
            }
        }))

        result = self.run_generator(has_iac="true", total="0", passed="5")
        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "All 5 security checks passed" in content

    def test_only_critical_findings_all_critical(self):
        """Test with all findings being CRITICAL."""
        json_file = self.checkov_reports / "checkov-results.json"
        json_file.write_text(json.dumps({
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {
                        "check_id": f"CKV-{i:03d}",
                        "check_name": f"Check {i}",
                        "resource": f"resource_{i}",
                        "file_path": "main.tf",
                        "severity": "CRITICAL"
                    } for i in range(1, 6)
                ]
            }
        }))

        result = self.run_generator(
            has_iac="true",
            critical="5",
            high="0",
            medium="0",
            low="0",
            total="5",
        )
        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "🚨 CRITICAL" in content
        assert "5 critical severity issues" in content

    def test_no_severity_field_in_any_check(self):
        """Test when NO checks have severity field (ungrouped format)."""
        json_file = self.checkov_reports / "checkov-results.json"
        json_file.write_text(json.dumps({
            "check_type": "terraform",
            "results": {
                "failed_checks": [{
                    "check_id": "CKV-001",
                    "check_name": "Check",
                    "resource": "resource",
                    "file_path": "main.tf",
                }]
            }
        }))

        result = self.run_generator(has_iac="true", total="1")
        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "Failed Checks" in content or "Check ID" in content

    def test_very_large_numbers(self):
        """Test with very large vulnerability counts."""
        json_file = self.checkov_reports / "checkov-results.json"
        json_file.write_text(json.dumps({
            "check_type": "terraform",
            "results": {"failed_checks": []}
        }))

        result = self.run_generator(
            has_iac="true",
            critical="9999",
            high="9999",
            medium="9999",
            low="9999",
            passed="9999999",
            total="39996",
        )
        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "9999" in content

    def test_empty_string_counts_via_cli(self):
        """Test CLI handles empty string counts (happens when has_iac=false skips parse-results)."""
        result = subprocess.run(
            [
                sys.executable, str(GENERATOR_SCRIPT),
                str(self.output_file),
                "--has-iac", "false",
                "--critical", "",
                "--high", "",
                "--medium", "",
                "--low", "",
                "--passed", "",
                "--total", "",
            ],
            capture_output=True,
            text=True,
            cwd=self.workspace,
            timeout=10,
        )
        assert result.returncode == 0, f"Script failed on empty strings: {result.stderr}"
        content = self.output_file.read_text()
        assert "Skipped" in content

    def test_file_path_with_leading_slash(self):
        """Test with file_path that has leading slash."""
        json_file = self.checkov_reports / "checkov-results.json"
        json_file.write_text(json.dumps({
            "check_type": "terraform",
            "results": {
                "failed_checks": [{
                    "check_id": "CKV-001",
                    "check_name": "Check",
                    "resource": "resource",
                    "file_path": "/absolute/path/main.tf",
                }]
            }
        }))

        result = self.run_generator(has_iac="true", total="1")
        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "absolute/path/main.tf" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
