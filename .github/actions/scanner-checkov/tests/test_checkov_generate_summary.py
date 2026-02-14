#!/usr/bin/env python3
"""
Unit tests for scanner-checkov/scripts/generate_summary.py
Tests markdown generation for Checkov IaC security scan results
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# Paths
REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
GENERATOR_SCRIPT = SCRIPTS_DIR / "generate_summary.py"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "scanner-outputs" / "checkov"


class TestCheckovGenerateSummary:
    """Test cases for scanner-checkov generate-summary.sh"""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up test workspace for each test."""
        self.workspace = tmp_path
        self.checkov_reports = tmp_path / "checkov-reports"
        self.checkov_reports.mkdir(parents=True)
        self.output_file = tmp_path / "summary.md"
        # Change to workspace directory
        self.original_dir = os.getcwd()
        os.chdir(tmp_path)
        yield
        os.chdir(self.original_dir)

    def run_generator(
        self,
        output_file=None,
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
        """Helper to run the generator script with arguments."""
        if output_file is None:
            output_file = str(self.output_file)

        cmd = [
            sys.executable,
            str(GENERATOR_SCRIPT),
            str(output_file),
            "--is-pr-comment", is_pr_comment,
            "--has-iac", has_iac,
            "--iac-path", iac_path,
            "--critical", critical,
            "--high", high,
            "--medium", medium,
            "--low", low,
            "--passed", passed,
            "--total", total,
            "--repo-url", repo_url,
            "--github-server-url", github_server_url,
            "--github-repo", github_repo,
            "--github-run-id", github_run_id,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=self.workspace,
        )
        return result

    def test_script_and_fixtures_exist(self):
        """Verify generator script and fixtures exist."""
        assert GENERATOR_SCRIPT.exists(), f"Script not found: {GENERATOR_SCRIPT}"
        assert FIXTURES_DIR.exists(), f"Fixtures not found: {FIXTURES_DIR}"
        assert (FIXTURES_DIR / "results-with-findings.json").exists()
        assert (FIXTURES_DIR / "results-zero-findings.json").exists()

    def test_missing_output_file_argument(self):
        """Test error when output file argument is missing."""
        result = subprocess.run(
            [sys.executable, str(GENERATOR_SCRIPT)],
            capture_output=True,
            text=True,
            cwd=self.workspace,
        )
        assert result.returncode != 0
        assert "required: output_file" in result.stderr or "the following arguments are required: output_file" in result.stderr

    def test_generates_summary_with_findings(self):
        """Test generating summary with findings (tests finding aggregation, formatting, framework info)."""
        # Copy fixture
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.json",
            self.checkov_reports / "checkov-results.json",
        )

        # Run generator (5 findings: 2 HIGH, 2 MEDIUM, 1 LOW)
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

        # Check for key elements
        assert "Checkov IaC Security" in content
        assert "Check Summary" in content
        # Check table row with counts
        assert "| **0** | **2** | **2** | **1** | **5** | **8** |" in content
        # Verify framework info appears
        assert "Framework:" in content
        # Verify non-PR format uses heading
        assert "## " in content
        assert "Checkov IaC Security Scan Summary" in content
        # Verify severity grouping
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
        result = self.run_generator(
            has_iac="false",
            iac_path="",
        )

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

        # PR comment should use collapsible format
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
        # Don't copy any JSON file
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
        self.original_dir = os.getcwd()
        os.chdir(tmp_path)
        yield
        os.chdir(self.original_dir)

    def run_generator(
        self,
        output_file=None,
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
        """Helper to run the generator script with arguments."""
        if output_file is None:
            output_file = str(self.output_file)

        cmd = [
            sys.executable,
            str(GENERATOR_SCRIPT),
            str(output_file),
            "--is-pr-comment", is_pr_comment,
            "--has-iac", has_iac,
            "--iac-path", iac_path,
            "--critical", critical,
            "--high", high,
            "--medium", medium,
            "--low", low,
            "--passed", passed,
            "--total", total,
            "--repo-url", repo_url,
            "--github-server-url", github_server_url,
            "--github-repo", github_repo,
            "--github-run-id", github_run_id,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=self.workspace,
        )
        return result

    def test_malformed_json_file(self):
        """Test with malformed JSON in results file."""
        bad_json = self.checkov_reports / "checkov-results.json"
        bad_json.write_text("{invalid json content")

        result = self.run_generator(
            has_iac="true",
            total="5",
        )
        # Should handle gracefully and still generate output
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
        # Should default to [1, 1]
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
            total="5"
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
            total="39996"
        )
        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "9999" in content

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
        # Leading slash should be removed
        assert "absolute/path/main.tf" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
