#!/usr/bin/env python3
"""
Unit tests for scanner-trivy-iac/scripts/generate_summary.py
Tests markdown generation for Trivy IaC security scan results

Uses in-process imports instead of subprocess for fast execution.
"""

import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.unit

# Paths
REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
GENERATOR_SCRIPT = SCRIPTS_DIR / "generate_summary.py"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "scanner-outputs" / "trivy-iac"

# Load module in-process via importlib
spec = importlib.util.spec_from_file_location(
    "trivy_iac_generate_summary", GENERATOR_SCRIPT,
)
gen_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen_mod)


def _run_in_process(
    workspace,
    output_file,
    is_pr_comment="false",
    has_iac="true",
    iac_path=None,
    repo_url="https://github.com/test/repo/blob/main",
    github_server_url="https://github.com",
    github_repo="test/repo",
    github_run_id="12345",
):
    """Run generate_trivy_iac_summary in-process, returning a result-like object."""
    original_dir = os.getcwd()
    try:
        os.chdir(workspace)
        gen_mod.generate_trivy_iac_summary(
            output_file,
            is_pr_comment,
            has_iac,
            iac_path or "",
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


class TestTrivyIaCGenerateSummary:
    """Test cases for scanner-trivy-iac generate_summary.py"""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up test workspace for each test."""
        self.workspace = tmp_path
        self.iac_path = tmp_path / "infrastructure"
        self.security_reports = self.iac_path / "security-reports"
        self.security_reports.mkdir(parents=True)
        self.output_file = tmp_path / "summary.md"

    def run_generator(self, **kwargs):
        """Helper to run the generator in-process."""
        kwargs.setdefault("output_file", str(self.output_file))
        kwargs.setdefault("iac_path", str(self.iac_path))
        return _run_in_process(self.workspace, **kwargs)

    def test_script_exists(self):
        """Verify generator script exists."""
        assert GENERATOR_SCRIPT.exists(), f"Script not found: {GENERATOR_SCRIPT}"

    def test_fixtures_exist(self):
        """Verify required fixtures exist."""
        assert FIXTURES_DIR.exists(), f"Fixtures not found: {FIXTURES_DIR}"
        assert (FIXTURES_DIR / "results-with-findings.json").exists()
        assert (FIXTURES_DIR / "results-with-findings.sarif").exists()
        assert (FIXTURES_DIR / "results-zero-findings.json").exists()

    def test_generates_summary_with_findings(self):
        """Test generating summary with findings."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.json",
            self.security_reports / "trivy-results.json",
        )
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.sarif",
            self.security_reports / "trivy-results.sarif",
        )

        result = self.run_generator(has_iac="true")

        assert result.returncode == 0, f"Script failed: {result.stderr}"
        assert self.output_file.exists(), "Output file not created"

        content = self.output_file.read_text()

        assert "Trivy IaC" in content
        assert "Findings Summary" in content
        assert "Critical" in content
        assert "High" in content

    def test_generates_summary_zero_findings(self):
        """Test generating summary with zero findings."""
        shutil.copy(
            FIXTURES_DIR / "results-zero-findings.json",
            self.security_reports / "trivy-results.json",
        )

        result = self.run_generator(has_iac="true")

        assert result.returncode == 0
        assert self.output_file.exists()

        content = self.output_file.read_text()
        assert "No misconfigurations detected" in content

    def test_skipped_no_iac_directory(self):
        """Test skipped status when no IaC directory."""
        result = self.run_generator(has_iac="false", iac_path="")

        assert result.returncode == 0
        assert self.output_file.exists()

        content = self.output_file.read_text()
        assert "Skipped" in content or "No IaC directory" in content

    def test_pr_comment_format_collapsible(self):
        """Test PR comment format uses collapsible sections."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.json",
            self.security_reports / "trivy-results.json",
        )
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.sarif",
            self.security_reports / "trivy-results.sarif",
        )

        result = self.run_generator(is_pr_comment="true", has_iac="true")

        assert result.returncode == 0
        content = self.output_file.read_text()

        assert "<details>" in content
        assert "<summary>" in content
        assert "</details>" in content

    def test_finding_details_section(self):
        """Test finding details section is present with findings."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.json",
            self.security_reports / "trivy-results.json",
        )
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.sarif",
            self.security_reports / "trivy-results.sarif",
        )

        result = self.run_generator(has_iac="true")

        assert result.returncode == 0
        content = self.output_file.read_text()

        assert "Finding Details" in content

    def test_artifact_link_present(self):
        """Test artifact link is present in output."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.json",
            self.security_reports / "trivy-results.json",
        )

        result = self.run_generator(
            has_iac="true",
            github_repo="test/repo",
            github_run_id="12345",
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
        assert "No results" in content or "No Trivy" in content

    def test_non_pr_format_has_heading(self):
        """Test non-PR format uses heading instead of details tag."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.json",
            self.security_reports / "trivy-results.json",
        )

        result = self.run_generator(is_pr_comment="false", has_iac="true")

        assert result.returncode == 0
        content = self.output_file.read_text()

        assert "## " in content
        assert "Trivy IaC" in content

    def test_severity_counts_in_table(self):
        """Test severity counts appear in summary table."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.json",
            self.security_reports / "trivy-results.json",
        )

        result = self.run_generator(has_iac="true")

        assert result.returncode == 0
        content = self.output_file.read_text()

        assert "Critical" in content
        assert "High" in content
        assert "Medium" in content
        assert "Low" in content

    def test_severity_grouping_in_details(self):
        """Test findings are grouped by severity in details."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.json",
            self.security_reports / "trivy-results.json",
        )
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.sarif",
            self.security_reports / "trivy-results.sarif",
        )

        result = self.run_generator(has_iac="true")

        assert result.returncode == 0
        content = self.output_file.read_text()

        assert "Critical Severity" in content or "High Severity" in content


class TestEdgeCases:
    """Edge case tests for Trivy IaC summary generation."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up test workspace for each test."""
        self.workspace = tmp_path
        self.iac_path = tmp_path / "infrastructure"
        self.security_reports = self.iac_path / "security-reports"
        self.security_reports.mkdir(parents=True)
        self.output_file = tmp_path / "summary.md"

    def run_generator(self, **kwargs):
        """Helper to run the generator in-process."""
        kwargs.setdefault("output_file", str(self.output_file))
        kwargs.setdefault("iac_path", str(self.iac_path))
        return _run_in_process(self.workspace, **kwargs)

    def test_no_iac_directory(self):
        """Test when IaC directory is not found."""
        result = self.run_generator(has_iac="false", iac_path="")
        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "No IaC directory" in content or "Skipped" in content

    def test_output_in_nested_directory(self):
        """Test creating output in nested directory."""
        nested_output = self.workspace / "a" / "b" / "c" / "summary.md"
        result = self.run_generator(output_file=str(nested_output))
        assert result.returncode == 0
        assert nested_output.exists()

    def test_malformed_trivy_results(self):
        """Test with malformed Trivy results JSON."""
        results_file = self.security_reports / "trivy-results.json"
        results_file.write_text("{invalid json")
        result = self.run_generator(has_iac="true")
        assert result.returncode == 0
        assert self.output_file.exists()

    def test_empty_results_json(self):
        """Test with empty Trivy results file."""
        results_file = self.security_reports / "trivy-results.json"
        results_file.write_text("")
        result = self.run_generator(has_iac="true")
        assert result.returncode == 0
        assert self.output_file.exists()

    def test_pr_comment_format(self):
        """Test PR comment format with no IaC."""
        result = self.run_generator(is_pr_comment="true", has_iac="false")
        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "<details>" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
