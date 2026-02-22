#!/usr/bin/env python3
"""
Unit tests for scanner-opengrep/scripts/generate_summary.py
Tests markdown generation for OpenGrep SAST scan results

Uses in-process imports instead of subprocess for fast execution.
"""

import importlib.util
import json
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.unit

# Paths
REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
GENERATOR_SCRIPT = SCRIPTS_DIR / "generate_summary.py"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "scanner-outputs" / "opengrep"

# Load module in-process via importlib
spec = importlib.util.spec_from_file_location(
    "opengrep_generate_summary", GENERATOR_SCRIPT,
)
gen_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen_mod)


def _run_in_process(
    workspace,
    output_file,
    is_pr_comment="false",
    error_count="0",
    warning_count="0",
    info_count="0",
    total="0",
    repo_url="https://github.com/test/repo/blob/main",
    server_url="https://github.com",
    repository="test/repo",
    run_id="12345",
):
    """Run generate_opengrep_summary in-process, returning a result-like object."""
    original_dir = os.getcwd()
    try:
        os.chdir(workspace)
        gen_mod.generate_opengrep_summary(
            output_file,
            is_pr_comment,
            error_count,
            warning_count,
            info_count,
            total,
            repo_url,
            server_url,
            repository,
            run_id,
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    except SystemExit as e:
        return SimpleNamespace(returncode=e.code or 1, stdout="", stderr="")
    except Exception as e:
        return SimpleNamespace(returncode=1, stdout="", stderr=str(e))
    finally:
        os.chdir(original_dir)


class TestOpenGrepGenerateSummary:
    """Test cases for scanner-opengrep generate_summary.py"""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up test workspace for each test."""
        self.workspace = tmp_path
        self.opengrep_reports = tmp_path / "opengrep-reports"
        self.opengrep_reports.mkdir(parents=True)
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

    def test_generates_summary_with_findings(self):
        """Test generating summary with findings."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.json",
            self.opengrep_reports / "opengrep.json",
        )

        result = self.run_generator(
            error_count="1",
            warning_count="2",
            info_count="1",
            total="4",
        )

        assert result.returncode == 0, f"Script failed: {result.stderr}"
        assert self.output_file.exists(), "Output file not created"

        content = self.output_file.read_text()

        assert "OpenGrep SAST" in content
        assert "Findings Summary" in content

    def test_generates_summary_zero_findings(self):
        """Test generating summary with zero findings."""
        shutil.copy(
            FIXTURES_DIR / "results-zero-findings.json",
            self.opengrep_reports / "opengrep.json",
        )

        result = self.run_generator(
            error_count="0",
            warning_count="0",
            info_count="0",
            total="0",
        )

        assert result.returncode == 0
        assert self.output_file.exists()

        content = self.output_file.read_text()
        assert "No security findings" in content

    def test_pr_and_non_pr_format(self):
        """Test PR comment format uses collapsible and non-PR uses heading."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.json",
            self.opengrep_reports / "opengrep.json",
        )

        # Test PR comment format
        result = self.run_generator(
            is_pr_comment="true",
            total="4",
        )

        assert result.returncode == 0
        content = self.output_file.read_text()

        assert "<details>" in content
        assert "<summary>" in content
        assert "</details>" in content

        # Test non-PR format (reuse same fixture, but clear output file)
        self.output_file.unlink()
        result = self.run_generator(
            is_pr_comment="false",
            total="4",
        )

        assert result.returncode == 0
        content = self.output_file.read_text()

        assert "## OpenGrep SAST Scan" in content

    def test_severity_priority_messages(self):
        """Test ERROR and WARNING severity priority messages appear."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.json",
            self.opengrep_reports / "opengrep.json",
        )

        result = self.run_generator(
            error_count="2",
            warning_count="0",
            info_count="0",
            total="2",
        )

        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "ERROR" in content
        assert "2 error-severity findings" in content

    def test_finding_details_section(self):
        """Test finding details section is present with findings."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.json",
            self.opengrep_reports / "opengrep.json",
        )

        result = self.run_generator(
            error_count="1",
            warning_count="2",
            info_count="1",
            total="4",
        )

        assert result.returncode == 0
        content = self.output_file.read_text()

        assert "Finding Details" in content
        assert "Severity" in content
        assert "Rule" in content
        assert "Location" in content

    def test_artifact_link_present(self):
        """Test artifact link is present in output."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.json",
            self.opengrep_reports / "opengrep.json",
        )

        result = self.run_generator(
            repository="test/repo",
            run_id="12345",
            total="4",
        )

        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "https://github.com/test/repo/actions/runs/12345" in content

    def test_handles_missing_json_file(self):
        """Test handles missing JSON file gracefully."""
        result = self.run_generator(total="0")

        assert result.returncode == 0
        assert self.output_file.exists()

        content = self.output_file.read_text()
        assert "OpenGrep" in content

    def test_summary_table_format(self):
        """Test summary table has correct format."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.json",
            self.opengrep_reports / "opengrep.json",
        )

        result = self.run_generator(
            error_count="1",
            warning_count="2",
            info_count="3",
            total="6",
        )

        assert result.returncode == 0
        content = self.output_file.read_text()

        assert "| Error | Warning | Info | Total |" in content
        assert "| **1** | **2** | **3** | **6** |" in content


class TestEdgeCases:
    """Edge case tests for OpenGrep summary generation."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up test workspace for each test."""
        self.workspace = tmp_path
        self.opengrep_reports = tmp_path / "opengrep-reports"
        self.opengrep_reports.mkdir(parents=True)
        self.output_file = tmp_path / "summary.md"

    def run_generator(self, **kwargs):
        """Helper to run the generator in-process."""
        kwargs.setdefault("output_file", str(self.output_file))
        return _run_in_process(self.workspace, **kwargs)

    def test_empty_findings_all_zero(self):
        """Test with zero findings across all severity levels."""
        result = self.run_generator(
            error_count="0", warning_count="0", info_count="0", total="0",
        )
        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "| **0** | **0** | **0** | **0** |" in content

    def test_very_large_counts(self):
        """Test with very large finding counts."""
        result = self.run_generator(
            error_count="9999", warning_count="9999", info_count="9999", total="29997",
        )
        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "9999" in content

    def test_pr_comment_with_zero_findings(self):
        """Test PR comment format with zero findings."""
        result = self.run_generator(is_pr_comment="true", total="0")
        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "<details>" in content

    def test_malformed_json_results_file(self):
        """Test with malformed JSON in results file."""
        bad_json = self.opengrep_reports / "opengrep.json"
        bad_json.write_text("{invalid json")
        result = self.run_generator(total="0")
        assert result.returncode == 0
        assert self.output_file.exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
