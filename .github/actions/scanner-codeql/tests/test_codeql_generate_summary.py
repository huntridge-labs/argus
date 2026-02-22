#!/usr/bin/env python3
"""
Unit tests for scanner-codeql/scripts/generate_summary.py
Tests markdown generation for CodeQL SAST scan results

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
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "scanner-outputs" / "codeql"

# Load module in-process via importlib
spec = importlib.util.spec_from_file_location(
    "codeql_generate_summary", GENERATOR_SCRIPT,
)
gen_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen_mod)


def _run_in_process(
    workspace,
    output_file,
    is_pr_comment="false",
    language="python",
    critical="0",
    high="0",
    medium="0",
    low="0",
    total="0",
    repo_url="https://github.com/test/repo/blob/main",
    server_url="https://github.com",
    repository="test/repo",
    run_id="12345",
):
    """Run generate_codeql_summary in-process, returning a result-like object."""
    original_dir = os.getcwd()
    try:
        os.chdir(workspace)
        gen_mod.generate_codeql_summary(
            output_file,
            is_pr_comment,
            language,
            critical,
            high,
            medium,
            low,
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


class TestCodeQLGenerateSummary:
    """Test cases for scanner-codeql generate_summary.py"""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up test workspace for each test."""
        self.workspace = tmp_path
        self.codeql_reports = tmp_path / "codeql-reports"
        self.sarif_dir = self.codeql_reports / "sarif"
        self.sarif_dir.mkdir(parents=True)
        self.output_file = tmp_path / "summary.md"

    def run_generator(self, **kwargs):
        """Helper to run the generator in-process."""
        kwargs.setdefault("output_file", str(self.output_file))
        return _run_in_process(self.workspace, **kwargs)

    def test_script_and_fixtures_exist(self):
        """Verify generator script and fixtures exist."""
        assert GENERATOR_SCRIPT.exists(), f"Script not found: {GENERATOR_SCRIPT}"
        assert FIXTURES_DIR.exists(), f"Fixtures not found: {FIXTURES_DIR}"
        assert (FIXTURES_DIR / "results-with-findings.sarif").exists()
        assert (FIXTURES_DIR / "results-zero-findings.sarif").exists()

    def test_generates_summary_with_findings(self):
        """Test generating summary with findings (tests language, format, severity grouping)."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.sarif",
            self.sarif_dir / "python.sarif",
        )

        result = self.run_generator(
            language="python",
            critical="0",
            high="2",
            medium="1",
            low="0",
            total="3",
            is_pr_comment="false",
        )

        assert result.returncode == 0, f"Script failed: {result.stderr}"
        assert self.output_file.exists(), "Output file not created"

        content = self.output_file.read_text()

        assert "CodeQL SAST" in content
        assert "python" in content.lower()
        assert "Findings Summary" in content
        assert "## 🔬 CodeQL SAST Scan (Python)" in content
        assert "Python" in content

    def test_generates_summary_zero_findings(self):
        """Test generating summary with zero findings."""
        shutil.copy(
            FIXTURES_DIR / "results-zero-findings.sarif",
            self.sarif_dir / "python.sarif",
        )

        result = self.run_generator(
            language="python",
            critical="0",
            high="0",
            medium="0",
            low="0",
            total="0",
        )

        assert result.returncode == 0
        assert self.output_file.exists()

        content = self.output_file.read_text()
        assert "No security findings" in content

    def test_pr_comment_format_collapsible(self):
        """Test PR comment format uses collapsible sections."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.sarif",
            self.sarif_dir / "python.sarif",
        )

        result = self.run_generator(
            is_pr_comment="true",
            language="python",
            total="3",
        )

        assert result.returncode == 0
        content = self.output_file.read_text()

        assert "<details>" in content
        assert "<summary>" in content
        assert "</details>" in content

    def test_critical_severity_message(self):
        """Test CRITICAL severity priority message appears."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.sarif",
            self.sarif_dir / "python.sarif",
        )

        result = self.run_generator(
            language="python",
            critical="2",
            total="2",
        )

        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "CRITICAL" in content
        assert "2 critical-severity findings" in content

    def test_finding_details_section(self):
        """Test finding details section is present with findings."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.sarif",
            self.sarif_dir / "python.sarif",
        )

        result = self.run_generator(
            language="python",
            high="2",
            medium="1",
            total="3",
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
            FIXTURES_DIR / "results-with-findings.sarif",
            self.sarif_dir / "python.sarif",
        )

        result = self.run_generator(
            language="python",
            repository="test/repo",
            run_id="12345",
            total="3",
        )

        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "https://github.com/test/repo/actions/runs/12345" in content

    def test_handles_no_sarif_directory(self):
        """Test handles missing SARIF directory gracefully."""
        shutil.rmtree(self.sarif_dir)

        result = self.run_generator(
            language="python",
            total="0",
        )

        assert result.returncode == 0
        assert self.output_file.exists()

        content = self.output_file.read_text()
        assert "CodeQL" in content

    def test_summary_table_format(self):
        """Test summary table has correct format."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.sarif",
            self.sarif_dir / "python.sarif",
        )

        result = self.run_generator(
            language="python",
            critical="1",
            high="2",
            medium="3",
            low="4",
            total="10",
        )

        assert result.returncode == 0
        content = self.output_file.read_text()

        assert "| Critical | High | Medium | Low | Total |" in content
        assert "| **1** | **2** | **3** | **4** | **10** |" in content


class TestEdgeCases:
    """Edge case tests for CodeQL summary generation."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up test workspace for each test."""
        self.workspace = tmp_path
        self.codeql_reports = tmp_path / "codeql-reports"
        self.sarif_dir = self.codeql_reports / "sarif"
        self.sarif_dir.mkdir(parents=True)
        self.output_file = tmp_path / "summary.md"

    def run_generator(self, **kwargs):
        """Helper to run the generator in-process."""
        kwargs.setdefault("output_file", str(self.output_file))
        return _run_in_process(self.workspace, **kwargs)

    def test_malformed_sarif_file(self):
        """Test with malformed SARIF JSON file."""
        bad_sarif = self.sarif_dir / "broken.sarif"
        bad_sarif.write_text("{invalid json content")

        result = self.run_generator(language="python", total="0")
        assert result.returncode == 0
        assert self.output_file.exists()

    def test_sarif_with_no_runs(self):
        """Test SARIF file with empty runs array."""
        sarif_file = self.sarif_dir / "python.sarif"
        sarif_file.write_text(json.dumps({"runs": []}))

        result = self.run_generator(language="python", total="0")
        assert result.returncode == 0
        assert self.output_file.exists()

    def test_sarif_with_no_results(self):
        """Test SARIF run with no results field."""
        sarif_file = self.sarif_dir / "python.sarif"
        sarif_file.write_text(json.dumps({
            "runs": [{"tool": {"driver": {"name": "CodeQL"}}}]
        }))

        result = self.run_generator(language="python", total="0")
        assert result.returncode == 0
        assert self.output_file.exists()

    def test_all_critical_findings(self):
        """Test with all critical findings."""
        result = self.run_generator(
            language="python",
            critical="5",
            high="0",
            medium="0",
            low="0",
            total="5",
        )
        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "CRITICAL" in content
        assert "5 critical-severity findings" in content

    def test_very_large_counts(self):
        """Test with very large vulnerability counts."""
        result = self.run_generator(
            language="python",
            critical="9999",
            high="9999",
            medium="9999",
            low="9999",
            total="39996",
        )
        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "9999" in content

    def test_sarif_with_empty_locations(self):
        """Test SARIF result with empty locations array."""
        sarif_file = self.sarif_dir / "python.sarif"
        sarif_file.write_text(json.dumps({
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [{
                    "level": "error",
                    "locations": []
                }]
            }]
        }))

        result = self.run_generator(language="python", critical="1", total="1")
        assert result.returncode == 0
        assert self.output_file.exists()

    def test_sarif_missing_level_field(self):
        """Test SARIF result missing level field."""
        sarif_file = self.sarif_dir / "python.sarif"
        sarif_file.write_text(json.dumps({
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [{
                    "ruleId": "py/test",
                    "message": {"text": "Test finding"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "test.py"}}}]
                }]
            }]
        }))

        result = self.run_generator(language="python", total="1")
        assert result.returncode == 0
        assert self.output_file.exists()

    def test_pr_comment_with_zero_findings(self):
        """Test PR comment format with zero findings."""
        result = self.run_generator(
            is_pr_comment="true",
            language="python",
            total="0",
        )
        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "<details>" in content
        assert "<summary>" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
