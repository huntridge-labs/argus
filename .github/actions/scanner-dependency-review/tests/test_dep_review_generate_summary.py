#!/usr/bin/env python3
"""
Unit tests for scanner-dependency-review/scripts/generate_summary.py
Tests markdown summary generation for dependency-review results.
"""

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
GENERATOR_SCRIPT = SCRIPTS_DIR / "generate_summary.py"

spec = importlib.util.spec_from_file_location("dep_review_generate_summary", GENERATOR_SCRIPT)
gen_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen_mod)


def _run_in_process(
    workspace,
    output_file,
    is_pr_comment="false",
    skipped="false",
    critical="0",
    high="0",
    medium="0",
    low="0",
    license_violations="0",
    results_file="",
    github_server_url="https://github.com",
    github_repo="test/repo",
    github_run_id="12345",
):
    original_dir = os.getcwd()
    try:
        os.chdir(workspace)
        gen_mod.generate_dependency_review_summary(
            output_file,
            is_pr_comment,
            skipped,
            critical,
            high,
            medium,
            low,
            license_violations,
            results_file,
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


class TestDepReviewGenerateSummary:
    """Test dependency-review summary generation."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        self.workspace = tmp_path / "workspace"
        self.workspace.mkdir()
        self.output_file = str(self.workspace / "scanner-summaries" / "dependency-review.md")

    def test_zero_findings_step_summary(self):
        result = _run_in_process(self.workspace, self.output_file)
        assert result.returncode == 0
        content = Path(self.output_file).read_text()
        assert "## 🔗 Dependency Review Summary" in content
        assert "No issues found" in content

    def test_zero_findings_pr_comment(self):
        result = _run_in_process(self.workspace, self.output_file, is_pr_comment="true")
        assert result.returncode == 0
        content = Path(self.output_file).read_text()
        assert "<details>" in content
        assert "<summary>🔗 Dependency Review</summary>" in content
        assert "</details>" in content

    def test_skipped_non_pr(self):
        result = _run_in_process(self.workspace, self.output_file, skipped="true")
        assert result.returncode == 0
        content = Path(self.output_file).read_text()
        assert "Skipped" in content
        assert "not a pull request event" in content
        assert "scanner-osv" in content

    def test_skipped_pr_comment(self):
        result = _run_in_process(
            self.workspace, self.output_file,
            is_pr_comment="true", skipped="true",
        )
        content = Path(self.output_file).read_text()
        assert "<details>" in content
        assert "Skipped" in content

    def test_skipped_no_artifacts_link(self):
        result = _run_in_process(self.workspace, self.output_file, skipped="true")
        content = Path(self.output_file).read_text()
        assert "View full report" not in content

    def test_with_vulnerabilities(self):
        result = _run_in_process(
            self.workspace, self.output_file,
            critical="1", high="2", medium="0", low="0",
        )
        assert result.returncode == 0
        content = Path(self.output_file).read_text()
        assert "Vulnerability Summary" in content
        assert "**1**" in content
        assert "CRITICAL" in content

    def test_with_license_violations(self):
        result = _run_in_process(
            self.workspace, self.output_file,
            license_violations="3",
        )
        assert result.returncode == 0
        content = Path(self.output_file).read_text()
        assert "License Violations" in content
        assert "3" in content

    def test_with_both_issues(self):
        result = _run_in_process(
            self.workspace, self.output_file,
            critical="1", high="0", medium="0", low="0",
            license_violations="2",
        )
        content = Path(self.output_file).read_text()
        assert "Vulnerability Summary" in content
        assert "License Violations" in content

    def test_critical_priority_message(self):
        result = _run_in_process(
            self.workspace, self.output_file,
            critical="2", high="0", medium="0", low="0",
        )
        content = Path(self.output_file).read_text()
        assert "2 critical severity" in content

    def test_high_priority_message(self):
        result = _run_in_process(
            self.workspace, self.output_file,
            critical="0", high="5", medium="0", low="0",
        )
        content = Path(self.output_file).read_text()
        assert "5 high severity" in content

    def test_with_results_file(self, tmp_path):
        results = {
            "vulnerabilities": [
                {
                    "package": "lodash",
                    "version": "4.17.20",
                    "ecosystem": "npm",
                    "severity": "CRITICAL",
                    "advisory_id": "GHSA-1234",
                    "advisory_url": "https://github.com/advisories/GHSA-1234",
                    "advisory_summary": "Test vuln",
                }
            ],
            "license_violations": {
                "count": 1,
                "violations": [
                    {
                        "package": "gpl-pkg",
                        "version": "1.0",
                        "license": "GPL-3.0",
                        "ecosystem": "pip",
                    }
                ],
            },
        }
        results_file = tmp_path / "results.json"
        results_file.write_text(json.dumps(results))

        result = _run_in_process(
            self.workspace, self.output_file,
            critical="1", high="0", medium="0", low="0",
            license_violations="1",
            results_file=str(results_file),
        )
        assert result.returncode == 0
        content = Path(self.output_file).read_text()
        assert "lodash" in content
        assert "GHSA-1234" in content
        assert "gpl-pkg" in content
        assert "GPL-3.0" in content

    def test_collapsible_severity_grouping(self, tmp_path):
        """Vulnerability details should be in collapsible sections grouped by severity."""
        results = {
            "vulnerabilities": [
                {
                    "package": "pkg-crit",
                    "version": "1.0",
                    "ecosystem": "npm",
                    "severity": "CRITICAL",
                    "advisory_id": "GHSA-0001",
                    "advisory_url": "https://github.com/advisories/GHSA-0001",
                },
                {
                    "package": "pkg-high",
                    "version": "2.0",
                    "ecosystem": "npm",
                    "severity": "HIGH",
                    "advisory_id": "GHSA-0002",
                    "advisory_url": "https://github.com/advisories/GHSA-0002",
                },
            ],
            "license_violations": {"count": 0, "violations": []},
        }
        results_file = tmp_path / "results.json"
        results_file.write_text(json.dumps(results))

        _run_in_process(
            self.workspace, self.output_file,
            critical="1", high="1", medium="0", low="0",
            results_file=str(results_file),
        )
        content = Path(self.output_file).read_text()

        # Outer collapsible wrapping all details
        assert "<summary>🔍 Vulnerable Dependencies (2)</summary>" in content

        # Per-severity collapsible groups
        assert "<details open>" in content  # CRITICAL is open by default
        assert "🚨 CRITICAL Severity (1)" in content
        assert "⚠️ HIGH Severity (1)" in content

        # Package data within severity groups
        assert "pkg-crit" in content
        assert "pkg-high" in content

    def test_collapsible_license_violations(self, tmp_path):
        """License violations should be in a collapsible section."""
        results = {
            "vulnerabilities": [],
            "license_violations": {
                "count": 2,
                "violations": [
                    {"package": "gpl-a", "version": "1.0", "license": "GPL-3.0", "ecosystem": "pip"},
                    {"package": "gpl-b", "version": "2.0", "license": "AGPL-3.0", "ecosystem": "pip"},
                ],
            },
        }
        results_file = tmp_path / "results.json"
        results_file.write_text(json.dumps(results))

        _run_in_process(
            self.workspace, self.output_file,
            license_violations="2",
            results_file=str(results_file),
        )
        content = Path(self.output_file).read_text()

        assert "<summary>⚖️ License Violations (2)</summary>" in content
        assert "gpl-a" in content
        assert "gpl-b" in content

    def test_artifacts_link(self):
        result = _run_in_process(
            self.workspace, self.output_file,
            github_server_url="https://github.com",
            github_repo="org/repo",
            github_run_id="99999",
        )
        content = Path(self.output_file).read_text()
        assert "https://github.com/org/repo/actions/runs/99999" in content

    def test_empty_string_counts(self):
        result = _run_in_process(
            self.workspace, self.output_file,
            critical="", high="", medium="", low="", license_violations="",
        )
        assert result.returncode == 0
        content = Path(self.output_file).read_text()
        assert "No issues found" in content

    def test_pr_comment_with_findings(self):
        result = _run_in_process(
            self.workspace, self.output_file,
            is_pr_comment="true",
            critical="1", high="0", medium="0", low="0",
        )
        content = Path(self.output_file).read_text()
        assert "<details>" in content
        assert "Issues found" in content

    def test_output_directory_created(self):
        deep_output = str(self.workspace / "a" / "b" / "output.md")
        result = _run_in_process(self.workspace, deep_output)
        assert result.returncode == 0
        assert Path(deep_output).exists()


class TestCLI:
    """Test CLI invocation."""

    def test_cli_zero_findings(self, tmp_path):
        output = tmp_path / "output.md"
        result = subprocess.run(
            [
                sys.executable, str(GENERATOR_SCRIPT),
                "--output-file", str(output),
            ],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert output.exists()

    def test_cli_skipped(self, tmp_path):
        output = tmp_path / "output.md"
        result = subprocess.run(
            [
                sys.executable, str(GENERATOR_SCRIPT),
                "--output-file", str(output),
                "--skipped", "true",
            ],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        content = output.read_text()
        assert "Skipped" in content
