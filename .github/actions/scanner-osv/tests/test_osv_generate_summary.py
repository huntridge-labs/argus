#!/usr/bin/env python3
"""
Unit tests for scanner-osv/scripts/generate_summary.py
Tests markdown summary generation for OSV-Scanner results.
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

spec = importlib.util.spec_from_file_location("osv_generate_summary", GENERATOR_SCRIPT)
gen_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen_mod)


def _run_in_process(
    workspace,
    output_file,
    is_pr_comment="false",
    results_file="",
    critical="0",
    high="0",
    medium="0",
    low="0",
    github_server_url="https://github.com",
    github_repo="test/repo",
    github_run_id="12345",
):
    original_dir = os.getcwd()
    try:
        os.chdir(workspace)
        gen_mod.generate_osv_summary(
            output_file,
            is_pr_comment,
            results_file,
            critical,
            high,
            medium,
            low,
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


class TestOsvGenerateSummary:
    """Test OSV summary generation."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        self.workspace = tmp_path / "workspace"
        self.workspace.mkdir()
        self.output_file = str(self.workspace / "scanner-summaries" / "osv.md")

    def test_zero_findings_step_summary(self):
        result = _run_in_process(self.workspace, self.output_file)
        assert result.returncode == 0
        content = Path(self.output_file).read_text()
        assert "## 📦 OSV Dependency Scan Summary" in content
        assert "No vulnerabilities found" in content

    def test_zero_findings_pr_comment(self):
        result = _run_in_process(self.workspace, self.output_file, is_pr_comment="true")
        assert result.returncode == 0
        content = Path(self.output_file).read_text()
        assert "<details>" in content
        assert "<summary>📦 OSV Dependency Scan</summary>" in content
        assert "</details>" in content
        assert "No vulnerabilities found" in content

    def test_with_findings_step_summary(self):
        result = _run_in_process(
            self.workspace, self.output_file,
            critical="1", high="2", medium="3", low="1",
        )
        assert result.returncode == 0
        content = Path(self.output_file).read_text()
        assert "## 📦 OSV Dependency Scan Summary" in content
        assert "Severity Summary" in content
        assert "**1**" in content
        assert "**2**" in content
        assert "CRITICAL" in content

    def test_with_findings_pr_comment(self):
        result = _run_in_process(
            self.workspace, self.output_file,
            is_pr_comment="true",
            critical="2", high="1", medium="0", low="0",
        )
        assert result.returncode == 0
        content = Path(self.output_file).read_text()
        assert "<details>" in content
        assert "Vulnerabilities found" in content
        assert "CRITICAL" in content

    def test_high_priority_message(self):
        result = _run_in_process(
            self.workspace, self.output_file,
            critical="0", high="3", medium="0", low="0",
        )
        content = Path(self.output_file).read_text()
        assert "HIGH" in content
        assert "3 high severity" in content

    def test_critical_priority_message(self):
        result = _run_in_process(
            self.workspace, self.output_file,
            critical="2", high="0", medium="0", low="0",
        )
        content = Path(self.output_file).read_text()
        assert "CRITICAL" in content
        assert "2 critical severity" in content

    def test_with_results_file(self, tmp_path):
        vulns = [
            {
                "id": "GHSA-1234",
                "package": "lodash",
                "version": "4.17.20",
                "ecosystem": "npm",
                "severity": "CRITICAL",
                "summary": "Command injection in lodash",
                "fixed_version": "4.17.21",
                "aliases": [],
                "source": "package-lock.json",
            }
        ]
        results_file = tmp_path / "vulns.json"
        results_file.write_text(json.dumps(vulns))

        result = _run_in_process(
            self.workspace, self.output_file,
            results_file=str(results_file),
            critical="1", high="0", medium="0", low="0",
        )
        assert result.returncode == 0
        content = Path(self.output_file).read_text()
        assert "lodash" in content
        assert "4.17.21" in content
        assert "GHSA-1234" in content

    def test_artifacts_link(self):
        result = _run_in_process(
            self.workspace, self.output_file,
            github_server_url="https://github.com",
            github_repo="org/repo",
            github_run_id="99999",
        )
        content = Path(self.output_file).read_text()
        assert "https://github.com/org/repo/actions/runs/99999" in content

    def test_empty_results_file(self, tmp_path):
        empty = tmp_path / "empty.json"
        empty.write_text("")
        result = _run_in_process(
            self.workspace, self.output_file,
            results_file=str(empty),
            critical="1", high="0", medium="0", low="0",
        )
        assert result.returncode == 0

    def test_malformed_results_file(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json")
        result = _run_in_process(
            self.workspace, self.output_file,
            results_file=str(bad),
            critical="1", high="0", medium="0", low="0",
        )
        assert result.returncode == 0

    def test_empty_string_counts(self):
        result = _run_in_process(
            self.workspace, self.output_file,
            critical="", high="", medium="", low="",
        )
        assert result.returncode == 0
        content = Path(self.output_file).read_text()
        assert "No vulnerabilities found" in content

    def test_output_directory_created(self):
        deep_output = str(self.workspace / "a" / "b" / "c" / "output.md")
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
                "--critical", "0",
                "--high", "0",
                "--medium", "0",
                "--low", "0",
            ],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert output.exists()

    def test_cli_with_findings(self, tmp_path):
        output = tmp_path / "output.md"
        result = subprocess.run(
            [
                sys.executable, str(GENERATOR_SCRIPT),
                "--output-file", str(output),
                "--critical", "1",
                "--high", "2",
                "--medium", "0",
                "--low", "0",
            ],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        content = output.read_text()
        assert "Severity Summary" in content
