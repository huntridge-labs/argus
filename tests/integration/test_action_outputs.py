#!/usr/bin/env python3
"""
Integration tests for argus action scripts.

Tests validate the critical GitHub Actions contract: every script's primary job
is to write correct content to GITHUB_OUTPUT and/or GITHUB_STEP_SUMMARY. A
dependency update that breaks output generation must NOT pass these tests.

Unit tests already cover individual commands, parsing logic, and markdown format
via subprocess calls. These integration tests focus exclusively on verifying the
file-write contract that unit tests do not cover.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ACTIONS_DIR = Path(__file__).parent.parent.parent / ".github/actions"


class TestGitHubActionsContract:
    """Test that scripts correctly write to GITHUB_OUTPUT and GITHUB_STEP_SUMMARY.

    These tests verify the critical contract: every script's primary job is to
    write correct content to GitHub Actions environment files. A dependency update
    that breaks output generation should NOT pass these tests.
    """

    TRIVY_PARSER = ACTIONS_DIR / "scanner-container/scripts/parse_trivy_results.py"
    GRYPE_PARSER = ACTIONS_DIR / "scanner-container/scripts/parse_grype_results.py"
    CONTAINER_SUMMARY = ACTIONS_DIR / "scanner-container/scripts/generate_container_summary.py"
    ZAP_PARSER = ACTIONS_DIR / "scanner-zap/scripts/parse_zap_results.py"
    ZAP_SUMMARY = ACTIONS_DIR / "scanner-zap/scripts/generate_zap_summary.py"
    CHECKOV_SUMMARY = ACTIONS_DIR / "scanner-checkov/scripts/generate_summary.py"
    CODEQL_SUMMARY = ACTIONS_DIR / "scanner-codeql/scripts/generate_summary.py"
    OPENGREP_SUMMARY = ACTIONS_DIR / "scanner-opengrep/scripts/generate_summary.py"
    TRIVY_IAC_SUMMARY = ACTIONS_DIR / "scanner-trivy-iac/scripts/generate_summary.py"
    CONTAINER_CONFIG = ACTIONS_DIR / "parse-container-config/scripts/parse_container_config.py"
    ZAP_CONFIG = ACTIONS_DIR / "parse-zap-config/scripts/parse_zap_config.py"
    CLAMAV_PARSER = ACTIONS_DIR / "scanner-clamav/scripts/parse-clamav-report.py"

    @pytest.mark.integration
    def test_container_summary_writes_github_output(self, tmp_path):
        """Verify generate_container_summary.py writes correct key=value pairs to GITHUB_OUTPUT."""
        github_output = tmp_path / "github_output"
        github_output.touch()

        github_step_summary = tmp_path / "step_summary"
        github_step_summary.touch()

        container_results = tmp_path / "container-scan-results-test-app"
        container_results.mkdir()

        trivy_results = container_results / "trivy-test-app-results.json"
        trivy_results.write_text(json.dumps({
            "Results": [
                {
                    "Vulnerabilities": [
                        {"Severity": "CRITICAL", "VulnerabilityID": "CVE-2021-1"},
                        {"Severity": "HIGH", "VulnerabilityID": "CVE-2021-2"},
                    ]
                }
            ],
            "Metadata": {"RepoTags": ["test-app:latest"]}
        }))

        env = os.environ.copy()
        env["GITHUB_OUTPUT"] = str(github_output)
        env["GITHUB_STEP_SUMMARY"] = str(github_step_summary)
        env["TRIVY_PARSER"] = str(self.TRIVY_PARSER)
        env["GRYPE_PARSER"] = str(self.GRYPE_PARSER)

        result = subprocess.run(
            [sys.executable, str(self.CONTAINER_SUMMARY)],
            env=env, capture_output=True, text=True, cwd=str(tmp_path)
        )

        assert result.returncode == 0, f"Script failed: {result.stderr}"

        output_content = github_output.read_text()
        assert "total_vulns=" in output_content, "Missing total_vulns in GITHUB_OUTPUT"
        assert "critical=" in output_content, "Missing critical in GITHUB_OUTPUT"
        assert "high=" in output_content, "Missing high in GITHUB_OUTPUT"
        assert "containers_scanned=" in output_content, "Missing containers_scanned in GITHUB_OUTPUT"

        summary_content = github_step_summary.read_text()
        assert "Container Security" in summary_content, "Missing header in STEP_SUMMARY"
        assert "|" in summary_content, "Missing markdown table in STEP_SUMMARY"

    @pytest.mark.integration
    def test_zap_summary_writes_github_step_summary(self, tmp_path):
        """Verify generate_zap_summary.py writes markdown to GITHUB_STEP_SUMMARY."""
        github_step_summary = tmp_path / "step_summary"
        github_step_summary.touch()

        zap_downloads = tmp_path / "zap-downloads"
        zap_downloads.mkdir()

        zap_report = zap_downloads / "report_json.json"
        zap_report.write_text(json.dumps({
            "site": [
                {
                    "@name": "http://localhost:8080",
                    "alerts": [
                        {"name": "SQL Injection", "riskcode": "3", "pluginid": "1", "count": "1", "cweid": "89", "instances": []},
                        {"name": "XSS", "riskcode": "3", "pluginid": "2", "count": "1", "cweid": "79", "instances": []},
                    ]
                }
            ]
        }))

        env = os.environ.copy()
        env["GITHUB_STEP_SUMMARY"] = str(github_step_summary)
        env["ZAP_PARSER"] = str(self.ZAP_PARSER)

        result = subprocess.run(
            [sys.executable, str(self.ZAP_SUMMARY)],
            env=env, capture_output=True, text=True, cwd=str(tmp_path)
        )

        assert result.returncode == 0, f"Script failed: {result.stderr}"

        summary_content = github_step_summary.read_text()
        assert "ZAP" in summary_content, "Missing ZAP header in STEP_SUMMARY"
        assert "|" in summary_content, "Missing markdown table in STEP_SUMMARY"

    @pytest.mark.integration
    def test_checkov_summary_writes_output(self, tmp_path):
        """Verify Checkov generate_summary.py produces a markdown file with correct content."""
        output_file = tmp_path / "checkov.md"

        checkov_reports = tmp_path / "checkov-reports"
        checkov_reports.mkdir()
        checkov_json = checkov_reports / "checkov-results.json"
        checkov_json.write_text(json.dumps({
            "check_type": "terraform",
            "results": {
                "failed_checks": [{
                    "check_id": "CKV_TF_1", "check_name": "Test Check",
                    "severity": "CRITICAL", "resource": "aws_s3_bucket.test",
                    "file_path": "/main.tf", "file_line_range": [1, 10]
                }]
            }
        }))

        result = subprocess.run(
            [sys.executable, str(self.CHECKOV_SUMMARY), str(output_file),
             "--has-iac", "true", "--critical", "1", "--high", "2",
             "--medium", "3", "--low", "1", "--passed", "50", "--total", "7",
             "--repo-url", "https://github.com/test/repo",
             "--github-server-url", "https://github.com",
             "--github-repo", "test/repo", "--github-run-id", "12345"],
            capture_output=True, text=True, cwd=str(tmp_path)
        )

        assert result.returncode == 0, f"Script failed: {result.stderr}"
        assert output_file.exists(), "Output file not created"
        content = output_file.read_text()
        assert "Checkov" in content, "Missing Checkov header"
        assert "|" in content, "Missing markdown table"

    @pytest.mark.integration
    def test_codeql_summary_writes_output(self, tmp_path):
        """Verify CodeQL generate_summary.py produces a markdown file with correct content."""
        output_file = tmp_path / "codeql.md"

        result = subprocess.run(
            [sys.executable, str(self.CODEQL_SUMMARY), str(output_file),
             "--language", "python", "--critical", "2", "--high", "3",
             "--medium", "4", "--low", "1", "--total", "10",
             "--repo-url", "https://github.com/test/repo",
             "--server-url", "https://github.com",
             "--repository", "test/repo", "--run-id", "12345"],
            capture_output=True, text=True
        )

        assert result.returncode == 0, f"Script failed: {result.stderr}"
        assert output_file.exists(), "Output file not created"
        content = output_file.read_text()
        assert "CodeQL" in content, "Missing CodeQL header"
        assert "|" in content, "Missing markdown table"

    @pytest.mark.integration
    def test_opengrep_summary_writes_output(self, tmp_path):
        """Verify OpenGrep generate_summary.py produces a markdown file with correct content."""
        output_file = tmp_path / "opengrep.md"

        result = subprocess.run(
            [sys.executable, str(self.OPENGREP_SUMMARY), str(output_file),
             "--error-count", "2", "--warning-count", "5", "--info-count", "3",
             "--total", "10", "--github-server-url", "https://github.com",
             "--github-repo", "test/repo", "--github-run-id", "12345"],
            capture_output=True, text=True
        )

        assert result.returncode == 0, f"Script failed: {result.stderr}"
        assert output_file.exists(), "Output file not created"
        content = output_file.read_text()
        assert "OpenGrep" in content, "Missing OpenGrep header"
        assert "|" in content, "Missing markdown table"

    @pytest.mark.integration
    def test_trivy_iac_summary_writes_output(self, tmp_path):
        """Verify Trivy IaC generate_summary.py produces a markdown file."""
        output_file = tmp_path / "trivy-iac.md"

        result = subprocess.run(
            [sys.executable, str(self.TRIVY_IAC_SUMMARY), str(output_file),
             "--has-iac", "false"],
            capture_output=True, text=True
        )

        assert result.returncode == 0, f"Script failed: {result.stderr}"
        assert output_file.exists(), "Output file not created"

    @pytest.mark.integration
    def test_container_config_writes_github_output(self, tmp_path):
        """Verify parse_container_config.py writes matrix JSON to GITHUB_OUTPUT."""
        config_file = tmp_path / "containers.yaml"
        schema_file = tmp_path / "schema.json"
        github_output = tmp_path / "output.txt"

        config_file.write_text("""
containers:
  - name: app
    image: myapp:latest
    scanners:
      - trivy
      - grype
    fail_on_severity: high
""")
        schema_file.write_text("{}")

        env = os.environ.copy()
        env["CONFIG_FILE"] = str(config_file)
        env["SCHEMA_FILE"] = str(schema_file)
        env["GITHUB_OUTPUT"] = str(github_output)

        result = subprocess.run(
            [sys.executable, str(self.CONTAINER_CONFIG)],
            env=env, capture_output=True, text=True
        )

        assert result.returncode == 0, f"Script failed: {result.stderr}"
        output_content = github_output.read_text()
        assert "matrix=" in output_content, "Missing matrix= in GITHUB_OUTPUT"

    @pytest.mark.integration
    def test_zap_config_writes_github_output(self, tmp_path):
        """Verify parse_zap_config.py writes matrix JSON to GITHUB_OUTPUT."""
        config_file = tmp_path / "zap.yaml"
        schema_file = tmp_path / "schema.json"
        github_output = tmp_path / "output.txt"

        config_file.write_text("""
scans:
  - name: baseline
    type: baseline
    target_url: http://localhost:8080
""")
        schema_file.write_text("{}")

        env = os.environ.copy()
        env["CONFIG_FILE"] = str(config_file)
        env["SCHEMA_FILE"] = str(schema_file)
        env["GITHUB_OUTPUT"] = str(github_output)

        result = subprocess.run(
            [sys.executable, str(self.ZAP_CONFIG)],
            env=env, capture_output=True, text=True
        )

        assert result.returncode == 0, f"Script failed: {result.stderr}"
        output_content = github_output.read_text()
        assert "matrix=" in output_content, "Missing matrix= in GITHUB_OUTPUT"

    @pytest.mark.integration
    def test_clamav_parser_writes_json_output(self, tmp_path):
        """Verify parse-clamav-report.py generates JSON output file."""
        report_file = tmp_path / "clamav-report.log"
        report_file.write_text("""
Scanning...
/app/malware.exe: Win.Trojan.Generic FOUND

----------- SUMMARY -----------
Scanned files: 100
Infected files: 1
""")

        result = subprocess.run(
            [sys.executable, str(self.CLAMAV_PARSER),
             "--report-path", str(report_file)],
            capture_output=True, text=True
        )

        assert result.returncode == 0, f"Script failed: {result.stderr}"
        json_file = tmp_path / "clamav-report.json"
        assert json_file.exists(), "JSON output file not created"
        data = json.loads(json_file.read_text())
        assert data["infected_files"] == 1, "Incorrect infected_files count"
        assert data["total_files"] == 100, "Incorrect total_files count"

    @pytest.mark.integration
    def test_container_config_fails_on_missing_input(self, tmp_path):
        """Verify parse_container_config.py exits nonzero when input file is missing."""
        env = os.environ.copy()
        env["CONFIG_FILE"] = str(tmp_path / "nonexistent.yaml")
        env["SCHEMA_FILE"] = str(tmp_path / "nonexistent.json")
        env["GITHUB_OUTPUT"] = str(tmp_path / "output.txt")

        result = subprocess.run(
            [sys.executable, str(self.CONTAINER_CONFIG)],
            env=env, capture_output=True, text=True
        )

        assert result.returncode != 0, "Script should fail with missing input file"

    @pytest.mark.integration
    def test_zap_config_fails_on_missing_input(self, tmp_path):
        """Verify parse_zap_config.py exits nonzero when input file is missing."""
        env = os.environ.copy()
        env["CONFIG_FILE"] = str(tmp_path / "nonexistent.yaml")
        env["SCHEMA_FILE"] = str(tmp_path / "nonexistent.json")
        env["GITHUB_OUTPUT"] = str(tmp_path / "output.txt")

        result = subprocess.run(
            [sys.executable, str(self.ZAP_CONFIG)],
            env=env, capture_output=True, text=True
        )

        assert result.returncode != 0, "Script should fail with missing input file"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
