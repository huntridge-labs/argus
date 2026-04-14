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

    CODEQL_SUMMARY = ACTIONS_DIR / "scanner-codeql/scripts/generate_summary.py"
    CONTAINER_CONFIG = ACTIONS_DIR / "parse-container-config/scripts/parse_container_config.py"
    ZAP_CONFIG = ACTIONS_DIR / "parse-zap-config/scripts/parse_zap_config.py"

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
