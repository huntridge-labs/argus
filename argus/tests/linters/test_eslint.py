"""Tests for argus.linters.eslint.EslintLinter.

Covers config detection, local + docker command construction, message
parsing, and the scan() flow under each branching condition (no config,
local eslint, docker fallback, no docker available, JSON parse error).
"""

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from argus.core.models import Severity
from argus.linters.eslint import EslintLinter


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(
        args=["fake"], returncode=returncode, stdout=stdout, stderr=stderr,
    )


# --------------------------------------------------------------------- #
# Metadata + protocol                                                   #
# --------------------------------------------------------------------- #


class TestEslintLinterMeta:
    def test_name(self):
        assert EslintLinter().name == "lint-javascript"

    def test_languages(self):
        assert "javascript" in EslintLinter.languages
        assert "typescript" in EslintLinter.languages

    def test_install_command(self):
        cmd = EslintLinter().install_command()
        assert cmd is not None
        assert "eslint" in cmd

    def test_container_image_set(self):
        assert "eslint" in EslintLinter().container_image


# --------------------------------------------------------------------- #
# Config detection                                                      #
# --------------------------------------------------------------------- #


class TestEslintConfigDetection:
    def test_explicit_config_overrides_workspace_check(self, tmp_path):
        # No real config file in tmp_path, but explicit_config wins.
        assert EslintLinter()._has_eslint_config(tmp_path, "eslint.config.js") is True

    @pytest.mark.parametrize("config_name", [
        "eslint.config.js",
        "eslint.config.mjs",
        "eslint.config.cjs",
        "eslint.config.ts",
        ".eslintrc.js",
        ".eslintrc.cjs",
        ".eslintrc.json",
        ".eslintrc.yml",
        ".eslintrc.yaml",
    ])
    def test_recognizes_config_filenames(self, tmp_path, config_name):
        (tmp_path / config_name).write_text("// stub")
        assert EslintLinter()._has_eslint_config(tmp_path, None) is True

    def test_recognizes_package_json_eslintconfig(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({
            "eslintConfig": {"rules": {}},
        }))
        assert EslintLinter()._has_eslint_config(tmp_path, None) is True

    def test_package_json_without_eslintconfig_doesnt_match(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({"name": "p"}))
        assert EslintLinter()._has_eslint_config(tmp_path, None) is False

    def test_malformed_package_json_doesnt_crash(self, tmp_path):
        (tmp_path / "package.json").write_text("{broken")
        assert EslintLinter()._has_eslint_config(tmp_path, None) is False

    def test_no_config_returns_false(self, tmp_path):
        assert EslintLinter()._has_eslint_config(tmp_path, None) is False


# --------------------------------------------------------------------- #
# Command construction                                                  #
# --------------------------------------------------------------------- #


class TestEslintBuildCommand:
    def test_local_command_basic(self):
        cmd = EslintLinter()._build_command("/repo", {})
        assert cmd[0] == "eslint"
        assert "--format" in cmd
        assert "json" in cmd
        assert "/repo" in cmd
        assert "--no-error-on-unmatched-pattern" in cmd

    def test_local_command_with_config(self):
        cmd = EslintLinter()._build_command("/repo", {"config_file": ".eslintrc.json"})
        assert "--config" in cmd
        assert ".eslintrc.json" in cmd


class TestEslintBuildDockerCommand:
    def test_returns_none_when_docker_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda _: None)
        assert EslintLinter()._build_docker_command(tmp_path, {}) is None

    def test_docker_command_has_workspace_mount(self, tmp_path, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/docker" if b == "docker" else None)
        cmd = EslintLinter()._build_docker_command(tmp_path, {})
        assert cmd is not None
        assert "docker" in cmd
        assert "run" in cmd
        assert "-v" in cmd
        # Mount uses absolute resolved path on host side, /workspace on container side.
        mount = next(c for c in cmd if ":" in c and ":/workspace" in c)
        assert str(tmp_path.resolve()) in mount
        # Working directory is /workspace.
        assert "/workspace" in cmd
        # The eslint binary name is included as args[0] after the image.
        assert "eslint" in cmd

    def test_docker_command_with_config(self, tmp_path, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/docker" if b == "docker" else None)
        cmd = EslintLinter()._build_docker_command(tmp_path, {"config_file": ".eslintrc.json"})
        assert cmd is not None
        assert "--config" in cmd
        assert "/workspace/.eslintrc.json" in cmd


# --------------------------------------------------------------------- #
# Message parsing                                                       #
# --------------------------------------------------------------------- #


class TestEslintMessageParsing:
    def test_error_severity_maps_to_low(self):
        f = EslintLinter()._parse_message(
            {"ruleId": "no-unused-vars", "severity": 2, "message": "x", "line": 5},
            "/workspace/app.js",
        )
        assert f.severity == Severity.LOW
        assert f.id == "no-unused-vars"

    def test_warning_severity_maps_to_info(self):
        f = EslintLinter()._parse_message(
            {"ruleId": "no-console", "severity": 1, "message": "y", "line": 9},
            "/workspace/app.js",
        )
        assert f.severity == Severity.INFO

    def test_unknown_severity_falls_back_to_info(self):
        f = EslintLinter()._parse_message(
            {"ruleId": "x", "severity": 0, "message": "z", "line": 1}, "f.js",
        )
        assert f.severity == Severity.INFO

    def test_null_rule_id_falls_back_to_eslint(self):
        f = EslintLinter()._parse_message(
            {"ruleId": None, "severity": 1, "message": "parser error", "line": 1},
            "f.js",
        )
        assert f.id == "eslint"

    def test_location_format(self):
        f = EslintLinter()._parse_message(
            {"ruleId": "r", "severity": 1, "message": "m", "line": 42},
            "/repo/src/index.js",
        )
        assert f.location == "/repo/src/index.js:42"

    def test_metadata_contains_column_and_node_type(self):
        f = EslintLinter()._parse_message(
            {"ruleId": "r", "severity": 1, "message": "m", "line": 1,
             "column": 7, "nodeType": "Identifier"},
            "f.js",
        )
        assert f.metadata["column"] == 7
        assert f.metadata["node_type"] == "Identifier"


# --------------------------------------------------------------------- #
# scan() integration                                                    #
# --------------------------------------------------------------------- #


class TestEslintScan:
    def test_no_config_returns_info_row(self, tmp_path):
        # Empty workspace, no eslint config anywhere.
        result = EslintLinter().scan(str(tmp_path))
        assert result.findings == []
        assert "info" in result.metadata
        assert "No ESLint config" in result.metadata["info"]

    def test_local_path_runs_eslint_when_available(self, tmp_path, monkeypatch):
        (tmp_path / ".eslintrc.json").write_text("{}")
        monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/eslint" if b == "eslint" else None)

        eslint_output = json.dumps([
            {
                "filePath": str(tmp_path / "src/app.js"),
                "messages": [
                    {"ruleId": "no-unused-vars", "severity": 2,
                     "message": "x is unused", "line": 3, "column": 5},
                ],
            },
        ])
        with patch("subprocess.run", return_value=_completed(stdout=eslint_output)):
            result = EslintLinter().scan(str(tmp_path))

        assert len(result.findings) == 1
        assert result.findings[0].id == "no-unused-vars"
        assert result.findings[0].severity == Severity.LOW

    def test_docker_fallback_when_local_missing(self, tmp_path, monkeypatch):
        (tmp_path / ".eslintrc.json").write_text("{}")
        # No local eslint, but docker is available.
        monkeypatch.setattr(
            "shutil.which",
            lambda b: "/usr/bin/docker" if b == "docker" else None,
        )

        captured: dict = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return _completed(stdout="[]")

        with patch("subprocess.run", side_effect=fake_run):
            result = EslintLinter().scan(str(tmp_path))

        assert result.findings == []
        # Confirm we actually went through docker, not local eslint.
        assert "docker" in captured["cmd"]

    def test_no_eslint_no_docker_returns_failure_row(self, tmp_path, monkeypatch):
        (tmp_path / ".eslintrc.json").write_text("{}")
        monkeypatch.setattr("shutil.which", lambda _: None)

        result = EslintLinter().scan(str(tmp_path))

        assert result.findings == []
        assert result.metadata.get("execution_failed") is True
        reason = result.metadata.get("execution_failure_reason", "")
        assert "eslint" in reason
        assert "Docker" in reason

    def test_clean_run_with_no_findings_is_not_a_failure(self, tmp_path, monkeypatch):
        (tmp_path / ".eslintrc.json").write_text("{}")
        monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/eslint" if b == "eslint" else None)

        # ESLint exits 0 when no issues — output is empty.
        with patch("subprocess.run", return_value=_completed(stdout="", returncode=0)):
            result = EslintLinter().scan(str(tmp_path))

        assert result.findings == []
        assert "execution_failed" not in result.metadata

    def test_tool_error_returns_failure_row(self, tmp_path, monkeypatch):
        (tmp_path / ".eslintrc.json").write_text("{}")
        monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/eslint" if b == "eslint" else None)

        # ESLint exits 2 (tool error) with no JSON output.
        with patch(
            "subprocess.run",
            return_value=_completed(stdout="", stderr="parser config invalid", returncode=2),
        ):
            result = EslintLinter().scan(str(tmp_path))

        assert result.metadata.get("execution_failed") is True
        assert "parser config invalid" in result.metadata.get("execution_failure_reason", "")

    def test_invalid_json_output_returns_failure_row(self, tmp_path, monkeypatch):
        (tmp_path / ".eslintrc.json").write_text("{}")
        monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/eslint" if b == "eslint" else None)

        with patch("subprocess.run", return_value=_completed(stdout="not json")):
            result = EslintLinter().scan(str(tmp_path))

        assert result.metadata.get("execution_failed") is True
        assert "Invalid JSON" in result.metadata.get("execution_failure_reason", "")
