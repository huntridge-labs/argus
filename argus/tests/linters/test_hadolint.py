"""Tests for argus.linters.hadolint.HadolintLinter.

Locks in the FileDiscoveryScanner-based behavior after the
linter_template migration: discovery of Dockerfile* files, batched
single-subprocess invocation (local), docker fallback when the
binary is missing, JSON output parsing, and the
``execution_failed`` / ``parse_failed`` metadata shapes.
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

import pytest

from argus.core.models import Severity
from argus.linters.hadolint import HadolintLinter


def _completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(
        args=["hadolint"], returncode=returncode, stdout=stdout, stderr=stderr,
    )


# ---------------------------------------------------------------- #
# Metadata + protocol surface                                      #
# ---------------------------------------------------------------- #


class TestHadolintLinterMeta:

    def test_name(self):
        assert HadolintLinter().name == "lint-dockerfile"

    def test_category(self):
        assert HadolintLinter().category == "linter"

    def test_languages(self):
        assert "dockerfile" in HadolintLinter().languages

    def test_install_command_returns_string(self):
        assert isinstance(HadolintLinter().install_command(), str)

    def test_file_glob(self):
        assert HadolintLinter.file_glob == "Dockerfile*"

    def test_container_image_declared(self):
        assert HadolintLinter.container_image
        assert "hadolint" in HadolintLinter.container_image.lower()

    def test_binary_attribute(self):
        # Required by the FileDiscoveryScanner base for shutil.which.
        assert HadolintLinter.binary == "hadolint"

    def test_accept_returncodes_includes_findings_path(self):
        # hadolint exits 1 when findings exist; that's the happy
        # path, not an execution failure.
        assert 1 in HadolintLinter.accept_returncodes


# ---------------------------------------------------------------- #
# scan() — discovery + dispatch                                    #
# ---------------------------------------------------------------- #


class TestHadolintScan:

    def test_no_dockerfiles_returns_clean_info_row(self, tmp_path):
        result = HadolintLinter().scan(str(tmp_path))
        assert result.findings == []
        assert "No files matching" in result.metadata.get("info", "")

    def test_local_invocation_when_binary_present(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM scratch")
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return _completed(stdout=json.dumps([{
                "code": "DL3001",
                "line": 1,
                "column": 1,
                "level": "warning",
                "file": "Dockerfile",
                "message": "Useless cd",
            }]))

        with patch("argus.core.linter_template.shutil.which") as mw, \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            mw.side_effect = lambda b: f"/usr/bin/{b}" if b == "hadolint" else None
            result = HadolintLinter().scan(str(tmp_path))

        # Local mode used.
        assert result.metadata["mode"] == "local"
        assert result.metadata["file_count"] == 1
        # Local args use the binary directly + json format.
        assert captured["cmd"][0] == "hadolint"
        assert "--format" in captured["cmd"]
        assert "json" in captured["cmd"]
        # Findings parsed.
        assert len(result.findings) == 1
        assert result.findings[0].id == "DL3001"
        assert result.findings[0].severity == Severity.INFO
        assert result.findings[0].location == "Dockerfile:1"

    def test_container_fallback_when_binary_missing(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM alpine")
        captured = {}

        def fake_which(b):
            return "/usr/bin/docker" if b == "docker" else None

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return _completed(stdout="[]")

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            result = HadolintLinter().scan(str(tmp_path))

        assert result.metadata["mode"] == "container"
        assert captured["cmd"][0] == "docker"
        # Container path includes the image and the binary as args.
        assert HadolintLinter.container_image in captured["cmd"]
        assert "hadolint" in captured["cmd"]
        # Container files are translated to /workspace/...
        assert any(arg.startswith("/workspace/") for arg in captured["cmd"])

    def test_unavailable_when_neither_binary_nor_docker(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM scratch")
        with patch("argus.core.linter_template.shutil.which", return_value=None):
            result = HadolintLinter().scan(str(tmp_path))
        assert result.metadata["execution_failed"] is True
        assert "hadolint" in result.metadata["execution_failure_reason"]

    def test_findings_with_exit_1_are_happy_path(self, tmp_path):
        # Exit 1 from hadolint = findings present. Must not be an
        # execution failure.
        (tmp_path / "Dockerfile").write_text("FROM scratch")

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "hadolint" else None

        def fake_run(cmd, **kwargs):
            return _completed(
                stdout=json.dumps([{
                    "code": "DL3025", "line": 1, "level": "warning",
                    "file": "Dockerfile", "message": "Use arguments JSON form",
                }]),
                returncode=1,
            )

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            result = HadolintLinter().scan(str(tmp_path))

        assert len(result.findings) == 1
        assert result.metadata.get("execution_failed") is not True

    def test_malformed_json_marks_parse_failed(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM alpine")

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "hadolint" else None

        def fake_run(cmd, **kwargs):
            return _completed(stdout="not really json")

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            result = HadolintLinter().scan(str(tmp_path))

        assert result.metadata["parse_failed"] is True
        assert "JSONDecodeError" in result.metadata["parse_failure_reason"]

    def test_multiple_dockerfiles_batched_in_one_call(self, tmp_path):
        # Roadmap motivation: avoid N subprocess startups for N files.
        (tmp_path / "Dockerfile").write_text("FROM alpine")
        (tmp_path / "Dockerfile.api").write_text("FROM alpine")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "Dockerfile").write_text("FROM scratch")

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "hadolint" else None

        call_count = {"n": 0}

        def fake_run(cmd, **kwargs):
            call_count["n"] += 1
            return _completed(stdout="[]")

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            result = HadolintLinter().scan(str(tmp_path))

        assert call_count["n"] == 1, "hadolint must be invoked once for the whole batch"
        assert result.metadata["file_count"] == 3

    def test_config_file_threaded_into_local_args(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM scratch")
        captured = {}

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "hadolint" else None

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return _completed(stdout="[]")

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            HadolintLinter().scan(str(tmp_path), config={"config_file": ".hadolint.yaml"})

        assert "--config" in captured["cmd"]
        idx = captured["cmd"].index("--config")
        assert captured["cmd"][idx + 1] == ".hadolint.yaml"

    def test_ignore_rules_threaded_into_local_args(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM scratch")
        captured = {}

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "hadolint" else None

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return _completed(stdout="[]")

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            HadolintLinter().scan(
                str(tmp_path), config={"ignore_rules": ["DL3025", "DL3008"]},
            )

        # Each rule passed as a separate --ignore <rule> pair.
        cmd = captured["cmd"]
        assert cmd.count("--ignore") == 2
        ignored = [cmd[i + 1] for i, c in enumerate(cmd) if c == "--ignore"]
        assert "DL3025" in ignored
        assert "DL3008" in ignored

    def test_empty_stdout_with_zero_exit_returns_no_findings(self, tmp_path):
        # Exit 0 + empty stdout = no findings. Some hadolint versions
        # emit nothing at all when there's nothing to report.
        (tmp_path / "Dockerfile").write_text("FROM scratch")

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "hadolint" else None

        def fake_run(cmd, **kwargs):
            return _completed(stdout="", returncode=0)

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            result = HadolintLinter().scan(str(tmp_path))

        assert result.findings == []
        assert result.metadata.get("execution_failed") is not True
