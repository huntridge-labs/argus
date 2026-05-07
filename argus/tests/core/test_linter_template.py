"""Tests for argus.core.linter_template.

Locks in the contract every migrated linter consumes: file discovery,
docker-fallback command building, UTF-8 subprocess, and the
FileDiscoveryScanner base's local→container dispatch + error
handling.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from argus.core.linter_template import (
    FileDiscoveryScanner,
    build_docker_command,
    discover_files,
    run_utf8,
)
from argus.core.models import Finding, Severity


# --------------------------------------------------------------------- #
# discover_files                                                        #
# --------------------------------------------------------------------- #


class TestDiscoverFiles:

    def test_target_is_file_returns_just_that_file(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM scratch")
        assert discover_files(f, ["Dockerfile*"]) == [f]

    def test_walks_recursively_for_glob_match(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "Dockerfile").write_text("FROM scratch")
        (tmp_path / "b").mkdir()
        (tmp_path / "b" / "Dockerfile.api").write_text("FROM alpine")
        (tmp_path / "b" / "ignore.txt").write_text("nope")

        result = discover_files(tmp_path, ["Dockerfile*"])
        names = sorted(p.name for p in result)
        assert names == ["Dockerfile", "Dockerfile.api"]

    def test_multiple_patterns_unioned(self, tmp_path):
        (tmp_path / "a.json").write_text("{}")
        (tmp_path / "b.yml").write_text("k: v")
        (tmp_path / "c.txt").write_text("nope")

        result = discover_files(tmp_path, ["*.json", "*.yml"])
        names = sorted(p.name for p in result)
        assert names == ["a.json", "b.yml"]

    def test_results_are_deduplicated(self, tmp_path):
        # Same file matched by two patterns shouldn't appear twice.
        (tmp_path / "Dockerfile").write_text("FROM scratch")
        result = discover_files(tmp_path, ["Dockerfile", "Dockerfile*"])
        assert len(result) == 1

    def test_results_sorted(self, tmp_path):
        (tmp_path / "z.json").write_text("{}")
        (tmp_path / "a.json").write_text("{}")
        (tmp_path / "m.json").write_text("{}")
        result = discover_files(tmp_path, ["*.json"])
        assert [p.name for p in result] == ["a.json", "m.json", "z.json"]

    def test_directories_are_not_returned(self, tmp_path):
        # A directory whose name matches the glob shouldn't be returned;
        # only files.
        (tmp_path / "Dockerfile").mkdir()
        (tmp_path / "Dockerfile.api").write_text("FROM scratch")
        result = discover_files(tmp_path, ["Dockerfile*"])
        assert [p.name for p in result] == ["Dockerfile.api"]

    def test_exclusions_filter_substring_matches(self, tmp_path):
        (tmp_path / "good.json").write_text("{}")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "lib.json").write_text("{}")
        result = discover_files(
            tmp_path, ["*.json"], exclusions={"node_modules"},
        )
        assert [p.name for p in result] == ["good.json"]

    def test_no_matches_returns_empty_list(self, tmp_path):
        assert discover_files(tmp_path, ["*.no-match"]) == []


# --------------------------------------------------------------------- #
# build_docker_command                                                  #
# --------------------------------------------------------------------- #


class TestBuildDockerCommand:

    def test_basic_shape(self, tmp_path):
        cmd = build_docker_command(
            "myimg:latest", tmp_path, ["--flag", "/workspace/file"],
        )
        # docker run --rm -v <abs>:/workspace:ro myimg:latest --flag ...
        assert cmd[0:3] == ["docker", "run", "--rm"]
        assert cmd[3] == "-v"
        assert cmd[4].endswith(":/workspace:ro")
        assert cmd[5] == "myimg:latest"
        assert cmd[6:] == ["--flag", "/workspace/file"]

    def test_mount_rw_drops_ro_suffix(self, tmp_path):
        cmd = build_docker_command(
            "img", tmp_path, ["x"], mount_rw=True,
        )
        v_index = cmd.index("-v")
        spec = cmd[v_index + 1]
        assert spec.endswith(":/workspace")
        assert not spec.endswith(":ro")

    def test_workdir_inserts_dash_w_before_image(self, tmp_path):
        cmd = build_docker_command(
            "img", tmp_path, ["x"], workdir="/workspace",
        )
        # -w must come BEFORE the image name (image is the docker run
        # positional after flags).
        w_index = cmd.index("-w")
        img_index = cmd.index("img")
        assert w_index < img_index
        assert cmd[w_index + 1] == "/workspace"

    def test_custom_ws_mount_path_used(self, tmp_path):
        cmd = build_docker_command(
            "img", tmp_path, ["x"], ws_mount="/scan",
        )
        assert any(c.endswith(":/scan:ro") for c in cmd)

    def test_workspace_is_resolved_to_absolute(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cmd = build_docker_command("img", Path("."), ["x"])
        # Spec must be absolute (`/`-rooted on Unix).
        v_index = cmd.index("-v")
        spec = cmd[v_index + 1]
        assert spec.startswith("/")


# --------------------------------------------------------------------- #
# run_utf8                                                              #
# --------------------------------------------------------------------- #


class TestRunUtf8:

    def test_passes_encoding_replace(self):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured.update(kwargs)
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            run_utf8(["echo", "hi"])

        assert captured["encoding"] == "utf-8"
        assert captured["errors"] == "replace"
        assert captured["text"] is True
        assert captured["capture_output"] is True

    def test_threads_cwd_through(self, tmp_path):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured.update(kwargs)
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            run_utf8(["echo"], cwd=tmp_path)

        assert captured["cwd"] == tmp_path

    def test_threads_timeout_through(self):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured.update(kwargs)
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            run_utf8(["echo"], timeout=5)

        assert captured["timeout"] == 5


# --------------------------------------------------------------------- #
# FileDiscoveryScanner — base class behavior                            #
# --------------------------------------------------------------------- #


class _TestableScanner(FileDiscoveryScanner):
    """Concrete subclass purely for testing the base."""

    name = "lint-test"
    file_glob = "*.txt"
    binary = "fake-binary"
    container_image = "fake/image:latest"

    def _build_local_args(self, files, config):
        return [self.binary, *[str(f) for f in files]]

    def _build_container_args(self, container_files, config):
        return [self.binary, *container_files]

    def _parse_results(self, stdout, completed):
        # One Finding per nonempty line in stdout.
        return [
            Finding(
                id="x", severity=Severity.INFO,
                title=line, description=line, scanner=self.name,
            )
            for line in stdout.splitlines()
            if line.strip()
        ]


def _completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(
        args=["fake"], returncode=returncode, stdout=stdout, stderr=stderr,
    )


class TestFileDiscoveryScanner:

    def test_no_matching_files_returns_clean_info_row(self, tmp_path):
        # Empty workspace — no *.txt anywhere.
        result = _TestableScanner().scan(str(tmp_path))
        assert result.findings == []
        assert "No files matching" in result.metadata.get("info", "")
        assert result.metadata.get("execution_failed") is not True

    def test_local_dispatch_when_binary_on_path(self, tmp_path):
        (tmp_path / "a.txt").write_text("x")
        (tmp_path / "b.txt").write_text("y")
        captured_cmd = {}

        def fake_run(cmd, **kwargs):
            captured_cmd["cmd"] = cmd
            return _completed(stdout="line1\nline2\n")

        with patch("argus.core.linter_template.shutil.which") as mock_which, \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            mock_which.side_effect = lambda b: f"/usr/bin/{b}" if b == "fake-binary" else None
            result = _TestableScanner().scan(str(tmp_path))

        # Two findings parsed; metadata says local mode.
        assert len(result.findings) == 2
        assert result.metadata["mode"] == "local"
        assert result.metadata["file_count"] == 2
        # Local args used the binary directly.
        assert captured_cmd["cmd"][0] == "fake-binary"
        assert captured_cmd["cmd"][1].endswith(".txt")

    def test_falls_back_to_container_when_binary_missing(self, tmp_path):
        (tmp_path / "a.txt").write_text("x")
        captured_cmd = {}

        def fake_run(cmd, **kwargs):
            captured_cmd["cmd"] = cmd
            return _completed(stdout="found something\n")

        def fake_which(b):
            # Binary missing, docker present.
            return "/usr/bin/docker" if b == "docker" else None

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            result = _TestableScanner().scan(str(tmp_path))

        assert result.metadata["mode"] == "container"
        # Command starts with `docker run --rm -v ... fake/image:latest fake-binary ...`
        assert captured_cmd["cmd"][0] == "docker"
        assert "fake/image:latest" in captured_cmd["cmd"]
        assert "fake-binary" in captured_cmd["cmd"]
        # Container files use /workspace prefix
        assert any(arg.startswith("/workspace/") for arg in captured_cmd["cmd"])

    def test_unavailable_when_neither_binary_nor_docker(self, tmp_path):
        (tmp_path / "a.txt").write_text("x")

        with patch("argus.core.linter_template.shutil.which", return_value=None):
            result = _TestableScanner().scan(str(tmp_path))

        assert result.metadata["execution_failed"] is True
        reason = result.metadata.get("execution_failure_reason", "")
        assert "not installed" in reason
        assert "Docker" in reason

    def test_filenotfound_during_run_emits_execution_failed(self, tmp_path):
        (tmp_path / "a.txt").write_text("x")

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "fake-binary" else None

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch(
                 "argus.core.linter_template.subprocess.run",
                 side_effect=FileNotFoundError(2, "no such file", "fake-binary"),
             ):
            result = _TestableScanner().scan(str(tmp_path))

        assert result.metadata["execution_failed"] is True
        assert "fake-binary" in result.metadata["execution_failure_reason"]

    def test_high_exit_with_no_stdout_marks_execution_failed(self, tmp_path):
        (tmp_path / "a.txt").write_text("x")

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "fake-binary" else None

        def fake_run(cmd, **kwargs):
            return _completed(stdout="", stderr="boom", returncode=42)

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            result = _TestableScanner().scan(str(tmp_path))

        assert result.metadata["execution_failed"] is True
        assert "exited 42" in result.metadata["execution_failure_reason"]
        assert "boom" in result.metadata["execution_failure_reason"]

    def test_findings_returncode_does_not_mark_failed(self, tmp_path):
        # Default accept_returncodes is (0, 1) — exit 1 with output is
        # the "lint findings present" happy path.
        (tmp_path / "a.txt").write_text("x")

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "fake-binary" else None

        def fake_run(cmd, **kwargs):
            return _completed(stdout="finding-line\n", returncode=1)

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            result = _TestableScanner().scan(str(tmp_path))

        assert len(result.findings) == 1
        assert result.metadata.get("execution_failed") is not True

    def test_parse_exception_marks_parse_failed(self, tmp_path):
        # parse_failed is the third state — scanner ran AND produced
        # output, we just couldn't interpret it.
        (tmp_path / "a.txt").write_text("x")

        class BoomParser(_TestableScanner):
            def _parse_results(self, stdout, completed):
                raise ValueError("malformed")

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "fake-binary" else None

        def fake_run(cmd, **kwargs):
            return _completed(stdout="some output")

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            result = BoomParser().scan(str(tmp_path))

        assert result.metadata.get("parse_failed") is True
        assert "ValueError" in result.metadata.get("parse_failure_reason", "")
        # Distinct from execution_failed — these are orthogonal signals.
        assert result.metadata.get("execution_failed") is not True

    def test_target_is_a_single_file(self, tmp_path):
        f = tmp_path / "single.txt"
        f.write_text("x")

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "fake-binary" else None

        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return _completed(stdout="finding\n")

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            result = _TestableScanner().scan(str(f))

        assert result.metadata["file_count"] == 1
        assert any("single.txt" in c for c in captured["cmd"])

    def test_subclass_must_implement_local_args_when_local_path_used(
        self, tmp_path
    ):
        class Incomplete(FileDiscoveryScanner):
            name = "incomplete"
            file_glob = "*.x"
            binary = "fake"

        (tmp_path / "a.x").write_text("x")
        with patch(
            "argus.core.linter_template.shutil.which",
            side_effect=lambda b: f"/usr/bin/{b}" if b == "fake" else None,
        ), pytest.raises(NotImplementedError):
            Incomplete().scan(str(tmp_path))

    def test_multi_glob_class_attr_supported(self, tmp_path):
        class MultiGlob(_TestableScanner):
            file_glob = ["*.json", "*.yml"]

        (tmp_path / "a.json").write_text("{}")
        (tmp_path / "b.yml").write_text("k: v")

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "fake-binary" else None

        def fake_run(cmd, **kwargs):
            return _completed(stdout="line\n")

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            result = MultiGlob().scan(str(tmp_path))

        assert result.metadata["file_count"] == 2
