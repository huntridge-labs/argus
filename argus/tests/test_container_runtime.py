"""Tests for argus.container_runtime — shared container helpers."""

from unittest.mock import MagicMock, patch

import pytest

import argus.container_runtime as cr


class TestDetectRuntime:
    """Test container runtime detection."""

    def setup_method(self):
        # Reset the module-level cache between tests
        cr._cached_runtime = None

    def test_detects_docker(self, monkeypatch):
        monkeypatch.delenv("ARGUS_CONTAINER_RUNTIME", raising=False)
        monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/docker" if x == "docker" else None)
        assert cr.detect_runtime() == "docker"

    def test_detects_podman(self, monkeypatch):
        monkeypatch.delenv("ARGUS_CONTAINER_RUNTIME", raising=False)
        monkeypatch.setattr(
            "shutil.which",
            lambda x: "/usr/bin/podman" if x == "podman" else None,
        )
        assert cr.detect_runtime() == "podman"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("ARGUS_CONTAINER_RUNTIME", "nerdctl")
        monkeypatch.setattr("shutil.which", lambda x: f"/usr/bin/{x}")
        assert cr.detect_runtime() == "nerdctl"

    def test_none_when_nothing_available(self, monkeypatch):
        monkeypatch.delenv("ARGUS_CONTAINER_RUNTIME", raising=False)
        monkeypatch.setattr("shutil.which", lambda x: None)
        assert cr.detect_runtime() is None

    def test_is_available(self, monkeypatch):
        monkeypatch.delenv("ARGUS_CONTAINER_RUNTIME", raising=False)
        monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/docker" if x == "docker" else None)
        assert cr.is_available() is True

    def test_runtime_cmd_defaults_to_docker(self, monkeypatch):
        monkeypatch.delenv("ARGUS_CONTAINER_RUNTIME", raising=False)
        monkeypatch.setattr("shutil.which", lambda x: None)
        assert cr.runtime_cmd() == "docker"


class TestPullImage:
    """Test image pull logic."""

    def setup_method(self):
        cr._cached_runtime = None

    @patch("argus.container_runtime.subprocess.run")
    def test_pull_always(self, mock_run, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/docker" if x == "docker" else None)
        mock_run.return_value = MagicMock(returncode=0)
        assert cr.pull_image("test:latest", policy="always") is True
        # Should call pull (not just inspect)
        calls = [c[0][0] for c in mock_run.call_args_list]
        assert any("pull" in c for c in calls)

    @patch("argus.container_runtime.subprocess.run")
    def test_pull_if_not_present_found(self, mock_run, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/docker" if x == "docker" else None)
        # image inspect succeeds → skip pull
        mock_run.return_value = MagicMock(returncode=0)
        assert cr.pull_image("test:latest", policy="if-not-present") is True

    @patch("argus.container_runtime.subprocess.run")
    def test_pull_never_missing(self, mock_run, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/docker" if x == "docker" else None)
        mock_run.return_value = MagicMock(returncode=1)
        assert cr.pull_image("test:latest", policy="never") is False

    @patch("argus.container_runtime.subprocess.run")
    def test_pull_retries_with_platform(self, mock_run, monkeypatch):
        """When native pull fails, retries with --platform linux/amd64."""
        monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/docker" if x == "docker" else None)
        # First call (inspect) fails, second (pull) fails, third (pull --platform) succeeds
        mock_run.side_effect = [
            MagicMock(returncode=1),              # inspect
            MagicMock(returncode=1, stderr="err"), # pull
            MagicMock(returncode=0),               # pull --platform
        ]
        assert cr.pull_image("test:latest", policy="if-not-present") is True
