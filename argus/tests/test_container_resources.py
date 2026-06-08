"""Tests for argus.container.resources — disk space, image management."""

from unittest.mock import patch, MagicMock
import subprocess

from argus.container.resources import (
    check_disk_space,
    remove_docker_image,
    is_image_local,
    get_image_digest,
)


class TestCheckDiskSpace:
    """Test check_disk_space returns free bytes."""

    @patch("argus.container.resources.shutil.disk_usage")
    def test_returns_free_bytes(self, mock_usage):
        mock_usage.return_value = MagicMock(free=5 * 1024**3)
        free = check_disk_space("/")
        assert free == 5 * 1024**3

    @patch("argus.container.resources.shutil.disk_usage")
    def test_low_disk_still_returns_value(self, mock_usage):
        mock_usage.return_value = MagicMock(free=500 * 1024**2)
        free = check_disk_space("/")
        assert free == 500 * 1024**2

    @patch("argus.container.resources.shutil.disk_usage", side_effect=OSError)
    def test_os_error_returns_zero(self, mock_usage):
        assert check_disk_space("/") == 0


class TestRemoveDockerImage:
    """Test remove_docker_image with mocked subprocess."""

    @patch("argus.container.resources.subprocess.run")
    @patch("argus.container.resources.shutil.which", return_value="/usr/bin/docker")
    def test_successful_removal(self, mock_which, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        assert remove_docker_image("app:latest") is True
        mock_run.assert_called_once()

    @patch("argus.container.resources.subprocess.run")
    @patch("argus.container.resources.shutil.which", return_value="/usr/bin/docker")
    def test_no_such_image_returns_true(self, mock_which, mock_run):
        mock_run.return_value = MagicMock(
            returncode=1, stderr="No such image: app:latest",
        )
        assert remove_docker_image("app:latest") is True

    @patch("argus.container.resources.subprocess.run")
    @patch("argus.container.resources.shutil.which", return_value="/usr/bin/docker")
    def test_other_failure_returns_false(self, mock_which, mock_run):
        mock_run.return_value = MagicMock(
            returncode=1, stderr="permission denied",
        )
        assert remove_docker_image("app:latest") is False

    @patch("argus.container.resources.shutil.which", return_value=None)
    def test_no_docker_returns_true(self, mock_which):
        assert remove_docker_image("app:latest") is True

    @patch("argus.container.resources.subprocess.run")
    @patch("argus.container.resources.shutil.which", return_value="/usr/bin/docker")
    def test_timeout_returns_false(self, mock_which, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired("docker", 60)
        assert remove_docker_image("app:latest") is False


class TestIsImageLocal:
    """Test is_image_local with mocked subprocess."""

    @patch("argus.container.resources.subprocess.run")
    @patch("argus.container.resources.shutil.which", return_value="/usr/bin/docker")
    def test_image_exists(self, mock_which, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        assert is_image_local("app:latest") is True

    @patch("argus.container.resources.subprocess.run")
    @patch("argus.container.resources.shutil.which", return_value="/usr/bin/docker")
    def test_image_missing(self, mock_which, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        assert is_image_local("app:latest") is False

    @patch("argus.container.resources.shutil.which", return_value=None)
    def test_no_docker_returns_false(self, mock_which):
        assert is_image_local("app:latest") is False

    @patch("argus.container.resources.subprocess.run")
    @patch("argus.container.resources.shutil.which", return_value="/usr/bin/docker")
    def test_timeout_returns_false(self, mock_which, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired("docker", 10)
        assert is_image_local("app:latest") is False


class TestGetImageDigest:
    """get_image_digest binds a scan to content, not a mutable tag (#237)."""

    @patch("argus.container.resources.subprocess.run")
    @patch("argus.container.resources.shutil.which", return_value="/usr/bin/docker")
    def test_pulled_image_prefers_repo_digest(self, mock_which, mock_run):
        # A pulled/pushed image carries a registry RepoDigest — return the
        # manifest digest (registry-comparable), not the config ID.
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='["ghcr.io/org/app@sha256:aaaa"]|sha256:cfgbbbb',
        )
        assert get_image_digest("ghcr.io/org/app:1.0") == "sha256:aaaa"

    @patch("argus.container.resources.subprocess.run")
    @patch("argus.container.resources.shutil.which", return_value="/usr/bin/docker")
    def test_local_built_falls_back_to_config_id(self, mock_which, mock_run):
        # A never-pushed local build has no RepoDigest — fall back to the
        # config ID, still a stable content hash of the build.
        mock_run.return_value = MagicMock(
            returncode=0, stdout="[]|sha256:cfgbbbb",
        )
        assert get_image_digest("app:scan-6d7bd4a0") == "sha256:cfgbbbb"

    @patch("argus.container.resources.subprocess.run")
    @patch("argus.container.resources.shutil.which", return_value="/usr/bin/docker")
    def test_inspect_failure_returns_empty(self, mock_which, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        assert get_image_digest("missing:tag") == ""

    @patch("argus.container.resources.shutil.which", return_value=None)
    def test_no_docker_returns_empty(self, mock_which):
        assert get_image_digest("app:latest") == ""

    @patch("argus.container.resources.subprocess.run")
    @patch("argus.container.resources.shutil.which", return_value="/usr/bin/docker")
    def test_timeout_returns_empty(self, mock_which, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired("docker", 10)
        assert get_image_digest("app:latest") == ""
