"""Tests for argus.container_runtime — shared container helpers."""

import json
from unittest.mock import MagicMock, patch

import pytest

import argus.container_runtime as cr


def _only_docker(monkeypatch):
    """Make ``docker`` the sole runtime on PATH.

    Used by every pull/manifest test: the code under test resolves its
    runtime via ``shutil.which``, so the stub has to answer for docker and
    deny podman/nerdctl.
    """
    monkeypatch.setattr(
        "shutil.which",
        lambda name: "/usr/bin/docker" if name == "docker" else None,
    )



class TestDetectRuntime:
    """Test container runtime detection."""

    def setup_method(self):
        # Reset the module-level cache between tests
        cr._cached_runtime = None

    def test_detects_docker(self, monkeypatch):
        monkeypatch.delenv("ARGUS_CONTAINER_RUNTIME", raising=False)
        _only_docker(monkeypatch)
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
        _only_docker(monkeypatch)
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
        _only_docker(monkeypatch)
        mock_run.return_value = MagicMock(returncode=0)
        assert cr.pull_image("test:latest", policy="always") is True
        # Should call pull (not just inspect)
        calls = [c[0][0] for c in mock_run.call_args_list]
        assert any("pull" in c for c in calls)

    @patch("argus.container_runtime.subprocess.run")
    def test_pull_if_not_present_found(self, mock_run, monkeypatch):
        _only_docker(monkeypatch)
        # image inspect succeeds → skip pull
        mock_run.return_value = MagicMock(returncode=0)
        assert cr.pull_image("test:latest", policy="if-not-present") is True

    @patch("argus.container_runtime.subprocess.run")
    def test_pull_never_missing(self, mock_run, monkeypatch):
        _only_docker(monkeypatch)
        mock_run.return_value = MagicMock(returncode=1)
        assert cr.pull_image("test:latest", policy="never") is False

    @patch("argus.container_runtime.subprocess.run")
    def test_pull_retries_with_the_images_own_platform(self, mock_run, monkeypatch):
        """A failed native pull retries against a platform the image publishes.

        Scanners read image layers rather than execute them, so an
        arm64-only image is perfectly scannable from an amd64 runner —
        the pull just has to name the architecture, because the daemon
        otherwise resolves the manifest against its own. The retry
        platform comes from the registry manifest, not a hardcoded
        linux/amd64 (which could never rescue an arm64-only image).
        """
        _only_docker(monkeypatch)
        monkeypatch.setattr(cr, "_native_platform", lambda: "linux/amd64")
        manifest = json.dumps([
            {"Descriptor": {"platform": {"os": "linux", "architecture": "arm64"}}},
        ])
        mock_run.side_effect = [
            MagicMock(returncode=1),                       # image inspect
            MagicMock(returncode=1, stderr="no match"),    # native pull
            MagicMock(returncode=0, stdout=manifest, stderr=""),  # manifest inspect
            MagicMock(returncode=0, stderr=""),            # pull --platform
        ]
        assert cr.pull_image("test:latest", policy="if-not-present") is True

        retry = mock_run.call_args_list[-1][0][0]
        assert "--platform" in retry
        assert retry[retry.index("--platform") + 1] == "linux/arm64"

    @patch("argus.container_runtime.subprocess.run")
    def test_pull_prefers_native_platform_when_image_publishes_it(
        self, mock_run, monkeypatch,
    ):
        """A multi-arch image retries on this host's own architecture.

        The native pull may have failed for an unrelated, transient
        reason; re-pulling the foreign variant of an image that does
        ship ours would be a silent downgrade.
        """
        _only_docker(monkeypatch)
        monkeypatch.setattr(cr, "_native_platform", lambda: "linux/amd64")
        manifest = json.dumps([
            {"Descriptor": {"platform": {"os": "linux", "architecture": "arm64"}}},
            {"Descriptor": {"platform": {"os": "linux", "architecture": "amd64"}}},
        ])
        mock_run.side_effect = [
            MagicMock(returncode=1),
            MagicMock(returncode=1, stderr="transient"),
            MagicMock(returncode=0, stdout=manifest, stderr=""),
            MagicMock(returncode=0, stderr=""),
        ]
        assert cr.pull_image("test:latest", policy="if-not-present") is True
        retry = mock_run.call_args_list[-1][0][0]
        assert retry[retry.index("--platform") + 1] == "linux/amd64"

    @patch("argus.container_runtime.subprocess.run")
    def test_pull_does_not_retry_without_platform_information(
        self, mock_run, monkeypatch,
    ):
        """A bad tag / auth failure costs one pull attempt, not two.

        The old unconditional ``--platform linux/amd64`` retry burned a
        second full pull on every permanently-failing reference.
        """
        _only_docker(monkeypatch)
        mock_run.side_effect = [
            MagicMock(returncode=1),                      # image inspect
            MagicMock(returncode=1, stderr="not found"),  # native pull
            MagicMock(returncode=1, stdout="", stderr="no such manifest"),
        ]
        assert cr.pull_image("test:latest", policy="if-not-present") is False
        pull_calls = [
            c[0][0] for c in mock_run.call_args_list if "pull" in c[0][0]
        ]
        assert len(pull_calls) == 1

    @patch("argus.container_runtime.subprocess.run")
    def test_explicit_platform_is_used_verbatim(self, mock_run, monkeypatch):
        """An explicit platform is honored with no fallback attempt."""
        _only_docker(monkeypatch)
        mock_run.side_effect = [
            MagicMock(returncode=1),            # image inspect
            MagicMock(returncode=0, stderr=""),  # pull --platform
        ]
        assert cr.pull_image(
            "test:latest", policy="if-not-present", platform="linux/s390x",
        ) is True
        pull = mock_run.call_args_list[-1][0][0]
        assert pull[pull.index("--platform") + 1] == "linux/s390x"

    @patch("argus.container_runtime.subprocess.run")
    def test_explicit_platform_failure_is_not_retried(self, mock_run, monkeypatch):
        """An explicit platform is the caller's stated intent.

        Falling back to a different architecture would scan something the
        caller did not ask for, so the failure is reported as-is and the
        registry manifest is never consulted.
        """
        _only_docker(monkeypatch)
        mock_run.side_effect = [
            MagicMock(returncode=1),                                # image inspect
            MagicMock(returncode=1, stderr="no matching manifest"),  # pull --platform
        ]
        assert cr.pull_image(
            "test:latest", policy="if-not-present", platform="linux/s390x",
        ) is False
        assert mock_run.call_count == 2  # no manifest inspect, no second pull


class TestDetectImagePlatforms:
    """``detect_image_platforms`` reads the registry manifest."""

    def setup_method(self):
        cr._cached_runtime = None

    def teardown_method(self):
        cr._cached_runtime = None

    @patch("argus.container_runtime.subprocess.run")
    def test_single_arch_image(self, mock_run, monkeypatch):
        _only_docker(monkeypatch)
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(
                {"Descriptor": {"platform": {
                    "os": "linux", "architecture": "arm", "variant": "v7",
                }}}
            ),
            stderr="",
        )
        assert cr.detect_image_platforms("armv7/app:1") == ["linux/arm/v7"]

    @patch("argus.container_runtime.subprocess.run")
    def test_attestation_entries_are_skipped(self, mock_run, monkeypatch):
        """buildx provenance entries are unknown/unknown and unpullable."""
        _only_docker(monkeypatch)
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps([
                {"Descriptor": {"platform": {"os": "linux", "architecture": "amd64"}}},
                {"Descriptor": {"platform": {
                    "os": "unknown", "architecture": "unknown",
                }}},
            ]),
            stderr="",
        )
        assert cr.detect_image_platforms("app:1") == ["linux/amd64"]

    @patch("argus.container_runtime.subprocess.run")
    def test_unreadable_manifest_returns_empty(self, mock_run, monkeypatch):
        """No information is not the same as no platforms."""
        _only_docker(monkeypatch)
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="denied")
        assert cr.detect_image_platforms("private/app:1") == []

    @patch("argus.container_runtime.subprocess.run")
    def test_non_mapping_entries_are_skipped(self, mock_run, monkeypatch):
        """A malformed manifest must not crash the pull path.

        detect_image_platforms runs on the failure path of a pull, so an
        exception here would replace a useful "pull failed" diagnostic with
        a traceback.
        """
        _only_docker(monkeypatch)
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps([
                "not-a-mapping",
                {"Descriptor": {"platform": {"os": "linux", "architecture": "arm64"}}},
            ]),
            stderr="",
        )
        assert cr.detect_image_platforms("app:1") == ["linux/arm64"]

    @patch("argus.container_runtime.subprocess.run")
    def test_entries_missing_os_or_arch_are_skipped(self, mock_run, monkeypatch):
        """Half a platform is not a pullable target."""
        _only_docker(monkeypatch)
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps([
                {"Descriptor": {"platform": {"os": "linux"}}},
                {"Descriptor": {"platform": {"architecture": "arm64"}}},
                {"Descriptor": {}},
                {"Descriptor": {"platform": {"os": "linux", "architecture": "s390x"}}},
            ]),
            stderr="",
        )
        assert cr.detect_image_platforms("app:1") == ["linux/s390x"]

    @patch("argus.container_runtime.subprocess.run")
    def test_unparsable_manifest_returns_empty(self, mock_run, monkeypatch):
        _only_docker(monkeypatch)
        mock_run.return_value = MagicMock(returncode=0, stdout="not json", stderr="")
        assert cr.detect_image_platforms("app:1") == []
