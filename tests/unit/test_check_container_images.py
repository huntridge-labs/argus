"""Tests for ``scripts/ci/check_container_images.py``.

Regression lock for a conflation that red-lined ``main``: the check treated
"the registry did not answer" identically to "this pin is wrong". Anonymous
Docker Hub pulls rate-limit routinely on shared runners, so a green-to-red
flip could carry no information about the pins at all.

The split has to hold in both directions. A rate limit must not fail PR CI,
and a genuinely bad pin must still fail even when registry errors are
tolerated — otherwise the flag becomes a way to ship a broken pin.
"""

from __future__ import annotations

import subprocess

import pytest

from scripts.ci import check_container_images as cci


def _proc(returncode: int, stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["docker", "manifest", "inspect", "x"],
        returncode=returncode,
        stdout="",
        stderr=stderr,
    )


class TestIsTransient:
    @pytest.mark.parametrize("stderr", [
        "toomanyrequests: You have reached your unauthenticated pull rate limit.",
        'Get "https://registry-1.docker.io/v2/": context deadline exceeded',
        "net/http: request canceled while waiting for connection",
        "dial tcp: lookup registry-1.docker.io: no such host",
        "received unexpected HTTP status: 503 Service Unavailable",
        "TLS handshake timeout",
    ])
    def test_registry_noise_is_transient(self, stderr):
        assert cci.is_transient(stderr) is True

    @pytest.mark.parametrize("stderr", [
        "manifest unknown: manifest unknown",
        "errors:\ndenied: requested access to the resource is denied",
        "unauthorized: authentication required",
        "invalid reference format",
        "no such manifest: aquasec/trivy:9.9.9",
    ])
    def test_real_pin_problems_are_not_transient(self, stderr):
        assert cci.is_transient(stderr) is False


class TestRetry:
    def test_retries_once_on_transient_then_succeeds(self, monkeypatch):
        calls = []

        def fake_inspect(image):
            calls.append(image)
            if len(calls) == 1:
                return _proc(1, "toomanyrequests: rate limit")
            return _proc(0)

        monkeypatch.setattr(cci, "inspect", fake_inspect)
        monkeypatch.setattr(cci.time, "sleep", lambda _s: None)

        result = cci.inspect_with_retry("img")

        assert result.returncode == 0
        assert len(calls) == 2

    def test_does_not_retry_a_real_failure(self, monkeypatch):
        calls = []

        def fake_inspect(image):
            calls.append(image)
            return _proc(1, "manifest unknown")

        monkeypatch.setattr(cci, "inspect", fake_inspect)
        monkeypatch.setattr(cci.time, "sleep", lambda _s: None)

        cci.inspect_with_retry("img")

        assert len(calls) == 1, "a bad pin should not be retried"


class TestExitCodes:
    @pytest.fixture(autouse=True)
    def _stub_environment(self, monkeypatch):
        monkeypatch.setattr(cci.shutil, "which", lambda _cmd: "/usr/bin/docker")
        monkeypatch.setattr(cci.time, "sleep", lambda _s: None)
        import argus.containers as containers

        monkeypatch.setattr(containers, "OFFICIAL_IMAGES", {"trivy": "aquasec/trivy:1.0.0"})
        monkeypatch.setattr(containers, "CUSTOM_IMAGES", {})

    def test_all_resolve_passes(self, monkeypatch):
        monkeypatch.setattr(cci, "inspect", lambda image: _proc(0))
        assert cci.main([]) == 0

    def test_bad_pin_fails_even_when_tolerating(self, monkeypatch):
        monkeypatch.setattr(cci, "inspect", lambda image: _proc(1, "manifest unknown"))
        assert cci.main(["--tolerate-registry-errors"]) == 1

    def test_rate_limit_fails_by_default(self, monkeypatch):
        """The release gate must not publish unverified manifests."""
        monkeypatch.setattr(
            cci, "inspect", lambda image: _proc(1, "toomanyrequests: rate limit")
        )
        assert cci.main([]) == 1

    def test_rate_limit_tolerated_when_asked(self, monkeypatch):
        monkeypatch.setattr(
            cci, "inspect", lambda image: _proc(1, "toomanyrequests: rate limit")
        )
        assert cci.main(["--tolerate-registry-errors"]) == 0

    def test_missing_docker_is_skipped_not_failed(self, monkeypatch):
        monkeypatch.setattr(cci.shutil, "which", lambda _cmd: None)
        assert cci.main([]) == 2
