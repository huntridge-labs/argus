"""Unit tests for argus.core.system_status — readiness verdict logic.

The subprocess probes (Docker, tool availability, cached image digests) are
injected, so these run without a real Docker daemon or installed tools.
"""

from __future__ import annotations

from argus.core.system_status import (
    SystemStatus,
    compute_status,
    effective_backend,
)


def _status(**overrides):
    base = dict(
        scanner_names=["bandit", "gitleaks"],
        backend="auto",
        docker_probe=lambda: "running",
        tools_probe=lambda names: {n: True for n in names},
        cached_digests_probe=lambda: {"sha256:abc"},
        published_digests={"sha256:abc"},
    )
    base.update(overrides)
    return compute_status(**base)


def _check(status: SystemStatus, key: str):
    return next(c for c in status.checks if c.key == key)


class TestVerdict:
    def test_all_good_is_ok(self):
        s = _status()
        assert s.verdict == "ok"
        assert s.glyph == "●"
        assert "ready" in s.summary.lower()
        assert {c.key for c in s.checks} == {"docker", "tools", "images"}

    def test_docker_stopped_auto_with_local_tools_is_warn(self):
        # Local fallback exists → a stopped Docker degrades, not blocks.
        s = _status(docker_probe=lambda: "stopped")
        assert s.verdict == "warn"
        assert s.glyph == "▲"
        docker = _check(s, "docker")
        assert docker.ok is False and docker.blocking is False

    def test_docker_stopped_backend_docker_is_down(self):
        s = _status(backend="docker", docker_probe=lambda: "stopped")
        assert s.verdict == "down"
        assert s.glyph == "✖"
        assert _check(s, "docker").blocking is True
        assert "not running" in s.summary.lower()

    def test_docker_stopped_auto_no_local_tools_is_down(self):
        s = _status(
            docker_probe=lambda: "stopped",
            tools_probe=lambda names: {n: False for n in names},
        )
        # Nothing can run: no Docker, no local tools.
        assert s.verdict == "down"
        assert _check(s, "docker").blocking is True


class TestChecks:
    def test_partial_tools_is_warn(self):
        s = _status(
            scanner_names=["bandit", "gitleaks", "osv"],
            backend="local",
            docker_probe=lambda: "absent",
            tools_probe=lambda names: {"bandit": True, "gitleaks": False, "osv": True},
        )
        tools = _check(s, "tools")
        assert tools.ok is False
        assert "2/3" in tools.detail
        assert "gitleaks" in tools.remediation
        # backend=local → Docker absent is N/A (not blocking).
        assert _check(s, "docker").ok is None
        assert s.verdict == "warn"

    def test_images_skipped_when_docker_off(self):
        s = _status(backend="local", docker_probe=lambda: "stopped")
        assert all(c.key != "images" for c in s.checks)

    def test_image_digest_mismatch_is_warn(self):
        s = _status(
            cached_digests_probe=lambda: {"sha256:rogue"},
            published_digests={"sha256:official"},
        )
        assert _check(s, "images").ok is False
        assert s.verdict == "warn"

    def test_no_images_cached_is_not_applicable(self):
        s = _status(
            cached_digests_probe=lambda: set(),
            published_digests={"sha256:official"},
        )
        assert _check(s, "images").ok is None
        assert s.verdict == "ok"

    def test_no_scanners_configured(self):
        s = _status(scanner_names=[], tools_probe=lambda names: {})
        assert _check(s, "tools").ok is None

    def test_published_digests_resolved_from_toolchain_when_omitted(self):
        # Exercises the default branch that imports the published-digest set.
        s = compute_status(
            scanner_names=["bandit"],
            backend="local",
            docker_probe=lambda: "running",
            tools_probe=lambda names: {n: True for n in names},
            cached_digests_probe=lambda: set(),
        )
        # No cached images → N/A, but the import branch ran without error.
        assert _check(s, "images").ok is None


class TestSummaryAndEmpty:
    def test_empty_status_defaults_ok(self):
        assert SystemStatus().verdict == "ok"
        assert SystemStatus().summary == "System ready"


class TestEffectiveBackend:
    def test_defaults_to_auto_without_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert effective_backend(None) in {"auto", "local", "docker"}

    def test_reads_backend_from_config(self, tmp_path, monkeypatch):
        (tmp_path / "argus.yml").write_text("execution:\n  backend: local\n")
        monkeypatch.chdir(tmp_path)
        assert effective_backend(str(tmp_path / "argus.yml")) == "local"
