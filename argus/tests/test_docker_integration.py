"""Integration tests for Docker execution paths.

These tests require a running Docker daemon. They are skipped automatically
when Docker is not available (CI without Docker, local dev without Docker).

Run explicitly with: pytest argus/tests/test_docker_integration.py -v
"""

import shutil
import subprocess
import sys

import pytest

# Skip entire module if Docker is not available
pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None,
    reason="Docker not available",
)


def _docker_running() -> bool:
    """Check if Docker daemon is actually responding."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


@pytest.fixture(autouse=True)
def _require_docker_daemon():
    """Skip tests if Docker daemon is not responding."""
    if not _docker_running():
        pytest.skip("Docker daemon not responding")


# Substrings that identify a registry or network failure rather than a defect
# in Argus. Anonymous Docker Hub pulls on shared CI runners time out and
# rate-limit often enough to red-line the release pipeline; a registry outage
# is not a regression we should block a release on. Anything else still fails.
_TRANSIENT_REGISTRY_ERRORS = (
    "context deadline exceeded",
    "client.timeout exceeded while awaiting headers",
    "net/http: request canceled",
    "i/o timeout",
    "tls handshake timeout",
    "temporary failure in name resolution",
    "no such host",
    "connection refused",
    "connection reset by peer",
    "toomanyrequests",
    "429 too many requests",
    "503 service unavailable",
)


def _skip_if_registry_unavailable(result: subprocess.CompletedProcess) -> None:
    """Turn a transient registry failure into a skip, leaving real ones fatal.

    Call this on a completed ``docker`` invocation before asserting on it.
    A zero exit returns immediately; a non-zero exit whose stderr matches no
    known transient marker returns too, so the caller's assertion still fires.
    """
    if result.returncode == 0:
        return

    stderr = (result.stderr or "").lower()
    for marker in _TRANSIENT_REGISTRY_ERRORS:
        if marker in stderr:
            first_line = (result.stderr or "").strip().splitlines()[0]
            pytest.skip(f"registry unavailable: {first_line[:200]}")


def _pull(image: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """Pull ``image``, skipping the test when the registry is unreachable."""
    result = subprocess.run(
        ["docker", "pull", image],
        capture_output=True, text=True, timeout=timeout,
    )
    _skip_if_registry_unavailable(result)
    return result


class TestTransientRegistryClassifier:
    """Lock the skip/fail boundary — a broken registry must not read as a bug,
    and a broken Argus must not hide behind a skip."""

    def _proc(self, returncode: int, stderr: str) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=["docker", "pull", "x"], returncode=returncode,
            stdout="", stderr=stderr,
        )

    def test_success_is_not_skipped(self):
        _skip_if_registry_unavailable(self._proc(0, ""))

    @pytest.mark.parametrize("stderr", [
        'Error response from daemon: Get "https://registry-1.docker.io/v2/": '
        "context deadline exceeded",
        "net/http: request canceled while waiting for connection "
        "(Client.Timeout exceeded while awaiting headers)",
        "toomanyrequests: You have reached your pull rate limit",
        "dial tcp: lookup registry-1.docker.io: no such host",
    ])
    def test_transient_registry_errors_skip(self, stderr):
        # pytest.skip raises Skipped, which derives from BaseException — catch
        # it by its real type or the skip escapes and the test self-skips
        # instead of asserting anything.
        with pytest.raises(pytest.skip.Exception, match="registry unavailable"):
            _skip_if_registry_unavailable(self._proc(1, stderr))

    @pytest.mark.parametrize("stderr", [
        "manifest unknown: manifest unknown",
        "docker: invalid reference format",
        "unauthorized: authentication required",
        "",
    ])
    def test_real_failures_fall_through_to_the_assertion(self, stderr):
        _skip_if_registry_unavailable(self._proc(1, stderr))


class TestDockerPull:
    """Test real Docker image pulls."""

    def test_pull_small_image(self):
        """Pull a tiny image to verify Docker execution works."""
        result = _pull("hello-world")
        assert result.returncode == 0

    def test_pull_nonexistent_image_fails(self):
        result = subprocess.run(
            ["docker", "pull", "nonexistent/image:doesnotexist"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode != 0


class TestDockerRun:
    """Test running containers for scanning."""

    def test_run_hello_world(self):
        result = subprocess.run(
            ["docker", "run", "--rm", "hello-world"],
            capture_output=True, text=True, timeout=30,
        )
        _skip_if_registry_unavailable(result)
        assert result.returncode == 0
        assert "Hello from Docker" in result.stdout

    def test_run_with_volume_mount(self, tmp_path):
        """Verify volume mounts work (critical for scanner execution)."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("argus-test-content")

        result = subprocess.run(
            ["docker", "run", "--rm",
             "-v", f"{tmp_path}:/workspace:ro",
             "alpine:3.19", "cat", "/workspace/test.txt"],
            capture_output=True, text=True, timeout=30,
        )
        _skip_if_registry_unavailable(result)
        assert result.returncode == 0
        assert "argus-test-content" in result.stdout

    def test_run_with_output_volume(self, tmp_path):
        """Verify output volume writes work (scanner results)."""
        result = subprocess.run(
            ["docker", "run", "--rm",
             "-v", f"{tmp_path}:/output",
             "alpine:3.19", "sh", "-c", "echo 'scan-result' > /output/results.txt"],
            capture_output=True, text=True, timeout=30,
        )
        _skip_if_registry_unavailable(result)
        assert result.returncode == 0
        assert (tmp_path / "results.txt").exists()
        assert "scan-result" in (tmp_path / "results.txt").read_text()


class TestEngineDockerExecution:
    """Test the ArgusEngine Docker execution path end-to-end."""

    def test_engine_pull_and_inspect(self):
        """Test _pull_image and _get_image_digest with a real image."""
        from argus.core.config import ArgusConfig
        from argus.core.engine import ArgusEngine

        engine = ArgusEngine(ArgusConfig.from_dict({
            "execution": {"pull_policy": "if-not-present"},
        }))

        # Preflight the same pull through docker directly so an unreachable
        # registry skips here instead of surfacing as `_pull_image` == False,
        # which is indistinguishable from a real engine defect.
        _pull("alpine:3.19")

        pulled = engine._pull_image("alpine:3.19")
        assert pulled is True

        # Get its digest
        digest = engine._get_image_digest("alpine:3.19")
        assert digest != "unknown"
        assert "sha256:" in digest

    def test_engine_pull_policy_never(self):
        """Test pull_policy=never with a likely-missing image."""
        from argus.core.config import ArgusConfig
        from argus.core.engine import ArgusEngine

        engine = ArgusEngine(ArgusConfig.from_dict({
            "execution": {"pull_policy": "never"},
        }))

        # This obscure image shouldn't exist locally
        found = engine._pull_image("argus-nonexistent-test-image:never")
        assert found is False


class TestArgusE2EScan:
    """End-to-end test running argus scan with Docker backend."""

    def test_argus_scan_gitleaks_docker(self, tmp_path):
        """Run argus scan gitleaks using Docker container (public image)."""
        # Create a file to scan
        test_file = tmp_path / "config.py"
        test_file.write_text("DATABASE_URL = 'postgresql://user:pass@localhost/db'\n")

        # Init a git repo (gitleaks requires it)
        subprocess.run(["git", "init", str(tmp_path)], capture_output=True)
        subprocess.run(
            ["git", "-C", str(tmp_path), "add", "."],
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(tmp_path), "commit", "-m", "init",
             "--author", "test <test@test.com>"],
            capture_output=True,
            env={**__import__("os").environ, "GIT_COMMITTER_NAME": "test",
                 "GIT_COMMITTER_EMAIL": "test@test.com"},
        )

        result = subprocess.run(
            [sys.executable, "-m", "argus", "scan", "gitleaks",
             "--path", str(tmp_path),
             "--format", "json",
             "--output-dir", str(tmp_path / "results"),
             "--no-timestamp",
             "--severity-threshold", "none"],
            capture_output=True, text=True, timeout=120,
        )

        # Should complete — gitleaks uses a public Docker Hub image
        assert result.returncode in (0, 1), (
            f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"
        )
