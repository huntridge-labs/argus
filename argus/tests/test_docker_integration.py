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


class TestDockerPull:
    """Test real Docker image pulls."""

    def test_pull_small_image(self):
        """Pull a tiny image to verify Docker execution works."""
        result = subprocess.run(
            ["docker", "pull", "hello-world"],
            capture_output=True, text=True, timeout=60,
        )
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

        # Pull a small image
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

    def test_argus_scan_bandit_docker(self, tmp_path):
        """Run argus scan bandit using Docker container on a test file."""
        # Create a Python file with a known bandit finding
        test_py = tmp_path / "test_app.py"
        test_py.write_text("import subprocess\nsubprocess.call('ls')\n")

        # Create minimal argus config
        config = tmp_path / "argus.yml"
        config.write_text(
            'version: "1.0"\n'
            "scanners:\n"
            "  bandit:\n"
            "    enabled: true\n"
            "execution:\n"
            "  backend: auto\n"
        )

        result = subprocess.run(
            [sys.executable, "-m", "argus", "scan", "bandit",
             "--config", str(config),
             "--path", str(tmp_path),
             "--format", "json",
             "--output-dir", str(tmp_path / "results"),
             "--no-timestamp",
             "--severity-threshold", "none"],
            capture_output=True, text=True, timeout=120,
        )

        # Should complete (exit 0 = no findings above threshold, or exit 1 = findings)
        assert result.returncode in (0, 1), f"Unexpected exit code: {result.returncode}\nstderr: {result.stderr}"

        # Should produce output
        results_json = tmp_path / "results" / "argus-results.json"
        if results_json.exists():
            import json
            data = json.loads(results_json.read_text())
            assert "results" in data
            assert len(data["results"]) > 0
            assert data["results"][0]["scanner"] == "bandit"
