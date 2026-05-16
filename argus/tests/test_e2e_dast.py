"""E2E tests for `argus scan zap` with Docker fallback.

These tests require a running Docker daemon and verify the full DAST
code path: CLI → DastEngine → ZAP container pull → scan → parse.

Skipped automatically when Docker is not available.
Run explicitly with: pytest argus/tests/test_e2e_dast.py -v --no-cov

These tests are slow (pull ZAP image ~1GB) — tagged @pytest.mark.slow.
"""

import http.server
import shutil
import subprocess
import threading
import time

import pytest

pytestmark = [
    pytest.mark.skipif(
        shutil.which("docker") is None,
        reason="Docker not available",
    ),
    pytest.mark.slow,
]


def _docker_running() -> bool:
    try:
        result = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


@pytest.fixture(autouse=True)
def _require_docker_daemon():
    if not _docker_running():
        pytest.skip("Docker daemon not responding")


class _SilentHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler that doesn't log to stderr."""
    def log_message(self, format, *args):
        pass


@pytest.fixture
def http_server():
    """Start a simple HTTP server on a random port, return (host, port)."""
    server = http.server.HTTPServer(("0.0.0.0", 0), _SilentHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield ("127.0.0.1", port)
    server.shutdown()


class TestZapImageResolution:
    """Verify the pinned ZAP image exists."""

    def test_zap_image_resolves(self):
        from argus.containers import OFFICIAL_IMAGES
        image = OFFICIAL_IMAGES["zap"]
        result = subprocess.run(
            ["docker", "manifest", "inspect", image],
            capture_output=True, timeout=30,
        )
        assert result.returncode == 0, f"ZAP image not found: {image}"


class TestZapPrePull:
    """Verify the DAST engine pre-pulls ZAP image (Bug 1 regression test)."""

    def test_zap_pull_succeeds(self):
        """ZAP image can be pulled without error."""
        from argus import container_runtime
        from argus.containers import get_image

        image = get_image("zap")
        assert container_runtime.pull_image(image), (
            f"Failed to pull ZAP image: {image}"
        )


class TestDastScanURL:
    """E2E test of ZAP scanning a live HTTP target.

    This test pulls the ZAP image (~1GB) and runs a baseline scan
    against a local HTTP server. It's slow but catches the exact
    class of bugs we hit in production (Bugs 1, 3).
    """

    def test_zap_scan_url_produces_output(self, http_server):
        """ZAP scan against a live HTTP server should produce a result.

        We don't assert specific findings — a simple HTTP server may
        or may not trigger ZAP alerts. The test verifies:
        1. ZAP image is pre-pulled (no stdout corruption)
        2. ZAP container starts and connects to the target
        3. The scan completes without RuntimeError
        4. Results are parseable (even if 0 findings)
        """
        from argus.dast.engine import DastEngine

        host, port = http_server
        engine = DastEngine({
            "scan_type": "baseline",
            "startup_timeout": 30,
            "targets": [{"url": f"http://host.docker.internal:{port}"}],
        })

        summary = engine.run()

        assert summary.target_count == 1
        result = summary.results[0]

        # The scan should complete — no RuntimeError from missing pull
        assert result.scan_error == "" or result.healthy, (
            f"ZAP scan error: {result.scan_error}. "
            "This may indicate a pre-pull or docker.sock issue."
        )
