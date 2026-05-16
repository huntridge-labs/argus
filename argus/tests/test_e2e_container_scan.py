"""E2E tests for `argus scan container` with Docker fallback.

These tests require a running Docker daemon and network access to pull
images. They verify the full code path: CLI → container engine →
Docker pull → trivy/grype run → findings parsed → results reported.

Skipped automatically when Docker is not available.
Run explicitly with: pytest argus/tests/test_e2e_container_scan.py -v --no-cov

These tests are slow (pull images, download DBs) — tagged @pytest.mark.slow.
"""

import shutil
import subprocess

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


class TestContainerScanDockerFallback:
    """Verify that `argus scan container` uses Docker when local tools are missing."""

    def test_trivy_image_resolves(self):
        """The pinned trivy image must exist on the registry."""
        from argus.containers import OFFICIAL_IMAGES
        image = OFFICIAL_IMAGES["trivy"]
        result = subprocess.run(
            ["docker", "manifest", "inspect", image],
            capture_output=True, timeout=30,
        )
        assert result.returncode == 0, f"trivy image not found: {image}"

    def test_grype_image_resolves(self):
        """The pinned grype image must exist on the registry."""
        from argus.containers import OFFICIAL_IMAGES
        image = OFFICIAL_IMAGES["grype"]
        result = subprocess.run(
            ["docker", "manifest", "inspect", image],
            capture_output=True, timeout=30,
        )
        assert result.returncode == 0, f"grype image not found: {image}"

    def test_container_scan_via_docker_produces_findings(self):
        """Scan a known-vulnerable image via Docker — must find CVEs.

        Uses python:3.9-slim which has known OS-level CVEs. Trivy and
        grype should both find vulnerabilities when run via their
        container images (no local install required).

        This is the test that would have caught Bugs 2-6:
        - Bug 2: no Docker fallback → 0 findings
        - Bug 3: DB download corrupts output → parse failure
        - Bug 4: wrong image tag → pull failure
        - Bug 5: no docker.sock → "unable to initialize"
        - Bug 6: scanner failure → silent 0 findings
        """
        from argus.container.scanner import scan_image, ContainerScanResult
        from argus.container.discovery import ContainerTarget

        target = ContainerTarget(
            name="e2e-test-vuln",
            image_ref="python:3.9-slim",
        )

        result = scan_image(target, scanners=("trivy",))

        assert isinstance(result, ContainerScanResult)

        # If there are scanner errors, the test should fail with details
        if result.scanner_errors:
            pytest.fail(
                f"Scanner errors: {result.scanner_errors}. "
                "This means the Docker fallback path is broken."
            )

        # python:3.9-slim has known CVEs — we should find some
        assert result.total_count > 0, (
            f"Expected findings for python:3.9-slim but got {result.total_count}. "
            f"Trivy findings: {len(result.trivy_findings)}"
        )

    def test_scanner_errors_surfaced_not_swallowed(self):
        """Scanning a nonexistent image should produce scanner_errors, not 0 findings."""
        from argus.container.scanner import scan_image
        from argus.container.discovery import ContainerTarget

        target = ContainerTarget(
            name="e2e-test-bad",
            image_ref="nonexistent-image-that-does-not-exist:v999",
        )

        result = scan_image(target, scanners=("trivy",))

        # Must have errors, not silent 0 findings
        assert result.scanner_errors or result.total_count == 0, (
            "Nonexistent image should produce scanner_errors"
        )
        # Should NOT report "0 findings" as if the scan succeeded
        if not result.scanner_errors and result.total_count == 0:
            pytest.fail(
                "Scanning a nonexistent image reported 0 findings with no errors. "
                "This is the false-green bug."
            )
