"""Shared container runtime helpers for Docker/Podman/nerdctl.

Provides pull, inspect, and runtime detection that can be used by
both the engine and individual scanners (DAST, container scanner)
without duplicating logic.
"""

import logging
import os
import shutil
import subprocess
import time

logger = logging.getLogger("argus")

# Cache runtime detection across calls within a process
_cached_runtime: str | None = None


def detect_runtime() -> str | None:
    """Detect the available container runtime.

    Checks: ARGUS_CONTAINER_RUNTIME env var → docker → podman → nerdctl.
    Returns None if no runtime is found.  Result is cached for the process.
    """
    global _cached_runtime
    if _cached_runtime is not None:
        return _cached_runtime if _cached_runtime else None

    override = os.environ.get("ARGUS_CONTAINER_RUNTIME")
    if override and shutil.which(override):
        _cached_runtime = override
        return override

    for rt in ("docker", "podman", "nerdctl"):
        if shutil.which(rt):
            _cached_runtime = rt
            return rt

    _cached_runtime = ""  # negative cache
    return None


def runtime_cmd() -> str:
    """Return the runtime command name, defaulting to 'docker'."""
    return detect_runtime() or "docker"


def is_available() -> bool:
    """Check if any container runtime is available."""
    return detect_runtime() is not None


def pull_image(image: str, policy: str = "if-not-present") -> bool:
    """Pull a container image respecting the given pull policy.

    Args:
        image: full image reference (e.g. 'aquasec/trivy:0.69.3')
        policy: 'always', 'if-not-present', or 'never'

    Returns True if the image is available after this call.
    """
    rt = runtime_cmd()

    if policy == "never":
        result = subprocess.run(
            [rt, "image", "inspect", image], capture_output=True,
        )
        if result.returncode != 0:
            logger.warning("Image '%s' not found locally and pull_policy=never", image)
        return result.returncode == 0

    if policy == "if-not-present":
        result = subprocess.run(
            [rt, "image", "inspect", image], capture_output=True,
        )
        if result.returncode == 0:
            logger.debug("Image '%s' found locally — skipping pull", image)
            return True
        logger.debug("Image '%s' not found locally — pulling", image)

    logger.info("Pulling container image: %s (this may take a moment)", image)
    start = time.monotonic()
    result = subprocess.run(
        [rt, "pull", image], capture_output=True, text=True,
    )
    elapsed = int((time.monotonic() - start) * 1000)

    if result.returncode != 0:
        logger.info(
            "Native pull failed for %s (%dms), retrying with --platform linux/amd64",
            image, elapsed,
        )
        start = time.monotonic()
        result = subprocess.run(
            [rt, "pull", "--platform", "linux/amd64", image],
            capture_output=True, text=True,
        )
        elapsed = int((time.monotonic() - start) * 1000)

    if result.returncode == 0:
        logger.info("Pulled %s in %dms", image, elapsed)
    else:
        logger.error(
            "Failed to pull %s after %dms: %s",
            image, elapsed, result.stderr.strip()[:300],
        )
    return result.returncode == 0


def run_container(
    image: str,
    args: list[str],
    volumes: dict[str, str] | None = None,
    network: str | None = None,
    entrypoint: str | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess:
    """Run a container with the detected runtime.

    Args:
        image: container image to run
        args: command args passed to the container
        volumes: host_path → container_path mappings
        network: Docker network name to attach to
        entrypoint: override the container entrypoint
        timeout: subprocess timeout in seconds

    Returns the CompletedProcess result.
    """
    rt = runtime_cmd()
    cmd = [rt, "run", "--rm"]

    if network:
        cmd.extend(["--network", network])

    for host_path, container_path in (volumes or {}).items():
        cmd.extend(["-v", f"{host_path}:{container_path}"])

    if entrypoint:
        cmd.extend(["--entrypoint", entrypoint])

    cmd.append(image)
    cmd.extend(args)

    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
    )
