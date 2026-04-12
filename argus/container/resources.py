"""Resource management for container scanning.

Cleans up images and temp files between scans to keep disk usage
bounded on constrained environments (CI runners, local machines).

No hard disk limits — we try the scan and handle failures gracefully
rather than refusing to run based on arbitrary thresholds.
"""

import logging
import shutil
import subprocess

logger = logging.getLogger("argus.container")

# Warning threshold — purely informational, never blocks a scan.
WARN_DISK_BYTES = 2 * 1024 * 1024 * 1024


def check_disk_space(path: str = "/") -> int:
    """Check available disk space. Returns free bytes.

    Logs a warning if space is low. Never blocks — just informs.
    """
    try:
        usage = shutil.disk_usage(path)
        free = usage.free
        if free < WARN_DISK_BYTES:
            logger.warning(
                "Low disk space: %.1f GB free",
                free / (1024 ** 3),
            )
        return free
    except OSError:
        return 0


def remove_docker_image(image_ref: str) -> bool:
    """Remove a Docker image to free disk space.

    Returns True if the image was removed or didn't exist.
    """
    if shutil.which("docker") is None:
        return True

    try:
        result = subprocess.run(
            ["docker", "rmi", "--force", image_ref],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            logger.debug("Removed image: %s", image_ref)
            return True
        # Image might not exist — that's fine
        if "No such image" in result.stderr:
            return True
        logger.warning(
            "Failed to remove image %s: %s",
            image_ref,
            result.stderr.strip(),
        )
        return False
    except subprocess.TimeoutExpired:
        logger.warning("Timeout removing image: %s", image_ref)
        return False
    except Exception:
        logger.debug("Could not remove image %s", image_ref, exc_info=True)
        return False


def prune_docker_build_cache() -> None:
    """Remove Docker build cache to free disk space.

    Only called when disk is critically low. Non-destructive to
    running containers or tagged images.
    """
    if shutil.which("docker") is None:
        return

    try:
        result = subprocess.run(
            ["docker", "builder", "prune", "--force", "--filter", "until=1h"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0 and result.stdout.strip():
            logger.info("Pruned Docker build cache: %s", result.stdout.strip())
    except (subprocess.TimeoutExpired, Exception):
        logger.debug("Build cache prune failed", exc_info=True)


def prune_dangling_images() -> None:
    """Remove dangling (untagged) Docker images."""
    if shutil.which("docker") is None:
        return

    try:
        result = subprocess.run(
            ["docker", "image", "prune", "--force"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0 and result.stdout.strip():
            logger.debug("Pruned dangling images: %s", result.stdout.strip())
    except (subprocess.TimeoutExpired, Exception):
        logger.debug("Dangling image prune failed", exc_info=True)


def estimate_image_size(image_ref: str) -> int:
    """Estimate the size of a Docker image in bytes.

    Returns 0 if the image isn't local or can't be inspected.
    """
    if shutil.which("docker") is None:
        return 0

    try:
        result = subprocess.run(
            ["docker", "image", "inspect", image_ref,
             "--format", "{{.Size}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return int(result.stdout.strip())
    except (subprocess.TimeoutExpired, ValueError, Exception):
        pass
    return 0
