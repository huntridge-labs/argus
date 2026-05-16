"""Build container images from Dockerfiles."""

import logging
import subprocess

from .discovery import ContainerTarget

logger = logging.getLogger("argus.container")


def build_image(target: ContainerTarget) -> bool:
    """Build a container image from a Dockerfile.

    Returns True on success. If the target has no Dockerfile (pre-built
    image), returns True immediately.
    """
    if target.dockerfile is None:
        return True

    if not target.dockerfile.exists():
        logger.error(
            "Dockerfile not found: %s", target.dockerfile
        )
        return False

    context = target.context or target.dockerfile.parent
    cmd = [
        "docker", "build",
        "--tag", target.image_ref,
        "--file", str(target.dockerfile),
        str(context),
    ]

    logger.info("Building image %s from %s", target.image_ref, target.dockerfile)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        logger.error("Docker CLI not found — is Docker installed?")
        return False

    if result.returncode != 0:
        logger.error(
            "Docker build failed for %s (exit %d): %s",
            target.image_ref,
            result.returncode,
            result.stderr.strip(),
        )
        return False

    logger.info("Successfully built %s", target.image_ref)
    return True
