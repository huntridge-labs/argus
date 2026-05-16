"""Inspect container images for exposed ports, entrypoint, and env."""

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger("argus.dast")


@dataclass
class ImageInfo:
    """Metadata extracted from a container image."""

    image_ref: str
    exposed_ports: list[int] = field(default_factory=list)
    entrypoint: list[str] = field(default_factory=list)
    cmd: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)


def inspect_image(image_ref: str) -> ImageInfo:
    """Extract ports, entrypoint, cmd, and env from a container image.

    Uses ``docker inspect``. If the image is not available locally,
    pulls it first. Raises ``RuntimeError`` when Docker is missing
    or the image cannot be inspected.
    """
    _require_docker()
    _ensure_image_local(image_ref)

    raw = _docker_inspect(image_ref)
    config = raw.get("Config", {})

    return ImageInfo(
        image_ref=image_ref,
        exposed_ports=_parse_ports(config.get("ExposedPorts")),
        entrypoint=_parse_string_list(config.get("Entrypoint")),
        cmd=_parse_string_list(config.get("Cmd")),
        env=_parse_env(config.get("Env")),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _require_docker() -> None:
    """Raise if Docker CLI is not on PATH."""
    if shutil.which("docker") is None:
        raise RuntimeError(
            "Docker is not installed or not on PATH. "
            "DAST scanning requires Docker to run target containers."
        )


def _ensure_image_local(image_ref: str) -> None:
    """Pull the image if it is not already available locally."""
    check = subprocess.run(
        ["docker", "image", "inspect", image_ref],
        capture_output=True,
        timeout=10,
    )
    if check.returncode == 0:
        logger.debug("Image already local: %s", image_ref)
        return

    logger.info("Pulling image: %s", image_ref)
    pull = subprocess.run(
        ["docker", "pull", image_ref],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if pull.returncode != 0:
        raise RuntimeError(
            f"Failed to pull image {image_ref}: "
            f"{pull.stderr.strip()[:500]}"
        )
    logger.info("Pulled image: %s", image_ref)


def _docker_inspect(image_ref: str) -> dict:
    """Run ``docker inspect`` and return the first result object."""
    result = subprocess.run(
        ["docker", "inspect", image_ref],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"docker inspect failed for {image_ref}: "
            f"{result.stderr.strip()[:500]}"
        )

    data = json.loads(result.stdout)
    if not data:
        raise RuntimeError(f"docker inspect returned empty result for {image_ref}")

    return data[0]


def _parse_ports(exposed_ports: dict | None) -> list[int]:
    """Parse ExposedPorts like ``{"80/tcp": {}, "443/tcp": {}}`` to ``[80, 443]``.

    Returns a sorted list of unique port numbers.
    """
    if not exposed_ports:
        return []

    ports: list[int] = []
    for key in exposed_ports:
        # Keys are "80/tcp", "8080/udp", etc.
        port_str = key.split("/")[0]
        try:
            ports.append(int(port_str))
        except ValueError:
            logger.warning("Could not parse exposed port: %s", key)

    return sorted(set(ports))


def _parse_string_list(value: list | None) -> list[str]:
    """Normalize entrypoint/cmd to a list of strings."""
    if value is None:
        return []
    return list(value)


def _parse_env(env_list: list[str] | None) -> dict[str, str]:
    """Parse ``["KEY=value", ...]`` into a dict.

    Handles values that contain ``=`` signs correctly.
    """
    if not env_list:
        return {}

    result: dict[str, str] = {}
    for entry in env_list:
        key, _, value = entry.partition("=")
        result[key] = value

    return result
