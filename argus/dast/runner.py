"""Manage the container lifecycle for DAST targets.

Handles starting containers on isolated Docker networks, probing for
health, and tearing everything down reliably — even on failures.
"""

import logging
import random
import shutil
import socket
import subprocess
import time
import urllib.request
from dataclasses import dataclass

from .inspect import inspect_image

logger = logging.getLogger("argus.dast")

# Port range for random host port selection when port 0 binding fails
_PORT_RANGE_MIN = 30000
_PORT_RANGE_MAX = 40000

# If the container exits within this many seconds, treat it as a crash
_CRASH_DETECT_SECONDS = 3


@dataclass
class DastTarget:
    """A running container target for DAST scanning."""

    name: str
    image_ref: str
    container_id: str = ""
    network_name: str = ""
    host: str = "localhost"
    port: int = 0
    url: str = ""
    healthy: bool = False


def start_target(
    image_ref: str,
    name: str = "",
    port: int | None = None,
    env: dict[str, str] | None = None,
    startup_timeout: int = 60,
) -> DastTarget:
    """Start a container and wait for it to become healthy.

    1. Inspect image for exposed ports (if *port* not specified)
    2. Create isolated Docker network ``argus-dast-{name}``
    3. Run container with port mapping
    4. Detect immediate crashes (exit within 3 seconds)
    5. Probe until healthy or *startup_timeout* exceeded
    6. Return :class:`DastTarget` with the reachable URL

    Raises :class:`RuntimeError` on Docker errors or if the
    container never becomes healthy.
    """
    _require_docker()

    if not name:
        name = _sanitize_name(image_ref)

    container_port = port
    if container_port is None:
        info = inspect_image(image_ref)
        if not info.exposed_ports:
            raise RuntimeError(
                f"Image {image_ref} has no exposed ports and no port "
                "was specified. Pass port= explicitly."
            )
        container_port = info.exposed_ports[0]
        logger.info(
            "Auto-detected exposed port %d for %s", container_port, image_ref,
        )

    network_name = f"argus-dast-{name}"
    container_name = f"argus-dast-{name}"
    target = DastTarget(
        name=name,
        image_ref=image_ref,
        network_name=network_name,
    )

    try:
        _create_network(network_name)
        host_port = _find_free_port()
        container_id = _run_container(
            image_ref=image_ref,
            container_name=container_name,
            network_name=network_name,
            host_port=host_port,
            container_port=container_port,
            env=env,
        )
        target.container_id = container_id
        target.port = host_port

        _detect_crash(container_id, container_name)

        logger.info(
            "Probing %s on localhost:%d (timeout %ds)",
            container_name, host_port, startup_timeout,
        )
        healthy = _probe_health("localhost", host_port, timeout=startup_timeout)
        target.healthy = healthy
        target.url = f"http://localhost:{host_port}/"

        if not healthy:
            _log_container_output(container_id, container_name)
            raise RuntimeError(
                f"Container {container_name} did not become healthy "
                f"within {startup_timeout}s on port {host_port}"
            )

        logger.info(
            "Target ready: %s at %s", container_name, target.url,
        )
        return target

    except Exception:
        # Cleanup on failure — stop_target is safe to call on partial state
        stop_target(target)
        raise


def stop_target(target: DastTarget) -> None:
    """Stop and remove the container and network.

    Always cleans up, even on errors. Idempotent — safe to call
    multiple times or on partially-started targets.
    """
    if target.container_id:
        _safe_docker("stop", target.container_id, timeout_flag="10")
        _safe_docker("rm", "--force", target.container_id)
        logger.debug("Stopped and removed container: %s", target.container_id)

    if target.network_name:
        _safe_docker("network", "rm", target.network_name)
        logger.debug("Removed network: %s", target.network_name)


def _probe_health(host: str, port: int, timeout: int = 60) -> bool:
    """Wait for an endpoint to become reachable.

    Tries TCP connect first (fast), then HTTP GET on success.
    Retries with exponential backoff up to *timeout* seconds.
    """
    deadline = time.monotonic() + timeout
    interval = 1.0

    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2):
                # TCP connected — try HTTP to confirm the app is ready
                try:
                    resp = urllib.request.urlopen(
                        f"http://{host}:{port}/", timeout=3,
                    )
                    if resp.status < 500:
                        return True
                except Exception:
                    # HTTP failed but TCP succeeded — some apps lack a /
                    # endpoint. TCP reachability is sufficient.
                    return True
        except (ConnectionRefusedError, OSError, socket.timeout):
            pass

        time.sleep(interval)
        interval = min(interval * 1.5, 5.0)

    return False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _require_docker() -> None:
    """Raise if Docker CLI is not on PATH."""
    if shutil.which("docker") is None:
        raise RuntimeError(
            "Docker is not installed or not on PATH. "
            "DAST scanning requires Docker."
        )


def _sanitize_name(image_ref: str) -> str:
    """Derive a safe container/network name from an image reference.

    Strips registry, tag, and replaces unsafe characters.
    """
    # Remove registry prefix (everything before last /)
    short = image_ref.rsplit("/", 1)[-1]
    # Remove tag/digest
    short = short.split(":")[0].split("@")[0]
    # Replace unsafe chars
    safe = "".join(c if c.isalnum() or c == "-" else "-" for c in short)
    return safe.strip("-") or "target"


def _create_network(network_name: str) -> None:
    """Create an isolated Docker network."""
    result = subprocess.run(
        ["docker", "network", "create", network_name],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        # Network might already exist from a previous incomplete run
        if "already exists" in result.stderr:
            logger.debug("Network already exists: %s", network_name)
            return
        raise RuntimeError(
            f"Failed to create Docker network {network_name}: "
            f"{result.stderr.strip()[:500]}"
        )
    logger.debug("Created network: %s", network_name)


def _find_free_port() -> int:
    """Find a free TCP port on the host.

    Binds to port 0 and reads the kernel-assigned port. Falls back
    to a random port in 30000-40000 on failure.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("", 0))
            return sock.getsockname()[1]
    except OSError:
        return random.randint(_PORT_RANGE_MIN, _PORT_RANGE_MAX)


def _run_container(
    image_ref: str,
    container_name: str,
    network_name: str,
    host_port: int,
    container_port: int,
    env: dict[str, str] | None = None,
) -> str:
    """Start a container in detached mode and return the container ID."""
    cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        "--network", network_name,
        "-p", f"{host_port}:{container_port}",
    ]

    for key, value in (env or {}).items():
        cmd.extend(["-e", f"{key}={value}"])

    cmd.append(image_ref)

    logger.info(
        "Starting container: %s (port %d -> %d)",
        container_name, host_port, container_port,
    )
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to start container {container_name}: "
            f"{result.stderr.strip()[:500]}"
        )

    container_id = result.stdout.strip()[:12]
    logger.debug("Container started: %s (%s)", container_name, container_id)
    return container_id


def _detect_crash(container_id: str, container_name: str) -> None:
    """Detect if the container exits immediately (crash loop).

    Waits a short time and checks if the container is still running.
    Raises ``RuntimeError`` with the container logs on crash.
    """
    time.sleep(_CRASH_DETECT_SECONDS)

    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", container_id],
        capture_output=True,
        text=True,
        timeout=10,
    )
    running = result.stdout.strip().lower() == "true"

    if not running:
        logs = _get_container_logs(container_id)
        raise RuntimeError(
            f"Container {container_name} exited within "
            f"{_CRASH_DETECT_SECONDS}s of starting (crash). "
            f"Logs:\n{logs}"
        )


def _get_container_logs(container_id: str, tail: int = 50) -> str:
    """Fetch the last N lines of container logs."""
    try:
        result = subprocess.run(
            ["docker", "logs", "--tail", str(tail), container_id],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr
        return output.strip()[:2000] or "(no logs)"
    except (subprocess.TimeoutExpired, Exception):
        return "(could not retrieve logs)"


def _log_container_output(container_id: str, container_name: str) -> None:
    """Log container output for debugging unhealthy containers."""
    logs = _get_container_logs(container_id)
    logger.warning(
        "Container %s did not become healthy. Logs:\n%s",
        container_name, logs,
    )


def _safe_docker(*args: str, timeout_flag: str = "") -> None:
    """Run a Docker command, swallowing all errors.

    Used for cleanup — must never raise.
    """
    cmd = ["docker"]
    if timeout_flag and args and args[0] == "stop":
        cmd.extend(["stop", "-t", timeout_flag])
        cmd.extend(args[1:])
    else:
        cmd.extend(args)

    try:
        subprocess.run(
            cmd,
            capture_output=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        logger.debug("Timeout running: docker %s", " ".join(args))
    except Exception:
        logger.debug("Failed running: docker %s", " ".join(args), exc_info=True)
