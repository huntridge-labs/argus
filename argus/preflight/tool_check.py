"""Pure-logic readiness checks for registered scanners.

Extracted from `argus validate --check-tools` so the same logic can drive
`argus init` (so users see what's runnable on this machine right after
generating a config) and end-of-scan nudges (so a user who just got an
empty scan knows *why* and where to look). Keep this module free of I/O
so callers own their own formatting.
"""

from __future__ import annotations

import shutil

from argus.preflight.report_body import ToolStatus


CONTAINER_RUNTIMES = ("docker", "podman", "nerdctl")


def container_runtime_available() -> bool:
    """True if docker, podman, or nerdctl is on PATH."""
    return any(shutil.which(r) for r in CONTAINER_RUNTIMES)


def resolve_image(image: str, registry: str) -> str:
    """Apply a registry override to an image reference."""
    if not registry or not image:
        return image
    parts = image.split("/", 1)
    if len(parts) == 2 and ("." in parts[0] or ":" in parts[0]):
        return f"{registry}/{parts[1]}"
    return f"{registry}/{image}"


def check_scanner_readiness(
    scanner_names: list[str],
    backend: str = "auto",
    registry: str = "",
) -> list[ToolStatus]:
    """Return a ToolStatus per scanner name — no I/O, no printing.

    A scanner is available when (a) its local binary is installed, or
    (b) the backend allows containers and a container runtime + image are
    both present. Unknown scanners are reported as unavailable with
    method="none" rather than raising, so callers can surface a full
    status table even when the config references typos.
    """
    from argus.containers import get_image
    from argus.preflight.network_deps import get_network_deps
    from argus.scanners import SCANNER_REGISTRY

    runtime_ok = container_runtime_available()
    statuses: list[ToolStatus] = []

    for name in scanner_names:
        net_deps = get_network_deps(name)
        cls = SCANNER_REGISTRY.get(name)
        if cls is None:
            statuses.append(ToolStatus(name, False, "none", network_deps=net_deps))
            continue

        scanner = cls()
        local = scanner.is_available()
        raw_image = get_image(name) or getattr(scanner, "container_image", "")
        image = resolve_image(raw_image, registry)

        if local:
            statuses.append(ToolStatus(name, True, "local", network_deps=net_deps))
        elif backend == "local":
            statuses.append(ToolStatus(name, False, "none", network_deps=net_deps))
        elif not runtime_ok:
            statuses.append(ToolStatus(name, False, "none", network_deps=net_deps))
        elif image:
            statuses.append(
                ToolStatus(name, True, "container", image=image, network_deps=net_deps)
            )
        else:
            statuses.append(ToolStatus(name, False, "none", network_deps=net_deps))

    return statuses


def summarize(statuses: list[ToolStatus]) -> dict[str, int]:
    """Bucket statuses by method for compact one-line summaries."""
    buckets = {"local": 0, "container": 0, "missing": 0}
    for s in statuses:
        if not s.available:
            buckets["missing"] += 1
        elif s.method == "local":
            buckets["local"] += 1
        elif s.method == "container":
            buckets["container"] += 1
    return buckets


def unavailable_names(statuses: list[ToolStatus]) -> list[str]:
    """Names of scanners that cannot run with the current setup."""
    return [s.name for s in statuses if not s.available]
