"""Container image manifest for argus scanners.

All container image references are centralized here for:
1. Single-point version updates
2. Dependabot/Renovate tracking
3. Registry override support
4. DB cache volume mounts for persistent vulnerability databases
"""

import os
from pathlib import Path

# Official images from tool authors (used directly, not rebuilt by argus)
OFFICIAL_IMAGES = {
    "trivy": "aquasec/trivy:0.69.3",
    "grype": "anchore/grype:0.111.0",
    "syft": "anchore/syft:1.42.4",
    "gitleaks": "zricethezav/gitleaks:v8.30.1",
    "clamav": "clamav/clamav:1.4",
    "checkov": "bridgecrew/checkov:3.2.346",
    "osv-scanner": "ghcr.io/google/osv-scanner:v2.3.5",
    "zap": "ghcr.io/zaproxy/zaproxy:2.16.0",
    "hadolint": "hadolint/hadolint:v2.12.0",
}

# Custom images built and published by Argus to ghcr.io/huntridge-labs/argus/
# Versions managed by release-it regex bumper
CUSTOM_IMAGES = {
    "bandit": "ghcr.io/huntridge-labs/argus/scanner-bandit:0.7.0",
    "semgrep": "ghcr.io/huntridge-labs/argus/scanner-opengrep:0.7.0",
    "supply-chain": "ghcr.io/huntridge-labs/argus/scanner-supply-chain:0.7.0",
    "cli": "ghcr.io/huntridge-labs/argus/cli:0.7.0",
}


# Aliases for scanners whose name differs from the image key
_ALIASES = {
    "opengrep": "semgrep",
    "trivy-iac": "trivy",
    "osv": "osv-scanner",
}


def get_image(scanner_name: str) -> str:
    """Get the container image for a scanner.

    Handles aliases (e.g. opengrep → semgrep image, osv → osv-scanner image).
    """
    key = _ALIASES.get(scanner_name, scanner_name)
    return OFFICIAL_IMAGES.get(key, CUSTOM_IMAGES.get(key, ""))


def expected_version(container_image: str) -> str | None:
    """Extract the expected tool version from a container image tag.

    Parses the tag portion of ``registry/repo:tag`` and strips a leading
    ``v`` prefix so that the result can be compared directly against the
    version string returned by a scanner's ``tool_version()`` method.

    Returns ``None`` when the image string is empty or has no tag.
    """
    if not container_image or ":" not in container_image:
        return None
    tag = container_image.rsplit(":", 1)[1]
    return tag.lstrip("v") if tag else None


def get_expected_version(scanner_name: str) -> str | None:
    """Extract the pinned tool version from the container image tag for a scanner.

    Convenience wrapper that resolves the scanner name to its container
    image via :func:`get_image`, then delegates to :func:`expected_version`.
    """
    image = get_image(scanner_name)
    return expected_version(image)


# Scanner → container cache path mappings.
# Keys are resolved via _ALIASES (same as get_image), values are the
# absolute path inside the container where the tool stores its DB/cache.
CACHE_MOUNTS: dict[str, str] = {
    "trivy": "/root/.cache/trivy",
    "grype": "/root/.cache/grype",
    "clamav": "/var/lib/clamav",
    "semgrep": "/root/.semgrep",
    "checkov": "/root/.checkov",
}


def _default_cache_root() -> Path:
    """Return the host-side cache root directory.

    Uses ``ARGUS_CACHE_DIR`` env var if set, otherwise a temporary
    directory (``$TMPDIR/argus-cache``).  The temp dir is non-intrusive —
    it persists across runs within a session but is cleaned on reboot,
    avoiding permanent disk consumption on the host.
    """
    env = os.environ.get("ARGUS_CACHE_DIR")
    if env:
        return Path(env)
    import tempfile
    return Path(tempfile.gettempdir()) / "argus-cache"


def get_cache_mount(scanner_name: str) -> tuple[Path, str] | None:
    """Return (host_path, container_path) for a scanner's DB cache.

    Returns ``None`` if the scanner has no known cache directory.
    The host directory is created lazily if it does not exist.
    """
    key = _ALIASES.get(scanner_name, scanner_name)
    container_path = CACHE_MOUNTS.get(key)
    if container_path is None:
        return None

    host_dir = _default_cache_root() / key
    host_dir.mkdir(parents=True, exist_ok=True)
    return (host_dir, container_path)
