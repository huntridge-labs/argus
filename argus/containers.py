"""Container image manifest for argus scanners.

All container image references are centralized here for:
1. Single-point version updates
2. Dependabot/Renovate tracking
3. Registry override support
"""

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
