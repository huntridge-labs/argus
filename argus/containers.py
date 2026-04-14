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
    "bandit": "ghcr.io/huntridge-labs/argus/scanner-bandit:1.0.0",
    "semgrep": "ghcr.io/huntridge-labs/argus/scanner-opengrep:1.0.0",
    "supply-chain": "ghcr.io/huntridge-labs/argus/scanner-supply-chain:1.0.0",
    "cli": "ghcr.io/huntridge-labs/argus/cli:1.0.0",
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
