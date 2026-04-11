"""Container image manifest for argus scanners.

All container image references are centralized here for:
1. Single-point version updates
2. Dependabot/Renovate tracking
3. Registry override support
"""

# Official images from tool authors
OFFICIAL_IMAGES = {
    "trivy": "aquasec/trivy:0.58.0",
    "grype": "anchore/grype:0.86.1",
    "syft": "anchore/syft:1.18.1",
    "gitleaks": "zricethezav/gitleaks:v8.22.1",
    "clamav": "clamav/clamav:1.4",
    "checkov": "bridgecrew/checkov:3.2.346",
    "osv-scanner": "ghcr.io/google/osv-scanner:latest",
    "zap": "ghcr.io/zaproxy/zaproxy:2.16.0",
    "semgrep": "returntocorp/semgrep:1.102.0",
}

# Custom images built by Argus (no official image available)
CUSTOM_IMAGES = {
    "bandit": "ghcr.io/huntridge-labs/argus/scanner-bandit:0.8.0",
    "supply-chain": "ghcr.io/huntridge-labs/argus/scanner-supply-chain:0.8.0",
    "cli": "ghcr.io/huntridge-labs/argus/cli:0.8.0",
}


def get_image(scanner_name: str) -> str:
    """Get the container image for a scanner."""
    return OFFICIAL_IMAGES.get(scanner_name, CUSTOM_IMAGES.get(scanner_name, ""))
