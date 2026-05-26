"""Runtime network dependency declarations for scanners.

Scanners that require network access at scan time (not just for
installation) are listed here so ``argus validate --check-tools``
can surface these as informational warnings.
"""

# Scanner name → list of human-readable network dependency descriptions.
# Only scanners with *runtime* network needs belong here — tools that
# just need to be installed are handled by is_available() / Docker pull.
RUNTIME_NETWORK_DEPS: dict[str, list[str]] = {
    "osv": [
        "OSV API (api.osv.dev) — queries vulnerability database at scan time",
    ],
    "clamav": [
        "ClamAV freshclam — downloads virus definitions on container start (~300 MB first run)",
    ],
    "trivy-iac": [
        "Trivy DB — downloads vulnerability database on first run or cache miss (~40 MB)",
    ],
    "container": [
        "Trivy DB — downloads vulnerability database on first run or cache miss",
        "Grype DB — downloads vulnerability database on first run or cache miss (~150 MB)",
    ],
    "checkov": [
        "Checkov registry — downloads custom policies if configured",
    ],
    "promptfoo": [
        "LLM provider APIs (OpenAI, Anthropic, etc.) — sends adversarial "
        "prompts to the configured model endpoints at scan time; "
        "requires provider API keys",
    ],
}


def get_network_deps(scanner_name: str) -> list[str]:
    """Return runtime network dependency descriptions for a scanner.

    Returns an empty list if the scanner has no known runtime network needs.
    """
    return RUNTIME_NETWORK_DEPS.get(scanner_name, [])
