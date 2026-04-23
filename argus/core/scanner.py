"""Scanner protocol definition for Argus scanner modules."""

from pathlib import Path
from typing import Protocol, runtime_checkable

from .models import Finding, ScanResult


@runtime_checkable
class Scanner(Protocol):
    """Protocol that all scanner modules must implement.

    Each scanner wraps an external security tool (e.g., Bandit, Trivy,
    Gitleaks) and normalizes its output into Argus Finding/ScanResult
    objects.

    Optional container support:
        container_image: str  — Docker image for running in a container
        container_args(config) — CLI args for the containerized invocation
        parse_results(path) — Parse output file into findings

    Supply-chain integrity:
        tool_version() — Detect locally installed tool version

    SBOM scanning:
        supports_sbom: bool — True when the scanner can accept a pre-built
            SBOM via ``config["sbom_path"]`` instead of a filesystem path.
            Consumed by ``argus scan --sbom`` to auto-select capable tools.
    """

    name: str
    supports_sbom: bool = False

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run the scanner against the given path and return results."""
        ...

    def is_available(self) -> bool:
        """Check if the underlying scanner tool is installed and reachable."""
        ...

    def install_command(self) -> str | None:
        """Return the shell command to install the scanner, or None."""
        ...

    def tool_version(self) -> str | None:
        """Return the installed tool version, or None if not available."""
        ...
