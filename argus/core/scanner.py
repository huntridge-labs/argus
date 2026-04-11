"""Scanner protocol definition for Argus scanner modules."""

from typing import Protocol, runtime_checkable

from .models import ScanResult


@runtime_checkable
class Scanner(Protocol):
    """Protocol that all scanner modules must implement.

    Each scanner wraps an external security tool (e.g., Bandit, Trivy,
    Gitleaks) and normalizes its output into Argus Finding/ScanResult
    objects.
    """

    name: str

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run the scanner against the given path and return results."""
        ...

    def is_available(self) -> bool:
        """Check if the underlying scanner tool is installed and reachable."""
        ...

    def install_command(self) -> str | None:
        """Return the shell command to install the scanner, or None."""
        ...
