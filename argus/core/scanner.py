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

    VEX filtering:
        supports_vex: bool — True when the underlying tool consumes OpenVEX
            (``--vex``) to drop ``not_affected`` / ``fixed`` findings at the
            source (trivy, grype). Such scanners read ``config["vex"]`` and
            wire it via the shared helpers in ``argus.core.vex`` — appending
            ``vex_cli_flags(...)`` in ``scan`` / ``container_args`` and
            returning ``vex_container_mounts(...)`` from ``container_mounts``.
            A new VEX-capable scanner opts in by setting this flag and calling
            those helpers; no engine change is required (the engine already
            bind-mounts whatever ``container_mounts`` returns).

    Config metadata (optional — drives config UIs like the Console / Argus Cloud):
        config_options: list[ConfigOption] — the scanner's own configurable
            knobs beyond the common base (see ``argus.core.config_options``).
        native_ignore: NativeIgnore — how to suppress findings at the source
            when there's no direct ``argus.yml`` key (e.g. ``.trivyignore``).
        A scanner that declares neither still surfaces the common base options,
        so a new scanner needs no config-UI change to be configurable.
    """

    name: str
    supports_sbom: bool = False
    supports_vex: bool = False

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
