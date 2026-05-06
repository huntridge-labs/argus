"""OSV-Scanner dependency vulnerability scanner."""

import json
import shutil
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity
from argus.core.scanner_template import ScanPaths, run_subprocess_scan
from argus.core.version import parse_tool_version


class OsvScanner:
    """Wraps OSV-Scanner to detect vulnerable dependencies."""

    name = "osv"
    description = "Dependency vulnerability scanner — checks lockfiles or an SBOM against the OSV database"
    category = "sca"
    languages = ["all"]
    container_image = get_image("osv-scanner")
    supports_sbom = True
    # The official osv-scanner image uses ENTRYPOINT ["/osv-scanner"]
    # — note the absolute path. ``$PATH`` inside the image does NOT
    # resolve a bare ``osv-scanner``; ``--entrypoint osv-scanner``
    # would exit 127. Pass the absolute path explicitly. Engine strips
    # argv[0] for ENTRYPOINT-based images so the binary name in
    # build_args() is informational only.
    container_entrypoint = "/osv-scanner"

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run OSV-Scanner against the given path and return results."""
        return run_subprocess_scan(self, path, config)

    def build_args(self, paths: ScanPaths, config: dict) -> list[str]:
        """Build the full argv (including the binary name).

        Engine drops argv[0] when the container image declares an
        ENTRYPOINT, so the same method works for both local and
        container execution.

        Two modes:
        - SBOM mode (``config["sbom_path"]`` set): passes the SBOM via
          ``-L`` to ``scan`` (osv-scanner v2 API).
        - Source mode (default): passes the workspace path to
          ``scan source``, with optional ``-L <lockfile>`` and
          ``--recursive``.
        """
        sbom_path = config.get("sbom_path")
        if sbom_path:
            # The engine sets ``sbom_mount_path`` for container execution
            # (it mounts the host SBOM into a known container path).
            # Otherwise: absolute SBOM paths pass through; relative ones
            # resolve against the workspace.
            mount_path = config.get("sbom_mount_path")
            if mount_path:
                sbom_in_context = mount_path
            elif sbom_path.startswith("/"):
                sbom_in_context = sbom_path
            else:
                sbom_in_context = f"{paths.workspace}/{sbom_path}"
            return [
                "osv-scanner",
                "scan",
                "--format", "json",
                "--output-file", paths.output,
                "-L", sbom_in_context,
            ]

        args = [
            "osv-scanner",
            "scan", "source",
            "--format", "json",
            "--output-file", paths.output,
        ]
        lockfile = config.get("lockfile")
        if lockfile:
            args.extend(["-L", f"{paths.workspace}/{lockfile}"])
        else:
            recursive = config.get("recursive", True)
            if str(recursive).lower() not in ("false", "0", "no"):
                args.append("--recursive")
            args.append(paths.workspace)
        if config.get("config_file"):
            args.extend(["--config", f"{paths.workspace}/{config['config_file']}"])
        return args

    def is_available(self) -> bool:
        """Check if OSV-Scanner is installed."""
        return shutil.which("osv-scanner") is not None

    def install_command(self) -> str | None:
        """Return install command for OSV-Scanner."""
        return "Install from https://github.com/google/osv-scanner"

    def tool_version(self) -> str | None:
        """Return the installed OSV-Scanner version, or None if not available."""
        if not self.is_available():
            return None
        return parse_tool_version(
            ["osv-scanner", "--version"],
            r"v?(\d+\.\d+(?:\.\d+)?[\w.-]*)",
        )

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse OSV-Scanner JSON output into findings."""
        text = raw_output_path.read_text().strip()
        if not text:
            return []

        data = json.loads(text)
        findings = []

        for source_result in data.get("results", []):
            source_path = source_result.get("source", {}).get("path", "")

            for package_entry in source_result.get("packages", []):
                pkg_info = package_entry.get("package", {})
                pkg_name = pkg_info.get("name", "")
                pkg_version = pkg_info.get("version", "")
                pkg_ecosystem = pkg_info.get("ecosystem", "")

                for vuln in package_entry.get("vulnerabilities", []):
                    finding = self._parse_vulnerability(
                        vuln, source_path, pkg_name, pkg_version, pkg_ecosystem
                    )
                    findings.append(finding)

        return findings

    def _parse_vulnerability(
        self,
        vuln: dict,
        source_path: str,
        pkg_name: str,
        pkg_version: str,
        pkg_ecosystem: str,
    ) -> Finding:
        """Convert a single OSV vulnerability into a Finding."""
        severity = self._extract_severity(vuln)
        cve = self._extract_cve(vuln)
        cwe = self._extract_cwe(vuln)

        return Finding(
            id=vuln.get("id", "UNKNOWN"),
            severity=severity,
            title=vuln.get("summary", "Unknown vulnerability"),
            description=vuln.get("summary", ""),
            location=source_path or None,
            cve=cve,
            cwe=cwe,
            scanner=self.name,
            metadata={
                "package_name": pkg_name,
                "package_version": pkg_version,
                "ecosystem": pkg_ecosystem,
                "aliases": vuln.get("aliases", []),
            },
        )

    def _extract_severity(self, vuln: dict) -> Severity:
        """Extract severity from database_specific or affected blocks."""
        db_specific = vuln.get("database_specific", {})
        raw_severity = db_specific.get("severity", "")
        if raw_severity:
            return Severity.from_string(raw_severity)

        # Fall back to affected[].database_specific.severity
        for affected in vuln.get("affected", []):
            affected_db = affected.get("database_specific", {})
            raw_severity = affected_db.get("severity", "")
            if raw_severity:
                return Severity.from_string(raw_severity)

        return Severity.UNKNOWN

    def _extract_cve(self, vuln: dict) -> str | None:
        """Extract the first CVE alias from the vulnerability."""
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                return alias
        return None

    def _extract_cwe(self, vuln: dict) -> str | None:
        """Extract the first CWE from database_specific.cwe_ids."""
        cwe_ids = vuln.get("database_specific", {}).get("cwe_ids", [])
        if cwe_ids:
            return cwe_ids[0]
        return None
