"""OSV-Scanner dependency vulnerability scanner."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity


class OsvScanner:
    """Wraps OSV-Scanner to detect vulnerable dependencies."""

    name = "osv"
    description = "Dependency vulnerability scanner — checks lockfiles or an SBOM against the OSV database"
    category = "sca"
    languages = ["all"]
    container_image = get_image("osv-scanner")
    supports_sbom = True

    def container_args(self, config: dict | None = None) -> list[str]:
        """Build container args from config — mirrors _build_command."""
        config = config or {}
        sbom_path = config.get("sbom_path")
        # osv-scanner v2: `scan --sbom` for SBOMs, `scan source` for source trees
        if sbom_path:
            sbom_in_container = config.get("sbom_mount_path") or f"/workspace/{sbom_path}"
            return ["scan", "--format", "json", "--output-file", "/output/results.json",
                    "-L", sbom_in_container]
        args = ["scan", "source", "--format", "json", "--output-file", "/output/results.json"]
        lockfile = config.get("lockfile")
        if lockfile:
            args.extend(["-L", f"/workspace/{lockfile}"])
        else:
            recursive = config.get("recursive", True)
            if str(recursive).lower() not in ("false", "0", "no"):
                args.append("--recursive")
            args.append("/workspace")
        if config.get("config_file"):
            args.extend(["--config", f"/workspace/{config['config_file']}"])
        return args

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run OSV-Scanner against the given path and return results."""
        config = config or {}

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_file = Path(tmp_dir) / "osv-results.json"
            cmd = self._build_command(path, output_file, config)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )

            # osv-scanner exits non-zero when vulnerabilities are found,
            # so we only treat truly unexpected failures as errors
            if result.returncode != 0 and not output_file.exists():
                return ScanResult(
                    scanner=self.name,
                    metadata={
                        "error": result.stderr.strip(),
                        "returncode": result.returncode,
                    },
                )

            if not output_file.exists():
                return ScanResult(
                    scanner=self.name,
                    metadata={"error": "No output file produced"},
                )

            findings = self.parse_results(output_file)
            return ScanResult(
                scanner=self.name,
                findings=findings,
                raw_report=output_file,
            )

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
        try:
            result = subprocess.run(
                ["osv-scanner", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            # Output varies: "osv-scanner version X.Y.Z" or similar
            text = result.stdout.strip()
            if not text:
                return None
            # Look for a version-like token (digits and dots)
            for line in text.splitlines():
                for part in line.split():
                    stripped = part.lstrip("v")
                    if stripped and stripped[0].isdigit() and "." in stripped:
                        return stripped
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return None

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

    def _build_command(
        self, path: str, output_file: Path, config: dict
    ) -> list[str]:
        """Build the OSV-Scanner CLI command."""
        cmd = [
            "osv-scanner",
            "scan",
            "--format", "json",
            "--output", str(output_file),
        ]

        config_file = config.get("config_file")
        if config_file:
            cmd.extend(["--config", config_file])

        sbom_path = config.get("sbom_path")
        if sbom_path:
            cmd.extend(["--sbom", str(sbom_path)])
            return cmd

        lockfile = config.get("lockfile")
        if lockfile:
            cmd.extend(["-L", lockfile])
        else:
            recursive = config.get("recursive", True)
            if str(recursive).lower() not in ("false", "0", "no"):
                cmd.append("--recursive")
            cmd.append(path)

        return cmd
