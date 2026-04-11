"""Container scanner orchestrating Trivy, Grype, and Syft."""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from argus.core.models import Finding, ScanResult, Severity


class ContainerScanner:
    """Wraps Trivy, Grype, and Syft for container image scanning."""

    name = "container"

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run enabled sub-scanners against a container image.

        The ``path`` argument is ignored; the image reference must be
        provided via ``config["image_ref"]``.
        """
        config = config or {}
        image_ref = config.get("image_ref")
        if not image_ref:
            return ScanResult(
                scanner=self.name,
                metadata={"error": "image_ref is required in config"},
            )

        enabled = self._enabled_scanners(config)
        all_findings: list[Finding] = []
        metadata: dict = {}
        seen_cves: set[str] = set()

        env = self._build_env(config)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            if "trivy" in enabled and shutil.which("trivy") is not None:
                trivy_output = tmp_path / "trivy-results.json"
                trivy_findings, trivy_meta = self._run_trivy(
                    image_ref, trivy_output, env
                )
                self._merge_findings(
                    trivy_findings, all_findings, seen_cves
                )
                metadata["trivy"] = trivy_meta

            if "grype" in enabled and shutil.which("grype") is not None:
                grype_output = tmp_path / "grype-results.json"
                grype_findings, grype_meta = self._run_grype(
                    image_ref, grype_output, env
                )
                self._merge_findings(
                    grype_findings, all_findings, seen_cves
                )
                metadata["grype"] = grype_meta

            if "syft" in enabled and shutil.which("syft") is not None:
                syft_output = tmp_path / "syft-sbom.json"
                syft_meta = self._run_syft(image_ref, syft_output, env)
                metadata["syft"] = syft_meta

            if not metadata:
                metadata["error"] = (
                    "None of the enabled scanners "
                    "(trivy, grype, syft) are installed"
                )

        return ScanResult(
            scanner=self.name,
            findings=all_findings,
            metadata=metadata,
        )

    def is_available(self) -> bool:
        """Check if at least one vulnerability scanner is installed."""
        return (
            shutil.which("trivy") is not None
            or shutil.which("grype") is not None
        )

    def install_command(self) -> str | None:
        """Return install hints for the container scanning tools."""
        return (
            "See https://aquasecurity.github.io/trivy, "
            "https://github.com/anchore/grype, "
            "https://github.com/anchore/syft"
        )

    def parse_trivy_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse Trivy container JSON output into findings."""
        data = json.loads(raw_output_path.read_text())
        findings: list[Finding] = []

        for target in data.get("Results", []):
            for vuln in target.get("Vulnerabilities", []):
                findings.append(self._parse_trivy_vuln(vuln))

        return findings

    def parse_grype_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse Grype JSON output into findings."""
        data = json.loads(raw_output_path.read_text())
        findings: list[Finding] = []

        for match in data.get("matches", []):
            findings.append(self._parse_grype_match(match))

        return findings

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _enabled_scanners(self, config: dict) -> list[str]:
        """Return list of enabled sub-scanner names from config."""
        raw = config.get("scanners", "trivy,grype,syft")
        return [s.strip().lower() for s in raw.split(",") if s.strip()]

    def _build_env(self, config: dict) -> dict[str, str]:
        """Build environment dict with optional registry credentials."""
        env = dict(os.environ)
        username = config.get("registry_username")
        password = config.get("registry_password")

        if username:
            env["TRIVY_USERNAME"] = username
            env["GRYPE_REGISTRY_AUTH_USERNAME"] = username
            env["SYFT_REGISTRY_AUTH_USERNAME"] = username
        if password:
            env["TRIVY_PASSWORD"] = password
            env["GRYPE_REGISTRY_AUTH_PASSWORD"] = password
            env["SYFT_REGISTRY_AUTH_PASSWORD"] = password

        return env

    def _run_trivy(
        self,
        image_ref: str,
        output_file: Path,
        env: dict[str, str],
    ) -> tuple[list[Finding], dict]:
        """Execute trivy image scan and return findings plus metadata."""
        cmd = [
            "trivy", "image",
            "--format", "json",
            "--output", str(output_file),
            image_ref,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
        )

        meta: dict = {"returncode": result.returncode}

        if not output_file.exists():
            meta["error"] = result.stderr.strip() or "No output produced"
            return [], meta

        findings = self.parse_trivy_results(output_file)
        return findings, meta

    def _run_grype(
        self,
        image_ref: str,
        output_file: Path,
        env: dict[str, str],
    ) -> tuple[list[Finding], dict]:
        """Execute grype scan and return findings plus metadata."""
        cmd = [
            "grype", image_ref,
            "-o", "json",
            "--file", str(output_file),
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
        )

        meta: dict = {"returncode": result.returncode}

        if not output_file.exists():
            meta["error"] = result.stderr.strip() or "No output produced"
            return [], meta

        findings = self.parse_grype_results(output_file)
        return findings, meta

    def _run_syft(
        self,
        image_ref: str,
        output_file: Path,
        env: dict[str, str],
    ) -> dict:
        """Execute syft SBOM generation and return metadata."""
        cmd = [
            "syft", image_ref,
            "-o", "cyclonedx-json",
            "--file", str(output_file),
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
        )

        meta: dict = {"returncode": result.returncode}

        if output_file.exists():
            meta["sbom_path"] = str(output_file)
        else:
            meta["error"] = result.stderr.strip() or "No output produced"

        return meta

    def _merge_findings(
        self,
        new_findings: list[Finding],
        target: list[Finding],
        seen_cves: set[str],
    ) -> None:
        """Append findings to target, deduplicating by CVE ID."""
        for finding in new_findings:
            cve = finding.cve
            if cve and cve in seen_cves:
                continue
            if cve:
                seen_cves.add(cve)
            target.append(finding)

    def _parse_trivy_vuln(self, vuln: dict) -> Finding:
        """Convert a single Trivy vulnerability to a Finding."""
        severity = Severity.from_string(
            vuln.get("Severity", "UNKNOWN")
        )

        cwe = None
        cwe_ids = vuln.get("CweIDs") or []
        if cwe_ids:
            cwe = cwe_ids[0]

        vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
        pkg = vuln.get("PkgName", "")
        installed = vuln.get("InstalledVersion", "")
        fixed = vuln.get("FixedVersion", "")

        return Finding(
            id=vuln_id,
            severity=severity,
            title=vuln.get("Title", vuln_id),
            description=vuln.get("Description", ""),
            location=f"{pkg}@{installed}" if pkg else None,
            cwe=cwe,
            cve=vuln_id if vuln_id.startswith("CVE-") else None,
            scanner=self.name,
            metadata={
                "tool": "trivy",
                "package": pkg,
                "installed_version": installed,
                "fixed_version": fixed,
            },
        )

    def _parse_grype_match(self, match: dict) -> Finding:
        """Convert a single Grype match to a Finding."""
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        vuln_id = vuln.get("id", "UNKNOWN")
        severity = Severity.from_string(
            vuln.get("severity", "Unknown")
        )

        pkg_name = artifact.get("name", "")
        pkg_version = artifact.get("version", "")

        fix_versions = vuln.get("fix", {}).get("versions", [])
        fixed = ", ".join(fix_versions) if fix_versions else ""

        return Finding(
            id=vuln_id,
            severity=severity,
            title=vuln.get("description", vuln_id),
            description=vuln.get("description", ""),
            location=f"{pkg_name}@{pkg_version}" if pkg_name else None,
            cve=vuln_id if vuln_id.startswith("CVE-") else None,
            scanner=self.name,
            metadata={
                "tool": "grype",
                "package": pkg_name,
                "installed_version": pkg_version,
                "fixed_version": fixed,
            },
        )
