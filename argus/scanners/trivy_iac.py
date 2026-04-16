"""Trivy IaC (Infrastructure as Code) scanner."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity


class TrivyIacScanner:
    """Wraps Trivy to scan infrastructure-as-code for misconfigurations."""

    name = "trivy-iac"
    container_image = get_image("trivy")

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run Trivy IaC scan against the given path and return results."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_output = Path(tmp_dir) / "trivy-iac-results.json"
            sarif_output = Path(tmp_dir) / "trivy-iac-results.sarif"

            # Run JSON scan
            json_result = subprocess.run(
                [
                    "trivy", "config",
                    "--format", "json",
                    "--output", str(json_output),
                    path,
                ],
                capture_output=True,
                text=True,
            )

            if json_result.returncode != 0 and not json_output.exists():
                return ScanResult(
                    scanner=self.name,
                    metadata={
                        "error": json_result.stderr.strip(),
                        "returncode": json_result.returncode,
                    },
                )

            # Run SARIF scan (best-effort, non-blocking)
            subprocess.run(
                [
                    "trivy", "config",
                    "--format", "sarif",
                    "--output", str(sarif_output),
                    path,
                ],
                capture_output=True,
                text=True,
            )

            findings = self.parse_results(json_output) if json_output.exists() else []

            return ScanResult(
                scanner=self.name,
                findings=findings,
                raw_report=json_output if json_output.exists() else None,
                sarif_report=sarif_output if sarif_output.exists() else None,
            )

    def is_available(self) -> bool:
        """Check if Trivy is installed."""
        return shutil.which("trivy") is not None

    def install_command(self) -> str | None:
        """Return install command for Trivy."""
        return "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh"

    def tool_version(self) -> str | None:
        """Return the installed Trivy version, or None if not available."""
        if not self.is_available():
            return None
        try:
            result = subprocess.run(
                ["trivy", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            # Output includes "Version: X.Y.Z" among other lines
            for line in result.stdout.strip().splitlines():
                if line.startswith("Version:"):
                    return line.split(":", 1)[1].strip()
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return None

    def container_args(self, config: dict | None = None) -> list[str]:
        """Return CLI args for running Trivy IaC in a container."""
        return [
            "config",
            "--format", "json",
            "--output", "/output/results.json",
            "/workspace",
        ]

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse Trivy IaC JSON output into findings."""
        data = json.loads(raw_output_path.read_text())
        results = data.get("Results", [])

        findings = []
        for target_result in results:
            target = target_result.get("Target", "")
            misconfigs = target_result.get("Misconfigurations", [])

            for misconfig in misconfigs:
                findings.append(self._parse_misconfiguration(target, misconfig))

        return findings

    def _parse_misconfiguration(self, target: str, misconfig: dict) -> Finding:
        """Convert a single Trivy misconfiguration into a Finding."""
        severity = Severity.from_string(misconfig.get("Severity", "UNKNOWN"))

        cause = misconfig.get("CauseMetadata", {})
        start_line = cause.get("StartLine")
        location = f"{target}:{start_line}" if start_line else target

        return Finding(
            id=misconfig.get("ID", "UNKNOWN"),
            severity=severity,
            title=misconfig.get("Title", ""),
            description=misconfig.get("Description", ""),
            location=location,
            scanner=self.name,
            metadata={
                "resolution": misconfig.get("Resolution", ""),
                "resource": cause.get("Resource", ""),
                "provider": cause.get("Provider", ""),
                "service": cause.get("Service", ""),
                "primary_url": misconfig.get("PrimaryURL", ""),
            },
        )
