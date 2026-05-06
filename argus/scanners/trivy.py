"""Trivy standalone scanner — SBOM-input vulnerability scanning.

Separate from ``trivy-iac`` (Terraform/K8s misconfig scanning) and from
the container scanner's bundled Trivy invocation. This module is the
standalone SBOM-mode wrapper that ``argus scan --sbom`` uses; filesystem
and image-based Trivy invocations remain the container scanner's job.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity
from argus.core.version import parse_tool_version

from argus.scanners._vuln_parsers import parse_trivy_vuln


class TrivyScanner:
    """Run Trivy against a CycloneDX/SPDX SBOM."""

    name = "trivy"
    description = "Vulnerability scanner — consumes CycloneDX/SPDX SBOMs"
    category = "sca"
    languages = ["all"]
    container_image = get_image("trivy")
    supports_sbom = True

    def container_args(self, config: dict | None = None) -> list[str]:
        """Container args for ``aquasec/trivy``.

        Trivy's image uses ``trivy`` as entrypoint; return only the
        subcommand + flags. SBOM is mounted at ``sbom_mount_path``
        (engine-set; defaults to ``/workspace/<sbom_filename>``).
        """
        config = config or {}
        sbom_path = config.get("sbom_path")
        if not sbom_path:
            raise RuntimeError(
                "trivy scanner requires sbom_path (run via `argus scan --sbom <path>`)"
            )
        mount = config.get("sbom_mount_path") or f"/workspace/{Path(sbom_path).name}"
        return [
            "sbom",
            "--format", "json",
            "--output", "/output/results.json",
            mount,
        ]

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run trivy against the SBOM given via ``config['sbom_path']``."""
        config = config or {}
        sbom_path = config.get("sbom_path")
        if not sbom_path:
            return ScanResult(
                scanner=self.name,
                metadata={"error": "trivy requires sbom_path"},
            )

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_file = Path(tmp_dir) / "trivy-results.json"
            cmd = [
                "trivy", "sbom",
                "--format", "json",
                "--output", str(output_file),
                str(sbom_path),
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if not output_file.exists():
                return ScanResult(
                    scanner=self.name,
                    metadata={
                        "error": result.stderr.strip() or "trivy produced no output",
                        "returncode": result.returncode,
                    },
                )
            findings = self.parse_results(output_file)
            return ScanResult(
                scanner=self.name,
                findings=findings,
                metadata={
                    "returncode": result.returncode,
                    "sbom_path": str(sbom_path),
                },
            )

    def is_available(self) -> bool:
        return shutil.which("trivy") is not None

    def install_command(self) -> str | None:
        return (
            "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/"
            "main/contrib/install.sh | sh -s -- -b /usr/local/bin"
        )

    def tool_version(self) -> str | None:
        if not self.is_available():
            return None
        return parse_tool_version(["trivy", "--version"], r"^Version: (\S+)")

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse Trivy JSON output into Finding objects."""
        try:
            data = json.loads(Path(raw_output_path).read_text())
        except (json.JSONDecodeError, OSError):
            return []
        findings: list[Finding] = []
        for r in data.get("Results") or []:
            for v in r.get("Vulnerabilities") or []:
                findings.append(parse_trivy_vuln(v, scanner_name=self.name))
        return findings
