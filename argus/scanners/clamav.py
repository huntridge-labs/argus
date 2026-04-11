"""ClamAV malware scanner."""

import re
import shutil
import subprocess
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity

_FOUND_PATTERN = re.compile(r"^(.+):\s+(.+)\s+FOUND$")


class ClamavScanner:
    """Wraps ClamAV (clamscan) to detect malware in files."""

    name = "clamav"
    container_image = get_image("clamav")

    def container_args(self, config: dict | None = None) -> list[str]:
        """Return CLI args for running ClamAV in a container."""
        return [
            "sh", "-c",
            "clamscan --recursive /workspace > /output/results.txt 2>&1 || true",
        ]

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run ClamAV against the given path and return results."""
        # Run detailed scan (no summary) to capture per-file results
        detail_result = subprocess.run(
            ["clamscan", "--recursive", "--no-summary", path],
            capture_output=True,
            text=True,
        )

        # Run with summary for metadata
        summary_result = subprocess.run(
            ["clamscan", "--recursive", path],
            capture_output=True,
            text=True,
        )

        combined_output = detail_result.stdout
        findings = self.parse_results_text(combined_output)

        summary_metadata = self._parse_summary(summary_result.stdout)

        return ScanResult(
            scanner=self.name,
            findings=findings,
            metadata=summary_metadata,
        )

    def is_available(self) -> bool:
        """Check if ClamAV is installed."""
        return shutil.which("clamscan") is not None

    def install_command(self) -> str | None:
        """Return install command for ClamAV."""
        return "apt-get install -y clamav"

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse ClamAV text output file into findings."""
        text = raw_output_path.read_text()
        return self.parse_results_text(text)

    def parse_results_text(self, text: str) -> list[Finding]:
        """Parse ClamAV text output string into findings."""
        findings = []
        for line in text.splitlines():
            match = _FOUND_PATTERN.match(line.strip())
            if not match:
                continue

            file_path = match.group(1).strip()
            virus_name = match.group(2).strip()

            findings.append(Finding(
                id=virus_name,
                severity=Severity.CRITICAL,
                title=f"Malware detected: {virus_name}",
                description=f"ClamAV detected {virus_name} in {file_path}",
                location=file_path,
                scanner=self.name,
            ))

        return findings

    def _parse_summary(self, text: str) -> dict:
        """Extract summary metadata from ClamAV output."""
        metadata = {}
        in_summary = False

        for line in text.splitlines():
            if "SCAN SUMMARY" in line:
                in_summary = True
                continue

            if not in_summary:
                continue

            if ":" not in line:
                continue

            key, _, value = line.partition(":")
            key = key.strip().lower().replace(" ", "_")
            metadata[key] = value.strip()

        return metadata
