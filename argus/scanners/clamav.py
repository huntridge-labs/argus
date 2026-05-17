"""ClamAV malware scanner."""

import re
import shutil
import subprocess
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity
from argus.core.version import parse_tool_version

_FOUND_PATTERN = re.compile(r"^(.+):\s+(.+)\s+FOUND$")


class ClamavScanner:
    """Wraps ClamAV (clamscan) to detect malware in files."""

    name = "clamav"
    description = "Malware detection scanner — file-based virus and threat scanning"
    category = "malware"
    languages = ["all"]
    container_image = get_image("clamav")
    # The official clamav/clamav image default entrypoint starts clamd as a
    # daemon, which is not what we want.  Override to /bin/sh so we can run
    # freshclam (virus DB update) followed by clamscan in a single command.
    container_entrypoint = "/bin/sh"

    def container_args(self, config: dict | None = None) -> list[str]:
        """Return CLI args for running ClamAV in a container.

        NOTE: The clamav/clamav:1.5 image ships with bundled virus
        definitions but does NOT auto-run freshclam when the entrypoint
        is overridden.  We prepend ``freshclam`` to ensure the DB is
        current before scanning (~60s on first run, cached thereafter).
        The engine passes these args after ``--entrypoint /bin/sh``.

        freshclam writes its state file (``freshclam.dat``) and the
        downloaded DBs to ``--datadir`` instead of the default
        ``/var/lib/clamav``. The bind-mounted host directory for that
        path is owned by the calling user, but the container's
        ``clamav`` system user lacks write access — freshclam then
        segfaults with ``Can't create freshclam.dat in /var/lib/clamav``
        (issue #168-N). Redirecting to a tmpfs-style ``/tmp`` path
        sidesteps the permissions problem; the DB is re-downloaded on
        every run as the trade-off.
        """
        return [
            "-c",
            (
                "mkdir -p /tmp/clamav-db && "
                "freshclam --datadir /tmp/clamav-db --quiet && "
                "clamscan --database /tmp/clamav-db --recursive /workspace"
            ),
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

    def tool_version(self) -> str | None:
        """Return the installed ClamAV version, or None if not available."""
        if not self.is_available():
            return None
        # Output: "ClamAV X.Y.Z/dbver/..." → take only the X.Y.Z part
        return parse_tool_version(["clamscan", "--version"], r"^ClamAV ([0-9.]+)")

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse ClamAV text output file into findings."""
        text = raw_output_path.read_text(encoding="utf-8", errors="replace")
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
