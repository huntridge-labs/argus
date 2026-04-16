"""Gitleaks secrets scanner."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity


class GitleaksScanner:
    """Wraps Gitleaks to scan repositories for leaked secrets."""

    name = "gitleaks"
    container_image = get_image("gitleaks")

    def container_args(self, config: dict | None = None) -> list[str]:
        """Build container args from config — mirrors _build_command."""
        config = config or {}
        args = [
            "detect", "--source", "/workspace",
            "--report-format", "json",
            "--report-path", "/output/results.json",
            "--exit-code", "0",
        ]
        config_file = config.get("config_file")
        if config_file:
            args.extend(["--config", f"/workspace/{config_file}"])
        return args

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run Gitleaks against the given path and return results."""
        config = config or {}

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_file = Path(tmp_dir) / "gitleaks-results.json"
            cmd = self._build_command(path, output_file, config)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )

            # --exit-code 0 means gitleaks always exits 0
            if result.returncode != 0:
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
        """Check if Gitleaks is installed."""
        return shutil.which("gitleaks") is not None

    def install_command(self) -> str | None:
        """Return install command for Gitleaks."""
        return "Install from https://github.com/gitleaks/gitleaks"

    def tool_version(self) -> str | None:
        """Return the installed Gitleaks version, or None if not available."""
        if not self.is_available():
            return None
        try:
            result = subprocess.run(
                ["gitleaks", "version"],
                capture_output=True, text=True, timeout=5,
            )
            # Output: "vX.Y.Z" — strip the leading v
            version_text = result.stdout.strip()
            if not version_text:
                return None
            return version_text.lstrip("v")
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return None

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse Gitleaks JSON output into findings."""
        text = raw_output_path.read_text().strip()
        if not text:
            return []

        data = json.loads(text)

        # Gitleaks outputs a JSON array, not an object
        if not isinstance(data, list):
            return []

        return [self._parse_finding(item) for item in data]

    def _parse_finding(self, item: dict) -> Finding:
        """Convert a single Gitleaks result into a Finding.

        All secrets findings are HIGH severity -- leaked credentials
        are always a high-priority issue.
        """
        file_path = item.get("File", "")
        start_line = item.get("StartLine", 0)
        location = f"{file_path}:{start_line}" if file_path else None

        return Finding(
            id=item.get("RuleID", "UNKNOWN"),
            severity=Severity.HIGH,
            title=item.get("Description", "Secret detected"),
            description=item.get("Description", ""),
            location=location,
            scanner=self.name,
            metadata={
                "commit": item.get("Commit", ""),
                "author": item.get("Author", ""),
                "rule_id": item.get("RuleID", ""),
                "match": item.get("Match", ""),
                "end_line": item.get("EndLine", 0),
            },
        )

    def _build_command(
        self, path: str, output_file: Path, config: dict
    ) -> list[str]:
        """Build the Gitleaks CLI command."""
        cmd = [
            "gitleaks",
            "detect",
            "--source", path,
            "--report-format", "json",
            "--report-path", str(output_file),
            "--exit-code", "0",
        ]

        config_file = config.get("config_file")
        if config_file:
            cmd.extend(["--config", config_file])

        return cmd
