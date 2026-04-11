"""Bandit SAST scanner for Python code."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from argus.core.models import Finding, ScanResult, Severity


class BanditScanner:
    """Wraps Bandit to scan Python code for security issues."""

    name = "bandit"

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run Bandit against the given path and return results."""
        config = config or {}

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_file = Path(tmp_dir) / "bandit-results.json"
            cmd = self._build_command(path, output_file, config)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )

            # Bandit uses --exit-zero so non-zero means a real error
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
        """Check if Bandit is installed."""
        return shutil.which("bandit") is not None

    def install_command(self) -> str | None:
        """Return install command for Bandit."""
        return "pip install bandit[toml,sarif]"

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse Bandit JSON output into findings."""
        data = json.loads(raw_output_path.read_text())
        results = data.get("results", [])

        return [self._parse_finding(item) for item in results]

    def _parse_finding(self, item: dict) -> Finding:
        """Convert a single Bandit result into a Finding."""
        severity = Severity.from_string(item.get("issue_severity", "UNKNOWN"))

        cwe = None
        issue_cwe = item.get("issue_cwe")
        if issue_cwe and "id" in issue_cwe:
            cwe = f"CWE-{issue_cwe['id']}"

        filename = item.get("filename", "")
        line_number = item.get("line_number", 0)
        location = f"{filename}:{line_number}" if filename else None

        return Finding(
            id=item.get("test_id", "UNKNOWN"),
            severity=severity,
            title=item.get("issue_text", ""),
            description=item.get("issue_text", ""),
            location=location,
            cwe=cwe,
            scanner=self.name,
            metadata={
                "test_name": item.get("test_name", ""),
                "confidence": item.get("issue_confidence", ""),
                "more_info": item.get("more_info", ""),
                "code": item.get("code", ""),
            },
        )

    def _build_command(
        self, path: str, output_file: Path, config: dict
    ) -> list[str]:
        """Build the Bandit CLI command."""
        cmd = [
            "bandit",
            "-r", path,
            "-f", "json",
            "-o", str(output_file),
            "--exit-zero",
        ]

        exclude = config.get("exclude")
        if exclude:
            cmd.extend(["--exclude", exclude])

        config_file = config.get("config_file")
        if config_file:
            cmd.extend(["-c", config_file])

        return cmd
