"""OpenGrep (semgrep fork) SAST scanner."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity


class OpengrepScanner:
    """Wraps OpenGrep to scan code for security issues using pattern matching."""

    name = "opengrep"
    container_image = get_image("semgrep")

    def container_args(self, config: dict | None = None) -> list[str]:
        """Build container args from config — mirrors _build_command.

        The semgrep image ENTRYPOINT is not semgrep, so we prefix the command.
        """
        config = config or {}
        args = ["semgrep", "scan", "--json", "--output", "/output/results.json"]
        rules_config = config.get("config")
        if rules_config:
            args.extend(["--config", rules_config])
        args.append("/workspace")
        return args

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run OpenGrep against the given path and return results."""
        config = config or {}

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_file = Path(tmp_dir) / "opengrep-results.json"
            cmd = self._build_command(path, output_file, config)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )

            # OpenGrep returns non-zero on findings or errors;
            # check for output file to distinguish
            if not output_file.exists():
                return ScanResult(
                    scanner=self.name,
                    metadata={
                        "error": result.stderr.strip() or "No output file produced",
                        "returncode": result.returncode,
                    },
                )

            findings = self.parse_results(output_file)
            return ScanResult(
                scanner=self.name,
                findings=findings,
                raw_report=output_file,
            )

    def is_available(self) -> bool:
        """Check if OpenGrep is installed."""
        return shutil.which("opengrep") is not None

    def install_command(self) -> str | None:
        """Return install command for OpenGrep."""
        return "pip install opengrep"

    def tool_version(self) -> str | None:
        """Return the installed OpenGrep version, or None if not available."""
        if not self.is_available():
            return None
        try:
            result = subprocess.run(
                ["opengrep", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            # Parse the version string from output
            version_text = result.stdout.strip()
            if not version_text:
                return None
            # Take the last token of the first line as the version
            first_line = version_text.splitlines()[0]
            parts = first_line.split()
            return parts[-1] if parts else None
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return None

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse OpenGrep JSON output into findings."""
        data = json.loads(raw_output_path.read_text())
        results = data.get("results", [])

        return [self._parse_finding(item) for item in results]

    def _parse_finding(self, item: dict) -> Finding:
        """Convert a single OpenGrep result into a Finding."""
        extra = item.get("extra", {})
        raw_severity = extra.get("severity", "UNKNOWN")
        severity = Severity.from_string(raw_severity)

        metadata_block = extra.get("metadata", {})
        cwe_list = metadata_block.get("cwe", [])
        cwe = cwe_list[0] if cwe_list else None

        check_id = item.get("check_id", "UNKNOWN")
        file_path = item.get("path", "")
        start = item.get("start", {})
        line = start.get("line", 0)
        location = f"{file_path}:{line}" if file_path else None

        return Finding(
            id=check_id,
            severity=severity,
            title=check_id,
            description=extra.get("message", ""),
            location=location,
            cwe=cwe,
            scanner=self.name,
            metadata={
                "owasp": metadata_block.get("owasp", []),
                "category": metadata_block.get("category", ""),
                "column": start.get("col", 0),
            },
        )

    def _build_command(
        self, path: str, output_file: Path, config: dict
    ) -> list[str]:
        """Build the OpenGrep CLI command."""
        cmd = [
            "opengrep",
            "--json",
            "--output", str(output_file),
        ]

        rules_config = config.get("config")
        if rules_config:
            cmd.extend(["--config", rules_config])

        cmd.append(path)
        return cmd
