"""JavaScript linter wrapping jshint."""

import shutil
import subprocess

from argus.core.models import Finding, ScanResult, Severity


class JshintLinter:
    """Wraps jshint to lint JavaScript code for errors and style issues."""

    name = "lint-javascript"

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run jshint against the given path and return results."""
        config = config or {}
        cmd = self._build_command(path, config)

        result = subprocess.run(cmd, capture_output=True, text=True)

        findings = self._parse_output(result.stdout)
        return ScanResult(
            scanner=self.name,
            findings=findings,
            metadata={"returncode": result.returncode},
        )

    def is_available(self) -> bool:
        """Check if jshint is installed."""
        return shutil.which("jshint") is not None

    def install_command(self) -> str | None:
        """Return install command for jshint."""
        return "npm install -g jshint"

    def tool_version(self) -> str | None:
        """Return the installed jshint version, or None if not available."""
        if not self.is_available():
            return None
        try:
            result = subprocess.run(
                ["jshint", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            # Output: "jshint vX.Y.Z" or "X.Y.Z"
            text = result.stdout.strip()
            if not text:
                return None
            version = text.splitlines()[0].strip()
            return version.lstrip("v") if version else None
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return None

    def _build_command(self, path: str, config: dict) -> list[str]:
        """Build the jshint CLI command."""
        cmd = ["jshint", path, "--reporter=unix"]

        config_file = config.get("config_file")
        if config_file:
            cmd.extend(["--config", config_file])

        return cmd

    def _parse_output(self, output: str) -> list[Finding]:
        """Parse jshint unix reporter output into findings.

        Format: file.js:10:1: message
        """
        findings = []
        for line in output.strip().splitlines():
            if not line.strip():
                continue
            finding = self._parse_line(line)
            if finding:
                findings.append(finding)
        return findings

    def _parse_line(self, line: str) -> Finding | None:
        """Parse a single jshint output line into a Finding."""
        # Format: file:line:col: message
        try:
            location_part, message_part = line.split(": ", 1)
            parts = location_part.rsplit(":", 2)
            if len(parts) < 3:
                return None

            file_path = parts[0]
            line_num = parts[1]
            location = f"{file_path}:{line_num}"

            return Finding(
                id="jshint",
                severity=Severity.INFO,
                title=message_part.strip(),
                description=message_part.strip(),
                location=location,
                scanner=self.name,
            )
        except (ValueError, IndexError):
            return None
