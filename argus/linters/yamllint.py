"""YAML linter wrapping yamllint."""

import shutil
import subprocess
from pathlib import Path

from argus.core.models import Finding, ScanResult, Severity


class YamllintLinter:
    """Wraps yamllint to lint YAML files for syntax and style issues."""

    name = "lint-yaml"

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run yamllint against the given path and return results."""
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
        """Check if yamllint is installed."""
        return shutil.which("yamllint") is not None

    def install_command(self) -> str | None:
        """Return install command for yamllint."""
        return "pip install yamllint"

    def _build_command(self, path: str, config: dict) -> list[str]:
        """Build the yamllint CLI command."""
        cmd = ["yamllint", "--format", "parsable"]

        config_file = config.get("config_file")
        if config_file:
            cmd.extend(["-c", config_file])

        cmd.append(path)
        return cmd

    def _parse_output(self, output: str) -> list[Finding]:
        """Parse yamllint parsable output into findings.

        Format: file.yml:3:1: [error] syntax error (key-duplicates)
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
        """Parse a single yamllint output line into a Finding."""
        # Format: path:line:col: [level] message (rule)
        try:
            location_part, message_part = line.split(": ", 1)
            parts = location_part.rsplit(":", 2)
            if len(parts) < 3:
                return None

            file_path = parts[0]
            line_num = parts[1]
            location = f"{file_path}:{line_num}"

            # Extract rule name from parentheses if present
            rule_id = "yamllint"
            if "(" in message_part and message_part.endswith(")"):
                rule_id = message_part.rsplit("(", 1)[1].rstrip(")")

            return Finding(
                id=rule_id,
                severity=Severity.INFO,
                title=message_part.strip(),
                description=message_part.strip(),
                location=location,
                scanner=self.name,
            )
        except (ValueError, IndexError):
            return None
