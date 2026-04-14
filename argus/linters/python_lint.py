"""Python linter wrapping flake8."""

import shutil
import subprocess

from argus.core.models import Finding, ScanResult, Severity


class PythonLinter:
    """Wraps flake8 to lint Python code for style and quality issues."""

    name = "lint-python"

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run flake8 against the given path and return results."""
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
        """Check if flake8 is installed."""
        return shutil.which("flake8") is not None

    def install_command(self) -> str | None:
        """Return install command for flake8."""
        return "pip install flake8"

    def _build_command(self, path: str, config: dict) -> list[str]:
        """Build the flake8 CLI command."""
        cmd = ["flake8", path, "--format=default"]

        max_line_length = config.get("max_line_length")
        if max_line_length:
            cmd.append(f"--max-line-length={max_line_length}")

        ignore = config.get("ignore")
        if ignore:
            ignore_str = ignore if isinstance(ignore, str) else ",".join(ignore)
            cmd.append(f"--ignore={ignore_str}")

        config_file = config.get("config_file")
        if config_file:
            cmd.append(f"--config={config_file}")

        return cmd

    def _parse_output(self, output: str) -> list[Finding]:
        """Parse flake8 default output into findings.

        Format: path/file.py:10:1: E501 line too long (82 > 79 characters)
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
        """Parse a single flake8 output line into a Finding."""
        # Format: file:line:col: CODE message
        try:
            location_part, message_part = line.split(": ", 1)
            parts = location_part.rsplit(":", 2)
            if len(parts) < 3:
                return None

            file_path = parts[0]
            line_num = parts[1]
            location = f"{file_path}:{line_num}"

            # Extract rule code (e.g., E501, W291)
            rule_code = message_part.split(" ", 1)[0] if message_part else "UNKNOWN"

            return Finding(
                id=rule_code,
                severity=Severity.INFO,
                title=message_part.strip(),
                description=message_part.strip(),
                location=location,
                scanner=self.name,
            )
        except (ValueError, IndexError):
            return None
