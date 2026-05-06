"""YAML linter wrapping yamllint."""

import shutil
import subprocess

from argus.core.models import Finding, ScanResult, Severity


class YamllintLinter:
    """Wraps yamllint to lint YAML files for syntax and style issues."""

    name = "lint-yaml"
    description = "YAML syntax and style linter"
    category = "linter"
    languages = ["yaml"]

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run yamllint against the given path and return results.

        yamllint exit codes (per its docs):
          * 0 — no problems found
          * 1 — lint problems found (this is the expected happy path
            when violations exist; NOT an execution failure)
          * 2+ — yamllint itself failed to run (bad config file path,
            unreadable input, internal error). stderr carries the
            reason; stdout is empty in this case.

        Previously, exit ≥ 2 was silently dropped: ``_parse_output("")``
        returned ``[]`` and the caller saw a clean ``ScanResult`` with
        zero findings. The terminal reporter would then print
        ``Scanner: lint-yaml (0 findings)`` followed by ``Status: PASS``,
        masking a real execution failure. Now we set the
        ``execution_failed`` metadata flag (same shape the engine's
        container path produces) so the reporter's
        ``Warning: scanner produced no output`` block surfaces it and
        ``--fail-on-scanner-error`` correctly fails the run.
        """
        config = config or {}
        cmd = self._build_command(path, config)

        result = subprocess.run(cmd, capture_output=True, text=True)

        findings = self._parse_output(result.stdout)
        metadata: dict = {"returncode": result.returncode}
        # Exit ≥ 2 with no findings parsed = real runtime/config error.
        # Exit 1 with findings is the lint-violations-found happy path.
        if result.returncode > 1 and not findings:
            metadata["execution_failed"] = True
            metadata["execution_failure_reason"] = (
                f"yamllint exited {result.returncode}. "
                f"stderr: {(result.stderr or '').strip()[:400]}"
            )
        return ScanResult(
            scanner=self.name,
            findings=findings,
            metadata=metadata,
        )

    def is_available(self) -> bool:
        """Check if yamllint is installed."""
        return shutil.which("yamllint") is not None

    def install_command(self) -> str | None:
        """Return install command for yamllint."""
        return "pip install yamllint"

    def tool_version(self) -> str | None:
        """Return the installed yamllint version, or None if not available."""
        if not self.is_available():
            return None
        try:
            result = subprocess.run(
                ["yamllint", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            # Output: "yamllint X.Y.Z"
            text = result.stdout.strip()
            if not text:
                return None
            parts = text.splitlines()[0].split()
            if len(parts) >= 2 and parts[0] == "yamllint":
                return parts[1]
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return None

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
