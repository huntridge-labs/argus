"""Bandit SAST scanner for Python code."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity


class BanditScanner:
    """Wraps Bandit to scan Python code for security issues."""

    name = "bandit"
    description = "Python security linter — detects common vulnerabilities in Python code"
    category = "sast"
    languages = ["python"]
    container_image = get_image("bandit")

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

    def tool_version(self) -> str | None:
        """Return the installed Bandit version, or None if not available."""
        if not self.is_available():
            return None
        try:
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            # Output: "bandit X.Y.Z ..."
            for line in result.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "bandit":
                    return parts[1]
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return None

    def container_args(self, config: dict | None = None) -> list[str]:
        """Build container args from config -- mirrors _build_command.

        NOTE: The custom bandit image (ghcr.io/huntridge-labs/argus/
        scanner-bandit) uses ENTRYPOINT ["bandit"], so these args are
        appended directly to the bandit command.  Do NOT include the
        ``bandit`` executable name here; the container entrypoint
        already provides it.
        """
        config = config or {}
        args = [
            "-r", "/workspace",
            "-f", "json",
            "-o", "/output/results.json",
            "--exit-zero",
        ]
        exclude = config.get("exclude")
        if exclude:
            args.extend(["--exclude", exclude])
        config_file = config.get("config_file")
        if config_file:
            args.extend(["-c", f"/workspace/{config_file}"])
        return args

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse Bandit JSON output into findings."""
        data = json.loads(raw_output_path.read_text())
        results = data.get("results", [])

        return [self._parse_finding(item) for item in results]

    # Bandit tests that detect hardcoded credentials. Their ``issue_text``
    # interpolates the matched literal verbatim
    # (e.g. ``Possible hardcoded password: 'hunter2'``) and the ``code``
    # excerpt contains the offending source line — both leak the secret
    # to terminal output, exports, and (most acutely) the MCP server's
    # AI-assistant context. We redact both for these IDs.
    _HARDCODED_SECRET_TESTS = frozenset({
        "B105",   # hardcoded_password_string
        "B106",   # hardcoded_password_funcarg
        "B107",   # hardcoded_password_default
    })

    def _parse_finding(self, item: dict) -> Finding:
        """Convert a single Bandit result into a Finding.

        Redaction commitment: for the hardcoded-credential tests
        (B105 / B106 / B107) bandit's ``issue_text`` and ``code``
        fields contain the matched secret value literally. Both
        are replaced with the redaction placeholder before they
        reach the Finding — see ``argus/core/redact.py``.
        """
        from argus.core.redact import REDACTED_PLACEHOLDER

        severity = Severity.from_string(item.get("issue_severity", "UNKNOWN"))

        cwe = None
        issue_cwe = item.get("issue_cwe")
        if issue_cwe and "id" in issue_cwe:
            cwe = f"CWE-{issue_cwe['id']}"

        filename = item.get("filename", "")
        line_number = item.get("line_number", 0)
        location = f"{filename}:{line_number}" if filename else None

        test_id = item.get("test_id", "UNKNOWN")
        issue_text = item.get("issue_text", "")
        code_excerpt = item.get("code", "")

        if test_id in self._HARDCODED_SECRET_TESTS:
            # Strip the quoted literal from the message — bandit's
            # template is ``...: '<value>'``. Anchored to the colon-quote
            # boundary so we don't false-positive on messages with
            # other punctuation.
            import re
            issue_text = re.sub(
                r":\s*['\"][^'\"]*['\"]",
                f": {REDACTED_PLACEHOLDER}",
                issue_text,
            )
            code_excerpt = REDACTED_PLACEHOLDER

        return Finding(
            id=test_id,
            severity=severity,
            title=issue_text,
            description=issue_text,
            location=location,
            cwe=cwe,
            scanner=self.name,
            metadata={
                "test_name": item.get("test_name", ""),
                "confidence": item.get("issue_confidence", ""),
                "more_info": item.get("more_info", ""),
                "code": code_excerpt,
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
