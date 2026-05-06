"""Bandit SAST scanner for Python code."""

import json
import re
import shutil
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity
from argus.core.redact import REDACTED_PLACEHOLDER
from argus.core.scanner_template import ScanPaths, run_subprocess_scan
from argus.core.version import parse_tool_version


# Bandit tests that detect hardcoded credentials. Their ``issue_text``
# interpolates the matched literal verbatim
# (e.g. ``Possible hardcoded password: 'hunter2'``) and the ``code``
# excerpt contains the offending source line — both leak the secret to
# terminal output, exports, and (most acutely) the MCP server's
# AI-assistant context. We redact both for these IDs.
_HARDCODED_SECRET_TESTS = frozenset({
    "B105",   # hardcoded_password_string
    "B106",   # hardcoded_password_funcarg
    "B107",   # hardcoded_password_default
})

_QUOTED_LITERAL_RE = re.compile(r":\s*['\"][^'\"]*['\"]")


class BanditScanner:
    """Wraps Bandit to scan Python code for security issues."""

    name = "bandit"
    description = "Python security linter — detects common vulnerabilities in Python code"
    category = "sast"
    languages = ["python"]
    container_image = get_image("bandit")
    # The custom argus bandit image uses ENTRYPOINT ["bandit"]; engine
    # strips argv[0] for ENTRYPOINT-based images.
    container_entrypoint = "bandit"

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run Bandit against *path* and return results."""
        return run_subprocess_scan(self, path, config)

    def build_args(self, paths: ScanPaths, config: dict) -> list[str]:
        """Build the full argv (including the binary name).

        Engine drops argv[0] when the container image declares an
        ENTRYPOINT, so the same method works for both local and
        container execution.
        """
        args = [
            "bandit",
            "-r", paths.workspace,
            "-f", "json",
            "-o", paths.output,
            "--exit-zero",
        ]
        config_file = config.get("config_file")
        if config_file:
            # Local: caller passes the host path; container: prefix
            # /workspace/ since the file is mounted there.
            args.extend(["-c", config_file if "/" in config_file else f"{paths.workspace}/{config_file}"])
        exclude = config.get("exclude")
        if exclude:
            args.extend(["--exclude", exclude])
        return args

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
        return parse_tool_version(["bandit", "--version"], r"^bandit (\S+)")

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse Bandit JSON output into findings."""
        data = json.loads(raw_output_path.read_text(encoding="utf-8", errors="replace"))
        return [self._parse_finding(item) for item in data.get("results", [])]

    def _parse_finding(self, item: dict) -> Finding:
        """Convert a single Bandit result into a Finding.

        Redaction commitment: for the hardcoded-credential tests
        (B105 / B106 / B107) bandit's ``issue_text`` and ``code`` fields
        contain the matched secret value literally. Both are replaced
        with the redaction placeholder before they reach the Finding —
        see ``argus/core/redact.py``.
        """
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

        if test_id in _HARDCODED_SECRET_TESTS:
            issue_text = _QUOTED_LITERAL_RE.sub(
                f": {REDACTED_PLACEHOLDER}", issue_text,
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
