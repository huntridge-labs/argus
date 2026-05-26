"""gosec SAST scanner for Go code.

gosec is to Go what Bandit is to Python: a language-native static
analysis tool that inspects the Go AST for security anti-patterns
(G101 hardcoded credentials, G201 SQL string-formatting, G304 file
path traversal, etc.). It ships richer, semantic rules than the
pattern-based opengrep coverage Argus relied on for Go before.
"""

import json
import shutil
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity
from argus.core.redact import redact_secret, redact_secret_in_message
from argus.core.scanner_template import ScanPaths, run_subprocess_scan
from argus.core.version import parse_tool_version


# gosec rules that flag hardcoded credentials. Their ``code`` excerpt is
# the offending Go source line (e.g. ``const apiKey = "AKIA…"``) and the
# ``details`` string can interpolate the literal — both leak the secret
# to terminal output, exports, and the MCP server's AI-assistant
# context. We redact the ``code`` field and scrub any occurrence of the
# literal from ``details`` for these IDs. Mirrors the Bandit
# B105/B106/B107 handling.
_HARDCODED_SECRET_RULES = frozenset({
    "G101",   # Look for hardcoded credentials
})


class GosecScanner:
    """Wraps gosec to scan Go code for security issues."""

    name = "gosec"
    description = "Go security linter — detects common vulnerabilities in Go code"
    category = "sast"
    languages = ["go"]
    container_image = get_image("gosec")
    # The securego/gosec image uses ENTRYPOINT ["gosec"]; the engine
    # strips argv[0] for ENTRYPOINT-based images.
    container_entrypoint = "gosec"

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run gosec against *path* and return results."""
        return run_subprocess_scan(self, path, config)

    def build_args(self, paths: ScanPaths, config: dict) -> list[str]:
        """Build the full argv (including the binary name).

        Engine drops argv[0] when the container image declares an
        ENTRYPOINT, so the same method works for both local and
        container execution. ``-no-fail`` keeps the exit code at 0 even
        when findings exist so the template treats the run as the happy
        path (gosec otherwise exits non-zero on any finding).
        """
        args = [
            "gosec",
            "-fmt=json",
            f"-out={paths.output}",
            "-no-fail",
        ]
        config_file = config.get("config_file")
        if config_file:
            # Local: caller passes the host path; container: prefix the
            # workspace mount since the file is mounted there.
            resolved = (
                config_file if "/" in config_file
                else f"{paths.workspace}/{config_file}"
            )
            args.extend(["-conf", resolved])
        exclude = config.get("exclude")
        if exclude:
            args.extend(["-exclude", exclude])
        # gosec scans Go packages recursively from the target directory.
        args.append(f"{paths.workspace}/...")
        return args

    def is_available(self) -> bool:
        """Check if gosec is installed."""
        return shutil.which("gosec") is not None

    def install_command(self) -> str | None:
        """Return install command for gosec."""
        return "go install github.com/securego/gosec/v2/cmd/gosec@latest"

    def tool_version(self) -> str | None:
        """Return the installed gosec version, or None if not available."""
        if not self.is_available():
            return None
        return parse_tool_version(["gosec", "-version"], r"Version:\s*(\S+)")

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse gosec JSON output into findings."""
        data = json.loads(
            raw_output_path.read_text(encoding="utf-8", errors="replace")
        )
        return [self._parse_finding(item) for item in data.get("Issues", [])]

    def _parse_finding(self, item: dict) -> Finding:
        """Convert a single gosec issue into a Finding.

        Redaction commitment: for the hardcoded-credential rule (G101)
        gosec's ``code`` excerpt is the offending Go source line and the
        matched literal may appear in ``details``. Both are scrubbed
        before they reach the Finding — see ``argus/core/redact.py``.
        """
        severity = Severity.from_string(item.get("severity", "UNKNOWN"))

        cwe = None
        cwe_obj = item.get("cwe")
        if isinstance(cwe_obj, dict) and cwe_obj.get("id"):
            cwe = f"CWE-{cwe_obj['id']}"

        filename = item.get("file", "")
        line = item.get("line", "")
        location = f"{filename}:{line}" if filename else None

        rule_id = item.get("rule_id", "UNKNOWN")
        details = item.get("details", "")
        code_excerpt = item.get("code", "")

        if rule_id in _HARDCODED_SECRET_RULES:
            # The code excerpt is the literal source line containing the
            # secret — drop it entirely. Then scrub the raw excerpt from
            # the human-readable details in case it was interpolated.
            details = redact_secret_in_message(details, code_excerpt)
            code_excerpt = redact_secret(code_excerpt)

        return Finding(
            id=rule_id,
            severity=severity,
            title=details,
            description=details,
            location=location,
            cwe=cwe,
            scanner=self.name,
            metadata={
                "confidence": item.get("confidence", ""),
                "rule_id": rule_id,
                "column": item.get("column", ""),
                "code": code_excerpt,
            },
        )
