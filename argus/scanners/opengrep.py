"""OpenGrep (semgrep fork) SAST scanner."""

import json
import shutil
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity
from argus.core.scanner_template import ScanPaths, run_subprocess_scan
from argus.core.version import parse_tool_version


class OpengrepScanner:
    """Wraps OpenGrep to scan code for security issues using pattern matching."""

    name = "opengrep"
    description = "Pattern-based SAST — fast multi-language static analysis (semgrep-compatible)"
    category = "sast"
    languages = ["python", "javascript", "typescript", "go", "java", "ruby", "c", "cpp"]
    container_image = get_image("semgrep")

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run OpenGrep against the given path and return results."""
        return run_subprocess_scan(self, path, config)

    def build_args(self, paths: ScanPaths, config: dict) -> list[str]:
        """Build the full argv (including the binary name).

        Note: local execution uses the ``opengrep`` binary; container
        execution (semgrep image) uses ``semgrep scan`` — if you need
        the semgrep image to work, override ``container_args`` or set
        the container image to one that ships the ``opengrep`` binary.
        """
        args = [
            "opengrep",
            "--json",
            "--output", paths.output,
        ]
        rules_config = config.get("config")
        if rules_config:
            args.extend(["--config", rules_config])
        args.append(paths.workspace)
        return args

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
        return parse_tool_version(["opengrep", "--version"], r"(\d+\.\d+\.\S+)")

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
