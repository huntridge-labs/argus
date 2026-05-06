"""Checkov infrastructure-as-code scanner."""

import json
import shutil
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity
from argus.core.scanner_template import ScanPaths, run_subprocess_scan
from argus.core.version import parse_tool_version


class CheckovScanner:
    """Wraps Checkov to scan IaC files for misconfigurations."""

    name = "checkov"
    description = "Infrastructure-as-code policy scanner — multi-framework (Terraform, K8s, CloudFormation)"
    category = "iac"
    languages = ["terraform", "kubernetes", "cloudformation"]
    container_image = get_image("checkov")
    # The official Checkov image uses ENTRYPOINT ["checkov"]; engine strips
    # argv[0] for ENTRYPOINT-based images.
    container_entrypoint = "checkov"

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run Checkov against the given path and return results."""
        return run_subprocess_scan(self, path, config)

    def build_args(self, paths: ScanPaths, config: dict) -> list[str]:
        """Build the full argv (including the binary name).

        Engine drops argv[0] when the container image declares an
        ENTRYPOINT, so the same method works for both local and
        container execution.

        Checkov writes JSON to stdout when given ``-o json``. The
        template's stdout fallback captures it and writes to the
        expected output file automatically.
        """
        args = [
            "checkov",
            "-d", paths.workspace,
            "-o", "json",
            "--quiet",
        ]
        framework = config.get("framework")
        if framework:
            args.extend(["--framework", framework])
        check = config.get("check")
        if check:
            args.extend(["--check", check])
        skip_check = config.get("skip_check")
        if skip_check:
            args.extend(["--skip-check", skip_check])
        return args

    def is_available(self) -> bool:
        """Check if Checkov is installed."""
        return shutil.which("checkov") is not None

    def install_command(self) -> str | None:
        """Return install command for Checkov."""
        return "pip install checkov"

    def tool_version(self) -> str | None:
        """Return the installed Checkov version, or None if not available."""
        if not self.is_available():
            return None
        return parse_tool_version(
            ["checkov", "--version"],
            r"(?:^|checkov )([0-9][\w.]*)",
            timeout=10,
        )

    def parse_results(self, raw_output_path: Path) -> tuple[list[Finding], int]:
        """Parse Checkov JSON output into findings and passed count."""
        text = raw_output_path.read_text().strip()
        if not text:
            return [], 0

        data = json.loads(text)

        # Checkov may return a list of results (one per framework)
        # or a single dict; normalize to list
        if isinstance(data, list):
            check_blocks = data
        else:
            check_blocks = [data]

        findings = []
        passed_count = 0
        for block in check_blocks:
            results = block.get("results", {})
            failed_checks = results.get("failed_checks", [])
            passed_checks = results.get("passed_checks", [])
            passed_count += len(passed_checks)
            findings.extend(
                self._parse_check(check) for check in failed_checks
            )

        return findings, passed_count

    def _parse_check(self, check: dict) -> Finding:
        """Convert a single Checkov failed check into a Finding."""
        raw_severity = check.get("severity", "")
        severity = (
            Severity.from_string(raw_severity) if raw_severity
            else Severity.MEDIUM
        )

        file_path = check.get("file_path", "")
        # Strip leading slash from file_path
        if file_path.startswith("/"):
            file_path = file_path[1:]

        line_range = check.get("file_line_range", [])
        start_line = line_range[0] if line_range else 0
        location = f"{file_path}:{start_line}" if file_path else None

        return Finding(
            id=check.get("check_id", "UNKNOWN"),
            severity=severity,
            title=check.get("check_name", ""),
            description=check.get("check_name", ""),
            location=location,
            scanner=self.name,
            metadata={
                "resource": check.get("resource", ""),
                "guideline": check.get("guideline", ""),
                "bc_check_id": check.get("bc_check_id", ""),
                "check_result": check.get("check_result", {}).get(
                    "result", ""
                ),
            },
        )
