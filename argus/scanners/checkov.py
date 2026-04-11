"""Checkov infrastructure-as-code scanner."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity


class CheckovScanner:
    """Wraps Checkov to scan IaC files for misconfigurations."""

    name = "checkov"
    container_image = get_image("checkov")

    def container_args(self, config: dict | None = None) -> list[str]:
        """Build container args from config — mirrors _build_command."""
        config = config or {}
        args = ["-d", "/workspace", "-o", "json", "--quiet", "--output-file-path", "/output"]
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

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run Checkov against the given path and return results."""
        config = config or {}

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_file = Path(tmp_dir) / "checkov-results.json"
            cmd = self._build_command(path, config)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )

            # Checkov outputs JSON to stdout with -o json
            if result.stdout.strip():
                output_file.write_text(result.stdout)
            elif result.returncode != 0:
                return ScanResult(
                    scanner=self.name,
                    metadata={
                        "error": result.stderr.strip(),
                        "returncode": result.returncode,
                    },
                )
            else:
                return ScanResult(
                    scanner=self.name,
                    metadata={"error": "No output produced"},
                )

            findings = self.parse_results(output_file)
            return ScanResult(
                scanner=self.name,
                findings=findings,
                raw_report=output_file,
            )

    def is_available(self) -> bool:
        """Check if Checkov is installed."""
        return shutil.which("checkov") is not None

    def install_command(self) -> str | None:
        """Return install command for Checkov."""
        return "pip install checkov"

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse Checkov JSON output into findings."""
        text = raw_output_path.read_text().strip()
        if not text:
            return []

        data = json.loads(text)

        # Checkov may return a list of results (one per framework)
        # or a single dict; normalize to list
        if isinstance(data, list):
            check_blocks = data
        else:
            check_blocks = [data]

        findings = []
        for block in check_blocks:
            results = block.get("results", {})
            failed_checks = results.get("failed_checks", [])
            findings.extend(
                self._parse_check(check) for check in failed_checks
            )

        return findings

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

    def _build_command(self, path: str, config: dict) -> list[str]:
        """Build the Checkov CLI command."""
        cmd = [
            "checkov",
            "-d", path,
            "-o", "json",
            "--quiet",
        ]

        framework = config.get("framework")
        if framework:
            cmd.extend(["--framework", framework])

        check = config.get("check")
        if check:
            cmd.extend(["--check", check])

        skip_check = config.get("skip_check")
        if skip_check:
            cmd.extend(["--skip-check", skip_check])

        return cmd
