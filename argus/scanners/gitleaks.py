"""Gitleaks secrets scanner."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity
from argus.core.version import parse_tool_version


class GitleaksScanner:
    """Wraps Gitleaks to scan repositories for leaked secrets."""

    name = "gitleaks"
    description = "Secret detection — scans git history and files for leaked credentials"
    category = "secrets"
    languages = ["all"]
    container_image = get_image("gitleaks")

    def container_args(self, config: dict | None = None) -> list[str]:
        """Build container args from config — mirrors _build_command."""
        config = config or {}
        args = [
            "detect", "--source", "/workspace",
            "--report-format", "json",
            "--report-path", "/output/results.json",
            "--exit-code", "0",
        ]
        config_file = config.get("config_file")
        if config_file:
            args.extend(["--config", f"/workspace/{config_file}"])
        return args

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run Gitleaks against the given path and return results."""
        config = config or {}

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_file = Path(tmp_dir) / "gitleaks-results.json"
            cmd = self._build_command(path, output_file, config)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )

            # --exit-code 0 means gitleaks always exits 0
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
        """Check if Gitleaks is installed."""
        return shutil.which("gitleaks") is not None

    def install_command(self) -> str | None:
        """Return install command for Gitleaks."""
        return "Install from https://github.com/gitleaks/gitleaks"

    def tool_version(self) -> str | None:
        """Return the installed Gitleaks version, or None if not available."""
        if not self.is_available():
            return None
        return parse_tool_version(["gitleaks", "version"], r"v?([0-9]\S*)")

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse Gitleaks JSON output into findings."""
        text = raw_output_path.read_text().strip()
        if not text:
            return []

        data = json.loads(text)

        # Gitleaks outputs a JSON array, not an object
        if not isinstance(data, list):
            return []

        return [self._parse_finding(item) for item in data]

    def _parse_finding(self, item: dict) -> Finding:
        """Convert a single Gitleaks result into a Finding.

        All secrets findings are HIGH severity — leaked credentials
        are always a high-priority issue.

        Redaction commitment: the actual secret value (``Match`` /
        ``Secret`` fields in Gitleaks's JSON) NEVER lands in the
        Finding. Same for committer email/name (PII), commit message
        (may contain credentials in rollbacks), and date (correlation
        risk). What we keep:

        - ``rule_id``: identifies the secret *type* (e.g.
          ``github-pat``) — safer + more useful than a raw prefix.
        - ``commit``: SHA only. Public once code is shared.
        - ``fingerprint``: Gitleaks's own deterministic identifier,
          safe to log and search across runs.
        - ``match_length``: integer length of the original secret,
          for the rare diagnostic case where two adjacent rules
          would otherwise be indistinguishable.
        - location ``file:line``: enough to find the right place to
          rotate the credential.

        Downstream consumers (terminal reporter, JSON export,
        Markdown export, MCP tool responses, AI-assistant context)
        therefore see no leakable content. See ``argus/core/redact.py``
        for the wider rationale.
        """
        from argus.core.redact import redact_secret

        file_path = item.get("File", "")
        start_line = item.get("StartLine", 0)
        location = f"{file_path}:{start_line}" if file_path else None

        raw_match = item.get("Match", "") or item.get("Secret", "")

        return Finding(
            id=item.get("RuleID", "UNKNOWN"),
            severity=Severity.HIGH,
            title=item.get("Description", "Secret detected"),
            description=item.get("Description", ""),
            location=location,
            scanner=self.name,
            metadata={
                "commit": item.get("Commit", ""),
                "rule_id": item.get("RuleID", ""),
                "fingerprint": item.get("Fingerprint", ""),
                "match": redact_secret(raw_match),
                "match_length": len(raw_match) if raw_match else 0,
                "end_line": item.get("EndLine", 0),
            },
        )

    def _build_command(
        self, path: str, output_file: Path, config: dict
    ) -> list[str]:
        """Build the Gitleaks CLI command."""
        cmd = [
            "gitleaks",
            "detect",
            "--source", path,
            "--report-format", "json",
            "--report-path", str(output_file),
            "--exit-code", "0",
        ]

        config_file = config.get("config_file")
        if config_file:
            cmd.extend(["--config", config_file])

        return cmd
