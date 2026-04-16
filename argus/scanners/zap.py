"""OWASP ZAP DAST scanner."""

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity

_RISKCODE_MAP = {
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
}


def _strip_html(text: str) -> str:
    """Remove HTML tags from a string."""
    return re.sub(r"<[^>]+>", "", text).strip()


class ZapScanner:
    """Wraps OWASP ZAP to perform dynamic application security testing."""

    name = "zap"
    container_image = get_image("zap")

    def container_args(self, config: dict | None = None) -> list[str]:
        """Return CLI args for running ZAP in a container."""
        target = (config or {}).get("target_url", "http://localhost:3000")
        return ["zap-baseline.py", "-t", target, "-J", "/output/results.json", "-I"]

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run ZAP quick-scan against a target URL and return results.

        Requires config["target_url"] to specify the scan target.
        The path argument is ignored for DAST scanning.
        """
        config = config or {}
        target_url = config.get("target_url")

        if not target_url:
            return ScanResult(
                scanner=self.name,
                metadata={"error": "target_url is required in config"},
            )

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_file = Path(tmp_dir) / "zap-results.json"
            cmd = self._build_command(target_url, output_file, config)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )

            if not output_file.exists():
                return ScanResult(
                    scanner=self.name,
                    metadata={
                        "error": (
                            result.stderr.strip()
                            or "No output file produced"
                        ),
                        "returncode": result.returncode,
                    },
                )

            findings = self.parse_results(output_file)
            return ScanResult(
                scanner=self.name,
                findings=findings,
                raw_report=output_file,
            )

    def is_available(self) -> bool:
        """Check if ZAP CLI is installed."""
        return shutil.which("zap-cli") is not None

    def install_command(self) -> str | None:
        """Return install command for ZAP CLI."""
        return "pip install python-owasp-zap-v2.4"

    def tool_version(self) -> str | None:
        """Return None — ZAP runs exclusively via Docker container."""
        return None

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse ZAP JSON output into findings."""
        data = json.loads(raw_output_path.read_text())
        findings: list[Finding] = []

        for site in data.get("site", []):
            alerts = site.get("alerts", [])
            for alert in alerts:
                finding = self._parse_alert(alert)
                findings.append(finding)

        return findings

    def _parse_alert(self, alert: dict) -> Finding:
        """Convert a single ZAP alert into a Finding."""
        riskcode = str(alert.get("riskcode", "0"))
        severity = _RISKCODE_MAP.get(riskcode, Severity.UNKNOWN)

        cweid = alert.get("cweid", "")
        cwe = f"CWE-{cweid}" if cweid and cweid != "0" else None

        location = self._extract_location(alert)
        raw_desc = alert.get("desc", "")
        description = _strip_html(raw_desc)

        return Finding(
            id=alert.get("pluginid", "UNKNOWN"),
            severity=severity,
            title=alert.get("name", ""),
            description=description,
            location=location,
            cwe=cwe,
            scanner=self.name,
            metadata={
                "riskdesc": alert.get("riskdesc", ""),
                "solution": _strip_html(alert.get("solution", "")),
                "instance_count": len(alert.get("instances", [])),
            },
        )

    def _extract_location(self, alert: dict) -> str | None:
        """Extract location from the first alert instance."""
        instances = alert.get("instances", [])
        if not instances:
            return None

        first = instances[0]
        uri = first.get("uri", "")
        method = first.get("method", "")

        if uri and method:
            return f"{method} {uri}"
        return uri or None

    def _build_command(
        self, target_url: str, output_file: Path, config: dict
    ) -> list[str]:
        """Build the ZAP CLI command."""
        cmd = [
            "zap-cli",
            "quick-scan",
            "--self-contained",
            "--start-options",
            "-config api.disablekey=true",
            "-f", "json",
            "-o", str(output_file),
        ]

        spider = config.get("spider", False)
        if spider:
            cmd.append("--spider")

        cmd.append(target_url)
        return cmd
