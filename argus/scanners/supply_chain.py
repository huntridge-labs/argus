"""Supply chain scanner wrapping zizmor and actionlint."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity

# zizmor security-severity score thresholds
_ZIZMOR_CRITICAL_THRESHOLD = 9.0
_ZIZMOR_HIGH_THRESHOLD = 7.0
_ZIZMOR_MEDIUM_THRESHOLD = 4.0


def _severity_from_score(score: float) -> Severity:
    """Map a CVSS-style security-severity score to a Severity level."""
    if score >= _ZIZMOR_CRITICAL_THRESHOLD:
        return Severity.CRITICAL
    if score >= _ZIZMOR_HIGH_THRESHOLD:
        return Severity.HIGH
    if score >= _ZIZMOR_MEDIUM_THRESHOLD:
        return Severity.MEDIUM
    return Severity.LOW


class SupplyChainScanner:
    """Wraps zizmor and actionlint to scan GitHub Actions workflows."""

    name = "supply-chain"
    container_image = get_image("supply-chain")

    def container_args(self, config: dict | None = None) -> list[str]:
        """Return CLI args for running zizmor+actionlint in a container."""
        return [
            "sh", "-c",
            "zizmor --format sarif /workspace/.github/ > /output/zizmor.json 2>/dev/null; "
            "actionlint -format '{{json .}}' /workspace/.github/workflows/ > /output/actionlint.json 2>/dev/null || true",
        ]

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run zizmor and actionlint against the given path."""
        config = config or {}
        all_findings: list[Finding] = []
        metadata: dict = {}

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Run zizmor if available
            if shutil.which("zizmor") is not None:
                zizmor_output = tmp_path / "zizmor-results.json"
                zizmor_findings, zizmor_meta = self._run_zizmor(
                    path, zizmor_output
                )
                all_findings.extend(zizmor_findings)
                metadata["zizmor"] = zizmor_meta

            # Run actionlint if available
            if shutil.which("actionlint") is not None:
                actionlint_output = tmp_path / "actionlint-results.json"
                actionlint_findings, actionlint_meta = self._run_actionlint(
                    path, actionlint_output
                )
                all_findings.extend(actionlint_findings)
                metadata["actionlint"] = actionlint_meta

            if not metadata:
                metadata["error"] = (
                    "Neither zizmor nor actionlint is installed"
                )

        return ScanResult(
            scanner=self.name,
            findings=all_findings,
            metadata=metadata,
        )

    def is_available(self) -> bool:
        """Check if at least one of zizmor or actionlint is installed."""
        return (
            shutil.which("zizmor") is not None
            or shutil.which("actionlint") is not None
        )

    def install_command(self) -> str | None:
        """Return install commands for zizmor and actionlint."""
        return (
            "cargo install zizmor && go install "
            "github.com/rhysd/actionlint/cmd/actionlint@latest"
        )

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse combined results. Detects format automatically.

        For explicit parsing, use parse_zizmor_results or
        parse_actionlint_results directly.
        """
        data = json.loads(raw_output_path.read_text())

        # SARIF format (zizmor)
        if "$schema" in data or "runs" in data:
            return self.parse_zizmor_results(raw_output_path)

        # JSON array (actionlint)
        if isinstance(data, list):
            return self.parse_actionlint_results(raw_output_path)

        return []

    def parse_zizmor_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse zizmor SARIF output into findings."""
        data = json.loads(raw_output_path.read_text())
        findings: list[Finding] = []

        for run in data.get("runs", []):
            rules_by_id = self._build_rules_map(run)
            results = run.get("results", [])

            for result in results:
                finding = self._parse_zizmor_finding(result, rules_by_id)
                findings.append(finding)

        return findings

    def parse_actionlint_results(
        self, raw_output_path: Path
    ) -> list[Finding]:
        """Parse actionlint JSON output into findings."""
        data = json.loads(raw_output_path.read_text())
        if not isinstance(data, list):
            return []

        return [self._parse_actionlint_finding(item) for item in data]

    def _run_zizmor(
        self, path: str, output_file: Path
    ) -> tuple[list[Finding], dict]:
        """Execute zizmor and return findings plus run metadata."""
        github_dir = Path(path) / ".github"
        cmd = [
            "zizmor",
            "--format", "sarif",
            str(github_dir),
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        if result.stdout.strip():
            output_file.write_text(result.stdout)

        meta = {"returncode": result.returncode}

        if not output_file.exists():
            meta["error"] = result.stderr.strip() or "No output produced"
            return [], meta

        findings = self.parse_zizmor_results(output_file)
        return findings, meta

    def _run_actionlint(
        self, path: str, output_file: Path
    ) -> tuple[list[Finding], dict]:
        """Execute actionlint and return findings plus run metadata."""
        workflows_dir = Path(path) / ".github" / "workflows"
        cmd = [
            "actionlint",
            "-format", "{{json .}}",
            str(workflows_dir),
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        output_text = result.stdout.strip()
        meta = {"returncode": result.returncode}

        if not output_text:
            meta["info"] = "No findings"
            return [], meta

        # actionlint outputs one JSON object per line; wrap as array
        lines = output_text.splitlines()
        json_array = "[" + ",".join(lines) + "]"
        output_file.write_text(json_array)

        findings = self.parse_actionlint_results(output_file)
        return findings, meta

    def _build_rules_map(self, run: dict) -> dict[str, dict]:
        """Build a rule-id to rule-properties map from a SARIF run."""
        driver = run.get("tool", {}).get("driver", {})
        rules = driver.get("rules", [])
        return {rule["id"]: rule for rule in rules if "id" in rule}

    def _parse_zizmor_finding(
        self, result: dict, rules_by_id: dict
    ) -> Finding:
        """Convert a single zizmor SARIF result into a Finding."""
        rule_id = result.get("ruleId", "UNKNOWN")
        rule = rules_by_id.get(rule_id, {})
        properties = rule.get("properties", {})

        score_str = properties.get("security-severity", "0")
        try:
            score = float(score_str)
        except (ValueError, TypeError):
            score = 0.0

        severity = _severity_from_score(score)
        message = result.get("message", {}).get("text", "")
        location = self._extract_sarif_location(result)

        return Finding(
            id=rule_id,
            severity=severity,
            title=rule.get("shortDescription", {}).get("text", rule_id),
            description=message,
            location=location,
            scanner=self.name,
            metadata={
                "tool": "zizmor",
                "security_severity": score,
                "level": result.get("level", ""),
            },
        )

    def _extract_sarif_location(self, result: dict) -> str | None:
        """Extract file:line location from a SARIF result."""
        locations = result.get("locations", [])
        if not locations:
            return None

        physical = locations[0].get("physicalLocation", {})
        artifact = physical.get("artifactLocation", {})
        uri = artifact.get("uri", "")
        region = physical.get("region", {})
        line = region.get("startLine", 0)

        if uri:
            return f"{uri}:{line}" if line else uri
        return None

    def _parse_actionlint_finding(self, item: dict) -> Finding:
        """Convert a single actionlint result into a Finding."""
        filepath = item.get("filepath", "")
        line = item.get("line", 0)
        location = f"{filepath}:{line}" if filepath else None

        return Finding(
            id=f"actionlint-{item.get('kind', 'unknown')}",
            severity=Severity.LOW,
            title=item.get("message", ""),
            description=item.get("message", ""),
            location=location,
            scanner=self.name,
            metadata={
                "tool": "actionlint",
                "kind": item.get("kind", ""),
                "column": item.get("column", 0),
            },
        )
