"""SARIF 2.1.0 reporter — generate SARIF-formatted results."""

import json
from typing import Optional
from pathlib import Path

from argus.core.models import Severity, ScanSummary, ScanResult, Finding


_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)

_SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
    Severity.UNKNOWN: "none",
}

_DEFAULT_OUTPUT_DIR = Path("./argus-results")


class SarifReporter:
    """Generate SARIF 2.1.0 report."""

    def report(self, summary: ScanSummary, output_dir: Optional[Path] = None) -> Path:
        """Write SARIF report to output_dir/argus-results.sarif.

        Returns the path to the written file.
        """
        dest = Path(output_dir) if output_dir else _DEFAULT_OUTPUT_DIR
        dest.mkdir(parents=True, exist_ok=True)
        filepath = dest / "argus-results.sarif"

        sarif = self._build(summary)
        filepath.write_text(
            json.dumps(sarif, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return filepath

    def _build(self, summary: ScanSummary) -> dict:
        runs = [self._build_run(result) for result in summary.results]
        return {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": runs,
        }

    def _build_run(self, result: ScanResult) -> dict:
        rules_map: dict[str, dict] = {}
        sarif_results: list[dict] = []

        for finding in result.findings:
            # Build rule entry (deduplicated by rule id)
            if finding.id not in rules_map:
                rule = {
                    "id": finding.id,
                    "shortDescription": {"text": finding.title},
                }
                if finding.cwe:
                    rule["properties"] = {"tags": [f"CWE-{finding.cwe}"]}
                rules_map[finding.id] = rule

            sarif_results.append(self._build_result(finding))

        return {
            "tool": {
                "driver": {
                    "name": f"argus/{result.scanner}",
                    "rules": list(rules_map.values()),
                },
            },
            "results": sarif_results,
        }

    def _build_result(self, finding: Finding) -> dict:
        level = _SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "none")

        result: dict = {
            "ruleId": finding.id,
            "level": level,
            "message": {"text": finding.title},
        }

        if finding.description:
            result["message"]["text"] = (
                f"{finding.title}\n\n{finding.description}"
            )

        if finding.location:
            result["locations"] = [self._parse_location(finding.location)]

        return result

    def _parse_location(self, location: str) -> dict:
        """Parse a location string like 'path/file.py:42' into SARIF format."""
        uri = location
        line = None

        if ":" in location:
            parts = location.rsplit(":", 1)
            if parts[1].isdigit():
                uri = parts[0]
                line = int(parts[1])

        physical_location: dict = {
            "artifactLocation": {"uri": uri},
        }

        if line is not None:
            physical_location["region"] = {"startLine": line}

        return {"physicalLocation": physical_location}
