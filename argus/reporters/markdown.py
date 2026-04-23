"""Markdown reporter — generate summary report as markdown."""

import os
from typing import Optional
from pathlib import Path

from argus.core.models import Severity, ScanSummary, ScanResult, Finding


_SEVERITY_EMOJI = {
    Severity.CRITICAL: "\U0001f6a8",
    Severity.HIGH: "\u26a0\ufe0f",
    Severity.MEDIUM: "\U0001f7e1",
    Severity.LOW: "\U0001f535",
    Severity.INFO: "\u2139\ufe0f",
    Severity.UNKNOWN: "\u2753",
}

_DEFAULT_OUTPUT_DIR = Path("./argus-results")


class MarkdownReporter:
    """Generate markdown summary report."""

    def report(self, summary: ScanSummary, output_dir: Optional[Path] = None) -> Path:
        """Write markdown report to output_dir/argus-summary.md.

        Returns the path to the written file.
        """
        dest = Path(output_dir) if output_dir else _DEFAULT_OUTPUT_DIR
        dest.mkdir(parents=True, exist_ok=True)
        filepath = dest / "argus-summary.md"

        content = self._build(summary)
        filepath.write_text(content, encoding="utf-8")
        return filepath

    def _build(self, summary: ScanSummary) -> str:
        lines: list[str] = []
        lines.append("# Argus Security Scan Results\n")

        # Status badge
        status = "PASS \u2705" if summary.passed else "FAIL \u274c"
        lines.append(f"**Status**: {status}\n")

        if summary.severity_threshold:
            lines.append(
                f"**Threshold**: {summary.severity_threshold.value}\n"
            )

        # Summary table
        lines.append("## Summary\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        lines.append(
            f"| {_SEVERITY_EMOJI[Severity.CRITICAL]} Critical "
            f"| {summary.critical_count} |"
        )
        lines.append(
            f"| {_SEVERITY_EMOJI[Severity.HIGH]} High "
            f"| {summary.high_count} |"
        )
        lines.append(
            f"| {_SEVERITY_EMOJI[Severity.MEDIUM]} Medium "
            f"| {summary.medium_count} |"
        )
        lines.append(
            f"| {_SEVERITY_EMOJI[Severity.LOW]} Low "
            f"| {summary.low_count} |"
        )
        lines.append(f"| **Total** | **{summary.total_count}** |")
        lines.append("")

        # Combined deduplicated view — only makes sense when two or more
        # scanners produced findings against the same source (SBOM scans
        # with osv + grype + trivy are the canonical case). For single-
        # scanner runs the dedup is a no-op, so we skip the section to
        # avoid noise.
        combined_block = self._build_combined_section(summary)
        if combined_block:
            lines.extend(combined_block)
            lines.append("")

        # Per-scanner sections
        lines.append("## Scanner Results\n")
        for result in summary.results:
            lines.append(f"### {result.scanner} ({result.total_count} findings)\n")

            if not result.findings:
                lines.append("No findings.\n")
                continue

            # Collapsible details
            lines.append("<details>")
            lines.append(f"<summary>View {result.total_count} findings</summary>\n")

            sorted_findings = sorted(
                result.findings,
                key=lambda f: -f.severity._order,
            )

            lines.append("| Severity | ID | Location | Description |")
            lines.append("|----------|----|----------|-------------|")

            for finding in sorted_findings:
                emoji = _SEVERITY_EMOJI.get(finding.severity, "\u2753")
                sev = finding.severity.value.capitalize()
                location = finding.location or "-"
                # Escape pipes in description for table safety
                desc = finding.title.replace("|", "\\|")
                lines.append(
                    f"| {emoji} {sev} | {finding.id} | "
                    f"`{location}` | {desc} |"
                )

            lines.append("\n</details>\n")

        return "\n".join(lines)

    def _build_combined_section(self, summary: ScanSummary) -> list[str]:
        """Return markdown lines for a deduplicated combined findings block.

        Dedup key is ``(cve or id, location)``. When multiple scanners
        report the same CVE against the same package@version, they
        collapse into a single row annotated with the list of reporters.
        Returns an empty list when dedup wouldn't collapse anything
        (single scanner or findings across scanners share no overlap).
        """
        scanners_with_findings = [
            r for r in summary.results if r.findings
        ]
        if len(scanners_with_findings) < 2:
            return []

        bucket: dict[tuple, dict] = {}
        for result in scanners_with_findings:
            for f in result.findings:
                key = (f.cve or f.id, f.location or "")
                existing = bucket.get(key)
                if existing is None:
                    bucket[key] = {
                        "finding": f,
                        "reporters": {result.scanner},
                    }
                else:
                    existing["reporters"].add(result.scanner)

        deduped_total = len(bucket)
        raw_total = sum(len(r.findings) for r in scanners_with_findings)
        if deduped_total >= raw_total:
            # Nothing to dedup — the per-scanner sections already cover it.
            return []

        out: list[str] = [
            "## Combined Findings (Deduplicated)\n",
            (
                f"**Unique findings:** {deduped_total} "
                f"(from {raw_total} raw across "
                f"{len(scanners_with_findings)} scanners)\n"
            ),
            "<details>",
            f"<summary>View {deduped_total} deduplicated findings</summary>\n",
            "| Severity | ID | Location | Reported by |",
            "|----------|----|----------|-------------|",
        ]

        ordered = sorted(
            bucket.values(),
            key=lambda entry: (-entry["finding"].severity._order, entry["finding"].id),
        )
        for entry in ordered:
            f = entry["finding"]
            emoji = _SEVERITY_EMOJI.get(f.severity, "❓")
            sev = f.severity.value.capitalize()
            reporters = ", ".join(sorted(entry["reporters"]))
            location = f.location or "-"
            out.append(
                f"| {emoji} {sev} | {f.id} | `{location}` | {reporters} |"
            )
        out.append("\n</details>")
        return out
