"""Container-specific markdown reporter for rich vulnerability reports.

Generates the collapsible, emoji-rich markdown format used by
scanner-container, with per-image breakdowns, per-scanner (Trivy/Grype)
subsections, and CVE tables.
"""

from pathlib import Path
from typing import Any, Optional

from argus.core.models import Finding, Severity


# The reporter consumes ContainerScanSummary / ContainerScanResult
# (from argus.container.scanner) but we type loosely via duck-typing
# to avoid circular imports.  The expected attributes are documented
# on each helper that accesses them.

SEVERITY_EMOJI = {
    Severity.CRITICAL: "\U0001f6a8",
    Severity.HIGH: "\u26a0\ufe0f",
    Severity.MEDIUM: "\U0001f7e1",
    Severity.LOW: "\U0001f535",
    Severity.INFO: "\u2139\ufe0f",
    Severity.UNKNOWN: "\u2753",
}

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

_DEFAULT_OUTPUT_DIR = Path("./argus-results")
_MAX_TABLE_ROWS = 50


class ContainerMarkdownReporter:
    """Generate rich container vulnerability scan markdown."""

    def report(
        self,
        summary: Any,
        output_dir: Optional[Path] = None,
        artifacts_url: str = "",
    ) -> Path:
        """Write container scan markdown to *output_dir*/container-scan.md.

        Parameters
        ----------
        summary:
            A ``ContainerScanSummary``-like object with ``results``,
            severity counts, ``container_count``, ``build_failures``,
            and ``unique_count`` attributes.
        output_dir:
            Directory to write the report into (created if missing).
        artifacts_url:
            Optional URL to link to uploaded artifacts.

        Returns the path to the written file.
        """
        dest = Path(output_dir) if output_dir else _DEFAULT_OUTPUT_DIR
        dest.mkdir(parents=True, exist_ok=True)
        filepath = dest / "container-scan.md"

        content = self._build(summary, artifacts_url)
        filepath.write_text(content, encoding="utf-8")
        return filepath

    # ------------------------------------------------------------------
    # Top-level builder (full multi-container report)
    # ------------------------------------------------------------------

    def _build(self, summary: Any, artifacts_url: str = "") -> str:
        lines: list[str] = []

        lines.append(
            "<details><summary>\U0001f433 Container Security Scan</summary>"
        )
        lines.append("")
        lines.append("**Status:** \u2705 Completed")
        lines.append("")

        lines.extend(self._build_combined_summary(summary))
        lines.extend(self._build_breakdown_table(summary))

        lines.append("### \U0001f50d Detailed Findings by Container")
        lines.append("")
        for result in summary.results:
            lines.extend(self._build_container_detail(result))

        if artifacts_url:
            lines.append(
                f"**\U0001f4c1 Artifacts:** "
                f"[Container Scan Reports]({artifacts_url})"
            )
            lines.append("")

        lines.append("</details>")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Single-container section (for CI matrix jobs)
    # ------------------------------------------------------------------

    def report_single(
        self,
        result: Any,
        output_dir: Optional[Path] = None,
    ) -> Path:
        """Write a single container's detail section to a named file.

        Produces just the per-container ``<details>`` block (no outer
        wrapper, no combined summary). Designed for CI matrix jobs
        where each container is scanned in a separate job and the
        results are combined later by ``build_combined_report``.
        """
        dest = Path(output_dir) if output_dir else _DEFAULT_OUTPUT_DIR
        dest.mkdir(parents=True, exist_ok=True)

        name = getattr(result, "name", "unknown")
        filepath = dest / f"{name}.md"
        content = "\n".join(self._build_container_detail(result))
        filepath.write_text(content, encoding="utf-8")
        return filepath

    @classmethod
    def build_combined_report(
        cls,
        section_files: list[Path],
        summary: Any,
        artifacts_url: str = "",
    ) -> str:
        """Combine per-container sections into a full report.

        Call this from the CI combine step after downloading all
        per-container markdown files from matrix job artifacts.

        Parameters
        ----------
        section_files:
            Paths to per-container markdown files (from ``report_single``).
        summary:
            A ``ContainerScanSummary`` with all results for the
            combined header and breakdown table.
        """
        reporter = cls()
        lines: list[str] = []

        lines.extend(reporter._build_combined_summary(summary))
        lines.extend(reporter._build_breakdown_table(summary))

        lines.append("### \U0001f50d Detailed Findings by Container")
        lines.append("")

        for path in sorted(section_files):
            if path.exists():
                lines.append(path.read_text(encoding="utf-8"))
                lines.append("")

        if artifacts_url:
            lines.append(
                f"**\U0001f4c1 Artifacts:** "
                f"[Container Scan Reports]({artifacts_url})"
            )
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Combined findings summary
    # ------------------------------------------------------------------

    def _build_combined_summary(self, summary: Any) -> list[str]:
        """Top-level severity counts across all containers."""
        lines: list[str] = []
        lines.append("### \U0001f4ca Combined Findings Summary")
        lines.append("")
        lines.append(
            "| \U0001f6a8 Critical | \u26a0\ufe0f High "
            "| \U0001f7e1 Medium | \U0001f535 Low "
            "| \U0001f4e6 Total | \U0001f522 Unique |"
        )
        lines.append(
            "|:-----------:|:-------:|:---------:|:------:|:--------:|:--------:|"
        )
        lines.append(
            f"| **{summary.critical_count}** "
            f"| **{summary.high_count}** "
            f"| **{summary.medium_count}** "
            f"| **{summary.low_count}** "
            f"| **{summary.total_count}** "
            f"| **{summary.unique_count}** |"
        )
        lines.append("")
        lines.append(
            f"**Scanned:** {summary.container_count} containers "
            f"| **Build Failures:** {summary.build_failures}"
        )
        lines.append("")
        return lines

    # ------------------------------------------------------------------
    # Per-container breakdown table
    # ------------------------------------------------------------------

    def _build_breakdown_table(self, summary: Any) -> list[str]:
        """Overview table with one row per container."""
        lines: list[str] = []
        lines.append("### \U0001f4e6 Container Breakdown")
        lines.append("")
        lines.append(
            "| Container | Image "
            "| \U0001f6a8 Crit | \u26a0\ufe0f High "
            "| \U0001f7e1 Med | \U0001f535 Low "
            "| Total | Unique | Status |"
        )
        lines.append(
            "|-----------|-------|:-------:|:-------:"
            "|:------:|:------:|:-----:|:------:|:------:|"
        )

        for result in summary.results:
            lines.append(self._breakdown_row(result))

        lines.append("")
        return lines

    def _breakdown_row(self, result: Any) -> str:
        status = self._result_status_label(result)

        if not getattr(result, "build_success", True):
            return (
                f"| {result.name} | - "
                f"| - | - | - | - | - | - | {status} |"
            )

        if getattr(result, "scan_error", ""):
            return (
                f"| {result.name} | `{result.image_ref}` "
                f"| - | - | - | - | - | - | {status} |"
            )

        return (
            f"| {result.name} | `{result.image_ref}` "
            f"| {result.critical_count} | {result.high_count} "
            f"| {result.medium_count} | {result.low_count} "
            f"| {result.total_count} | {result.unique_count} "
            f"| {status} |"
        )

    # ------------------------------------------------------------------
    # Detailed per-container section
    # ------------------------------------------------------------------

    def _build_container_detail(self, result: Any) -> list[str]:
        """Collapsible detail section for one container image."""
        lines: list[str] = []

        # Build failure
        if not getattr(result, "build_success", True):
            lines.append("<details>")
            lines.append(
                f"<summary>\u274c <strong>{result.name}</strong>"
                " - Build failed</summary>"
            )
            lines.append("")
            lines.append(f"Image build failed for `{result.image_ref}`")
            lines.append("")
            lines.append("</details>")
            lines.append("")
            return lines

        # Scan error
        scan_error = getattr(result, "scan_error", "")
        if scan_error:
            lines.append("<details>")
            lines.append(
                f"<summary>\u26a0\ufe0f <strong>{result.name}</strong>"
                " - Scan error</summary>"
            )
            lines.append("")
            lines.append(f"**Image:** `{result.image_ref}`")
            lines.append(f"**Error:** {scan_error}")
            lines.append("")
            lines.append("</details>")
            lines.append("")
            return lines

        icon = self._severity_icon(result)

        lines.append("<details>")
        lines.append(
            f"<summary>{icon} <strong>{result.name}</strong> "
            f"- {result.total_count} vulnerabilities "
            f"({result.unique_count} unique)</summary>"
        )
        lines.append("")
        lines.append(f"**Image:** `{result.image_ref}`")

        digest = getattr(result, "digest", "")
        if digest:
            lines.append(f"**Digest:** `{digest}`")

        lines.append("")

        # Combined dedup table
        lines.append("#### Combined (Deduplicated)")
        lines.append("")
        lines.append(
            "| \U0001f6a8 Critical | \u26a0\ufe0f High "
            "| \U0001f7e1 Medium | \U0001f535 Low "
            "| Total | Unique |"
        )
        lines.append(
            "|:-----------:|:-------:|:---------:|:------:|:-----:|:------:|"
        )
        lines.append(
            f"| **{result.critical_count}** "
            f"| **{result.high_count}** "
            f"| **{result.medium_count}** "
            f"| **{result.low_count}** "
            f"| **{result.total_count}** "
            f"| **{result.unique_count}** |"
        )
        lines.append("")

        # Trivy subsection
        trivy_findings = getattr(result, "trivy_findings", None)
        if trivy_findings is not None:
            lines.extend(
                self._build_scanner_section(
                    scanner_name="Trivy",
                    icon="\U0001f537",
                    findings=trivy_findings,
                )
            )

        # Grype subsection
        grype_findings = getattr(result, "grype_findings", None)
        if grype_findings is not None:
            lines.extend(
                self._build_scanner_section(
                    scanner_name="Grype",
                    icon="\u2693",
                    findings=grype_findings,
                )
            )

        lines.append("</details>")
        lines.append("")
        return lines

    # ------------------------------------------------------------------
    # Per-scanner findings subsection
    # ------------------------------------------------------------------

    def _build_scanner_section(
        self,
        scanner_name: str,
        icon: str,
        findings: list[Finding],
    ) -> list[str]:
        """Collapsible subsection for one scanner's findings."""
        lines: list[str] = []
        unique_count = len({f.cve or f.id for f in findings})

        lines.append("<details open>")
        lines.append(
            f"<summary>{icon} {scanner_name} Scanner "
            f"({len(findings)} findings, {unique_count} unique)</summary>"
        )
        lines.append("")

        if not findings:
            lines.append(
                f"\u2705 No vulnerabilities detected by {scanner_name}"
            )
        else:
            lines.extend(self._build_findings_table(findings))

        lines.append("</details>")
        lines.append("")
        return lines

    # ------------------------------------------------------------------
    # CVE findings table
    # ------------------------------------------------------------------

    def _build_findings_table(
        self,
        findings: list[Finding],
        max_rows: int = _MAX_TABLE_ROWS,
    ) -> list[str]:
        """Severity-sorted table of CVE findings."""
        lines: list[str] = []
        lines.append("| CVE | Severity | Package | Version | Fixed |")
        lines.append("|-----|----------|---------|---------|-------|")

        sorted_findings = sorted(
            findings,
            key=lambda f: (
                SEVERITY_ORDER.index(f.severity)
                if f.severity in SEVERITY_ORDER
                else 99
            ),
        )

        shown = sorted_findings[:max_rows]
        for finding in shown:
            emoji = SEVERITY_EMOJI.get(finding.severity, "\u2753")
            sev_label = finding.severity.value.upper()
            cve_id = finding.cve or finding.id
            pkg = finding.metadata.get(
                "package", finding.metadata.get("tool", "")
            )
            version = finding.metadata.get("installed_version", "")
            fixed = finding.metadata.get("fixed_version", "") or "N/A"
            lines.append(
                f"| {cve_id} | {emoji} {sev_label} "
                f"| {pkg} | {version} | {fixed} |"
            )

        remaining = len(findings) - len(shown)
        if remaining > 0:
            lines.append("")
            lines.append(f"_...and {remaining} more_")

        lines.append("")
        return lines

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _severity_icon(result: Any) -> str:
        """Pick the summary-line icon based on highest severity present."""
        if getattr(result, "critical_count", 0) > 0:
            return "\U0001f6a8"
        if getattr(result, "high_count", 0) > 0:
            return "\u26a0\ufe0f"
        if getattr(result, "total_count", 0) > 0:
            return "\U0001f7e1"
        return "\u2705"

    @staticmethod
    def _result_status_label(result: Any) -> str:
        """Return a short status string for the breakdown table."""
        if not getattr(result, "build_success", True):
            return "\u274c Build failed"
        if getattr(result, "scan_error", ""):
            return "\u26a0\ufe0f Scan error"
        return "\u2705"
