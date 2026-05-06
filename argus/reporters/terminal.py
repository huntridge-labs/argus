"""Terminal reporter — pretty stdout output using only stdlib."""

import sys
from typing import Optional
from pathlib import Path

from argus.core.models import Severity, ScanSummary, ScanResult, Finding


_SEVERITY_LABELS = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED ",
    Severity.LOW: "LOW ",
    Severity.INFO: "INFO",
    Severity.UNKNOWN: "UNKN",
}

# Display order: most severe first
_SEVERITY_DISPLAY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.UNKNOWN,
]


class TerminalReporter:
    """Print scan results as formatted tables to stdout."""

    def report(self, summary: ScanSummary, output_dir: Optional[Path] = None) -> None:
        """Print summary to terminal. output_dir is ignored."""
        self._print_header()
        self._print_summary_table(summary)
        self._print_scanner_results(summary)
        self._print_status(summary)

    def _print_header(self) -> None:
        border = "\u2550" * 43
        print(f"\n{border}")
        print("  Argus Security Scan Results")
        print(f"{border}\n")

    def _print_summary_table(self, summary: ScanSummary) -> None:
        headers = ["Critical", "High", "Medium", "Low", "Total"]
        values = [
            str(summary.critical_count),
            str(summary.high_count),
            str(summary.medium_count),
            str(summary.low_count),
            str(summary.total_count),
        ]

        col_widths = [
            max(len(h), len(v)) + 2
            for h, v in zip(headers, values)
        ]

        top = "\u250c" + "\u252c".join("\u2500" * w for w in col_widths) + "\u2510"
        mid = "\u251c" + "\u253c".join("\u2500" * w for w in col_widths) + "\u2524"
        bot = "\u2514" + "\u2534".join("\u2500" * w for w in col_widths) + "\u2518"

        header_row = "\u2502" + "\u2502".join(
            f" {h:<{w - 1}}" for h, w in zip(headers, col_widths)
        ) + "\u2502"
        value_row = "\u2502" + "\u2502".join(
            f" {v:<{w - 1}}" for v, w in zip(values, col_widths)
        ) + "\u2502"

        print("Summary:")
        print(top)
        print(header_row)
        print(mid)
        print(value_row)
        print(bot)
        print()

    def _print_scanner_results(self, summary: ScanSummary) -> None:
        for result in summary.results:
            if not result.findings:
                print(f"Scanner: {result.scanner} (0 findings)")
                print()
                continue

            print(f"Scanner: {result.scanner} ({result.total_count} findings)")

            sorted_findings = sorted(
                result.findings,
                key=lambda f: -f.severity._order,
            )

            for finding in sorted_findings:
                label = _SEVERITY_LABELS.get(finding.severity, "UNKN")
                location = f" {finding.location}" if finding.location else ""
                title = finding.title
                print(f"  {label}   {finding.id}{location} - {title}")

            print()

    def _print_status(self, summary: ScanSummary) -> None:
        # Three orthogonal signals get rendered here:
        #   * threshold outcome — drives Status: PASS / FAIL
        #   * scanner execution outcome — ran-or-not, surfaced as
        #     ``execution_failed`` by the engine and adapters
        #   * parse outcome — ran-and-produced-output-but-couldn't-be-
        #     interpreted, surfaced as ``parse_failed``
        # Each gets its own warning block carrying the scanner-specific
        # reason (engine collects ``execution_failure_reason`` /
        # ``parse_failure_reason`` per scanner). Generic "uid mismatch
        # / crashed / wrong entrypoint" boilerplate is *not* printed —
        # it was misleading for OSV exit-1-with-findings and yamllint
        # binary-not-found cases. The reason from the adapter wins.
        exec_failed = [
            r for r in summary.results
            if r.metadata.get("execution_failed")
        ]
        parse_failed = [
            r for r in summary.results
            if r.metadata.get("parse_failed")
        ]

        if exec_failed:
            print(f"Warning: {len(exec_failed)} scanner(s) did not run cleanly:")
            for r in exec_failed:
                reason = r.metadata.get(
                    "execution_failure_reason", "no reason recorded",
                )
                print(f"  - {r.scanner}: {reason}")
            print(
                "  Pass --fail-on-scanner-error to fail the scan when "
                "this happens."
            )

        if parse_failed:
            print(
                f"Warning: {len(parse_failed)} scanner(s) produced "
                f"output that could not be parsed:"
            )
            for r in parse_failed:
                reason = r.metadata.get(
                    "parse_failure_reason", "no reason recorded",
                )
                print(f"  - {r.scanner}: {reason}")
            print(
                "  This usually means a scanner output schema changed; "
                "report at https://github.com/huntridge-labs/argus/issues."
            )

        if summary.passed:
            if exec_failed or parse_failed:
                parts = []
                if exec_failed:
                    parts.append(f"{len(exec_failed)} did not run")
                if parse_failed:
                    parts.append(f"{len(parse_failed)} unparsable")
                print(f"Status: PASS (degraded — {', '.join(parts)})")
            else:
                print("Status: PASS")
        else:
            threshold = summary.severity_threshold.value if summary.severity_threshold else "none"
            print(f"Status: FAIL (findings above threshold: {threshold})")
        print()
