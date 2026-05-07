"""GitHub Actions annotation reporter.

Emits ``::error::``, ``::warning::``, and ``::notice::`` workflow
commands to stdout, one per finding. When run inside a GitHub Actions
job these become inline annotations on the PR diff and the workflow
summary page.

Severity mapping:
    CRITICAL, HIGH   -> ``error``
    MEDIUM           -> ``warning``
    LOW, INFO, UNKNOWN -> ``notice``

Title prefix is ``[<scanner>][<id>]`` so the annotation is
self-describing even when many scanners run in the same step.

Limitation: GitHub caps annotations at 10 per kind (error/warning/
notice) per step. Findings beyond the cap will still be printed but
will not surface as annotations in the GitHub UI. The full set is
always present in ``argus-results.json`` and the SARIF artifact.
"""

import sys
from pathlib import Path
from typing import Optional, TextIO

from argus.core.models import Finding, ScanSummary, Severity


_SEVERITY_TO_ANNOTATION = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "notice",
    Severity.INFO: "notice",
    Severity.UNKNOWN: "notice",
}


def _escape(value: str) -> str:
    """Escape characters that have meaning in workflow command syntax.

    GitHub's workflow command parser uses ``%`` as an escape prefix and
    treats raw newlines/CRs as command terminators. The official
    encoding is documented at:
    https://docs.github.com/en/actions/using-workflows/workflow-commands
    """
    return (
        value.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


class GitHubReporter:
    """Emit GitHub Actions annotations to stdout."""

    def report(
        self,
        summary: ScanSummary,
        output_dir: Optional[Path] = None,
        stream: Optional[TextIO] = None,
    ) -> None:
        """Print one annotation line per finding.

        ``output_dir`` is accepted for protocol compatibility but
        unused — GitHub annotations are read from stdout, not from a
        file artifact.
        """
        out = stream if stream is not None else sys.stdout

        for result in summary.results:
            for finding in result.findings:
                line = self._format_annotation(result.scanner, finding)
                print(line, file=out)

    def _format_annotation(self, scanner: str, finding: Finding) -> str:
        level = _SEVERITY_TO_ANNOTATION.get(finding.severity, "notice")
        path, line_no, col_no = self._parse_location(finding.location)

        params: list[str] = []
        if path:
            params.append(f"file={_escape(path)}")
        if line_no is not None:
            params.append(f"line={line_no}")
        if col_no is not None:
            params.append(f"col={col_no}")

        param_str = ",".join(params)
        title = f"[{scanner}][{finding.id}] {finding.title}"
        message = _escape(title)

        if param_str:
            return f"::{level} {param_str}::{message}"
        return f"::{level}::{message}"

    def _parse_location(
        self, location: Optional[str]
    ) -> tuple[Optional[str], Optional[int], Optional[int]]:
        """Split ``path:line:col`` (or ``path:line``) into pieces.

        Returns ``(path, line, col)``. Any component that wasn't
        present, or wasn't a valid integer, is returned as ``None``.
        Trailing ``:`` segments that aren't integers are folded back
        into the path so ``C:\\Windows\\file.txt`` doesn't lose its
        drive prefix.
        """
        if not location:
            return None, None, None

        parts = location.split(":")
        if len(parts) == 1:
            return parts[0], None, None

        # Walk from the right collecting numeric segments. Stop at
        # the first non-numeric — everything before that is the path
        # (rejoined with ``:`` so Windows drive letters and URL-like
        # locations survive).
        numerics: list[int] = []
        cut = len(parts)
        for idx in range(len(parts) - 1, 0, -1):
            seg = parts[idx]
            if seg.isdigit():
                numerics.insert(0, int(seg))
                cut = idx
            else:
                break

        path = ":".join(parts[:cut]) or None
        line_no = numerics[0] if len(numerics) >= 1 else None
        col_no = numerics[1] if len(numerics) >= 2 else None
        return path, line_no, col_no
