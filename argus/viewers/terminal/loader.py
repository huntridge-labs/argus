"""Load an argus-results.json into an in-memory ScanSummary.

Kept separate from the Textual UI so it can be tested without importing
the UI stack. Handles both the common case (one ``argus-results.json``
at the root of the output dir) and the less common "user pointed us at
the file directly" case. Raises ``FileNotFoundError`` when neither path
works — the CLI surfaces that with a friendly message.
"""

from __future__ import annotations

import json
from pathlib import Path

from argus.core.models import ScanSummary


RESULTS_FILENAME = "argus-results.json"


def locate_results(path: str | Path | None) -> Path:
    """Resolve ``path`` to an ``argus-results.json`` file.

    - ``None`` → ``./argus-results/argus-results.json``
    - a directory → ``{dir}/argus-results.json``
    - a file      → use as-is (must exist and parse as JSON)
    """
    if path is None:
        candidate = Path("argus-results") / RESULTS_FILENAME
    else:
        p = Path(path)
        candidate = p / RESULTS_FILENAME if p.is_dir() else p
    if not candidate.is_file():
        # Defer to the shared diagnoser so the message identifies the
        # likely root cause (most often: ``reporting.formats`` in
        # argus.yml omits ``json``) rather than just reporting the
        # missing file. Both viewers raise this exception and surface
        # the message verbatim, so users get the same actionable
        # remediation regardless of which interface they invoked.
        from argus.viewers.diagnose import diagnose_missing_results
        raise FileNotFoundError(diagnose_missing_results(candidate))
    return candidate


def load_summary(path: str | Path | None) -> tuple[ScanSummary, Path]:
    """Load the ScanSummary at ``path``; returns (summary, resolved_path)."""
    resolved = locate_results(path)
    data = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(
            f"{resolved} is not a valid argus results file (expected an object)."
        )
    return ScanSummary.from_dict(data), resolved


def flatten_findings(summary: ScanSummary) -> list:
    """Return every Finding across every ScanResult as a flat list.

    Preserves the scanner on each finding. Older fixtures occasionally
    leave ``Finding.scanner`` blank — we rebuild with the enclosing
    ``ScanResult.scanner`` via ``dataclasses.replace`` since Finding is
    a frozen dataclass.
    """
    from dataclasses import replace
    flat = []
    for result in summary.results:
        for finding in result.findings:
            if not finding.scanner:
                finding = replace(finding, scanner=result.scanner)
            flat.append(finding)
    return flat
