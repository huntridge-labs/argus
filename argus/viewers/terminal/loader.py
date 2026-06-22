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
from argus.core.run_discovery import RESULTS_FILENAME, discover_runs

# Re-exported from argus.core.run_discovery (its canonical home) so existing
# ``from argus.viewers.terminal.loader import RESULTS_FILENAME`` call sites
# keep working without reaching into core directly.
__all__ = ["RESULTS_FILENAME", "flatten_findings", "load_summary", "locate_results"]


def locate_results(path: str | Path | None) -> Path:
    """Resolve ``path`` to an ``argus-results.json`` file.

    Mirrors ``argus scan``'s actual output layout — and the browser viewer's
    resolution — so the terminal viewer opens a scan from a *directory* the
    same way, in order:

    - a file → use as-is.
    - ``{dir}/argus-results.json`` (a direct drop) → use it.
    - ``{dir}/latest/argus-results.json`` → use it. ``argus scan`` writes to a
      timestamped subdir (``argus-results/2026-…Z/``) and maintains a
      ``latest`` symlink; this is the common shape, and the reason a bare
      ``argus`` → "View findings" used to flicker straight back to the home
      screen (the old code only looked for the non-existent
      ``argus-results/argus-results.json``).
    - the newest timestamped run under ``{dir}`` (via ``discover_runs``) →
      use it, for layouts without a ``latest`` symlink.

    ``None`` resolves against the conventional ``./argus-results`` home.
    """
    if path is not None:
        p = Path(path)
        if p.is_file():
            return p
        if not p.is_dir():
            # A specific path the user named that's neither file nor dir —
            # diagnose against it directly rather than appending a filename.
            from argus.viewers.diagnose import diagnose_missing_results
            raise FileNotFoundError(diagnose_missing_results(p))
        base = p
    else:
        base = Path("argus-results")

    direct = base / RESULTS_FILENAME
    if direct.is_file():
        return direct

    latest = base / "latest" / RESULTS_FILENAME
    if latest.is_file():
        return latest.resolve()

    if base.is_dir():
        runs = discover_runs(base.resolve())
        if runs:
            newest = Path(runs[0]["path"]) / RESULTS_FILENAME
            if newest.is_file():
                return newest

    # Defer to the shared diagnoser so the message identifies the likely
    # root cause (most often: ``reporting.formats`` in argus.yml omits
    # ``json``) rather than just reporting the missing file. Both viewers
    # raise this and surface it verbatim, so the remediation is identical
    # regardless of which interface was invoked.
    from argus.viewers.diagnose import diagnose_missing_results
    raise FileNotFoundError(diagnose_missing_results(direct))


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
