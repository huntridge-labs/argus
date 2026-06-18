"""Pure formatting for the terminal viewer's runs sidebar.

The sidebar lists the scan runs ``discover_runs`` found and lets the
user switch between them. The Textual ``OptionList`` that renders it
lives in ``app.py``; everything here is pure string/id work so it can
be unit-tested without Textual.

A run row reads at a glance:

    ● 🚨 CRIT  2026-06-12T14-54Z   142
    ‑ severity glyph of the worst finding, current-run marker, label,
      and the finding count.

The worst-severity glyph is the same one the findings list uses
(``SEVERITY_GLYPH``) so the colour/severity language is consistent
across the whole TUI.
"""

from __future__ import annotations

from argus.core.findings_view import SEVERITY_GLYPH
from argus.core.models import Severity


# Marker for the run currently loaded in the findings list. A filled dot
# reads as "you are here" without needing colour.
_CURRENT_MARKER = "●"
_OTHER_MARKER = " "

# Shown when a run has no findings (a clean scan) or none carried a
# recognizable severity — distinct from any severity glyph so a clean
# run never looks like a low-severity one.
_CLEAN_GLYPH = "✓ none"


def run_glyph(worst_severity: Severity | None) -> str:
    """Return the severity glyph for a run's worst finding.

    ``None`` (clean scan / no recognizable severity) renders as the
    neutral "no findings" glyph rather than borrowing a severity colour.
    """
    if worst_severity is None:
        return _CLEAN_GLYPH
    return SEVERITY_GLYPH.get(worst_severity, "❓ ???")


def format_run_row(run: dict, *, current: bool) -> str:
    """Render one ``discover_runs`` entry as a single sidebar line.

    ``current`` marks the run loaded in the findings list. ``run`` is a
    dict from ``discover_runs`` — ``label``, ``count``, and
    ``worst_severity`` are read; missing keys degrade to safe defaults
    so a partial dict never crashes the sidebar.
    """
    marker = _CURRENT_MARKER if current else _OTHER_MARKER
    glyph = run_glyph(run.get("worst_severity"))
    label = run.get("label") or "(run)"
    count = run.get("count") or 0
    return f"{marker} {glyph}  {label}   {count}"


def run_option_id(run: dict) -> str:
    """Stable OptionList id for a run row — its absolute path.

    The app maps a selected option back to a scan by this id, so it must
    be the path ``discover_runs`` recorded (which is what the run loader
    accepts).
    """
    return str(run.get("path") or "")
