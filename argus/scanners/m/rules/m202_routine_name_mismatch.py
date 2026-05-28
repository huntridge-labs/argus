"""M202 — first label doesn't match the routine filename (diagnostic).

GT.M, YottaDB, and InterSystems Caché all enforce a convention that
the first label in a ``.m`` file must equal the file's basename. The
runtime uses the filename to locate the routine when dispatched via
``D ^ROUTINENAME``; a mismatch loads either the wrong routine or
errors at link time. mHawk flags this as a diagnostic; we match
that at INFO severity.

Detection: read the first ``label`` node in the file, compare its
uppercased name to the uppercased file stem. Flag when they differ.
Names are case-insensitive on every MUMPS dialect we target.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule


def _first_label(parsed: ParsedSource):
    """Return the first ``label`` node in document order, or None."""
    for node in walk(parsed.tree.root_node):
        if node.type == "label":
            return node
    return None


def _label_name(parsed: ParsedSource, label_node) -> str:
    text = parsed.node_text(label_node).strip()
    return text.split(None, 1)[0].upper() if text else ""


class RoutineNameMismatchRule(Rule):
    id = "M202"
    severity = Severity.INFO
    title = "Routine name does not match filename"
    cwe = None  # diagnostic

    def analyze(self, parsed: ParsedSource) -> Iterable[Finding]:
        first = _first_label(parsed)
        if first is None:
            return
        declared = _label_name(parsed, first)
        if not declared:
            return
        expected = Path(parsed.path).stem.upper()
        if declared == expected:
            return
        yield self.make_finding(
            parsed,
            first,
            description=(
                f"First label '{declared}' does not match the file stem "
                f"'{expected}'. GT.M / YottaDB / Caché all link the routine "
                "by filename; a mismatch loads the wrong routine or errors "
                "at dispatch. Rename the label or the file so they agree."
            ),
            metadata={
                "declared": declared,
                "expected": expected,
            },
        )
