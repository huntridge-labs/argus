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

import re
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


def _normalize_routine_name(name: str) -> str:
    """Drop the percent-routine sigil so a ``%``-routine matches its
    on-disk filename.

    VistA's percent-routines (``%ZTLOAD``) are stored on filesystems
    that disallow ``%`` as ``_ZTLOAD.m`` — the universal ``%``↔``_``
    substitution. Stripping a single leading ``%`` or ``_`` from both
    sides before comparison makes the convention a match instead of a
    finding.
    """
    return name[1:] if name[:1] in ("%", "_") else name


class RoutineNameMismatchRule(Rule):
    id = "M202"
    severity = Severity.INFO
    title = "Routine name does not match filename"
    cwe = None  # diagnostic

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        first = _first_label(parsed)
        if first is None:
            return
        declared = _label_name(parsed, first)
        if not declared:
            return
        expected = Path(parsed.path).stem.upper()
        # Percent-routine convention: ``%FOO`` <-> ``_FOO.m``.
        if _normalize_routine_name(declared) == _normalize_routine_name(expected):
            return
        # Percent-routine platform-variant families: a ``%``-routine's source
        # is routinely split across files whose stem begins with the
        # de-sigiled label plus a platform tag (``%ZIS4`` -> ZIS4ONT.m /
        # ZIS4DTM.m; ``%ZOSVKR`` -> ZOSVKRO.m). The filename still resolves
        # the routine within the family, so the mismatch is by design, not a
        # dispatch error. Restricted to ``%``/``_``-sigiled labels — a plain
        # label/file mismatch is still a real finding.
        denorm = _normalize_routine_name(declared)
        if declared[:1] in ("%", "_") and denorm and expected.startswith(denorm):
            return
        # Site-configurable ignore patterns (regex, matched against the
        # uppercased declared name) for platform-variant routine
        # families, e.g. ``.*(VXD|IS2|ONT|DTM|MSM|GTM)$``.
        ignore = (config or {}).get("rules", {}).get(self.id, {}).get("ignore_patterns") or []
        for pat in ignore:
            try:
                if re.search(pat, declared, re.IGNORECASE):
                    return
            except re.error:
                continue
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
