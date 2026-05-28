"""M005 — tainted dynamic routine dispatch (CWE-95).

The fourth mHawk taint sink. ``DO @VAR`` and ``DO @^GLOB(SUB)`` resolve
the routine to invoke from the runtime value of ``VAR`` or the global
subscript. When that value originates from a ``READ`` (or any future
taint source) the caller chooses which routine runs — an OS- and
language-level RCE on most MUMPS implementations.

Distinct from M002 (which fires on *any* non-literal indirection at
HIGH): M005 confirms a flow from a READ-source variable into a
``do_statement`` indirection and raises the severity to CRITICAL.

Detection runs in two passes over the document:

1. Collect READ-tainted identifier names (uppercased).
2. For each ``do_statement`` whose ``routine_call`` contains an
   ``indirection``, intersect the indirection's identifier names with
   the tainted set. If non-empty, emit a finding.
"""

from __future__ import annotations

from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule
from ..taint import resolve_tainted


def _indirection_descendants(do_node):
    """Yield every ``indirection`` node anywhere inside a do_statement."""
    for descendant in walk(do_node):
        if descendant.type == "indirection":
            yield descendant


def _identifier_names(node) -> set[str]:
    """Collect uppercased identifier names inside ``node`` (any depth)."""
    names: set[str] = set()
    for descendant in walk(node):
        if descendant.type in {"identifier", "local_variable", "variable"}:
            names.add(
                descendant.text.decode("utf-8", errors="replace").strip().upper()
            )
    return names


class TaintedDispatchRule(Rule):
    id = "M005"
    severity = Severity.CRITICAL
    title = "DO of READ-tainted indirection (dynamic routine dispatch)"
    cwe = "CWE-95"

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        tainted = resolve_tainted(parsed, config)
        if not tainted:
            return
        for node in walk(parsed.tree.root_node):
            if node.type != "do_statement":
                continue
            for indirection in _indirection_descendants(node):
                referenced = _identifier_names(indirection)
                hits = referenced & tainted
                if not hits:
                    continue
                command_text = parsed.node_text(node).strip()
                yield self.make_finding(
                    parsed,
                    node,
                    description=(
                        f"DO statement '{command_text[:80]}' dispatches to a "
                        f"routine resolved through indirection of READ-tainted "
                        f"variable(s) {sorted(hits)}. The runtime value of "
                        "those variables names the routine that executes; "
                        "the caller controls which routine runs."
                    ),
                    metadata={
                        "taint_sources": sorted(hits),
                        "command": command_text[:200],
                    },
                )
                break  # one finding per do_statement, not per indirection
