"""Cross-file call graph for the MUMPS scanner.

The Phase 1 rules treat each ``.m`` file as an isolated scope: a
``READ`` in one routine never taints a variable seen by an ``XECUTE``
in another routine. That's intentional — full inter-procedural taint
propagation is the single largest remaining technical lift on the
roadmap (per-routine taint summaries, worklist iteration to fixpoint,
formal-argument sub-typing).

This module is the *foundation* for that future work. It loads every
``.m`` file in the scan path, walks each one for cross-routine
references (``D LABEL^ROUTINE``, ``D ^ROUTINE``, ``GOTO ^ROUTINE``),
and produces an immutable :class:`CallGraph` keyed by routine name.
Rules can consume the graph through ``config['_callgraph']`` (set by
``MScanner.scan`` when it runs over a directory) to annotate findings
with caller information today; the actual taint-propagation pass
that consumes the same graph lands in Phase 2.5.

Routine identity is the file basename without extension, uppercased
— matching the GT.M / YottaDB / Caché dispatch convention. The first
label in a file is treated as the routine's primary entry point;
other labels are entry points within that routine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .parser import ParsedSource, walk


@dataclass(frozen=True)
class CallEdge:
    """One ``DO`` / ``GOTO`` reference from one routine to another."""

    caller: str
    """Uppercased routine name that contains the call site."""

    callee_routine: str
    """Uppercased routine name being called (may equal ``caller`` for
    self-recursion)."""

    callee_label: str | None
    """Uppercased label name within the callee, or ``None`` when the
    call invokes the routine's entry point (``D ^OTHER``)."""

    call_site: str
    """``path:line:col`` of the call site, for downstream Finding
    location."""


@dataclass(frozen=True)
class RoutineNode:
    """One routine in the call graph.

    ``parsed`` is the ParsedSource the rest of the scanner already
    holds — keeping it here lets call-graph consumers re-walk the
    routine without re-parsing.
    """

    name: str
    """Uppercased routine name (file basename without extension)."""

    parsed: ParsedSource

    labels: frozenset[str]
    """All label names declared in this routine, uppercased."""


@dataclass(frozen=True)
class CallGraph:
    """The complete call graph for one scan invocation."""

    routines: dict[str, RoutineNode] = field(default_factory=dict)
    """name -> RoutineNode."""

    edges: tuple[CallEdge, ...] = ()
    """All cross-routine references found, in scan order."""

    def callers_of(self, routine: str) -> tuple[CallEdge, ...]:
        """Return every CallEdge whose ``callee_routine`` is ``routine``."""
        target = routine.upper()
        return tuple(edge for edge in self.edges if edge.callee_routine == target)

    def callees_of(self, routine: str) -> tuple[CallEdge, ...]:
        """Return every CallEdge whose ``caller`` is ``routine``."""
        source = routine.upper()
        return tuple(edge for edge in self.edges if edge.caller == source)


# Matches the ``LABEL^ROUTINE`` and ``^ROUTINE`` reference forms in
# a ``routine_call`` node's source text. The grammar surfaces these
# in different shapes depending on context (sometimes wrapped in an
# ERROR node) so a text-anchored extraction is more reliable than
# child_by_field_name traversal.
_CROSS_ROUTINE_RE = re.compile(
    r"""
    (?:                              # Optional ``LABEL`` prefix:
        (?P<label>[A-Za-z%][A-Za-z0-9]*)
    )?
    \^                               # The ``^`` routine sigil
    (?P<routine>[A-Za-z%][A-Za-z0-9]*)
    """,
    re.VERBOSE,
)


def _collect_labels(parsed: ParsedSource) -> frozenset[str]:
    labels: set[str] = set()
    for node in walk(parsed.tree.root_node):
        if node.type != "label":
            continue
        text = parsed.node_text(node).strip()
        if not text:
            continue
        first = text.split(None, 1)[0]
        # Strip a parenthesized formal-arg list if present.
        first = first.split("(", 1)[0]
        if first:
            labels.add(first.upper())
    return frozenset(labels)


def _collect_call_edges(node_name: str, parsed: ParsedSource) -> list[CallEdge]:
    edges: list[CallEdge] = []
    for node in walk(parsed.tree.root_node):
        if node.type != "routine_call":
            continue
        text = parsed.node_text(node).strip()
        if "^" not in text:
            # Intra-file reference; M201 covers undeclared targets.
            continue
        match = _CROSS_ROUTINE_RE.search(text)
        if match is None:
            continue
        callee_routine = match.group("routine").upper()
        callee_label = match.group("label")
        callee_label_upper = callee_label.upper() if callee_label else None
        edges.append(CallEdge(
            caller=node_name,
            callee_routine=callee_routine,
            callee_label=callee_label_upper,
            call_site=parsed.location(node),
        ))
    return edges


def build_callgraph(parsed_sources: Iterable[ParsedSource]) -> CallGraph:
    """Construct a :class:`CallGraph` from the parsed sources for one scan.

    Cheap: one walk per source for labels, one walk per source for
    cross-routine references. No taint propagation, no fixpoint
    iteration — pure structural extraction.
    """
    routines: dict[str, RoutineNode] = {}
    edges: list[CallEdge] = []
    for parsed in parsed_sources:
        name = Path(parsed.path).stem.upper()
        labels = _collect_labels(parsed)
        routines[name] = RoutineNode(name=name, parsed=parsed, labels=labels)
        edges.extend(_collect_call_edges(name, parsed))
    return CallGraph(routines=routines, edges=tuple(edges))
