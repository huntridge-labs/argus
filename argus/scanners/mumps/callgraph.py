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
``MumpsScanner.scan`` when it runs over a directory) to annotate findings
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

    actual_arg_names: tuple[frozenset[str], ...] = ()
    """Positional actual arguments at the call site. Entry ``i`` is the
    set of uppercased identifier names referenced in the i-th actual
    (``D RUN^B(CMD,1)`` -> ``(frozenset({'CMD'}), frozenset())``).
    Drives one-hop inter-procedural taint: if an actual references a
    tainted name, the callee's i-th formal becomes tainted."""


@dataclass(frozen=True)
class RoutineNode:
    """One routine in the call graph.

    Holds only lightweight facts — the routine name, its source path,
    and its declared labels. It deliberately does NOT retain the
    tree-sitter parse tree: pinning every file's tree was what made the
    full-corpus scan exhaust memory. Consumers that need to re-walk a
    routine re-parse it on demand from ``path``.
    """

    name: str
    """Uppercased routine name (file basename without extension)."""

    path: Path
    """Source file path, for on-demand re-parse."""

    labels: frozenset[str]
    """All label names declared in this routine, uppercased."""

    entry_formals: dict[str, tuple[str, ...]] = field(default_factory=dict)
    """Entry-label (uppercased) -> positional formal parameter names.
    ``RUN(P,Q)`` -> ``{'RUN': ('P', 'Q')}``. Used by the inter-procedural
    taint pass to map a caller's tainted actual to the callee's formal."""


@dataclass(frozen=True)
class RoutineFacts:
    """Lightweight per-file extraction result.

    Produced by :func:`extract_facts` from a parsed source, holding
    everything the call graph needs (name, path, labels, edges,
    entry formals) and **no reference to the parse tree** so the tree
    can be released immediately after extraction. This is the unit the
    streaming scan loop accumulates instead of holding every tree
    resident.
    """

    name: str
    path: Path
    labels: frozenset[str]
    edges: tuple[CallEdge, ...]
    entry_formals: dict[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class CallGraph:
    """The complete call graph for one scan invocation."""

    routines: dict[str, RoutineNode] = field(default_factory=dict)
    """name -> RoutineNode."""

    edges: tuple[CallEdge, ...] = ()
    """All cross-routine references found, in scan order."""

    # Pre-built indexes so ``callers_of`` / ``callees_of`` are O(1)
    # instead of an O(edges) linear scan per lookup. On a 4,000-edge
    # graph queried per finding that linear scan was O(edges x findings).
    _callers_by_routine: dict[str, tuple[CallEdge, ...]] = field(default_factory=dict)
    _callees_by_routine: dict[str, tuple[CallEdge, ...]] = field(default_factory=dict)

    def callers_of(self, routine: str) -> tuple[CallEdge, ...]:
        """Return every CallEdge whose ``callee_routine`` is ``routine``."""
        return self._callers_by_routine.get(routine.upper(), ())

    def callees_of(self, routine: str) -> tuple[CallEdge, ...]:
        """Return every CallEdge whose ``caller`` is ``routine``."""
        return self._callees_by_routine.get(routine.upper(), ())


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


_VAR_NODE_TYPES = frozenset({"local_variable", "identifier", "variable"})


def _identifier_names_in(node, parsed: ParsedSource) -> frozenset[str]:
    """Uppercased identifier names referenced anywhere under ``node``."""
    names: set[str] = set()
    for descendant in walk(node):
        if descendant.type in _VAR_NODE_TYPES:
            names.add(parsed.node_text(descendant).strip().upper())
    return frozenset(names)


def _actual_arg_names(routine_call_node, parsed: ParsedSource):
    """Positional actual-argument identifier sets for a call site.

    ``RUN^B(CMD,1)`` -> ``(frozenset({'CMD'}), frozenset())`` — the
    grammar shapes a call's actuals as a single ``arguments`` child of
    ``routine_call`` with positional ``argument`` children.
    """
    args = None
    for child in routine_call_node.children:
        if child.type == "arguments":
            args = child
            break
    if args is None:
        return ()
    actuals: list[frozenset[str]] = []
    for child in args.children:
        if child.type == "argument":
            actuals.append(_identifier_names_in(child, parsed))
    return tuple(actuals)


def _collect_entry_formals(parsed: ParsedSource) -> dict[str, tuple[str, ...]]:
    """Map each entry label to its positional formal-parameter names.

    A parameterized label parses as ``routine_definition`` -> ``label``,
    then an ``arguments`` node as a *direct child* of the
    routine_definition (command argument lists live nested under their
    ``command`` node, never directly under routine_definition).
    """
    formals: dict[str, tuple[str, ...]] = {}
    for node in walk(parsed.tree.root_node):
        if node.type != "routine_definition":
            continue
        label_name = None
        arg_node = None
        for child in node.children:
            if child.type == "label" and label_name is None:
                text = parsed.node_text(child).strip()
                label_name = text.split(None, 1)[0].split("(", 1)[0].upper() if text else None
            elif child.type == "arguments" and arg_node is None:
                arg_node = child
        if not label_name or arg_node is None:
            continue
        positions: list[str] = []
        for child in arg_node.children:
            if child.type == "argument":
                names = [
                    parsed.node_text(d).strip().upper()
                    for d in walk(child)
                    if d.type in _VAR_NODE_TYPES
                ]
                positions.append(names[0] if names else "")
        if positions:
            formals[label_name] = tuple(positions)
    return formals


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
            actual_arg_names=_actual_arg_names(node, parsed),
        ))
    return edges


def extract_facts(parsed: ParsedSource) -> RoutineFacts:
    """Extract the lightweight call-graph facts for one parsed source.

    Two walks (labels, cross-routine references) producing only strings
    — the returned :class:`RoutineFacts` holds no reference to the parse
    tree, so the caller can drop the tree immediately after this returns.
    This is what lets the streaming scan loop bound memory to one tree
    at a time instead of holding every file's tree resident.
    """
    name = Path(parsed.path).stem.upper()
    return RoutineFacts(
        name=name,
        path=Path(parsed.path),
        labels=_collect_labels(parsed),
        edges=tuple(_collect_call_edges(name, parsed)),
        entry_formals=_collect_entry_formals(parsed),
    )


def build_callgraph_from_facts(facts: Iterable[RoutineFacts]) -> CallGraph:
    """Build a :class:`CallGraph` from pre-extracted lightweight facts.

    No parse trees involved — pure structural assembly plus the O(1)
    caller/callee index construction.
    """
    routines: dict[str, RoutineNode] = {}
    edges: list[CallEdge] = []
    for fact in facts:
        routines[fact.name] = RoutineNode(
            name=fact.name,
            path=fact.path,
            labels=fact.labels,
            entry_formals=fact.entry_formals,
        )
        edges.extend(fact.edges)
    callers: dict[str, list[CallEdge]] = {}
    callees: dict[str, list[CallEdge]] = {}
    for edge in edges:
        callers.setdefault(edge.callee_routine, []).append(edge)
        callees.setdefault(edge.caller, []).append(edge)
    return CallGraph(
        routines=routines,
        edges=tuple(edges),
        _callers_by_routine={k: tuple(v) for k, v in callers.items()},
        _callees_by_routine={k: tuple(v) for k, v in callees.items()},
    )


def build_callgraph(parsed_sources: Iterable[ParsedSource]) -> CallGraph:
    """Construct a :class:`CallGraph` from parsed sources.

    Convenience wrapper over :func:`extract_facts` +
    :func:`build_callgraph_from_facts`, kept for callers (and tests)
    that already hold the parsed sources. Note this form materializes
    facts for every source before building; the memory-bounded streaming
    path in ``MumpsScanner.scan`` calls ``extract_facts`` per file and
    drops each tree instead.
    """
    return build_callgraph_from_facts(extract_facts(p) for p in parsed_sources)
