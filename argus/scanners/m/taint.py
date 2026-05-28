"""Shared taint-source collection for MUMPS rules.

Multiple rules (``M001`` XECUTE, ``M003`` OPEN/USE, ``M005`` tainted
dispatch) all need the same first pass: walk the parse tree, identify
variables assigned from a tainted source, hand the rule a ``set`` of
uppercased identifier names. Keeping the logic here removes the
near-duplicate ``_READ_KEYWORD_RE`` + ``_extract_target_identifiers``
copies that lived inside each rule module.

Phase 1 taint sources:

* ``READ`` / ``R`` commands. Every identifier in the argument subtree
  is added to the tainted set. Format specifiers (``!``) and string
  prompts are skipped naturally because they aren't ``local_variable``
  / ``identifier`` nodes.

Phase 2 will broaden this to include ``$ZARGV`` (process arguments),
formal arguments on entry labels, and the HTTP context globals
``^%CGI`` / ``^%session``. The collector signature is intentionally
stable so adding sources doesn't require rule changes.
"""

from __future__ import annotations

import re

from .parser import ParsedSource, walk


# Anchored to the command's leading token — the grammar elides the
# ``keyword`` child for single-letter READ commands (``R CMD``), so a
# text-anchored match is more reliable than a child_by_field_name lookup.
_READ_KEYWORD_RE = re.compile(r"^\s*R(?:EAD)?\b", re.IGNORECASE)


def _argument_node(command_node):
    """Return the arguments subtree for a command, or None."""
    for field_name in ("arguments", "argument", "expression"):
        node = command_node.child_by_field_name(field_name)
        if node is not None:
            return node
    for child in command_node.children:
        if child.type in {"arguments", "argument"}:
            return child
    return None


def _extract_target_identifiers(arg_node) -> list[str]:
    """Identifier tokens that are direct read-targets of ``READ``.

    READ arguments mix format-control characters (``!``, ``#``), prompt
    strings, and target variables. Identifier nodes from the arguments
    subtree are a conservative approximation; false positives here only
    widen the tainted set, never narrow it.
    """
    if arg_node is None:
        return []
    targets: list[str] = []
    for node in walk(arg_node):
        if node.type in {"identifier", "local_variable", "variable"}:
            targets.append(node.text.decode("utf-8", errors="replace").strip())
    return targets


def collect_read_tainted_variables(parsed: ParsedSource) -> set[str]:
    """Return the set of uppercased identifier names assigned from READ.

    Single pass over the parse tree. Order matters for *checking* taint
    (the sink rules walk in document order so a READ later than the
    sink doesn't taint it), but for the collected set itself it doesn't
    — the rule rebuilds taint incrementally during its own walk in
    document order. This helper is here for rules that don't need
    document-order incrementality (most diagnostic-style sinks).
    """
    tainted: set[str] = set()
    for node in walk(parsed.tree.root_node):
        if node.type != "command":
            continue
        if not _READ_KEYWORD_RE.match(parsed.node_text(node)):
            continue
        for name in _extract_target_identifiers(_argument_node(node)):
            if name:
                tainted.add(name.upper())
    return tainted


def is_read_command(parsed: ParsedSource, command_node) -> bool:
    """Lightweight predicate for "is this command a READ?" — used by
    rules that walk the tree once incrementally rather than pre-collect
    via ``collect_read_tainted_variables``. The read-target identifier
    extraction lives in ``read_targets``."""
    return bool(_READ_KEYWORD_RE.match(parsed.node_text(command_node)))


def read_targets(command_node) -> list[str]:
    """Identifier tokens read into by a READ command. Returns uppercased
    names for ease of comparison with the tainted set."""
    return [n.upper() for n in _extract_target_identifiers(_argument_node(command_node))]
