"""M203 — local variable read before it was defined (diagnostic).

MUMPS quietly treats undefined locals as the empty string, so a typo
(``S USER=...`` then ``W USR``) silently silently produces wrong
output instead of raising. mHawk surfaces this; we match the
behaviour at INFO severity.

Detection: walk the file in document order, maintain an incremental
``defined`` set. A local-variable node is a *definition* when its
parent is an ``assignment`` and it's the LHS, or when it's a target
identifier inside a ``NEW`` / ``READ`` command. Every other local-
variable reference is a *use*, and a use of a name not yet in the
``defined`` set is flagged.

Known limitations (intentional for Phase 1):

* Formal arguments on entry labels (``LABEL(ARG)``) — we add them to
  ``defined`` greedily from the ``label`` node's text rather than
  attaching them to that label's scope. This trades scope precision
  for fewer false positives.
* Cross-routine implicit-NEW (``ARG`` brought in by a calling routine)
  — out of scope until inter-procedural taint lands in Phase 2.
* MUMPS chained SETs (``S X=1,Y=X+1``) — covered correctly because the
  grammar parses each ``=`` pair as a separate ``assignment`` node and
  DFS visits them in document order.
"""

from __future__ import annotations

import re
from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule

_NEW_KEYWORD_RE = re.compile(r"^\s*N(?:EW)?\b", re.IGNORECASE)
_READ_KEYWORD_RE = re.compile(r"^\s*R(?:EAD)?\b", re.IGNORECASE)
# Variable references in the M scanner uniformly use these node types.
_VAR_TYPES = frozenset({"local_variable", "identifier", "variable"})
# A handful of MUMPS built-ins surface in the grammar as `local_variable`
# nodes (``$T``, ``$ZARGV``, format helpers). Recognize them so we
# don't flag intrinsics as undefined locals.
_INTRINSIC_PREFIXES = ("$", "%")


def _argument_node(command_node):
    for field_name in ("arguments", "argument", "expression"):
        node = command_node.child_by_field_name(field_name)
        if node is not None:
            return node
    for child in command_node.children:
        if child.type in {"arguments", "argument"}:
            return child
    return None


def _collect_definition_positions(parsed: ParsedSource) -> set[tuple[int, int]]:
    """Return ``(start_byte, end_byte)`` tuples for every local_variable
    node that is a definition site (assignment LHS, NEW target, READ
    target). Positions are stable identifiers — Node identity isn't
    guaranteed across walks but byte-range is."""
    defs: set[tuple[int, int]] = set()
    for node in walk(parsed.tree.root_node):
        if node.type == "assignment":
            named = [c for c in node.children if c.is_named]
            if named and named[0].type in _VAR_TYPES:
                defs.add((named[0].start_byte, named[0].end_byte))
        elif node.type == "command":
            text = parsed.node_text(node)
            if not (_NEW_KEYWORD_RE.match(text) or _READ_KEYWORD_RE.match(text)):
                continue
            args = _argument_node(node)
            if args is None:
                continue
            for descendant in walk(args):
                if descendant.type in _VAR_TYPES:
                    defs.add((descendant.start_byte, descendant.end_byte))
    return defs


def _collect_label_arguments(parsed: ParsedSource) -> set[str]:
    """Return uppercased names of formal arguments declared on any
    label in the file. Conservative — we accept any token inside the
    parentheses following a label name as a formal argument."""
    names: set[str] = set()
    for node in walk(parsed.tree.root_node):
        if node.type != "label":
            continue
        text = parsed.node_text(node)
        match = re.search(r"\(([^)]*)\)", text)
        if not match:
            continue
        for arg in match.group(1).split(","):
            cleaned = arg.strip().upper()
            if cleaned and cleaned.replace("%", "").isalnum():
                names.add(cleaned)
    return names


def _is_intrinsic(name: str) -> bool:
    return any(name.startswith(p) for p in _INTRINSIC_PREFIXES)


class ImplicitDeclarationRule(Rule):
    id = "M203"
    severity = Severity.INFO
    title = "Local variable read before it was defined"
    cwe = None  # diagnostic

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        def_positions = _collect_definition_positions(parsed)
        defined = _collect_label_arguments(parsed)
        flagged_names: set[str] = set()
        for node in walk(parsed.tree.root_node):
            if node.type not in _VAR_TYPES:
                continue
            position = (node.start_byte, node.end_byte)
            if position in def_positions:
                name = parsed.node_text(node).strip().upper()
                if name:
                    defined.add(name)
                continue
            name = parsed.node_text(node).strip().upper()
            if not name or _is_intrinsic(name):
                continue
            if name in defined:
                continue
            # One finding per undefined-name per file. The same name
            # may be referenced many times; flagging each is noise.
            if name in flagged_names:
                continue
            flagged_names.add(name)
            yield self.make_finding(
                parsed,
                node,
                description=(
                    f"Local variable '{name}' is read but never appears as a "
                    "SET / NEW / READ target earlier in the routine. MUMPS "
                    "treats undefined locals as the empty string, so the bug "
                    "is silent at runtime. Common cause: a typo on the "
                    "definition site."
                ),
                metadata={"variable": name},
            )
