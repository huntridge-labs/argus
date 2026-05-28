"""M001 — XECUTE injection from READ-tainted input (CWE-95).

``XECUTE expr`` evaluates ``expr`` as MUMPS code at runtime. When
``expr`` is composed from anything a caller can influence (a ``READ``
into a terminal variable, an HTTP query parameter loaded into a global,
a routine-argument string from an upstream caller) the call is
remote-code-execution.

The grammar (``janus-llm/tree-sitter-mumps``) collapses every command
keyword into a single regex node, so structural querying alone cannot
distinguish ``XECUTE`` from ``SET``. Detection runs in two passes over
the tree:

1. **Source pass** — collect the set of variable names that were
   assigned from a ``READ`` command earlier in source order.
2. **Sink pass** — for each ``XECUTE`` / ``X`` command, check whether
   its argument expression text references any tainted name. If so,
   emit a finding.

Phase 1 is intra-file (a "routine" is treated as one scope). Phase 2
will add per-routine scoping plus inter-procedural call-graph taint.
String-literal XECUTEs (``X "WRITE 1"``) are always safe and never
flagged.
"""

from __future__ import annotations

import re
from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule


_READ_KEYWORDS = frozenset({"R", "READ"})
_XECUTE_KEYWORDS = frozenset({"X", "XECUTE"})


def _keyword_text(parsed: ParsedSource, command_node) -> str:
    """Return the command keyword in uppercase, or empty string."""
    field = command_node.child_by_field_name("keyword")
    if field is not None:
        return parsed.node_text(field).strip().upper()
    for child in command_node.children:
        if child.type == "keyword":
            return parsed.node_text(child).strip().upper()
    return ""


def _argument_node(command_node):
    """Return the arguments subtree for a command, or None."""
    for field_name in ("arguments", "argument", "expression"):
        node = command_node.child_by_field_name(field_name)
        if node is not None:
            return node
    return None


def _extract_target_identifiers(arg_node) -> list[str]:
    """Identifier tokens that are direct read-targets of ``READ``.

    MUMPS ``READ`` arguments mix format-control characters (``!``,
    ``#``), prompt strings, and target variables. We collect identifier
    nodes from the arguments subtree as a conservative approximation;
    false positives here only widen the tainted set, never narrow it.
    """
    if arg_node is None:
        return []
    targets: list[str] = []
    for node in walk(arg_node):
        if node.type in {"identifier", "local_variable", "variable"}:
            targets.append(node.text.decode("utf-8", errors="replace").strip())
    return targets


def _argument_is_string_literal(parsed: ParsedSource, arg_node) -> bool:
    """True when an XECUTE argument is a single string literal.

    Concatenations like ``X "WRITE "_INPUT`` are not literals: they're
    built at runtime and remain candidates for the sink pass.
    """
    if arg_node is None:
        return False
    if arg_node.type in {"string_literal", "string"}:
        return True
    children = [c for c in arg_node.children if c.is_named]
    if len(children) == 1 and children[0].type in {"string_literal", "string"}:
        return True
    return False


class XECUTEInjectionRule(Rule):
    id = "M001"
    severity = Severity.HIGH
    title = "XECUTE of READ-tainted expression"
    cwe = "CWE-95"

    def analyze(self, parsed: ParsedSource) -> Iterable[Finding]:
        tainted: set[str] = set()
        for node in walk(parsed.tree.root_node):
            if node.type != "command":
                continue
            keyword = _keyword_text(parsed, node)
            args = _argument_node(node)
            if keyword in _READ_KEYWORDS:
                for name in _extract_target_identifiers(args):
                    if name:
                        tainted.add(name.upper())
                continue
            if keyword not in _XECUTE_KEYWORDS:
                continue
            if _argument_is_string_literal(parsed, args):
                continue
            arg_text = parsed.node_text(args).strip() if args else ""
            hits = self._tainted_references(arg_text, tainted)
            if not hits:
                continue
            yield self.make_finding(
                parsed,
                node,
                description=(
                    f"XECUTE argument references variable(s) {sorted(hits)} "
                    "previously assigned from READ. The runtime value of "
                    "those variables is executed as MUMPS code."
                ),
                metadata={
                    "taint_sources": sorted(hits),
                    "argument": arg_text[:200],
                },
            )

    @staticmethod
    def _tainted_references(arg_text: str, tainted: set[str]) -> set[str]:
        """Return the subset of ``tainted`` referenced as identifiers in
        ``arg_text``. Whole-word match (case-insensitive) to avoid
        flagging substrings of unrelated variable names.
        """
        hits: set[str] = set()
        if not arg_text or not tainted:
            return hits
        upper_arg = arg_text.upper()
        for name in tainted:
            if re.search(rf"\b{re.escape(name)}\b", upper_arg):
                hits.add(name)
        return hits
