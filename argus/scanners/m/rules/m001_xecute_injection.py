"""M001 — XECUTE injection from READ-tainted input (CWE-95).

``XECUTE expr`` evaluates ``expr`` as MUMPS code at runtime. When
``expr`` is composed from anything a caller can influence (a ``READ``
into a terminal variable, an HTTP query parameter loaded into a global,
a routine-argument string from an upstream caller) the call is
remote-code-execution.

The grammar (``janus-llm/tree-sitter-mumps``) sometimes elides the
``keyword`` child of a ``command`` node for short single-letter keywords
like ``R`` (READ), so this rule does keyword detection via a regex
against the command's source text rather than the structural field.
Detection runs in two passes over the tree:

1. **Source pass** — find every ``command`` whose text begins with
   ``R``/``READ`` and add its target variable identifiers to a tainted
   set.
2. **Sink pass** — for each ``X``/``XECUTE`` command, check whether its
   argument expression text references any tainted name. If so, emit a
   finding.

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


# Text-anchored keyword detection. The command's source includes any
# leading whitespace, the keyword, an optional postconditional
# (``S:cond X=Y``), and the arguments. Matching against the leading
# token sidesteps the grammar's inconsistent ``keyword`` field surface.
_READ_KEYWORD_RE = re.compile(r"^\s*R(?:EAD)?\b", re.IGNORECASE)
_XECUTE_KEYWORD_RE = re.compile(r"^\s*X(?:ECUTE)?\b", re.IGNORECASE)


def _argument_node(command_node):
    """Return the arguments subtree for a command, or None.

    The grammar declares ``arguments`` as a child type rather than a
    named field on every command alternative, so we fall back to a
    type-based scan when ``child_by_field_name`` returns nothing.
    """
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
            command_text = parsed.node_text(node)
            args = _argument_node(node)
            if _READ_KEYWORD_RE.match(command_text):
                for name in _extract_target_identifiers(args):
                    if name:
                        tainted.add(name.upper())
                continue
            if not _XECUTE_KEYWORD_RE.match(command_text):
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
