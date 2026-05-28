"""M002 — indirection (``@``) injection (CWE-94).

MUMPS indirection lets a variable expand into arbitrary code: ``SET
X="^GLOBAL(""KEY"")=1"`` followed by ``XECUTE @X`` runs whatever the
attacker can put into ``X``. Indirection of a variable expression is
the lowest-friction code-injection primitive in the language.

The ``indirection`` node is named in ``janus-llm/tree-sitter-mumps`` so
this is the cleanest structural rule of Phase 1. We flag every
indirection whose operand is **not** a string literal — those are the
ones where the runtime value comes from somewhere other than the source
file.

Phase 2 will refine this with intra-procedural taint so we only flag
indirections of values originating from ``READ`` / globals / formal
arguments rather than every variable indirection.
"""

from __future__ import annotations

from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule

# Operand types that represent a constant value baked into source. An
# indirection whose operand is one of these has nothing to inject and
# is a false positive in practice.
_CONSTANT_OPERAND_TYPES = frozenset({
    "string_literal",
    "string",
    "number",
    "numeric_literal",
    "integer_literal",
})


class IndirectionInjectionRule(Rule):
    id = "M002"
    severity = Severity.HIGH
    title = "Possible code-injection via indirection (@)"
    cwe = "CWE-94"

    def analyze(self, parsed: ParsedSource) -> Iterable[Finding]:
        for node in walk(parsed.tree.root_node):
            if node.type != "indirection":
                continue
            operand = self._operand(node)
            if operand is None:
                # Empty indirection (grammar accepts ``@`` standalone in
                # places) — nothing actionable, skip.
                continue
            if operand.type in _CONSTANT_OPERAND_TYPES:
                continue
            operand_text = parsed.node_text(operand).strip()
            yield self.make_finding(
                parsed,
                node,
                description=(
                    "Indirection of a non-constant expression "
                    f"(@{operand_text}). The value of '{operand_text}' is "
                    "evaluated as MUMPS code at runtime; if it can be "
                    "influenced by external input the caller can execute "
                    "arbitrary commands."
                ),
                metadata={"operand": operand_text, "operand_type": operand.type},
            )

    @staticmethod
    def _operand(indirection_node):
        """Return the expression node inside an ``@expr`` indirection.

        Tries the ``operand`` / ``expression`` field name first, then
        falls back to the first non-``@`` child to stay resilient against
        minor grammar revisions.
        """
        for field_name in ("operand", "expression", "argument"):
            child = indirection_node.child_by_field_name(field_name)
            if child is not None:
                return child
        for child in indirection_node.children:
            if child.type != "@":
                return child
        return None
