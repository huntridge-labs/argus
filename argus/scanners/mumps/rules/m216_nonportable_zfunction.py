"""M216 — non-portable $Z intrinsic function (diagnostic, off by default).

``$Z*`` intrinsic functions (``$ZDATE``, ``$ZSEARCH``, ``$ZCONVERT``,
...) are vendor extensions, not ANSI/ISO M. They are a portability
inventory: useful when planning a platform migration, noise on a
single-platform codebase — so this ships off by default.

Detection (probe-verified): an intrinsic call parses as ``function_call``
-> ``function_name`` with a single ``$`` sigil. A ``$$`` extrinsic
(user function) is distinct and never matched.
"""

from __future__ import annotations

from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule


def _function_name(parsed: ParsedSource, call_node) -> str:
    field = call_node.child_by_field_name("name")
    if field is not None:
        return parsed.node_text(field).strip()
    for child in call_node.children:
        if child.type == "function_name":
            return parsed.node_text(child).strip()
    return ""


class NonPortableZFunctionRule(Rule):
    id = "M216"
    severity = Severity.INFO
    title = "Non-portable $Z intrinsic function"
    cwe = None  # portability diagnostic
    enabled_by_default = False

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        for node in walk(parsed.tree.root_node):
            if node.type != "function_call":
                continue
            name = _function_name(parsed, node)
            upper = name.upper()
            # ``$Z...`` intrinsic, not a ``$$Z...`` extrinsic.
            if not upper.startswith("$Z") or upper.startswith("$$"):
                continue
            yield self.make_finding(
                parsed,
                node,
                description=(
                    f"'{name}' is a vendor-specific $Z intrinsic function, "
                    "not portable ANSI/ISO M. Flagged for portability "
                    "inventory; safe to ignore on single-platform code."
                ),
                metadata={"function": upper},
            )
