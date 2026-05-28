"""M101 — duplicate label in a routine (diagnostic).

A MUMPS routine may declare each label name at most once. Two labels
with the same name compile in many implementations but the second
silently shadows the first, so ``DO LABEL`` jumps to the earlier
definition and the later block becomes unreachable. mHawk surfaces this
as a diagnostic; we match the behaviour at INFO severity.

Detection: walk the parse tree, collect every ``label`` node's name in
file order, flag every occurrence after the first per name.
"""

from __future__ import annotations

from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule


class DuplicateLabelRule(Rule):
    id = "M101"
    severity = Severity.INFO
    title = "Duplicate label declared in routine"
    cwe = None  # diagnostic, not a CWE

    def analyze(self, parsed: ParsedSource) -> Iterable[Finding]:
        seen: dict[str, object] = {}
        for node in walk(parsed.tree.root_node):
            if node.type != "label":
                continue
            name = self._label_name(parsed, node)
            if not name:
                continue
            first = seen.get(name)
            if first is None:
                seen[name] = node
                continue
            yield self.make_finding(
                parsed,
                node,
                description=(
                    f"Label '{name}' is already declared earlier in this "
                    f"routine at {parsed.location(first)}. The second "
                    "declaration silently shadows the first."
                ),
                metadata={
                    "label": name,
                    "first_declaration": parsed.location(first),
                },
            )

    @staticmethod
    def _label_name(parsed: ParsedSource, label_node) -> str:
        """Extract the label's identifier text, tolerant of grammar shape."""
        named = label_node.child_by_field_name("name")
        if named is not None:
            return parsed.node_text(named).strip()
        for child in label_node.children:
            if child.type in {"identifier", "label_name"}:
                return parsed.node_text(child).strip()
        # Fall back to the first whitespace-delimited token on the label's line.
        text = parsed.node_text(label_node).strip()
        return text.split(None, 1)[0] if text else ""
