"""M218 — executable code on the routine's label (first) line (SAC).

VistA SAC requires the first line of a routine to be the routine-name
label plus a comment header — no executable code. ``EN S X=1 Q`` puts
code on the header line; ``EN ; description`` followed by code on the
next line is correct.

Detection (probe-verified): take the file's first ``routine_definition``
whose ``label`` is on line 1; if it has an executable child
(``command`` / ``assignment`` / ``do_statement`` / ``if_statement`` /
``for_statement``) starting on that same line, flag it.
"""

from __future__ import annotations

from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource
from ..rule import Rule

_EXECUTABLE = frozenset({
    "command", "assignment", "do_statement", "if_statement", "for_statement",
})


def _first_routine_definition(root):
    for child in root.children:
        if child.type == "routine_definition":
            return child
        if child.type == "program":
            for grandchild in child.children:
                if grandchild.type == "routine_definition":
                    return grandchild
    return None


class ExecOnLabelLineRule(Rule):
    id = "M218"
    severity = Severity.LOW
    title = "Executable code on the routine label (first) line"
    cwe = None  # SAC convention

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        rdef = _first_routine_definition(parsed.tree.root_node)
        if rdef is None:
            return
        label = next((c for c in rdef.children if c.type == "label"), None)
        if label is None or label.start_point[0] != 0:
            return
        label_row = label.start_point[0]
        for child in rdef.children:
            if child.type in _EXECUTABLE and child.start_point[0] == label_row:
                yield self.make_finding(
                    parsed,
                    child,
                    description=(
                        "Executable code on the routine's first line. SAC "
                        "requires the header line to be the routine-name label "
                        "plus a comment only; move the code to the next line."
                    ),
                    metadata={"code": parsed.node_text(child).strip()[:80]},
                )
                return
