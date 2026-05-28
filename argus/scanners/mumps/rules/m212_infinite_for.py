"""M212 — argumentless FOR with no loop exit (CWE-835 infinite loop).

``FOR`` with no loop controller (``F  <body>``) iterates forever unless
its body executes a ``QUIT`` / ``GOTO`` / ``HALT`` (or ``BREAK``). The
canonical safe idiom carries an inline exit:

    F  S X=$O(^G(X)) Q:X=""  D WORK

A truly unbounded ``F  W "spin"`` with no exit on the line is a
production hang.

Grammar reality (probe-verified): an argumentless FOR's ``for_statement``
node keeps only its *first* body command; the rest of the body and the
``Q:`` exit spill out to **sibling** nodes. So the exit must be looked
for on the physical source line, not just inside the for_statement
subtree. A counted FOR (``F I=1:1:10``) has a ``loop_control`` child and
is never flagged.
"""

from __future__ import annotations

import re
from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule
from ._common import is_argumentless_for, physical_line

# A QUIT / GOTO / HALT / BREAK token standing alone on the line (with a
# postconditional ``Q:`` or as a bare command). BREAK is included: a
# ``F  BREAK`` debug/server loop is a deliberate suspend, not a hang.
_EXIT_RE = re.compile(
    r"(?:^|\s)(?:Q(?:UIT)?|G(?:OTO)?|H(?:ALT)?|B(?:REAK)?)(?::|\s|$)",
    re.IGNORECASE,
)


class InfiniteForRule(Rule):
    id = "M212"
    severity = Severity.HIGH
    title = "Argumentless FOR with no loop exit (possible infinite loop)"
    cwe = "CWE-835"

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        for node in walk(parsed.tree.root_node):
            if node.type != "for_statement":
                continue
            if not is_argumentless_for(parsed, node):
                continue
            line = physical_line(parsed, node)
            if _EXIT_RE.search(line):
                continue
            yield self.make_finding(
                parsed,
                node,
                description=(
                    "Argumentless FOR with no QUIT / GOTO / HALT on the loop "
                    "line iterates forever. Add an inline exit "
                    "(e.g. `F  S X=$O(^G(X)) Q:X=\"\"  ...`) or give the loop "
                    "a controller. A genuine endless server loop should use "
                    "an explicit BREAK so the intent is visible."
                ),
                metadata={"line": line.strip()[:200]},
            )
