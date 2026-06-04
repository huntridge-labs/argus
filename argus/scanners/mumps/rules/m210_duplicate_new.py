"""M210 — duplicate variable name in a single NEW argument list.

``N IEN,STA,IEN,DA`` lists ``IEN`` twice — a copy/paste typo. It is
harmless to the runtime but signals the author meant a different name,
and it's near-zero false-positive (validated on VistA Kernel: 17
findings across 13 files, every one a typo).

Scope is a single ``NEW`` command, so this never collides with the
legitimate idiom of NEWing the same variable in different labels.
Exclusive NEW (``N (A,B)`` — protect-all-except) is excluded: the
grammar emits a ``(`` child / an ERROR for that form, and its
semantics differ.
"""

from __future__ import annotations

import re
from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule
from ._common import VAR_TYPES, argument_node

_NEW_KEYWORD_RE = re.compile(r"^\s*N(?:EW)?\b", re.IGNORECASE)


class DuplicateNewRule(Rule):
    id = "M210"
    severity = Severity.LOW
    title = "Duplicate variable in a single NEW argument list"
    cwe = None  # diagnostic

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        for node in walk(parsed.tree.root_node):
            if node.type != "command":
                continue
            if not _NEW_KEYWORD_RE.match(parsed.node_text(node)):
                continue
            args = argument_node(node)
            if args is None:
                continue
            # Exclusive NEW (``N (A,B)``) parses with a '(' / ERROR child
            # and means something different — skip it.
            if any(c.type in ("(", "ERROR") for c in args.children):
                continue
            seen: set[str] = set()
            for child in args.children:
                if child.type != "argument":
                    continue
                named = [c for c in child.children if c.is_named]
                # Only simple ``local_variable`` targets; skip @indirection.
                if len(named) != 1 or named[0].type not in VAR_TYPES:
                    continue
                name = parsed.node_text(named[0]).strip().upper()
                if not name:
                    continue
                if name in seen:
                    yield self.make_finding(
                        parsed,
                        node,
                        description=(
                            f"Variable '{name}' appears more than once in this "
                            "NEW argument list — likely a copy/paste typo for a "
                            "different variable name."
                        ),
                        metadata={"variable": name, "command": parsed.node_text(node).strip()[:120]},
                    )
                    break
                seen.add(name)
