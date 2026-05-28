"""M102 — unreachable code after an unconditional QUIT / HALT (diagnostic).

A ``Q`` (QUIT) or ``H`` (HALT) command without a postconditional ends
the current scope immediately. Any sibling command that follows on the
same block level is dead — it never executes. mHawk surfaces this as a
diagnostic; we match the behaviour at INFO severity.

Postconditionals (``Q:cond``, ``H:cond``) are *conditional* exits and
do not make following code unreachable; this rule recognizes them
syntactically and skips. Returning a value (``Q result``) is still an
unconditional exit and *does* flag the next sibling.
"""

from __future__ import annotations

import re
from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule

# Match Q / QUIT / H / HALT at the start of the command text, requiring
# whitespace or end-of-string immediately after — that rules out
# postconditionals (``Q:cond ...``) which start with ``Q:`` and are
# conditional.
_UNCONDITIONAL_BREAK_RE = re.compile(
    r"^\s*(?:Q(?:UIT)?|H(?:ALT)?)(?:\s|$)",
    re.IGNORECASE,
)


def _is_unconditional_break(parsed: ParsedSource, command_node) -> bool:
    text = parsed.node_text(command_node)
    return bool(_UNCONDITIONAL_BREAK_RE.match(text))


class UnreachableAfterQuitRule(Rule):
    id = "M102"
    severity = Severity.INFO
    title = "Unreachable code after unconditional QUIT / HALT"
    cwe = None  # diagnostic, not a CWE

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        for parent in walk(parsed.tree.root_node):
            # Look for command siblings: consecutive ``command`` children
            # under the same parent. After the first unconditional break
            # we flag the next command sibling (one finding per break,
            # not one per following command, to keep noise down).
            command_children = [c for c in parent.children if c.type == "command"]
            if len(command_children) < 2:
                continue
            for i, cmd in enumerate(command_children[:-1]):
                if not _is_unconditional_break(parsed, cmd):
                    continue
                next_cmd = command_children[i + 1]
                break_text = parsed.node_text(cmd).strip()
                next_text = parsed.node_text(next_cmd).strip()
                yield self.make_finding(
                    parsed,
                    next_cmd,
                    description=(
                        f"Command '{next_text[:80]}' follows an unconditional "
                        f"'{break_text}' in the same block; control never "
                        "reaches it. Move the command before the break, or "
                        "remove it."
                    ),
                    metadata={
                        "break_command": break_text,
                        "unreachable_command": next_text[:200],
                    },
                )
