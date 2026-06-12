"""M207 — bare KILL command deletes every local variable (diagnostic).

``K`` with no arguments (also ``KILL``) deletes every local variable
in the current scope. It's a legal MUMPS construct but almost always
a mistake: callers expect to clean up a *specific* variable and the
no-argument form is reached by accidentally omitting the target.
Production VistA incidents have traced data loss back to a bare
``K`` that wiped state a caller still needed.

The tree-sitter-mumps grammar can't parse bare ``K`` cleanly — it
ends up swallowed into an ERROR node alongside the surrounding
comments. Detection runs against the raw source line: each line with
a leading ``K`` / ``KILL`` followed by nothing but whitespace or a
comment is flagged. False positives on string literals containing
``K`` are not possible because we anchor to the line start.
"""

from __future__ import annotations

import re
from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource
from ..rule import Rule

_BARE_KILL_RE = re.compile(r"^\s+K(?:ILL)?\s*(?:;.*)?$", re.IGNORECASE)


class BareKillRule(Rule):
    id = "M207"
    severity = Severity.INFO
    title = "Bare KILL command deletes every local variable"
    cwe = None  # diagnostic, but high real-world impact

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        source = parsed.source_text
        for line_index, line in enumerate(source.splitlines()):
            if not _BARE_KILL_RE.match(line):
                continue
            yield Finding(
                id=self.id,
                severity=self.severity,
                title=self.title,
                description=(
                    "``K`` with no arguments deletes every local variable in "
                    "the current routine scope. Specify the target you mean "
                    "to delete (``K X``) or, when wiping a whole scope is "
                    "intentional, add an inline comment explaining the intent."
                ),
                location=f"{parsed.path}:{line_index + 1}:1",
                cwe=self.cwe,
                scanner="mumps",
                metadata={"line": line.rstrip()},
            )
