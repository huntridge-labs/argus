"""M208 — bare NEW command stacks every local variable (diagnostic).

``N`` (or ``NEW``) with no arguments stacks every local variable in
the current scope — saving each so its value is restored when the
scope exits. It's legal MUMPS but heavy-handed: callers usually want
to NEW a specific subset for safety, and the no-argument form is
almost always reached by accidentally omitting the targets.

Like M207, the grammar can't reliably parse the bare form so
detection runs against the raw source line.
"""

from __future__ import annotations

import re
from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource
from ..rule import Rule

_BARE_NEW_RE = re.compile(r"^\s+N(?:EW)?\s*(?:;.*)?$", re.IGNORECASE)


class BareNewRule(Rule):
    id = "M208"
    severity = Severity.INFO
    title = "Bare NEW command stacks every local variable"
    cwe = None  # diagnostic

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        source = parsed.source_text
        for line_index, line in enumerate(source.splitlines()):
            if not _BARE_NEW_RE.match(line):
                continue
            yield Finding(
                id=self.id,
                severity=self.severity,
                title=self.title,
                description=(
                    "``N`` with no arguments stacks every local variable in "
                    "the current routine scope. Name the specific locals to "
                    "protect (``N X,Y``); when wholesale scope isolation is "
                    "the intent, add an inline comment so a future reader "
                    "knows the heaviness was deliberate."
                ),
                location=f"{parsed.path}:{line_index + 1}:1",
                cwe=self.cwe,
                scanner="m",
                metadata={"line": line.rstrip()},
            )
