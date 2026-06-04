"""M219 — source line exceeds the SAC 245-character limit.

VistA SAC caps a routine line at 245 characters; longer lines are
truncated on load by some implementations, silently corrupting code.
This is a pure text check — line length is independent of the parse
tree, and going through the AST would only add fragility.

Configurable limit via ``scanners.mumps.max_line_length`` (default 245).
"""

from __future__ import annotations

from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource
from ..rule import Rule

_DEFAULT_LIMIT = 245


class LineLengthRule(Rule):
    id = "M219"
    severity = Severity.LOW
    title = "Source line exceeds the SAC length limit"
    cwe = None  # SAC convention

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        try:
            limit = int((config or {}).get("max_line_length", _DEFAULT_LIMIT))
        except (TypeError, ValueError):
            limit = _DEFAULT_LIMIT
        path = str(parsed.path)
        for line_index, line in enumerate(parsed.source_text.split("\n")):
            if len(line) <= limit:
                continue
            yield Finding(
                id=self.id,
                severity=self.severity,
                title=self.title,
                description=(
                    f"Line is {len(line)} characters, over the {limit}-char "
                    "SAC limit. Some MUMPS implementations truncate long "
                    "routine lines on load, silently corrupting the code."
                ),
                location=f"{path}:{line_index + 1}:{limit + 1}",
                cwe=self.cwe,
                scanner="mumps",
                metadata={"length": len(line), "limit": limit},
            )
