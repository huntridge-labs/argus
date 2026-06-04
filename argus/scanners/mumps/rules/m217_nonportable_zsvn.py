"""M217 — non-portable $Z special variable (diagnostic, off by default).

``$Z*`` special variables (``$ZTRAP``, ``$ZVERSION``, ``$ZJOB``,
``$ZA``, ``$ZTIMESTAMP``, ...) are vendor extensions, not ANSI/ISO M.
Like M216 this is a portability inventory and ships off by default.

Detection (probe-verified): they parse as a ``special_variable`` node
whose text begins with ``$Z``.
"""

from __future__ import annotations

from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule


class NonPortableZSpecialVarRule(Rule):
    id = "M217"
    severity = Severity.INFO
    title = "Non-portable $Z special variable"
    cwe = None  # portability diagnostic
    enabled_by_default = False

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        seen: set[str] = set()
        for node in walk(parsed.tree.root_node):
            if node.type != "special_variable":
                continue
            text = parsed.node_text(node).strip()
            if not text.upper().startswith("$Z"):
                continue
            key = text.upper()
            if key in seen:
                continue
            seen.add(key)
            yield self.make_finding(
                parsed,
                node,
                description=(
                    f"'{text}' is a vendor-specific $Z special variable, not "
                    "portable ANSI/ISO M. Flagged for portability inventory; "
                    "safe to ignore on single-platform code."
                ),
                metadata={"special_variable": key},
            )
