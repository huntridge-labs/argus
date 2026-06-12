"""M214 — naked global reference (diagnostic, off by default).

A naked reference ``^(sub)`` omits the global name and resolves against
the *last global referenced* at runtime. It is compact but notoriously
fragile: inserting or reordering an intervening global reference
silently retargets it, a classic source of MUMPS data-corruption bugs.

Detection is exact (probe-verified): a named reference ``^DPT(1)``
parses as ``global_array`` whose first child is ``global_variable``; a
naked ``^(1)`` parses as ``global_array`` whose first child is the bare
``^`` token. So flag ``global_array`` nodes whose first child is ``^``.

Off by default: naked references are endemic idiomatic VistA (hundreds
per package), so this is a code-review / modernization signal, not a CI
gate. Enable with ``scanners.mumps.rules.M214.enabled: true``.
"""

from __future__ import annotations

from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule


class NakedGlobalRule(Rule):
    id = "M214"
    severity = Severity.INFO
    title = "Naked global reference (^ with no global name)"
    cwe = None  # diagnostic
    enabled_by_default = False

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        for node in walk(parsed.tree.root_node):
            if node.type != "global_array":
                continue
            kids = node.children
            if not kids or kids[0].type != "^":
                continue
            yield self.make_finding(
                parsed,
                node,
                description=(
                    "Naked global reference resolves against the last global "
                    "referenced at runtime; an inserted or reordered global "
                    "access silently retargets it. Use the fully named form "
                    "(^GLOBAL(subscripts)) for clarity and safety."
                ),
                metadata={"reference": parsed.node_text(node).strip()[:80]},
            )
