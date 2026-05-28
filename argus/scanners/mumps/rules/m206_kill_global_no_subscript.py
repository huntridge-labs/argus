"""M206 — KILL of an entire global tree (diagnostic, high impact).

``K ^G`` (no subscript) deletes the *entire* global ``^G`` from the
database. ``K ^G(...)`` deletes just the named subscript. The two
forms differ by a single character and the former is almost always a
mistake — production VistA outages have been traced to a script that
meant to KILL a single record and accidentally KILLed an entire
file's worth of patient data.

mHawk surfaces this as a high-impact diagnostic; we match at INFO
severity (because the construct is technically valid MUMPS) but the
description and metadata escalate the message so reviewers can't
miss it.

Detection:

1. Walk for ``command`` nodes whose source text begins with
   ``K`` / ``KILL``.
2. Inspect the argument subtree. When the argument is a
   ``global_variable`` (bare ``^G``) rather than a ``global_array``
   (``^G(...)``), the kill is unsubscripted — flag it.
3. ``K ^G,^H`` chains are parsed as separate argument children;
   flag each unsubscripted global within the same KILL.
"""

from __future__ import annotations

import re
from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule

_KILL_KEYWORD_RE = re.compile(r"^\s*K(?:ILL)?\b", re.IGNORECASE)


def _argument_node(command_node):
    for field_name in ("arguments", "argument", "expression"):
        node = command_node.child_by_field_name(field_name)
        if node is not None:
            return node
    for child in command_node.children:
        if child.type in {"arguments", "argument"}:
            return child
    return None


class KillGlobalNoSubscriptRule(Rule):
    id = "M206"
    severity = Severity.INFO
    title = "KILL of an entire global tree (no subscript)"
    cwe = None  # diagnostic, but high real-world impact

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        for node in walk(parsed.tree.root_node):
            if node.type != "command":
                continue
            if not _KILL_KEYWORD_RE.match(parsed.node_text(node)):
                continue
            args = _argument_node(node)
            if args is None:
                continue
            for target in self._global_targets(args):
                name = parsed.node_text(target).strip()
                yield self.make_finding(
                    parsed,
                    target,
                    description=(
                        f"KILL '{name}' has no subscript — it deletes the "
                        f"entire global tree ``{name}`` from the database, "
                        "not a single record. Production data-loss incidents "
                        "in VistA have been traced to exactly this construct. "
                        f"Did you mean ``K {name}(...)``? If a wholesale "
                        "wipe is intentional, add an inline comment so a "
                        "future reader sees the intent."
                    ),
                    metadata={"global": name},
                )

    @staticmethod
    def _global_targets(arguments_node):
        """Yield ``global_variable`` nodes inside the KILL arguments
        that are *not* wrapped in a ``global_array`` (which would
        imply a subscript was supplied)."""
        for descendant in walk(arguments_node):
            if descendant.type != "global_variable":
                continue
            # Skip when the parent is a global_array — that's the
            # subscripted form (``^G(...)``), which is safe.
            parent = descendant.parent
            if parent is not None and parent.type == "global_array":
                continue
            yield descendant
