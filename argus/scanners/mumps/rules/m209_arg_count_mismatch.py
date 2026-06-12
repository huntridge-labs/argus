"""M209 — call passes more arguments than the entry point declares.

``D RUN^OTHER(A,B,C)`` where ``RUN`` is declared ``RUN(P1,P2)`` passes
more actuals than there are formals. In GT.M / YottaDB this is a hard
runtime error (MAXARGCNT / "actual list exceeds formal list"); it is
always a bug.

This is genuinely inter-procedural and complements the intra-file
def-use rules (M203 / M204). The data it needs already exists on the
call graph built every scan: ``CallEdge.actual_arg_names`` (positional
actuals) and ``RoutineNode.entry_formals`` (the callee's declared
formals per entry label).

Conservative scoping (keeps false positives near zero):
* Only ``DO`` / ``GOTO`` cross-routine edges (``$$fn^rtn`` extrinsics
  parse as ``function_call`` and never build an edge).
* Skip edges whose actuals contain a nested call — the positional split
  is unreliable there (``CallEdge.has_nested_call``).
* Only flag when the callee entry's formal list is known; a call into an
  entry we didn't index (no declared formals, or callee not in the scan)
  is left alone rather than guessed at.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource
from ..rule import Rule


class ArgCountMismatchRule(Rule):
    id = "M209"
    severity = Severity.MEDIUM
    title = "Call passes more arguments than the entry point declares"
    cwe = None  # correctness bug, not a CWE category

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        callgraph = (config or {}).get("_callgraph")
        if callgraph is None:
            return
        caller = Path(parsed.path).stem.upper()
        for edge in callgraph.callees_of(caller):
            if edge.has_nested_call:
                continue
            n_actuals = len(edge.actual_arg_names)
            if n_actuals == 0:
                continue
            callee = callgraph.routines.get(edge.callee_routine)
            if callee is None:
                continue
            entry = edge.callee_label or edge.callee_routine
            formals = callee.entry_formals.get(entry)
            if formals is None:
                # Entry's formal list unknown — don't guess.
                continue
            if n_actuals <= len(formals):
                continue
            target = (
                f"{entry}^{edge.callee_routine}"
                if edge.callee_label else f"^{edge.callee_routine}"
            )
            yield Finding(
                id=self.id,
                severity=self.severity,
                title=self.title,
                description=(
                    f"Call to {target} passes {n_actuals} argument(s) but the "
                    f"entry declares only {len(formals)} formal parameter(s) "
                    f"{list(formals)}. GT.M / YottaDB raise a runtime error "
                    "when the actual list exceeds the formal list."
                ),
                location=edge.call_site,
                cwe=self.cwe,
                scanner="mumps",
                metadata={
                    "callee": target,
                    "actuals": n_actuals,
                    "formals": len(formals),
                },
            )
