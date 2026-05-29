"""M002 — indirection (``@``) injection (CWE-94).

MUMPS indirection lets a variable expand into arbitrary code: ``SET
X="^GLOBAL(""KEY"")=1"`` followed by ``XECUTE @X`` runs whatever the
attacker can put into ``X``. Indirection of a *tainted* value is a
code-injection primitive.

Precision: the rule is **taint-gated**. It fires at HIGH only when the
indirected expression references a tainted variable (READ / $ZARGV /
HTTP context global, or a config-supplied source) — the same AST
intersect model M005 uses. This is the Phase-2 refinement the original
docstring promised: flagging *every* non-literal indirection produced
~5,000 findings on two VistA packages (≈94% of all core-sink noise),
almost all benign ``S @X=Y`` / ``W @X`` idioms, which made the whole
core surface un-gateable.

The generic "indirection of a non-constant, non-tainted expression"
signal is still available for audit / modernization sweeps, but it
ships **off by default** and at INFO: set
``scanners.mumps.flag_generic_indirection: true`` to surface it. It
never counts toward a severity gate.

Constant indirection (``@("WRITE 1")``, ``@(1)``) has no variable to
inject and is never flagged.
"""

from __future__ import annotations

from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule
from ..taint import resolve_tainted
from ._common import identifier_names


class IndirectionInjectionRule(Rule):
    id = "M002"
    severity = Severity.HIGH
    title = "Possible code-injection via indirection (@)"
    cwe = "CWE-94"

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        tainted = resolve_tainted(parsed, config)
        flag_generic = bool((config or {}).get("flag_generic_indirection", False))
        if not tainted and not flag_generic:
            return
        for node in walk(parsed.tree.root_node):
            if node.type != "indirection":
                continue
            # All identifier names inside the indirection — handles
            # ``@VAR``, ``@(U_VAR)`` (the ``@(expr)`` form whose operand
            # the grammar shapes as a bare ``(`` token), and
            # ``@^GLOB(SUB)``. Empty / pure-constant indirection
            # (``@("x")`` / ``@(1)``) has no names and is skipped.
            names = identifier_names(parsed, node)
            if not names:
                continue
            text = parsed.node_text(node).strip()
            hits = names & tainted
            if hits:
                yield self.make_finding(
                    parsed,
                    node,
                    description=(
                        f"Indirection (@{text.lstrip('@')}) of tainted "
                        f"variable(s) {sorted(hits)}. The value is evaluated "
                        "as MUMPS code / a name reference at runtime; an "
                        "externally-controlled value here is code injection."
                    ),
                    metadata={"taint_sources": sorted(hits), "operand": text[:200]},
                )
            elif flag_generic:
                yield self.make_finding(
                    parsed,
                    node,
                    severity=Severity.INFO,
                    description=(
                        f"Indirection of a non-constant expression (@{text.lstrip('@')}). "
                        "Not taint-confirmed; review if the value can be "
                        "externally influenced. (Generic-indirection advisory; "
                        "enable via scanners.mumps.flag_generic_indirection.)"
                    ),
                    metadata={"operand": text[:200], "generic": True},
                )
