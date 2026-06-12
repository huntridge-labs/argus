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
from ..taint import filter_charset_guarded, resolve_tainted
from ._common import identifier_names

# Commands whose indirection operand is a NAME / glvn target, not an
# evaluated expression — ``K @(X)`` / ``L +@(X)`` / ``M @(X)=^G`` / ``N @(X)``
# resolve a variable name, they do not execute code.
_NAME_TARGET_MNEMONICS = frozenset({"K", "KILL", "L", "LOCK", "M", "MERGE", "N", "NEW"})
# Dispatch / execute commands whose indirection IS executable but is already
# owned by the dedicated sinks: XECUTE (M001) and DO/GOTO/JOB dispatch (M005).
# Excluding them keeps M002 from double-reporting the same site.
_DISPATCH_MNEMONICS = frozenset({"X", "XECUTE", "D", "DO", "G", "GOTO", "J", "JOB"})


def _preceding_command_token(src: bytes, at: int) -> str:
    """Uppercased alphabetic token immediately preceding byte offset ``at``
    (spaces/tabs skipped) — the command letter governing the indirection."""
    j = at - 1
    while j >= 0 and src[j:j + 1] in (b" ", b"\t"):
        j -= 1
    k = j
    while k >= 0 and chr(src[k]).isalpha():
        k -= 1
    return src[k + 1:j + 1].decode("ascii", errors="replace").upper()


def _is_executable_expression_indirection(parsed: ParsedSource, node) -> bool:
    """True only for the ``@(<expr>)`` paren / expression form in a value
    position — indirection that evaluates a *computed string* as MUMPS
    source (``I @("$T(+2^"_RTN_")...")``), the genuine code-injection
    primitive. Decided from source text, which is robust to the grammar
    mis-spanning the node, and suppresses:

    * SET / assignment targets — a ``)=`` inside the node, or ``=`` right
      after it (the grammar sometimes ends the node before the ``=``);
    * KILL / LOCK / MERGE / NEW name targets and XECUTE / DO / GOTO / JOB
      dispatch (the latter owned by M001 / M005), keyed off the command
      token preceding the ``@``;
    * simple ``@VAR`` / ``@VAR@(sub)`` forms (not the ``@(`` paren form).
    """
    src = parsed.source_bytes
    start, end = node.start_byte, node.end_byte
    if src[start:start + 2] != b"@(":
        return False
    node_bytes = src[start:end]
    if b")=" in node_bytes or src[end:end + 1] == b"=":
        return False  # SET / assignment target — a name, not an expression
    prev = _preceding_command_token(src, start)
    return prev not in _NAME_TARGET_MNEMONICS and prev not in _DISPATCH_MNEMONICS


class IndirectionInjectionRule(Rule):
    id = "M002"
    severity = Severity.HIGH
    title = "Possible code-injection via indirection (@)"
    cwe = "CWE-94"
    # Position-aware: fires HIGH only on the ``@(<expr>)`` paren / expression
    # form in a value position — the indirection that evaluates a computed
    # string as MUMPS source. Simple ``@VAR`` / ``@VAR@(sub)`` name & glvn
    # references and SET/KILL/LOCK targets resolve a name (not code) and are
    # suppressed; XECUTE / DO / GOTO dispatch is owned by M001 / M005. This
    # gating is what makes the rule trustworthy on real code, so it ships on.

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
            hits = filter_charset_guarded(parsed, config, names & tainted, node.start_point[0])
            if hits and _is_executable_expression_indirection(parsed, node):
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
