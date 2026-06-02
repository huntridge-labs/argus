"""M211 — scratch global (^TMP / ^UTILITY) written without a $J subscript
(CWE-362 race condition).

VistA's shared scratch globals (``^TMP``, ``^UTILITY``) are used by
every concurrent process. The SAC requires subscripting them by ``$J``
(the process id) so each job gets a private branch:

    S ^TMP($J,"KEY")=value     ; correct — per-process
    S ^TMP("KEY")=value        ; WRONG — cross-process collision

A write (or KILL / MERGE) of a scratch global with no ``$J`` in its
subscripts can clobber another process's data — a real concurrency bug.
Technically valid M, so this ships at INFO with the impact spelled out
in the description (mirrors M206's escalate-via-text approach).

Detection (probe-verified): an ``assignment`` whose write target is a
``global_array`` named ``^TMP`` / ``^UTILITY`` with no ``special_variable
'$J'`` in its ``array_index``; likewise ``KILL`` / ``MERGE`` targets.
``LOCK`` is excluded automatically — it wraps the global in a
``unary_expression`` under a ``command``, not an assignment / KILL /
MERGE. The scratch-global set is configurable via
``scanners.mumps.scratch_globals``.
"""

from __future__ import annotations

import re
from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule
from ._common import argument_node

_DEFAULT_SCRATCH = ("^TMP", "^UTILITY")
_KILL_MERGE_RE = re.compile(r"^\s*(?:K(?:ILL)?|M(?:ERGE)?)\b", re.IGNORECASE)
# An assignment whose RHS is exactly the process-id special variable
# (``S JOB=$J`` / ``S L=$JOB``) yields a job-private value, so a scratch
# global subscripted by that local is per-process — not a race.
_JOB_DERIVE_RE = re.compile(r"^\$J(?:OB)?$", re.IGNORECASE)


def _scratch_globals(config: dict | None) -> set[str]:
    extra = (config or {}).get("scratch_globals")
    names = list(extra) if extra else list(_DEFAULT_SCRATCH)
    return {str(n).strip().upper() for n in names}


def _job_private_locals(parsed: ParsedSource, config: dict | None) -> set[str]:
    """Local variable names that hold the process id, so a scratch global
    subscripted by one of them is process-private.

    Sound by construction: a name qualifies only if it is *provably* assigned
    ``$J``/``$JOB`` somewhere in the routine, or it is in the configurable
    ``rules.M211.job_subscripts`` allowlist (for the cross-routine convention
    where the job id arrives as a formal argument named e.g. ``JOB``)."""
    names: set[str] = set()
    for node in walk(parsed.tree.root_node):
        if node.type != "assignment":
            continue
        named = [c for c in node.children if c.is_named]
        if len(named) < 2 or named[0].type not in {"local_variable", "identifier", "variable"}:
            continue
        if _JOB_DERIVE_RE.match(parsed.node_text(named[-1]).strip()):
            names.add(parsed.node_text(named[0]).strip().upper())
    allow = (config or {}).get("rules", {}).get("M211", {}).get("job_subscripts") or []
    names |= {str(n).strip().upper() for n in allow}
    return names


def _global_array_name(parsed: ParsedSource, garr) -> str:
    for child in garr.children:
        if child.type == "global_variable":
            return parsed.node_text(child).strip().upper()
    return ""


def _has_job_subscript(parsed: ParsedSource, garr, job_locals: set[str]) -> bool:
    for desc in walk(garr):
        if desc.type == "special_variable" and parsed.node_text(desc).strip().upper() == "$J":
            return True
        if (
            job_locals
            and desc.type in {"local_variable", "identifier", "variable"}
            and parsed.node_text(desc).strip().upper() in job_locals
        ):
            return True
    return False


class ScratchGlobalNoJobRule(Rule):
    id = "M211"
    severity = Severity.INFO
    title = "Scratch global written without a $J subscript"
    cwe = "CWE-362"

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        scratch = _scratch_globals(config)
        job_locals = _job_private_locals(parsed, config)
        for node in walk(parsed.tree.root_node):
            target = None
            if node.type == "assignment":
                named = [c for c in node.children if c.is_named]
                if named and named[0].type == "global_array":
                    target = named[0]
            elif node.type == "command" and _KILL_MERGE_RE.match(parsed.node_text(node)):
                args = argument_node(node)
                if args is not None:
                    target = next(
                        (d for d in walk(args) if d.type == "global_array"), None,
                    )
            if target is None:
                continue
            name = _global_array_name(parsed, target)
            if name not in scratch:
                continue
            if _has_job_subscript(parsed, target, job_locals):
                continue
            yield self.make_finding(
                parsed,
                target,
                description=(
                    f"{name} is a shared scratch global but this write has no "
                    "$J subscript, so concurrent processes can clobber each "
                    f"other's data. Subscript by $J, e.g. {name}($J,...). "
                    "(CWE-362 race condition.)"
                ),
                metadata={"global": name, "reference": parsed.node_text(target).strip()[:80]},
            )
