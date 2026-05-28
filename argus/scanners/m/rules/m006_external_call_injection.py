"""M006 — tainted argument to external system call ($&) (CWE-78).

MUMPS implementations expose host OS functionality via the ``$&``
external-call mechanism. ``$&CALLOUT(...)`` invokes a C-implemented
helper registered by the runtime; the standard distribution and
custom routine libraries register helpers that exec shell commands,
write files, open sockets, or run privileged operations. When an
argument to a ``$&`` call comes from a tainted source (READ,
``$ZARGV``, an HTTP context global) the caller controls what the
host-side helper runs.

Detection: walk for ``function_call`` nodes whose ``function_name``
starts with ``$&``. Compare the argument-subtree text against the
shared tainted-variable set produced by
:func:`argus.scanners.m.taint.collect_tainted_variables`.

HIGH severity rather than CRITICAL — the helper's effect depends on
the specific implementation. Some helpers are pure (``$&strlen``);
others are arbitrary-execution (``$&system``, ``$&pipe``). Phase 2
will add a configurable helper-classification map so each helper
gets its calibrated severity bump.
"""

from __future__ import annotations

import re
from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule
from ..taint import collect_tainted_variables


def _function_name_text(parsed: ParsedSource, call_node) -> str:
    """Extract the called function/helper name from a ``function_call``."""
    name = call_node.child_by_field_name("name")
    if name is not None:
        return parsed.node_text(name).strip()
    for child in call_node.children:
        if child.type == "function_name":
            return parsed.node_text(child).strip()
    return ""


def _is_external_call(name: str) -> bool:
    """``$&Helper`` is an external system call; ``$Function`` is a
    built-in intrinsic. Only the ``$&`` form invokes host-side code."""
    return name.startswith("$&")


class ExternalCallInjectionRule(Rule):
    id = "M006"
    severity = Severity.HIGH
    title = "Tainted argument to external ($&) call"
    cwe = "CWE-78"

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        tainted = collect_tainted_variables(parsed, config)
        if not tainted:
            return
        for node in walk(parsed.tree.root_node):
            if node.type != "function_call":
                continue
            name = _function_name_text(parsed, node)
            if not _is_external_call(name):
                continue
            call_text = parsed.node_text(node)
            hits = _tainted_references(call_text, tainted)
            if not hits:
                continue
            yield self.make_finding(
                parsed,
                node,
                description=(
                    f"External call '{name}' receives argument(s) referencing "
                    f"tainted variable(s) {sorted(hits)}. Depending on the "
                    "host-side helper, the runtime value may be passed to a "
                    "shell command, file path, or socket — full OS-level "
                    "RCE for general-purpose helpers like $&system / $&pipe."
                ),
                metadata={
                    "function": name,
                    "taint_sources": sorted(hits),
                },
            )


def _tainted_references(call_text: str, tainted: set[str]) -> set[str]:
    hits: set[str] = set()
    if not call_text or not tainted:
        return hits
    upper = call_text.upper()
    for name in tainted:
        if re.search(rf"\b{re.escape(name)}\b", upper):
            hits.add(name)
    return hits
