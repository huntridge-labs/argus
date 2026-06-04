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
:func:`argus.scanners.mumps.taint.collect_tainted_variables`.

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
from ..taint import filter_charset_guarded, resolve_tainted
from ._common import tainted_references

# GT.M / YottaDB ``$ZF(-n, ...)`` invokes a host OS function; ``$ZF(-1, cmd)``
# runs ``cmd`` through the shell. The negative-selector forms are the
# OS-exec surface — a tainted argument there is command injection, the same
# class as a ``$&`` helper. (Positive-index ``$ZF`` forms are string ops.)
_ZF_SHELL_RE = re.compile(r"\$ZF\s*\(\s*-\s*\d", re.IGNORECASE)


def _function_name_text(parsed: ParsedSource, call_node) -> str:
    """Extract the called function/helper name from a ``function_call``."""
    name = call_node.child_by_field_name("name")
    if name is not None:
        return parsed.node_text(name).strip()
    for child in call_node.children:
        if child.type == "function_name":
            return parsed.node_text(child).strip()
    return ""


def _is_external_call(name: str, call_text: str) -> bool:
    """True for a host-side external call: the ``$&Helper`` mechanism, or
    the GT.M/YottaDB ``$ZF(-n, ...)`` OS-function form. A plain
    ``$Function`` intrinsic is not."""
    return name.startswith("$&") or bool(_ZF_SHELL_RE.search(call_text))


# Decode the $ZF selector to grade impact: $ZF(-1,...) execs a shell command
# (RCE), other negative selectors invoke host functions (file/socket/lib).
_ZF_SELECTOR_RE = re.compile(r"\$ZF\s*\(\s*(-?\d+)", re.IGNORECASE)

# Helper-classification map for the $& mechanism, keyed by the de-sigiled
# helper base name. Execution helpers are RCE (CRITICAL); file/socket helpers
# are HIGH; provably pure string/math helpers carry no injection risk and are
# suppressed. An UNKNOWN helper defaults to HIGH — conservative, since we
# cannot prove it is safe. Extensible later via config.
_EXEC_HELPERS = frozenset({
    "SYSTEM", "PIPE", "SPAWN", "EXEC", "SHELL", "POPEN", "ZSYSTEM",
    "SH", "COMMAND", "RUNCMD", "FORK",
})
_FILE_SOCKET_HELPERS = frozenset({
    "OPEN", "FOPEN", "SOCKET", "CONNECT", "SEND", "RECV", "RECEIVE",
    "WRITE", "READFILE", "FILE", "SENDMAIL", "BIND", "LISTEN",
})
_PURE_HELPERS = frozenset({
    "STRLEN", "LEN", "LENGTH", "UPCASE", "LOWCASE", "TOUPPER", "TOLOWER",
    "TRIM", "SUBSTR", "STRCMP", "ABS", "SQRT", "SIN", "COS", "TAN",
    "LOG", "EXP", "POW", "RANDOM",
})


def _classify_helper(name: str, call_text: str) -> Severity | None:
    """Return the calibrated severity for an external call, or ``None`` to
    suppress (provably pure helper). $ZF selector and helper-name keyed."""
    zf = _ZF_SELECTOR_RE.search(call_text)
    if zf:
        selector = int(zf.group(1))
        if selector < 0:
            return Severity.CRITICAL if selector == -1 else Severity.HIGH
        return None  # positive-index $ZF is a string operation, not OS exec
    base = name.lstrip("$&").lstrip("^").split("(")[0].split("^")[0].strip().upper().lstrip("%")
    if base in _PURE_HELPERS:
        return None
    if base in _EXEC_HELPERS:
        return Severity.CRITICAL
    if base in _FILE_SOCKET_HELPERS:
        return Severity.HIGH
    return Severity.HIGH  # unknown $& helper — conservative


class ExternalCallInjectionRule(Rule):
    id = "M006"
    severity = Severity.HIGH
    title = "Tainted argument to external ($& / $ZF) call"
    cwe = "CWE-78"

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        tainted = resolve_tainted(parsed, config)
        if not tainted:
            return
        for node in walk(parsed.tree.root_node):
            if node.type != "function_call":
                continue
            name = _function_name_text(parsed, node)
            call_text = parsed.node_text(node)
            if not _is_external_call(name, call_text):
                continue
            severity = _classify_helper(name, call_text)
            if severity is None:
                # Provably pure helper (e.g. $&strlen) or a positive-index
                # $ZF string op — no injection surface, do not report.
                continue
            hits = tainted_references(call_text, tainted)
            hits = filter_charset_guarded(parsed, config, hits, node.start_point[0])
            if not hits:
                continue
            yield self.make_finding(
                parsed,
                node,
                severity=severity,
                description=(
                    f"External call '{name}' receives argument(s) referencing "
                    f"tainted variable(s) {sorted(hits)}. Depending on the "
                    "host-side helper, the runtime value may be passed to a "
                    "shell command, file path, or socket — full OS-level "
                    "RCE for general-purpose helpers like $&system / $&pipe "
                    "or $ZF(-1,...)."
                ),
                metadata={
                    "function": name,
                    "taint_sources": sorted(hits),
                },
            )
