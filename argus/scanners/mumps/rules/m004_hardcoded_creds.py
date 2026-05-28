"""M004 — hard-coded credentials in MUMPS globals (CWE-798).

Storing a credential in a global with a credential-shaped subscript is
the canonical leak pattern: ``SET ^CONFIG("DB","PASSWORD")="hunter2"``.
The literal sits in the routine source, gets checked into VCS, and
persists in compiled object files. mHawk flags this as one of its four
taint sinks at HIGH severity; we match that posture at CRITICAL severity
given the literal's permanence.

The grammar parses ``SET <global>=<literal>`` as an ``assignment`` node,
not a ``command`` node — separate from XECUTE / READ / OPEN. The
``assignment`` has the global on the left, an unnamed ``=`` operator
literal, and the value on the right. We walk the LHS for a
credential-shaped subscript string and verify the RHS is a single
string literal before flagging.

The matched literal value is **redacted** before it lands in the
finding — this rule must not exfiltrate the very secret it flags.
"""

from __future__ import annotations

from typing import Iterable, Optional

from argus.core.models import Finding, Severity
from argus.core.redact import REDACTED_PLACEHOLDER
from ..parser import ParsedSource, walk
from ..rule import Rule

# Subscript tokens that strongly suggest a credential. Kept narrow to
# keep false-positive rate low; broaden in Phase 2 once we have a
# triage cycle against real MUMPS corpora.
_CREDENTIAL_KEYS = frozenset({
    "PASSWORD", "PASSWD", "PWD",
    "SECRET", "API_KEY", "APIKEY", "APITOKEN",
    "TOKEN", "CREDENTIAL", "CREDENTIALS",
    "PRIVATE_KEY", "PRIVATEKEY",
})


def _named_children(node):
    return [c for c in node.children if c.is_named]


def _lhs_rhs(assignment_node):
    """Return ``(lhs_node, rhs_node)`` from an ``assignment`` subtree.

    The grammar lays the assignment out as ``lhs '=' rhs`` with the
    ``=`` token as an unnamed child. Pick the first and last named
    children to stay resilient against minor grammar revisions.
    """
    named = _named_children(assignment_node)
    if len(named) < 2:
        return None, None
    return named[0], named[-1]


def _credential_subscript(parsed: ParsedSource, lhs_node) -> Optional[str]:
    """Return a matched credential subscript name, or None.

    Walks ``lhs_node`` (a ``global_array``) looking for string literals
    inside its ``array_index``. Compares the unquoted, uppercased text
    against ``_CREDENTIAL_KEYS``.
    """
    for descendant in walk(lhs_node):
        if descendant.type != "string":
            continue
        raw = parsed.node_text(descendant).strip()
        unquoted = raw[1:-1] if raw.startswith('"') and raw.endswith('"') else raw
        normalized = unquoted.upper()
        if normalized in _CREDENTIAL_KEYS:
            return normalized
    return None


def _is_string_literal(node) -> bool:
    return node is not None and node.type in {"string", "string_literal"}


class HardcodedCredentialsRule(Rule):
    id = "M004"
    severity = Severity.CRITICAL
    title = "Hard-coded credential in MUMPS global"
    cwe = "CWE-798"

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        for node in walk(parsed.tree.root_node):
            if node.type != "assignment":
                continue
            lhs, rhs = _lhs_rhs(node)
            if lhs is None or rhs is None:
                continue
            if lhs.type != "global_array":
                continue
            if not _is_string_literal(rhs):
                continue
            key = _credential_subscript(parsed, lhs)
            if key is None:
                continue
            yield self.make_finding(
                parsed,
                node,
                description=(
                    f"SET assigns a literal value to a global with a "
                    f"'{key}'-shaped subscript. The literal sits in "
                    "the routine source and compiled object files. "
                    "Replace with a runtime lookup against a secret "
                    "store or environment variable."
                ),
                metadata={
                    "credential_key": key,
                    "value": REDACTED_PLACEHOLDER,
                },
            )
