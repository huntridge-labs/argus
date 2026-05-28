"""M004 — hard-coded credentials in MUMPS globals (CWE-798).

Storing a credential in a global with a credential-shaped subscript is
the canonical pattern: ``SET ^CONFIG("DB","PASSWORD")="hunter2"``. The
literal sits in the routine source, gets checked into VCS, and persists
in compiled object files. mHawk flags this as one of its four taint
sinks at HIGH severity; we match that posture at CRITICAL severity given
the literal's permanence.

Detection runs over tree-sitter ``command`` nodes (so commented-out
examples and string literals appearing in unrelated contexts cannot
false-positive) and applies a focused regex to each ``SET`` command's
text:

  SET  ^GLOBAL ( ... "PASSWORD-LIKE-KEY" ... )  =  "literal"

The literal value is **redacted** before it lands in the finding; this
rule must not exfiltrate the very secret it flags.
"""

from __future__ import annotations

import re
from typing import Iterable

from argus.core.models import Finding, Severity
from argus.core.redact import REDACTED_PLACEHOLDER
from ..parser import ParsedSource, walk
from ..rule import Rule

# Subscript tokens that strongly suggest a credential. Kept narrow to
# keep false-positive rate low; broaden in Phase 2 once we have a
# triage cycle against real MUMPS corpora.
_CREDENTIAL_KEYS = (
    "PASSWORD", "PASSWD", "PWD",
    "SECRET", "API_KEY", "APIKEY", "APITOKEN",
    "TOKEN", "CREDENTIAL", "PRIVATE_KEY", "PRIVATEKEY",
)

# One regex compiled once for performance. The (?i) flag makes the
# credential subscript matching case-insensitive; literal values keep
# their original case for redaction.
_SET_KEYWORD_RE = re.compile(r"^\s*S(?:ET)?(?::[^\s]+)?\b", re.IGNORECASE)

_CREDENTIAL_SET_RE = re.compile(
    r"""
    \^                              # global sigil
    [A-Za-z%][A-Za-z0-9]*           # global name
    \(                              # subscript open
    [^)]*?                          # any preceding subscripts (lazy)
    "(?P<key>"""
    + "|".join(_CREDENTIAL_KEYS) +
    r""")"                          # the credential-shaped subscript literal
    [^)]*?                          # any trailing subscripts (lazy)
    \)                              # subscript close
    \s*=\s*                         # assignment
    "(?P<value>[^"]+)"              # the credential literal value
    """,
    re.IGNORECASE | re.VERBOSE,
)


class HardcodedCredentialsRule(Rule):
    id = "M004"
    severity = Severity.CRITICAL
    title = "Hard-coded credential in MUMPS global"
    cwe = "CWE-798"

    def analyze(self, parsed: ParsedSource) -> Iterable[Finding]:
        for node in walk(parsed.tree.root_node):
            if node.type != "command":
                continue
            command_text = parsed.node_text(node)
            if not _SET_KEYWORD_RE.match(command_text):
                continue
            for match in _CREDENTIAL_SET_RE.finditer(command_text):
                key = match.group("key").upper()
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
