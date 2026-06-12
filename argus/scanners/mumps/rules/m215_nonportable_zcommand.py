"""M215 — non-portable Z-command (diagnostic).

``Z*`` commands (``ZSYSTEM``, ``ZGOTO``, ``ZSAVE``, ...) are
implementation-specific extensions, not ANSI/ISO M. Code using them is
locked to one MUMPS platform. ``ZSYSTEM`` additionally shells out and
overlaps CWE-78 when it builds a command line from input.

The grammar's tokenization of Z-commands is uneven (``ZSYSTEM`` keeps a
full ``keyword``; ``ZSAVE`` splits to ``ZS`` + a phantom argument), so
detection works off the leading whitespace-delimited token of each
``command`` node's source text, checked against a known Z-command set —
robust to the truncation and free of false positives from locals whose
names merely start with ``Z`` (they aren't in the set).
"""

from __future__ import annotations

from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule

# Standard implementation-specific Z-commands across GT.M / YottaDB /
# Caché. A leading token in this set marks a non-portable command.
_Z_COMMANDS = frozenset({
    "ZSYSTEM", "ZGOTO", "ZQUIT", "ZSAVE", "ZLOAD", "ZWRITE", "ZINSERT",
    "ZREMOVE", "ZPRINT", "ZBREAK", "ZKILL", "ZNEW", "ZTRAP", "ZUSE",
    "ZHALT", "ZHANG", "ZALLOCATE", "ZDEALLOCATE", "ZSHOW", "ZMESSAGE",
    "ZWITHDRAW", "ZEDIT", "ZHELP", "ZJOB", "ZSTEP", "ZLINK", "ZCOMPILE",
    "ZSYNC", "ZTCOMMIT", "ZTSTART",
})


class NonPortableZCommandRule(Rule):
    id = "M215"
    severity = Severity.LOW
    title = "Non-portable Z-command"
    cwe = None  # portability diagnostic

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        for node in walk(parsed.tree.root_node):
            if node.type != "command":
                continue
            text = parsed.node_text(node).strip()
            token = text.split(None, 1)[0].upper() if text else ""
            # Strip a postconditional (``ZSYSTEM:cond``) off the token.
            token = token.split(":", 1)[0]
            if token not in _Z_COMMANDS:
                continue
            yield self.make_finding(
                parsed,
                node,
                description=(
                    f"'{token}' is an implementation-specific Z-command, not "
                    "portable ANSI/ISO M. Code using it is locked to one "
                    "MUMPS platform; prefer a standard equivalent where one "
                    "exists."
                ),
                metadata={"command": token},
            )
