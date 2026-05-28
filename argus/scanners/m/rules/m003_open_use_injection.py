"""M003 — OPEN / USE injection from tainted input (CWE-78).

MUMPS implementations let device arguments shape what the runtime does
with the device. The relevant abuses:

* **PIPE devices (YottaDB):** ``OPEN PIPE:(COMMAND="some-cmd":...)`` and
  the ``USE`` of a PIPE-bound device let the device argument string
  execute arbitrary shell commands. A tainted device name or parameter
  string is OS command injection.
* **File / socket devices:** a tainted device name controls which file
  or network endpoint a routine reads from or writes to. Path traversal
  on file devices, attacker-chosen server on socket devices.

Detection uses the shared
:func:`argus.scanners.m.taint.collect_tainted_variables` collector to
seed the tainted set (READ, ``$ZARGV``, HTTP context globals) and then
walks for ``O`` / ``OPEN`` and ``U`` / ``USE`` commands whose argument
expression text references one of those names.

HIGH severity (not CRITICAL): accurate ``PIPE`` detection requires
parsing the device parameter string (``/COMMAND=...``), and most
non-PIPE devices are lower-impact. The PIPE-specific severity bump
lands in Phase 2 alongside the parameter parser.
"""

from __future__ import annotations

import re
from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule
from ..taint import collect_tainted_variables

_OPEN_KEYWORD_RE = re.compile(r"^\s*O(?:PEN)?\b", re.IGNORECASE)
_USE_KEYWORD_RE = re.compile(r"^\s*U(?:SE)?\b", re.IGNORECASE)


def _argument_node(command_node):
    for field_name in ("arguments", "argument", "expression"):
        node = command_node.child_by_field_name(field_name)
        if node is not None:
            return node
    for child in command_node.children:
        if child.type in {"arguments", "argument"}:
            return child
    return None


class OpenUseInjectionRule(Rule):
    id = "M003"
    severity = Severity.HIGH
    title = "OPEN / USE of tainted device argument"
    cwe = "CWE-78"

    def analyze(self, parsed: ParsedSource) -> Iterable[Finding]:
        tainted = collect_tainted_variables(parsed)
        if not tainted:
            return
        for node in walk(parsed.tree.root_node):
            if node.type != "command":
                continue
            command_text = parsed.node_text(node)
            is_open = bool(_OPEN_KEYWORD_RE.match(command_text))
            is_use = bool(_USE_KEYWORD_RE.match(command_text))
            if not (is_open or is_use):
                continue
            args = _argument_node(node)
            arg_text = parsed.node_text(args).strip() if args else ""
            hits = _tainted_references(arg_text, tainted)
            if not hits:
                continue
            keyword = "OPEN" if is_open else "USE"
            yield self.make_finding(
                parsed,
                node,
                description=(
                    f"{keyword} argument references variable(s) {sorted(hits)} "
                    "assigned from an externally-controlled source (READ, "
                    "$ZARGV, or an HTTP context global). A tainted device "
                    "name or parameter string can redirect I/O to "
                    "attacker-chosen files / sockets or, on PIPE devices, "
                    "execute arbitrary shell commands."
                ),
                metadata={
                    "command": keyword,
                    "taint_sources": sorted(hits),
                    "argument": arg_text[:200],
                },
            )


def _tainted_references(arg_text: str, tainted: set[str]) -> set[str]:
    hits: set[str] = set()
    if not arg_text or not tainted:
        return hits
    upper_arg = arg_text.upper()
    for name in tainted:
        if re.search(rf"\b{re.escape(name)}\b", upper_arg):
            hits.add(name)
    return hits
