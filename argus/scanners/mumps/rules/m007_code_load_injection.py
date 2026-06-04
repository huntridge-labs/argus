"""M007 — tainted source loaded / compiled as executable code (CWE-95).

The Z-command family that loads, inserts, or compiles MUMPS source treats
its argument as *code*, not data:

* ``ZLINK name`` / ``ZL name`` — compile-and-link the routine named by the
  argument, then make it callable. A tainted name links an attacker-chosen
  (or attacker-written) routine.
* ``ZINSERT src`` / ``ZI src`` — insert a line of MUMPS source into the
  current routine buffer. A tainted argument injects attacker code that a
  following ``ZSAVE`` persists and a later ``DO`` executes.
* ``ZLOAD name`` — load the named routine into the buffer for execution.
* ``ZCOMPILE expr`` — compile the named/expressed source.

When the argument derives from a tainted source (READ, ``$ZARGV``, an HTTP
context global) the caller controls which code is loaded or compiled — the
same code-execution class as XECUTE (M001), so HIGH / CWE-95.

Detection mirrors the other taint sinks: the shared tainted-variable set
plus the flow-sensitive charset-guard filter, intersected against the
command's argument text.
"""

from __future__ import annotations

import re
from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule
from ..taint import filter_charset_guarded, resolve_tainted
from ._common import tainted_references

# Z-commands that load / insert / compile MUMPS source as code. ``ZL`` and
# ``ZI`` are the standard abbreviations of ZLINK and ZINSERT; ``\b`` keeps
# ``ZL`` from matching the longer, distinct ``ZLOAD`` in the ZL branch.
_CODE_LOAD_RE = re.compile(
    r"^\s*(ZL(?:INK)?|ZI(?:NSERT)?|ZLOAD|ZCOMPILE)\b", re.IGNORECASE,
)


class CodeLoadInjectionRule(Rule):
    id = "M007"
    severity = Severity.HIGH
    title = "Tainted source loaded/compiled as code (ZLINK / ZINSERT / ZCOMPILE)"
    cwe = "CWE-95"

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        tainted = resolve_tainted(parsed, config)
        if not tainted:
            return
        lines = parsed.source_bytes.split(b"\n")
        for node in walk(parsed.tree.root_node):
            if node.type != "command":
                continue
            text = parsed.node_text(node)
            match = _CODE_LOAD_RE.match(text)
            if match is None:
                continue
            # The grammar splits an argument that looks like a command
            # (``ZINSERT LINE`` -> [ZINSERT, LINE]), leaving the command node
            # argument-less. Take the argument from the physical source line
            # (keyword + trailing comment stripped) so the split arg is seen.
            row = node.start_point[0]
            line = lines[row].decode("utf-8", errors="replace") if row < len(lines) else text
            semi = line.find(";")
            if semi >= 0:
                line = line[:semi]
            arg_text = _CODE_LOAD_RE.sub("", line, count=1).strip()
            if not arg_text:
                continue
            hits = tainted_references(arg_text, tainted)
            hits = filter_charset_guarded(parsed, config, hits, node.start_point[0])
            if not hits:
                continue
            keyword = match.group(1).upper()
            yield self.make_finding(
                parsed,
                node,
                description=(
                    f"{keyword} loads/compiles source referencing tainted "
                    f"variable(s) {sorted(hits)} (READ, $ZARGV, or an HTTP "
                    "context global). The runtime value selects or supplies "
                    "the code that is linked, inserted, or compiled — an "
                    "attacker controls which code executes (code injection)."
                ),
                metadata={
                    "command": keyword,
                    "taint_sources": sorted(hits),
                    "argument": arg_text[:200],
                },
            )
