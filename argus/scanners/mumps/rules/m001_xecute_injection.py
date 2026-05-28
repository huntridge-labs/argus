"""M001 — XECUTE injection from tainted input (CWE-95).

``XECUTE expr`` evaluates ``expr`` as MUMPS code at runtime. When
``expr`` is composed from anything a caller can influence (a ``READ``
into a terminal variable, ``$ZARGV`` on a YottaDB / GT.M command line,
an HTTP context global like ``^%CGI``) the call is remote-code-
execution.

Detection runs in two passes:

1. **Source pass** — :func:`argus.scanners.mumps.taint.collect_tainted_variables`
   walks the routine once, collecting every variable assigned from a
   Phase 1+ taint source. Sources: ``READ`` arguments, assignment RHS
   referencing ``$ZARGV``, and assignment RHS referencing the HTTP
   context globals ``^%CGI`` / ``^%REQUEST`` / ``^%session``.
2. **Sink pass** — for each ``X`` / ``XECUTE`` command, check whether
   its argument expression text references any tainted name. If so,
   emit a finding.

Phase 1 is intra-file (a "routine" is treated as one scope). Phase 2
adds per-routine scoping plus inter-procedural call-graph taint.
String-literal XECUTEs (``X "WRITE 1"``) are always safe and never
flagged.
"""

from __future__ import annotations

import re
from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule
from ..taint import collect_tainted_variables


_XECUTE_KEYWORD_RE = re.compile(r"^\s*X(?:ECUTE)?\b", re.IGNORECASE)


def _argument_node(command_node):
    for field_name in ("arguments", "argument", "expression"):
        node = command_node.child_by_field_name(field_name)
        if node is not None:
            return node
    for child in command_node.children:
        if child.type in {"arguments", "argument"}:
            return child
    return None


def _argument_is_string_literal(parsed: ParsedSource, arg_node) -> bool:
    """True when an XECUTE argument is a single string literal.

    Concatenations like ``X "WRITE "_INPUT`` are not literals: they're
    built at runtime and remain candidates for the sink pass.
    """
    if arg_node is None:
        return False
    if arg_node.type in {"string_literal", "string"}:
        return True
    children = [c for c in arg_node.children if c.is_named]
    if len(children) == 1 and children[0].type in {"string_literal", "string"}:
        return True
    return False


class XECUTEInjectionRule(Rule):
    id = "M001"
    severity = Severity.HIGH
    title = "XECUTE of tainted expression"
    cwe = "CWE-95"

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        tainted = collect_tainted_variables(parsed, config)
        if not tainted:
            return
        # Cross-routine context: when MumpsScanner.scan ran over multiple
        # files it puts the call graph on ``config['_callgraph']``.
        # Use it to annotate findings with the routines that reach
        # this one, so reviewers see the blast radius without re-
        # scanning. Full inter-procedural taint propagation lands in
        # Phase 2.5; this is the demonstrative wiring.
        callers = _resolve_callers(parsed, config)
        for node in walk(parsed.tree.root_node):
            if node.type != "command":
                continue
            command_text = parsed.node_text(node)
            if not _XECUTE_KEYWORD_RE.match(command_text):
                continue
            args = _argument_node(node)
            if _argument_is_string_literal(parsed, args):
                continue
            arg_text = parsed.node_text(args).strip() if args else ""
            hits = _tainted_references(arg_text, tainted)
            if not hits:
                continue
            metadata: dict = {
                "taint_sources": sorted(hits),
                "argument": arg_text[:200],
            }
            if callers:
                metadata["inter_procedural_callers"] = callers
            yield self.make_finding(
                parsed,
                node,
                description=(
                    f"XECUTE argument references variable(s) {sorted(hits)} "
                    "assigned from an externally-controlled source (READ, "
                    "$ZARGV, or an HTTP context global). The runtime value "
                    "of those variables is executed as MUMPS code."
                ),
                metadata=metadata,
            )


def _resolve_callers(parsed: ParsedSource, config: dict | None) -> list[str]:
    """Return uppercased routine names that call into the routine
    containing ``parsed``, or an empty list when there's no call graph
    or no callers. Resolves the current routine's name from its file
    basename (matches GT.M / YottaDB / Caché dispatch)."""
    if not config:
        return []
    callgraph = config.get("_callgraph")
    if callgraph is None:
        return []
    from pathlib import Path
    name = Path(parsed.path).stem.upper()
    return sorted({edge.caller for edge in callgraph.callers_of(name)})


def _tainted_references(arg_text: str, tainted: set[str]) -> set[str]:
    """Return the subset of ``tainted`` referenced as identifiers in
    ``arg_text``. Whole-word match (case-insensitive) to avoid flagging
    substrings of unrelated variable names.
    """
    hits: set[str] = set()
    if not arg_text or not tainted:
        return hits
    upper_arg = arg_text.upper()
    for name in tainted:
        if re.search(rf"\b{re.escape(name)}\b", upper_arg):
            hits.add(name)
    return hits
