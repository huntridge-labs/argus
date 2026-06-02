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
from ..taint import filter_charset_guarded, resolve_tainted
from ._common import argument_node, tainted_references


_XECUTE_KEYWORD_RE = re.compile(r"^\s*X(?:ECUTE)?\b", re.IGNORECASE)


def _argument_is_string_literal(parsed: ParsedSource, arg_node) -> bool:
    """True when an XECUTE argument bottoms out in a single string literal.

    The grammar nests a constant XECUTE as
    ``arguments -> argument -> string`` (the string is a *grandchild*),
    so a single-level child check misses it and the literal fires — a
    pure false positive. Descend through single-named-child wrappers
    and return True only when the bottom node is a string.

    A concatenation like ``X "WRITE "_INPUT`` has more than one named
    child at the ``argument`` level, so it is *not* a literal and
    correctly remains a candidate for the taint sink pass.
    """
    node = arg_node
    while node is not None:
        if node.type in {"string_literal", "string"}:
            return True
        named = [c for c in node.children if c.is_named]
        if len(named) != 1:
            return False
        node = named[0]
    return False


def _is_real_xecute(command_text: str) -> bool:
    """Discriminate a real XECUTE command from a grammar misparse.

    ``_XECUTE_KEYWORD_RE`` matches at a word boundary, so an expression
    the grammar mis-shaped into a command — ``I X<1!(X>OSMAX)`` — looks
    like ``X`` glued to a relational/pattern operator. A genuine XECUTE
    is ``X <expr>`` or ``X:cond <expr>``: the keyword is followed by
    whitespace, end-of-text, or a postconditional ``:``. Anything else
    (``<``, ``>``, ``=``, ``[``, ``'``, ``(``) is a misparse.
    """
    m = _XECUTE_KEYWORD_RE.match(command_text)
    if m is None:
        return False
    after = command_text[m.end():m.end() + 1]
    return after == "" or after.isspace() or after == ":"


class XECUTEInjectionRule(Rule):
    id = "M001"
    severity = Severity.HIGH
    title = "XECUTE of tainted expression"
    cwe = "CWE-95"

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        tainted = resolve_tainted(parsed, config)
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
            if not _is_real_xecute(command_text):
                continue
            args = argument_node(node)
            if _argument_is_string_literal(parsed, args):
                continue
            arg_text = parsed.node_text(args).strip() if args else ""
            hits = tainted_references(arg_text, tainted)
            hits = filter_charset_guarded(parsed, config, hits, node.start_point[0])
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
