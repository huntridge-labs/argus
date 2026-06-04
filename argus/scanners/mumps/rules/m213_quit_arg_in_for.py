"""M213 — QUIT with an argument inside a FOR loop (diagnostic).

``QUIT <expr>`` returns a value from an extrinsic function; inside a
``FOR`` loop it instead terminates the loop after a single iteration
and (in a non-extrinsic context) is a syntax/logic error. A loop body
that means to break should use argumentless ``QUIT`` or postconditional
``Q:cond``; a value-returning QUIT inside a FOR is almost always a bug.

Detection splits on FOR shape (probe-verified):

* **Counted FOR** (``F I=1:1:3 Q 5``) keeps its body nested, so the
  ``command`` (keyword ``Q`` + ``arguments``, no ``postconditional``)
  is found by walking the for_statement subtree.
* **Argumentless FOR** spills its body to sibling nodes, so the
  value-QUIT is detected on the physical loop line via text.
"""

from __future__ import annotations

import re
from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule
from ._common import is_argumentless_for, physical_line

# Q / QUIT followed by whitespace then a non-colon, non-empty token —
# an argument. ``Q:cond`` (postconditional) and bare ``Q`` are excluded.
_QUIT_ARG_RE = re.compile(r"(?:^|\s)Q(?:UIT)?\s+[^\s:]", re.IGNORECASE)


def _subtree_quit_with_arg(for_node):
    """Yield ``command`` nodes inside a counted FOR that are a QUIT with
    an argument and no postconditional."""
    for desc in walk(for_node):
        if desc.type != "command":
            continue
        kw = None
        has_args = False
        has_postcond = False
        for child in desc.children:
            if child.type == "keyword" and kw is None:
                kw = child
            elif child.type == "arguments":
                has_args = True
            elif child.type == "postconditional":
                has_postcond = True
        if kw is None or has_postcond or not has_args:
            continue
        yield desc, kw


class QuitArgInForRule(Rule):
    id = "M213"
    severity = Severity.MEDIUM
    title = "QUIT with an argument inside a FOR loop"
    cwe = None  # diagnostic

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        for node in walk(parsed.tree.root_node):
            if node.type != "for_statement":
                continue
            if is_argumentless_for(parsed, node):
                # Argumentless FOR — body spilled to siblings; scan the
                # physical loop line for ``Q <expr>``.
                line = physical_line(parsed, node)
                if _QUIT_ARG_RE.search(line):
                    yield self._finding(parsed, node, line)
            else:
                # Controller FOR — body is nested; walk the subtree.
                for cmd, kw in _subtree_quit_with_arg(node):
                    if parsed.node_text(kw).strip().upper() in ("Q", "QUIT"):
                        yield self._finding(parsed, cmd)

    def _finding(self, parsed, node, line: str | None = None) -> Finding:
        return self.make_finding(
            parsed,
            node,
            description=(
                "QUIT with an argument inside a FOR loop terminates the loop "
                "after one iteration (or is a syntax error outside an "
                "extrinsic). Use argumentless QUIT or a postconditional "
                "`Q:cond` to break, and return values only from $$ extrinsic "
                "labels."
            ),
            metadata={"line": (line or parsed.node_text(node)).strip()[:200]},
        )
