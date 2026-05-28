"""M204 — local variable set but never read (diagnostic).

A SET that no later expression consumes is dead code — usually a typo
on the *use* site (the user meant a different name) or a leftover
from a removed feature. mHawk surfaces this as a diagnostic; we match
at INFO severity.

Detection mirrors M203: collect (start_byte, end_byte) positions for
every local-variable definition site (assignment LHS, NEW target,
READ target), walk again for non-definition local-variable
references, and report any defined name that never appears among the
references.

Known limitations (intentional for Phase 1):

* Cross-routine reads — if a routine SETs a variable that a callee
  reads via implicit-NEW inheritance, we'll false-positive flag the
  setter as unused. Resolves with inter-procedural analysis in Phase 2.
* Indirection / XECUTE consumption — ``X "W Y"`` reads ``Y`` at
  runtime through the executed string. Phase 1 conservatively
  considers the name used when it appears anywhere in the file's
  source text outside its own definition site, even inside a string
  literal.
"""

from __future__ import annotations

import re
from typing import Iterable

from argus.core.models import Finding, Severity
from ..parser import ParsedSource, walk
from ..rule import Rule

_NEW_KEYWORD_RE = re.compile(r"^\s*N(?:EW)?\b", re.IGNORECASE)
_READ_KEYWORD_RE = re.compile(r"^\s*R(?:EAD)?\b", re.IGNORECASE)
_VAR_TYPES = frozenset({"local_variable", "identifier", "variable"})


def _argument_node(command_node):
    for field_name in ("arguments", "argument", "expression"):
        node = command_node.child_by_field_name(field_name)
        if node is not None:
            return node
    for child in command_node.children:
        if child.type in {"arguments", "argument"}:
            return child
    return None


def _collect_definitions(parsed: ParsedSource):
    """Yield ``(start_byte, end_byte, name)`` for every definition site."""
    for node in walk(parsed.tree.root_node):
        if node.type == "assignment":
            named = [c for c in node.children if c.is_named]
            if named and named[0].type in _VAR_TYPES:
                yield (
                    named[0].start_byte,
                    named[0].end_byte,
                    parsed.node_text(named[0]).strip().upper(),
                    named[0],
                )
        elif node.type == "command":
            text = parsed.node_text(node)
            if not (_NEW_KEYWORD_RE.match(text) or _READ_KEYWORD_RE.match(text)):
                continue
            args = _argument_node(node)
            if args is None:
                continue
            for descendant in walk(args):
                if descendant.type in _VAR_TYPES:
                    yield (
                        descendant.start_byte,
                        descendant.end_byte,
                        parsed.node_text(descendant).strip().upper(),
                        descendant,
                    )


def _strip_mumps_comments(source: str) -> str:
    """Return ``source`` with each line's trailing ``;...`` comment
    replaced by spaces (preserving offsets, so byte ranges still
    align). Comment-stripping is naive — a ``;`` inside a string
    literal is incorrectly treated as a comment start. Acceptable
    for the use-detection backstop: the worst case is a missed use
    (and thus a false positive at most), not a false negative."""
    out = []
    for line in source.splitlines(keepends=True):
        semi = line.find(";")
        if semi < 0:
            out.append(line)
            continue
        # Keep the prefix and newline so byte positions don't shift.
        prefix = line[:semi]
        # Preserve the newline if present so total length matches.
        trailing = "\n" if line.endswith("\n") else ""
        spaces = " " * (len(line) - len(prefix) - len(trailing))
        out.append(prefix + spaces + trailing)
    return "".join(out)


class UnusedLocalRule(Rule):
    id = "M204"
    severity = Severity.INFO
    title = "Local variable set but never read"
    cwe = None  # diagnostic

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        defs = list(_collect_definitions(parsed))
        def_positions = {(s, e) for s, e, _, _ in defs}
        # Collect every local-variable reference outside the def sites
        # as a "use". Also include the raw source-text count as a
        # backstop for indirection / XECUTE consumption: if the name
        # appears anywhere outside its own definition byte range,
        # consider it referenced.
        used_names: set[str] = set()
        for node in walk(parsed.tree.root_node):
            if node.type not in _VAR_TYPES:
                continue
            pos = (node.start_byte, node.end_byte)
            if pos in def_positions:
                continue
            name = parsed.node_text(node).strip().upper()
            if name:
                used_names.add(name)
        # Source-text fallback for XECUTE indirection: if the name
        # appears as a whole word anywhere in the file (case-
        # insensitive) outside the definition site AND outside a
        # MUMPS comment, count it as used. Comment-stripping prevents
        # a docstring that mentions the variable from making it look
        # used.
        source_text_no_comments = _strip_mumps_comments(parsed.source_text)
        flagged_positions: set[tuple[int, int]] = set()
        for start, end, name, node in defs:
            if not name:
                continue
            if name in used_names:
                continue
            # Backstop: look for the name outside its definition range
            # in the comment-stripped source. Eliminates false positives
            # on names consumed via XECUTE @VAR / indirection that the
            # AST walker can't trace, without letting a docstring
            # mention re-mark the name as used.
            before = source_text_no_comments[:start]
            after = source_text_no_comments[end:]
            pattern = re.compile(rf"\b{re.escape(name)}\b", re.IGNORECASE)
            if pattern.search(before) or pattern.search(after):
                continue
            # One finding per definition site.
            if (start, end) in flagged_positions:
                continue
            flagged_positions.add((start, end))
            yield self.make_finding(
                parsed,
                node,
                description=(
                    f"Local variable '{name}' is assigned here but never "
                    "read anywhere else in the routine. If this is dead "
                    "code, remove the SET. If callers read it through "
                    "indirection (`X @VAR`) or inter-routine scope, that "
                    "use is not tracked by Phase 1 — add an explanatory "
                    "comment or wait for the Phase 2 inter-procedural "
                    "pass."
                ),
                metadata={"variable": name},
            )
