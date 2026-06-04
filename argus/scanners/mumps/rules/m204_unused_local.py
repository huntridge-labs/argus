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
from ._common import VAR_TYPES, argument_node, known_external_vars

_NEW_KEYWORD_RE = re.compile(r"^\s*N(?:EW)?\b", re.IGNORECASE)
_READ_KEYWORD_RE = re.compile(r"^\s*R(?:EAD)?\b", re.IGNORECASE)


def _used_token_pattern(name: str) -> re.Pattern:
    """Whole-token matcher for ``name`` that tolerates a leading ``%``.

    A plain ``\\b{name}\\b`` never matches a ``%``-prefixed local because
    there is no word boundary before ``%`` (both ``%`` and a preceding
    space/start are non-word) — that bug made ~two-thirds of ``%``-var
    M204 findings false. Use explicit token-boundary lookarounds that
    treat ``%`` as part of the identifier instead.
    """
    return re.compile(
        rf"(?<![A-Za-z0-9%]){re.escape(name)}(?![A-Za-z0-9])",
        re.IGNORECASE,
    )


def _glued_to_prev_token(parsed: ParsedSource, node) -> bool:
    """True when ``node`` is immediately preceded by an alphanumeric byte —
    the signature of a grammar mis-split, not a real definition target. A
    genuine SET / NEW / READ target is always preceded by whitespace, a
    comma, or ``(``; never glued to a letter. Catches the ``R VAL:DTIME``
    timeout mis-tokenizing into a phantom ``TIME`` declaration."""
    start = node.start_byte
    return start > 0 and chr(parsed.source_bytes[start - 1]).isalnum()


def _collect_definitions(parsed: ParsedSource):
    """Yield ``(start_byte, end_byte, name, node, origin)`` for every
    definition site."""
    for node in walk(parsed.tree.root_node):
        if node.type == "assignment":
            named = [c for c in node.children if c.is_named]
            if named and named[0].type in VAR_TYPES and not _glued_to_prev_token(parsed, named[0]):
                yield (
                    named[0].start_byte,
                    named[0].end_byte,
                    parsed.node_text(named[0]).strip().upper(),
                    named[0],
                    "ASSIGN",
                )
        elif node.type == "command":
            text = parsed.node_text(node)
            if not (_NEW_KEYWORD_RE.match(text) or _READ_KEYWORD_RE.match(text)):
                continue
            args = argument_node(node)
            if args is None:
                continue
            for descendant in walk(args):
                if descendant.type in VAR_TYPES and not _glued_to_prev_token(parsed, descendant):
                    yield (
                        descendant.start_byte,
                        descendant.end_byte,
                        parsed.node_text(descendant).strip().upper(),
                        descendant,
                        "DECL",
                    )


def _makes_external_call(parsed: ParsedSource) -> bool:
    """True when the file makes any external ``^ROUTINE`` call (``D X^Y``,
    ``$$F^Y``, ``G ^Y``). Such a call inherits the caller's local scope, so a
    NEW-scoped variable that is unused *in this file* may still be read by the
    callee through MUMPS implicit-NEW inheritance — meaning it cannot soundly
    be called dead. Restricted to routine_call / function_call nodes so a
    plain global reference (``^TMP``) does not count."""
    for node in walk(parsed.tree.root_node):
        if node.type in ("routine_call", "function_call") and "^" in parsed.node_text(node):
            return True
    return False


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
    title = "Local variable declared (NEW/READ) but never read"
    cwe = None  # diagnostic
    # On by default: the implicit-NEW inheritance false positives are closed
    # by the external-call gate (a NEW'd var in a file that makes any
    # ^ROUTINE call is treated as possibly-inherited, not dead), and the
    # glued-token guard drops READ-timeout mis-tokenizations. Validated at
    # scale: 832 -> 6 on the VistA Kernel, all genuine dead declarations.

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        # A NEW-scoped variable unused in this file may still be read by a
        # callee via implicit-NEW inheritance. If the file makes any external
        # ^ROUTINE call, we cannot soundly call such a declaration dead, so
        # we report nothing — conservative until per-callee inherited-read
        # analysis lands. (Leaf routines with no external call still report.)
        if _makes_external_call(parsed):
            return
        defs = list(_collect_definitions(parsed))
        def_positions = {(s, e) for s, e, _, _, _ in defs}
        # Collect every local-variable reference outside the def sites
        # as a "use". Also include the raw source-text count as a
        # backstop for indirection / XECUTE consumption: if the name
        # appears anywhere outside its own definition byte range,
        # consider it referenced.
        used_names: set[str] = set()
        for node in walk(parsed.tree.root_node):
            if node.type not in VAR_TYPES:
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
        # Well-known platform / API variables are read by callers, not
        # this routine — never flag a SET to one as "unused".
        external = known_external_vars(config)
        flagged_positions: set[tuple[int, int]] = set()
        for start, end, name, node, origin in defs:
            if not name:
                continue
            # Only flag NEW / READ declarations that go unused. A bare
            # ``S X=...`` that nothing reads in-file is the FP-prone case:
            # the value is frequently consumed by a callee through implicit
            # NEW inheritance or returned via a by-reference actual — reads
            # the intra-file pass cannot see (~45% FP on real code). A dead
            # NEW/READ has no such inter-routine escape hatch and is a
            # reliable signal. The SET-then-unused case returns with the
            # Phase-2 inter-procedural pass.
            if origin == "ASSIGN":
                continue
            if name in used_names or name in external:
                continue
            # Backstop: look for the name outside its definition range
            # in the comment-stripped source. Eliminates false positives
            # on names consumed via XECUTE @VAR / indirection that the
            # AST walker can't trace, without letting a docstring
            # mention re-mark the name as used. The token matcher
            # tolerates a leading ``%`` (the old ``\b`` form could not).
            before = source_text_no_comments[:start]
            after = source_text_no_comments[end:]
            pattern = _used_token_pattern(name)
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
                    f"Local variable '{name}' is declared (NEW/READ) here "
                    "but never read anywhere in the routine. A dead NEW/READ "
                    "is almost always a leftover or a typo on the use site — "
                    "remove the declaration or fix the reader. (SET-but-"
                    "unused locals are not flagged: their value is often "
                    "consumed by a callee through implicit-NEW inheritance, "
                    "which the Phase 1 intra-routine pass cannot see.)"
                ),
                metadata={"variable": name},
            )
