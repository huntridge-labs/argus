"""Shared helpers for MUMPS rule modules.

Consolidates structural helpers and constants that several rules need,
so a grammar quirk or a VistA-convention fix lives in one place instead
of being re-derived (and drifting) across rule files.
"""

from __future__ import annotations

from ..parser import ParsedSource, walk

# Node types the grammar uses for a variable reference.
VAR_TYPES = frozenset({"local_variable", "identifier", "variable"})

# MUMPS command mnemonics — single-letter keywords plus their long
# forms, and the transaction commands. Used by M201 to discard
# ``routine_call`` nodes that are really misparsed command keywords
# (the grammar sometimes emits a leading command letter as a
# ``routine_call`` when it can't parse the surrounding line, e.g. a
# read-timeout ``R X:DTIME`` splits ``DTIME`` into ``D`` + ``TIME``).
COMMAND_MNEMONICS = frozenset({
    "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
    "N", "O", "Q", "R", "S", "U", "V", "W", "X", "Z",
    "BREAK", "CLOSE", "DO", "ELSE", "FOR", "GOTO", "HALT", "HANG",
    "IF", "JOB", "KILL", "LOCK", "MERGE", "NEW", "OPEN", "QUIT",
    "READ", "SET", "USE", "VIEW", "WRITE", "XECUTE",
    "TSTART", "TCOMMIT", "TROLLBACK", "TRESTART",
})

# Well-known VistA / FileMan / Kernel / TaskMan variables that are set
# by the platform or a calling API rather than the current routine.
# M203 treats these as externally-defined (so a read isn't "undefined")
# and M204 treats them as externally-read. Extensible per-site via
# ``scanners.mumps.known_external_vars``. Conservative explicit list —
# prefix families (XQ*, ZT*) are left to site config to avoid
# over-suppression.
DEFAULT_EXTERNAL_VARS = frozenset({
    # FileMan / DIC entry points and their I/O variables
    "DUZ", "DT", "DTIME", "U", "DA", "DIC", "DIR", "DR", "DR0",
    "D0", "D1", "DG", "DIE", "DIK", "DIQ", "DIWF", "DIWL", "DIWR",
    "DLAYGO", "DINUM", "DIDEL", "DUOUT", "DTOUT", "DUz",
    # I/O / device variables (Kernel %ZIS)
    "IO", "ION", "IOF", "IOM", "IOSL", "IOST", "IOT", "IOXY",
    "IOBS", "IOP", "IOS", "POP", "ZTSK", "ZTQUEUED", "ZTREQ",
    # Common scratch / menu globals-as-locals
    "X", "Y", "XQY", "XQDIC", "XQABTST", "XUMF", "XQUR",
})


def argument_node(command_node):
    """Return the arguments subtree for a command, or None.

    The grammar declares ``arguments`` as a child type rather than a
    named field on every command alternative, so fall back to a
    type-based scan when ``child_by_field_name`` returns nothing.
    """
    for field_name in ("arguments", "argument", "expression"):
        node = command_node.child_by_field_name(field_name)
        if node is not None:
            return node
    for child in command_node.children:
        if child.type in {"arguments", "argument"}:
            return child
    return None


def collect_formal_args(parsed: ParsedSource) -> set[str]:
    """Return uppercased formal-argument names declared on any entry
    label in the file.

    The grammar parses a parameterized label ``TAG(A,B)`` as::

        routine_definition
          label 'TAG'
          '('
          arguments 'A,B'      <- direct child of routine_definition
            argument -> local_variable 'A'
            argument -> local_variable 'B'
          ')'
          <commands...>

    so the formal list is the ``arguments`` node that sits as a *direct
    child of routine_definition* (command argument lists live nested
    under their ``command`` node, never directly under
    ``routine_definition``). Collecting those is both precise and cheap.
    """
    names: set[str] = set()
    for node in walk(parsed.tree.root_node):
        if node.type != "routine_definition":
            continue
        for child in node.children:
            if child.type != "arguments":
                continue
            for descendant in walk(child):
                if descendant.type in VAR_TYPES:
                    names.add(parsed.node_text(descendant).strip().upper())
    return names


def known_external_vars(config: dict | None) -> set[str]:
    """Built-in external-variable allowlist unioned with any
    ``scanners.mumps.known_external_vars`` entries from config."""
    extra = (config or {}).get("known_external_vars") or []
    return set(DEFAULT_EXTERNAL_VARS) | {str(v).strip().upper() for v in extra}


def is_command_mnemonic(text: str) -> bool:
    """True when ``text`` (a routine_call's source) is really a command
    keyword the grammar misparsed as a call target."""
    return text.strip().upper() in COMMAND_MNEMONICS


def preceded_by_error(node) -> bool:
    """True when ``node`` (or its parent) has an immediately preceding
    ERROR sibling — the signature of a grammar misparse such as the
    read-timeout ``R X:DTIME`` that emits ``... ERROR(':') do_statement``.
    """
    for candidate in (node, node.parent):
        if candidate is None:
            continue
        prev = candidate.prev_sibling
        if prev is not None and prev.type == "ERROR":
            return True
    return False
