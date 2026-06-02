"""Shared helpers for MUMPS rule modules.

Consolidates structural helpers and constants that several rules need,
so a grammar quirk or a VistA-convention fix lives in one place instead
of being re-derived (and drifting) across rule files.
"""

from __future__ import annotations

import re

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

# OPEN / USE device-parameter keywords. The vendored tree-sitter-mumps
# grammar does not model device-parameter lists (``U IO:(READONLY:NOECHO)``),
# so it mis-emits each keyword as a ``local_variable`` node. M203/M204 treat
# these as non-variables. Conservative list — only tokens that are device
# keywords, never plausible user locals.
DEVICE_PARAM_KEYWORDS = frozenset({
    "READONLY", "WRITEONLY", "NOECHO", "ECHO", "WIDTH", "LENGTH",
    "TERMINATOR", "WRAP", "NOWRAP", "FIXED", "VARIABLE", "APPEND",
    "NEWVERSION", "DENSITY", "BLOCKSIZE", "RECORDSIZE", "PADDING",
    "REWIND", "CHSET", "SHELL", "COMMAND", "PARSE", "MODE", "STREAM",
    "ZBFSIZE", "DISCONNECT", "DELIMITER", "ATTACH", "DETACH", "SEEK",
})

# A label line declares formal arguments as ``LABEL(A,B,C)`` starting in
# column 0. We extract them textually as a fallback because an upstream
# grammar misparse (e.g. an argumentless FOR with inline postconditionals
# on the preceding line) can cause the label line to parse as a function
# call, so its formal args never reach the structural
# ``routine_definition > arguments`` shape ``collect_formal_args`` relies on.
_LABEL_FORMALS_RE = re.compile(r"^[%A-Za-z][A-Za-z0-9]*\(([^)]*)\)")
_FORMAL_NAME_RE = re.compile(r"^[%A-Za-z][A-Za-z0-9]*$")


def text_formal_args(source_bytes: bytes) -> set[str]:
    """Uppercased formal-arg names extracted textually from label lines.

    Resilient to grammar misparses that the structural collector misses.
    """
    names: set[str] = set()
    for raw in source_bytes.split(b"\n"):
        line = raw.decode("utf-8", errors="replace")
        # Label lines start in column 0; body/comment lines are indented.
        if not line or line[0] in (" ", "\t", ";"):
            continue
        match = _LABEL_FORMALS_RE.match(line)
        if not match:
            continue
        for part in match.group(1).split(","):
            token = part.strip().upper()
            if _FORMAL_NAME_RE.match(token):
                names.add(token)
    return names


def within_error(node) -> bool:
    """True when ``node`` or any ancestor is a grammar ERROR node.

    Tokens inside a misparse are unreliable (the grammar guessed at their
    shape), so structural rules skip them rather than emit noise.
    """
    cur = node
    while cur is not None:
        if cur.type == "ERROR":
            return True
        cur = cur.parent
    return False


# A controller FOR (``F I=1:1:N``) DEFINES its loop variable; an
# argumentless FOR (``F  ...``) has none. The control var sits between the
# FOR keyword and the ``=``. Matched textually (command position: line
# start or after whitespace, never after ``$`` so ``$F`` / ``IF`` don't
# match) because the grammar drops the loop-control child for
# expression-bound counted FORs.
_FOR_VAR_RE = re.compile(
    r"(?<![\w$])F(?:OR)?\s+([%A-Za-z][A-Za-z0-9]*)\s*=", re.IGNORECASE,
)


def for_loop_vars(source_bytes: bytes) -> set[str]:
    """Uppercased control-variable names of every counted FOR in the file."""
    text = source_bytes.decode("utf-8", errors="replace")
    return {m.group(1).upper() for m in _FOR_VAR_RE.finditer(text)}


_GUARD_PREFIXES = ("$G(", "$GET(", "$D(", "$DATA(", "$T(", "$TEXT(")


def guarded_read(parsed: ParsedSource, node) -> bool:
    """True when ``node`` sits inside an intrinsic whose operand is not a
    plain local-variable value read.

    ``$GET()`` / ``$DATA()`` explicitly handle an undefined variable
    (returning a default / a 0 existence code), so a read through them is a
    deliberate defensive read, never the silent empty-string bug M203
    targets. ``$TEXT()`` / ``$T()`` take a *label* reference, not a variable.
    Checks the innermost enclosing function call.
    """
    cur = node.parent
    while cur is not None:
        if cur.type == "function_call":
            head = parsed.node_text(cur).lstrip().upper()
            return any(head.startswith(p) for p in _GUARD_PREFIXES)
        cur = cur.parent
    return False


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
    # Text-based fallback: catches formal args on label lines the grammar
    # misparsed into a function call (so the structural pass above missed).
    names |= text_formal_args(parsed.source_bytes)
    return names


def identifier_names(parsed: ParsedSource, node) -> set[str]:
    """Uppercased identifier/local-variable names referenced anywhere
    under ``node``. Used by the taint-sink rules to intersect a sink's
    operand against the tainted set (the AST-precise model M005 pioneered
    and M002 now shares)."""
    names: set[str] = set()
    for descendant in walk(node):
        if descendant.type in VAR_TYPES:
            names.add(parsed.node_text(descendant).strip().upper())
    return names


def tainted_references(arg_text: str, tainted: set[str]) -> set[str]:
    """Return the subset of ``tainted`` referenced as a MUMPS identifier
    token in ``arg_text`` (case-insensitive).

    Shared by the taint-sink rules (M001 / M003 / M006) that check
    whether a sink argument mentions a tainted variable.

    Token boundaries use ``[A-Za-z0-9%]`` lookarounds, NOT ``\\b``:
    ``\\b`` treats ``_`` (MUMPS's concatenation operator) as a word
    character, so ``"code"_TAINTED`` would never match the tainted var
    after the ``_`` — a false negative on exactly the dangerous
    concatenated-injection pattern. The ``%`` in the class keeps a
    plain ``X`` from matching inside ``%X`` (a distinct variable).
    """
    hits: set[str] = set()
    if not arg_text or not tainted:
        return hits
    upper = arg_text.upper()
    for name in tainted:
        pattern = rf"(?<![A-Za-z0-9%]){re.escape(name)}(?![A-Za-z0-9%])"
        if re.search(pattern, upper):
            hits.add(name)
    return hits


def known_external_vars(config: dict | None) -> set[str]:
    """Built-in external-variable allowlist unioned with any
    ``scanners.mumps.known_external_vars`` entries from config."""
    extra = (config or {}).get("known_external_vars") or []
    return set(DEFAULT_EXTERNAL_VARS) | {str(v).strip().upper() for v in extra}


def is_command_mnemonic(text: str) -> bool:
    """True when ``text`` (a routine_call's source) is really a command
    keyword the grammar misparsed as a call target."""
    return text.strip().upper() in COMMAND_MNEMONICS


# MUMPS argumentless FOR: the empty argument is written as the keyword
# followed by TWO spaces (the missing arg, then the command separator),
# or the keyword alone at end of line. A controller FOR (``F I=1:1:N``)
# has exactly one space before the loop variable. This text test is the
# reliable discriminator — the grammar drops the ``loop_control`` child
# for expression-bound counted FORs (``F J=1:1:$L(X)``), so a
# structural "no loop_control" check misclassifies them as argumentless.
_ARGLESS_FOR_RE = re.compile(r"^\s*F(?:OR)?(?:\s{2,}|\s*$)", re.IGNORECASE)


def is_argumentless_for(parsed: ParsedSource, for_node) -> bool:
    """True when ``for_node`` is an argumentless FOR (``F  ...`` / bare
    ``F``), as opposed to a controller FOR (``F I=1:1:N``)."""
    return bool(_ARGLESS_FOR_RE.match(parsed.node_text(for_node)))


def physical_line(parsed: ParsedSource, node, from_column: bool = True) -> str:
    """Return the source line containing ``node``, comment-stripped.

    Several constructs the grammar mis-shapes (OPEN parameter lists, an
    argumentless ``FOR`` whose body + ``Q:`` exit spill out to sibling
    nodes) can only be reasoned about from the raw physical line. With
    ``from_column`` the slice starts at the node's start column so an
    earlier token on the same line isn't considered.

    Comment-stripping is naive (a ``;`` inside a string literal ends the
    line early); the failure mode is a missed token, never a spurious
    one — acceptable for the line-scan heuristics that use this.
    """
    row = node.start_point[0]
    lines = parsed.source_bytes.split(b"\n")
    if row >= len(lines):
        return parsed.node_text(node)
    line = lines[row].decode("utf-8", errors="replace")
    if from_column:
        line = line[node.start_point[1]:]
    semi = line.find(";")
    if semi >= 0:
        line = line[:semi]
    return line


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
