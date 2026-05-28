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

# PIPE-device markers. Either of these in the command's source text
# strongly indicates a PIPE device (YottaDB ``OPEN "PIPE":(COMMAND=...)``
# or the parameter-string form ``OPEN dev:(COMMAND="...")``). PIPE
# device arguments execute as shell commands, so a tainted PIPE
# argument is OS-level RCE rather than just I/O redirection.
_PIPE_MARKERS = (
    re.compile(r'"\s*PIPE\s*"', re.IGNORECASE),
    re.compile(r"/?COMMAND\s*=", re.IGNORECASE),
)


def _is_pipe_device(command_text: str) -> bool:
    return any(p.search(command_text) for p in _PIPE_MARKERS)


def _command_line_text(parsed: ParsedSource, node) -> str:
    """Return the source line containing ``node`` with any trailing
    MUMPS comment stripped.

    The grammar can't parse OPEN's full ``DEV:(PARAMS):TIMEOUT`` form
    — ``:(PARAMS)`` ends up as a phantom sibling command with an empty
    keyword. Rule logic that needs to see the parameters has to fall
    back to the raw source line. Comment-stripping prevents a comment
    word like ``; PIPE not used here`` from tripping the PIPE markers.
    """
    row = node.start_point[0]
    lines = parsed.source_bytes.split(b"\n")
    if row >= len(lines):
        return parsed.node_text(node)
    line = lines[row].decode("utf-8", errors="replace")
    # Strip trailing ``;...`` MUMPS comment. Naive: doesn't account for
    # a ``;`` inside a string literal, but that's rare on OPEN / USE
    # lines and the worst case is a missed PIPE marker, not a false
    # positive.
    semi = line.find(";")
    if semi >= 0:
        line = line[:semi]
    return line


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

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        tainted = collect_tainted_variables(parsed, config)
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
            # Use the full source line for both taint detection and
            # PIPE classification. The grammar's OPEN-parameter-list
            # gap (see ``_command_line_text`` docstring) means the
            # argument subtree misses ``:(COMMAND=...)`` content.
            line_text = _command_line_text(parsed, node)
            # Drop the keyword token from the line so we don't match
            # a variable named ``O`` or ``U`` against the keyword itself.
            args_for_taint = re.sub(
                r"^\s*(?:O(?:PEN)?|U(?:SE)?)\b", "", line_text, count=1, flags=re.IGNORECASE,
            )
            hits = _tainted_references(args_for_taint, tainted)
            if not hits:
                continue
            keyword = "OPEN" if is_open else "USE"
            is_pipe = _is_pipe_device(line_text)
            arg_text = args_for_taint.strip()
            severity = Severity.CRITICAL if is_pipe else self.severity
            description = (
                f"{keyword} argument references variable(s) {sorted(hits)} "
                "assigned from an externally-controlled source (READ, "
                "$ZARGV, or an HTTP context global). "
            )
            if is_pipe:
                description += (
                    "The command targets a PIPE device (`PIPE` device-name "
                    "or `COMMAND=` parameter detected), so the tainted "
                    "value is shell-executed at runtime: OS-level RCE."
                )
            else:
                description += (
                    "A tainted device name or parameter string can redirect "
                    "I/O to attacker-chosen files / sockets."
                )
            yield self.make_finding(
                parsed,
                node,
                description=description,
                severity=severity,
                metadata={
                    "command": keyword,
                    "device_class": "PIPE" if is_pipe else "generic",
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
