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
:func:`argus.scanners.mumps.taint.collect_tainted_variables` collector to
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
from ..taint import resolve_tainted
from ._common import (
    argument_node,
    known_external_vars,
    preceded_by_error,
    tainted_references,
)

_OPEN_KEYWORD_RE = re.compile(r"^\s*O(?:PEN)?\b", re.IGNORECASE)
_USE_KEYWORD_RE = re.compile(r"^\s*U(?:SE)?\b", re.IGNORECASE)
_KEYWORD_STRIP_RE = re.compile(r"^\s*(?:O(?:PEN)?|U(?:SE)?)\b", re.IGNORECASE)


def _device_expression(args_for_taint: str) -> str:
    """Return just the first device expression from an OPEN/USE argument
    string (keyword already stripped).

    ``O:cond DEV:(params):timeout,DEV2`` -> ``DEV``. Strips a leading
    postconditional (``:cond`` attached to the keyword, ending at the
    first space) and stops at the first param delimiter ``:`` or
    next-device ``,``. The point is to taint-match the *device* slice
    only, not the whole line — most generic-path false positives were a
    tainted var elsewhere on the line (a READ target, a timeout) being
    matched as if it were the device.
    """
    s = args_for_taint.strip()
    if s.startswith(":"):
        sp = s.find(" ")
        s = s[sp + 1:].strip() if sp >= 0 else ""
    end = len(s)
    for i, ch in enumerate(s):
        if ch in ":,":
            end = i
            break
    return s[:end].strip()

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


# Socket / network device markers (GT.M "SOCKET" / Caché |TCP|/|TNT|, or a
# CONNECT= parameter). A tainted socket target is an attacker-chosen network
# endpoint — SSRF / connection redirection, not OS command execution.
_SOCKET_MARKERS = (
    re.compile(r"\|\s*T(?:CP|NT)\s*\|", re.IGNORECASE),
    re.compile(r'"\s*SOCKET\s*"', re.IGNORECASE),
    re.compile(r"/?CONNECT\s*=", re.IGNORECASE),
    re.compile(r"\bZSOCKET\b", re.IGNORECASE),
)
# File-device parameter markers. A plain file OPEN with a tainted path is a
# path-traversal / arbitrary file read-write — serious, but not RCE.
_FILE_PARAM_MARKERS = (
    re.compile(
        r"/?(?:NEWVERSION|READONLY|WRITEONLY|RECORDSIZE|BLOCKSIZE|APPEND|REWIND)\b",
        re.IGNORECASE,
    ),
)


def _classify_device(command_text: str) -> str:
    """Classify the OPEN/USE device by blast radius: PIPE (shell command
    execution), SOCKET (network endpoint), FILE (filesystem path), or
    GENERIC (unclassified I/O redirection)."""
    if _is_pipe_device(command_text):
        return "PIPE"
    if any(p.search(command_text) for p in _SOCKET_MARKERS):
        return "SOCKET"
    if any(p.search(command_text) for p in _FILE_PARAM_MARKERS):
        return "FILE"
    return "GENERIC"


# Severity by device class: a PIPE command string is shell-executed (RCE),
# a socket target is SSRF, a file path is traversal/file-write, and an
# unclassified device is lower-impact I/O redirection. This replaces the
# old flat-HIGH-for-everything behaviour that over-severitied plain reads.
_DEVICE_SEVERITY = {
    "PIPE": Severity.CRITICAL,
    "SOCKET": Severity.HIGH,
    "FILE": Severity.MEDIUM,
    "GENERIC": Severity.MEDIUM,
}
# PIPE and SOCKET carry the tainted value inside the parameter list (the
# COMMAND= / CONNECT= string), so taint-match the whole argument; FILE and
# GENERIC put the tainted value in the device expression itself.
_WHOLE_ARG_CLASSES = frozenset({"PIPE", "SOCKET"})


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


class OpenUseInjectionRule(Rule):
    id = "M003"
    severity = Severity.HIGH
    title = "OPEN / USE of tainted device argument"
    cwe = "CWE-78"

    def analyze(self, parsed: ParsedSource, config: dict | None = None) -> Iterable[Finding]:
        tainted = resolve_tainted(parsed, config)
        if not tainted:
            return
        external = known_external_vars(config)
        for node in walk(parsed.tree.root_node):
            if node.type != "command":
                continue
            command_text = parsed.node_text(node)
            is_open = bool(_OPEN_KEYWORD_RE.match(command_text))
            is_use = bool(_USE_KEYWORD_RE.match(command_text))
            if not (is_open or is_use):
                continue
            # Must be a real OPEN/USE with an argument. This also drops
            # the ``D O...`` (DO subroutine) misparse where the grammar
            # emits a bare ``O`` command, which sits next to an ERROR node.
            if argument_node(node) is None or preceded_by_error(node):
                continue
            line_text = _command_line_text(parsed, node)
            args_for_taint = _KEYWORD_STRIP_RE.sub("", line_text, count=1)
            keyword = "OPEN" if is_open else "USE"
            device_class = _classify_device(line_text)
            # PIPE / SOCKET carry the tainted value inside the parameter
            # list, so match the whole argument string. FILE / GENERIC put
            # the tainted value in the device expression itself — matching
            # only that slice keeps a tainted READ-target or timeout
            # elsewhere on the line from firing as if it were the device.
            scope = (
                args_for_taint
                if device_class in _WHOLE_ARG_CLASSES
                else _device_expression(args_for_taint)
            )
            hits = tainted_references(scope, tainted) - external
            if not hits:
                continue
            arg_text = scope.strip()
            severity = _DEVICE_SEVERITY[device_class]
            impact = {
                "PIPE": (
                    "The command targets a PIPE device (`PIPE` device-name or "
                    "`COMMAND=`/`SHELL=` parameter detected), so the tainted "
                    "value is shell-executed at runtime: OS-level RCE."
                ),
                "SOCKET": (
                    "The device is a network socket, so a tainted target lets "
                    "an attacker choose the endpoint the routine connects to "
                    "(SSRF / connection redirection)."
                ),
                "FILE": (
                    "A tainted file device path is a path-traversal / "
                    "arbitrary file read-write primitive."
                ),
                "GENERIC": (
                    "A tainted device name or parameter string can redirect "
                    "I/O to an attacker-influenced destination."
                ),
            }[device_class]
            description = (
                f"{keyword} argument references variable(s) {sorted(hits)} "
                "assigned from an externally-controlled source (READ, "
                f"$ZARGV, or an HTTP context global). {impact}"
            )
            yield self.make_finding(
                parsed,
                node,
                description=description,
                severity=severity,
                metadata={
                    "command": keyword,
                    "device_class": device_class,
                    "taint_sources": sorted(hits),
                    "argument": arg_text[:200],
                },
            )
