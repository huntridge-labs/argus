"""Log file parsing + filtering for the browser interface.

UI-free, mirrors the pattern in ``argus.core.findings_view``: keep the
parsing and filtering pure so route handlers, templates, and tests can
all share the same code path.

Argus emits log lines in the standard Python logging shape::

    07:13:58 DEBUG    argus Container exited: code=0, duration=701ms
    07:13:59 INFO     viewers.browser argus view browser listening on …

A regex extracts the four fields. Lines that don't match are treated as
continuations of the previous entry's message — common when a scanner
dumps a multi-line stderr blob that the engine forwards verbatim.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


# The structured-line regex. Argus uses Python logging's default time
# format ``%H:%M:%S`` plus a level + logger + message tail. Levels
# include both Python's canonical names (DEBUG/INFO/WARNING/ERROR/
# CRITICAL) and the shortened ``WARN`` we sometimes see in container
# stderr that's been forwarded through.
_LOG_LINE_RE = re.compile(
    r"^(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<level>DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL)\s+"
    r"(?P<logger>\S+)\s+"
    r"(?P<msg>.*)$"
)


# Severity ranking for ``min_level`` filtering. Matches Python's
# ``logging`` module values so "WARN and above" is the obvious thing.
LEVEL_RANK: dict[str, int] = {
    "DEBUG": 10,
    "INFO": 20,
    "WARN": 30,
    "WARNING": 30,
    "ERROR": 40,
    "CRITICAL": 50,
}


@dataclass(frozen=True)
class LogEntry:
    """A single parsed log entry.

    ``msg`` includes any continuation lines that follow the header line
    (joined with ``\n``) so the renderer doesn't have to know about
    multi-line entries — it just paints what we hand it.
    """

    line_no: int    # 1-based line number of the header line in the source file
    time: str       # "07:13:58"
    level: str      # canonicalized: DEBUG / INFO / WARNING / ERROR / CRITICAL
    logger: str     # "argus", "viewers.browser", etc.
    msg: str        # full message including any continuation lines


def _canonicalize_level(level: str) -> str:
    """Fold the short ``WARN`` form onto Python's canonical ``WARNING``.

    Other levels passthrough. Centralizing the rule keeps filter
    comparisons (``LEVEL_RANK[entry.level]``) consistent regardless of
    which form the underlying logger emits.
    """
    return "WARNING" if level == "WARN" else level


def parse_log(text: str) -> list[LogEntry]:
    """Parse the contents of an ``argus.log`` file into structured entries.

    Lines that don't start with the standard timestamp+level prefix are
    treated as continuations of the previous header line — that's how
    argus wraps multi-line scanner output today. Continuation text
    before any header line at all is silently dropped (we don't have a
    reasonable level/logger to assign it).
    """
    entries: list[LogEntry] = []
    current_match: re.Match[str] | None = None
    current_line_no = 0
    current_lines: list[str] = []

    def _flush() -> None:
        if current_match is None:
            return
        entries.append(LogEntry(
            line_no=current_line_no,
            time=current_match["time"],
            level=_canonicalize_level(current_match["level"]),
            logger=current_match["logger"],
            msg="\n".join(current_lines).rstrip(),
        ))

    for i, line in enumerate(text.splitlines(), start=1):
        match = _LOG_LINE_RE.match(line)
        if match:
            _flush()
            current_match = match
            current_line_no = i
            # The first line carries the structured prefix; we keep
            # only the message portion in current_lines so the rendered
            # output doesn't re-display time/level/logger inline.
            current_lines = [match["msg"]]
        elif current_match is not None:
            current_lines.append(line)
    _flush()
    return entries


def filter_entries(
    entries: Iterable[LogEntry],
    *,
    min_level: str | None = None,
    query: str | None = None,
) -> list[LogEntry]:
    """Filter entries by minimum severity and an optional substring query.

    ``min_level`` accepts any case and the short ``WARN`` form; an
    unrecognized value is treated as "no level filter" rather than
    erroring (user URLs are untrusted).

    ``query`` is matched case-insensitively against the level + logger
    + message concatenation, so a search like ``q=container`` catches
    both ``DEBUG argus Container exited: …`` and any logger named
    ``container.runtime``.
    """
    rank = LEVEL_RANK.get((min_level or "").upper(), 0)
    needle = (query or "").strip().lower()

    out: list[LogEntry] = []
    for entry in entries:
        if LEVEL_RANK.get(entry.level, 0) < rank:
            continue
        if needle:
            haystack = f"{entry.level} {entry.logger} {entry.msg}".lower()
            if needle not in haystack:
                continue
        out.append(entry)
    return out


def load_log(scan_dir: Path) -> tuple[list[LogEntry], int] | None:
    """Read ``argus.log`` from a scan directory and parse it.

    Returns ``(entries, total_lines)`` so the template can show
    "showing N of M" without re-iterating. Returns ``None`` if the
    log file is missing — older scans, or runs that wrote results
    without emitting the log, get a clean empty-state instead of a
    500.
    """
    log_path = scan_dir / "argus.log"
    if not log_path.exists():
        return None
    text = log_path.read_text(errors="replace")
    entries = parse_log(text)
    return entries, len(text.splitlines())
