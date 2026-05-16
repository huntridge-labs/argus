"""Log file parsing + filtering for the browser interface.

UI-free, mirrors the pattern in ``argus.core.findings_view``: keep the
parsing and filtering pure so route handlers, templates, and tests can
all share the same code path.

argus writes ``argus.log`` as one JSON object per line via
:class:`argus.audit.logger.JsonLogFormatter`. Each entry looks like::

    {"timestamp": "2026-05-04T11:13:58.531038+00:00",
     "level": "INFO", "module": "argus", "function": "_cmd_source_scan",
     "line": 1093, "message": "Argus scan starting"}

The parser reads JSON-lines, dropping any malformed line silently
(rather than 500ing on a partially-flushed log file). Continuation
handling that was needed for plain-text logs is unnecessary here:
multi-line messages live inside the ``message`` string and the
``<pre>`` template renders the embedded newlines as-is.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


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
    """A single parsed log entry — display shape only.

    The on-disk JSON record carries more (function, line, optional
    scanner / phase / image / duration_ms), but the viewer only needs
    these five fields. Keep the dataclass narrow so future renderer
    changes don't have to know about the file format.
    """

    line_no: int    # 1-based line number in the source file (for reference)
    time: str       # "07:13:58" — extracted from the ISO timestamp
    level: str      # canonical: DEBUG / INFO / WARNING / ERROR / CRITICAL
    logger: str     # "argus", "viewers.browser", etc. (the JSON ``module`` field)
    msg: str        # the rendered message string


def _canonicalize_level(level: str) -> str:
    """Fold the short ``WARN`` form onto Python's canonical ``WARNING``.

    ``JsonLogFormatter`` emits ``WARNING`` directly, but defensive in
    case future scanner-forwarded entries use the short form. Other
    levels passthrough.
    """
    upper = (level or "").upper()
    return "WARNING" if upper == "WARN" else upper


def _extract_time(iso_timestamp: str) -> str:
    """Extract the ``HH:MM:SS`` portion from an ISO 8601 timestamp.

    Returns an empty string if the input is missing or unparsable —
    we'd rather render a blank time field than crash a whole render
    on one weird line. Tolerant of microseconds and any timezone
    suffix (``+00:00``, ``-05:00``, ``Z``).
    """
    if not iso_timestamp or "T" not in iso_timestamp:
        return ""
    time_part = iso_timestamp.split("T", 1)[1]
    # Trim microseconds before timezone matters since ``.`` always
    # precedes ``+/-`` / ``Z`` when present.
    if "." in time_part:
        time_part = time_part.split(".", 1)[0]
    elif time_part.endswith("Z"):
        time_part = time_part[:-1]
    elif "+" in time_part:
        time_part = time_part.split("+", 1)[0]
    elif "-" in time_part:
        time_part = time_part.split("-", 1)[0]
    return time_part


def parse_log(text: str) -> list[LogEntry]:
    """Parse the contents of an ``argus.log`` file (JSON-lines) into entries.

    Skips:
    - empty lines
    - lines that aren't valid JSON
    - JSON values that aren't objects (shouldn't happen with
      ``JsonLogFormatter``, defensive)
    - records with a ``level`` we don't recognize (rather than
      assigning them an arbitrary rank that would warp filters)

    Doesn't enforce field presence beyond that — missing ``module``
    falls back to ``"argus"``, missing ``message`` to ``""``.
    """
    entries: list[LogEntry] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        level = _canonicalize_level(data.get("level", ""))
        if level not in LEVEL_RANK:
            continue
        entries.append(LogEntry(
            line_no=i,
            time=_extract_time(data.get("timestamp", "")),
            level=level,
            logger=str(data.get("module") or "argus"),
            msg=str(data.get("message", "")),
        ))
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
