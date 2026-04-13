"""Structured logging with colored console output and JSON log file.

Dual output:
  - Colored console on stderr (human-friendly)
  - One-JSON-object-per-line log file (machine-friendly evidence)

All output is run through secret masking before being emitted.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from .secrets import mask_secrets


# ---------------------------------------------------------------------------
# ANSI color codes (stdlib only, no external deps)
# ---------------------------------------------------------------------------

class _Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"


_LEVEL_COLORS = {
    logging.DEBUG: _Colors.GRAY,
    logging.INFO: _Colors.CYAN,
    logging.WARNING: _Colors.YELLOW,
    logging.ERROR: _Colors.RED,
    logging.CRITICAL: _Colors.BG_RED + _Colors.BOLD,
}


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

class ColoredConsoleFormatter(logging.Formatter):
    """Colored formatter for terminal output. Masks secrets."""

    def __init__(self, use_color: bool = True):
        super().__init__()
        self._use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        record.msg = mask_secrets(str(record.msg))

        ts = self.formatTime(record, "%H:%M:%S")
        name = record.name.replace("argus.", "")
        msg = record.getMessage()

        if not self._use_color:
            return f"{ts} {record.levelname:<8} {name} {msg}"

        color = _LEVEL_COLORS.get(record.levelno, "")
        levelname = f"{color}{record.levelname:<8}{_Colors.RESET}"
        ts_colored = f"{_Colors.GRAY}{ts}{_Colors.RESET}"
        module = f"{_Colors.BLUE}{name}{_Colors.RESET}"
        return f"{ts_colored} {levelname} {module} {msg}"


class JsonLogFormatter(logging.Formatter):
    """Structured JSON formatter for log files. Masks secrets.

    Writes one JSON object per line (JSONL) for easy parsing.
    """

    def format(self, record: logging.LogRecord) -> str:
        record.msg = mask_secrets(str(record.msg))
        entry: dict = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "module": record.name,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
        }
        # Include extra fields if present (scanner name, phase, etc.)
        for key in ("scanner", "phase", "image", "duration_ms"):
            if hasattr(record, key):
                entry[key] = getattr(record, key)
        return json.dumps(entry, default=str)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_logger(
    name: str = "argus",
    output_dir: str | Path | None = None,
    verbose: bool = False,
) -> logging.Logger:
    """Get a configured argus logger with colored console + JSON file output.

    If *output_dir* is provided, writes structured JSON logs to
    ``{output_dir}/argus.log`` alongside scan results.

    The logger is created once per *name*; subsequent calls with the same
    name return the existing logger without adding duplicate handlers.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        # Existing loggers should still honor a later verbose request,
        # especially when shared across command flows.
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                desired_level = logging.DEBUG if verbose else logging.INFO
                if handler.level != desired_level:
                    handler.setLevel(desired_level)

        # Add file logging if this call requests it and none exists yet.
        has_file_handler = any(
            isinstance(handler, logging.FileHandler)
            for handler in logger.handlers
        )
        if output_dir and not has_file_handler:
            log_dir = Path(output_dir)
            log_dir.mkdir(parents=True, exist_ok=True)
            log_path = log_dir / "argus.log"
            file_handler = logging.FileHandler(
                log_path, mode="a", encoding="utf-8"
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(JsonLogFormatter())
            logger.addHandler(file_handler)

        return logger

    logger.setLevel(logging.DEBUG)

    # Console handler -- colored, INFO level (DEBUG if verbose)
    use_color = sys.stderr.isatty()
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(ColoredConsoleFormatter(use_color=use_color))
    logger.addHandler(console)

    # File handler -- JSON, DEBUG level (captures everything)
    if output_dir:
        log_dir = Path(output_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "argus.log"
        file_handler = logging.FileHandler(
            log_path, mode="a", encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JsonLogFormatter())
        logger.addHandler(file_handler)

    return logger
