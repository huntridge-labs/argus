"""Tests for argus.audit.logger -- structured logging."""

import json
import logging
from pathlib import Path

import pytest

from argus.audit.logger import (
    ColoredConsoleFormatter,
    JsonLogFormatter,
    get_logger,
)


@pytest.fixture(autouse=True)
def _clean_loggers():
    """Remove argus loggers between tests to avoid handler accumulation."""
    yield
    for name in list(logging.Logger.manager.loggerDict):
        if name.startswith("argus"):
            logger = logging.getLogger(name)
            logger.handlers.clear()


class TestColoredConsoleFormatter:
    """Verify the colored console formatter."""

    def test_format_info_message(self):
        formatter = ColoredConsoleFormatter(use_color=False)
        record = logging.LogRecord(
            name="argus.scanner.bandit",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="found 3 issues",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        assert "INFO" in result
        assert "scanner.bandit" in result
        assert "found 3 issues" in result

    def test_format_masks_secrets(self):
        formatter = ColoredConsoleFormatter(use_color=False)
        record = logging.LogRecord(
            name="argus",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="using token=supersecret",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        assert "supersecret" not in result
        assert "<REDACTED>" in result

    def test_color_mode_includes_ansi(self):
        formatter = ColoredConsoleFormatter(use_color=True)
        record = logging.LogRecord(
            name="argus",
            level=logging.WARNING,
            pathname="",
            lineno=0,
            msg="check this",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        assert "\033[" in result  # Contains ANSI escape codes

    def test_no_color_mode_excludes_ansi(self):
        formatter = ColoredConsoleFormatter(use_color=False)
        record = logging.LogRecord(
            name="argus",
            level=logging.WARNING,
            pathname="",
            lineno=0,
            msg="check this",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        assert "\033[" not in result


class TestJsonLogFormatter:
    """Verify the JSON log formatter."""

    def test_produces_valid_json(self):
        formatter = JsonLogFormatter()
        record = logging.LogRecord(
            name="argus.scanner.trivy",
            level=logging.ERROR,
            pathname="engine.py",
            lineno=42,
            msg="scan failed",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        parsed = json.loads(result)
        assert parsed["level"] == "ERROR"
        assert parsed["module"] == "argus.scanner.trivy"
        assert parsed["message"] == "scan failed"
        assert parsed["line"] == 42
        assert "timestamp" in parsed

    def test_masks_secrets_in_json(self):
        formatter = JsonLogFormatter()
        record = logging.LogRecord(
            name="argus",
            level=logging.DEBUG,
            pathname="",
            lineno=0,
            msg="password=hunter2",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        parsed = json.loads(result)
        assert "hunter2" not in parsed["message"]
        assert "<REDACTED>" in parsed["message"]

    def test_includes_extra_fields(self):
        formatter = JsonLogFormatter()
        record = logging.LogRecord(
            name="argus",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="scanning",
            args=(),
            exc_info=None,
        )
        record.scanner = "bandit"
        record.phase = "parse"
        result = formatter.format(record)
        parsed = json.loads(result)
        assert parsed["scanner"] == "bandit"
        assert parsed["phase"] == "parse"

    def test_timestamp_is_utc_iso(self):
        formatter = JsonLogFormatter()
        record = logging.LogRecord(
            name="argus",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="test",
            args=(),
            exc_info=None,
        )
        result = formatter.format(record)
        parsed = json.loads(result)
        assert "+00:00" in parsed["timestamp"] or "Z" in parsed["timestamp"]


class TestGetLogger:
    """Verify the get_logger factory."""

    def test_returns_logger(self):
        logger = get_logger("argus.test.basic")
        assert isinstance(logger, logging.Logger)

    def test_has_console_handler(self):
        logger = get_logger("argus.test.console")
        handler_types = [type(h).__name__ for h in logger.handlers]
        assert "StreamHandler" in handler_types

    def test_no_file_handler_without_output_dir(self):
        logger = get_logger("argus.test.nofile")
        handler_types = [type(h).__name__ for h in logger.handlers]
        assert "FileHandler" not in handler_types

    def test_file_handler_with_output_dir(self, tmp_path):
        output_dir = tmp_path / "logs"
        logger = get_logger("argus.test.withfile", output_dir=output_dir)

        handler_types = [type(h).__name__ for h in logger.handlers]
        assert "FileHandler" in handler_types
        assert (output_dir / "argus.log").exists()

    def test_writes_jsonl_to_file(self, tmp_path):
        output_dir = tmp_path / "logs"
        logger = get_logger("argus.test.jsonl", output_dir=output_dir)
        logger.info("test message one")
        logger.warning("test message two")

        # Flush handlers
        for handler in logger.handlers:
            handler.flush()

        log_path = output_dir / "argus.log"
        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            parsed = json.loads(line)
            assert "timestamp" in parsed
            assert "message" in parsed

    def test_idempotent_handler_setup(self):
        logger_a = get_logger("argus.test.idem")
        handler_count = len(logger_a.handlers)
        logger_b = get_logger("argus.test.idem")
        assert len(logger_b.handlers) == handler_count
        assert logger_a is logger_b

    def test_verbose_sets_debug_on_console(self):
        logger = get_logger("argus.test.verbose", verbose=True)
        console_handler = next(
            h for h in logger.handlers if isinstance(h, logging.StreamHandler)
        )
        assert console_handler.level == logging.DEBUG

    def test_non_verbose_sets_info_on_console(self):
        logger = get_logger("argus.test.nonverbose", verbose=False)
        console_handler = next(
            h for h in logger.handlers if isinstance(h, logging.StreamHandler)
        )
        assert console_handler.level == logging.INFO

    def test_existing_logger_honors_later_verbose(self):
        logger = get_logger("argus.test.reconfigure", verbose=False)
        logger = get_logger("argus.test.reconfigure", verbose=True)
        console_handler = next(
            h for h in logger.handlers if isinstance(h, logging.StreamHandler)
        )
        assert console_handler.level == logging.DEBUG
