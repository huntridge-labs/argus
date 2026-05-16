"""Tests for scripts/ci/check_cli_docs.py.

Covers the check mode, fix mode, stale detection, and volatile line stripping.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.ci.check_cli_docs import _strip_volatile_lines, _generate_quiet, main


class TestStripVolatileLines:
    """Tests for _strip_volatile_lines() date-line removal."""

    def test_removes_auto_generated_date_line(self):
        text = (
            "# Argus CLI Reference (v0.7.0)\n"
            "\n"
            "> Auto-generated from argparse definitions on 2026-04-14.\n"
            "> Do not edit manually.\n"
            "\n"
            "## Usage\n"
        )
        result = _strip_volatile_lines(text)
        assert "> Auto-generated from argparse definitions on" not in result
        assert "## Usage" in result

    def test_preserves_non_volatile_lines(self):
        text = "## Commands\n\n### argus scan\n"
        assert _strip_volatile_lines(text) == text.rstrip("\n")

    def test_handles_empty_string(self):
        assert _strip_volatile_lines("") == ""

    def test_different_dates_produce_same_result(self):
        day1 = (
            "# Title\n"
            "> Auto-generated from argparse definitions on 2026-01-01.\n"
            "Content\n"
        )
        day2 = (
            "# Title\n"
            "> Auto-generated from argparse definitions on 2026-12-31.\n"
            "Content\n"
        )
        assert _strip_volatile_lines(day1) == _strip_volatile_lines(day2)


class TestGenerateQuiet:
    """Tests for _generate_quiet() stdout suppression."""

    def test_returns_string(self):
        result = _generate_quiet()
        assert isinstance(result, str)

    def test_contains_cli_reference_header(self):
        result = _generate_quiet()
        assert "# Argus CLI Reference" in result

    def test_contains_scan_subcommand(self):
        result = _generate_quiet()
        assert "### `argus scan`" in result


class TestMain:
    """Tests for main() check and fix modes."""

    def test_check_passes_when_docs_current(self):
        exit_code = main()
        assert exit_code == 0

    def test_check_fails_when_docs_stale(self, tmp_path, monkeypatch):
        stale_docs = tmp_path / "cli-reference.md"
        stale_docs.write_text("# Old content\n")
        monkeypatch.setattr(
            "scripts.ci.check_cli_docs.DOCS_PATH", stale_docs,
        )
        exit_code = main()
        assert exit_code == 1

    def test_check_fails_when_docs_missing(self, tmp_path, monkeypatch):
        missing = tmp_path / "does-not-exist.md"
        monkeypatch.setattr(
            "scripts.ci.check_cli_docs.DOCS_PATH", missing,
        )
        exit_code = main()
        assert exit_code == 1

    def test_fix_mode_writes_file(self, tmp_path, monkeypatch):
        target = tmp_path / "cli-reference.md"
        monkeypatch.setattr(
            "scripts.ci.check_cli_docs.DOCS_PATH", target,
        )
        monkeypatch.setattr("sys.argv", ["check_cli_docs", "--fix"])

        exit_code = main()

        assert exit_code == 0
        assert target.exists()
        content = target.read_text()
        assert "# Argus CLI Reference" in content
        assert "### `argus scan`" in content

    def test_fix_then_check_passes(self, tmp_path, monkeypatch):
        target = tmp_path / "cli-reference.md"
        monkeypatch.setattr(
            "scripts.ci.check_cli_docs.DOCS_PATH", target,
        )

        # Fix
        monkeypatch.setattr("sys.argv", ["check_cli_docs", "--fix"])
        assert main() == 0

        # Check
        monkeypatch.setattr("sys.argv", ["check_cli_docs"])
        assert main() == 0
