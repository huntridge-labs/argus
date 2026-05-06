"""Tests for argus.core.version.parse_tool_version.

Locks in the contract: 9 scanner modules now depend on this helper, so
any regression here breaks every scanner's tool_version() at once.
"""

import re
import subprocess
from unittest.mock import patch

import pytest

from argus.core.version import parse_tool_version


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(
        args=["fake"], returncode=returncode, stdout=stdout, stderr=stderr,
    )


class TestParseToolVersion:
    """Happy-path regex matching across the parser styles in use."""

    def test_returns_first_capture_group(self):
        with patch("subprocess.run", return_value=_completed("bandit 1.7.5")):
            assert parse_tool_version(["bandit", "--version"], r"^bandit (\S+)") == "1.7.5"

    def test_strips_surrounding_whitespace(self):
        with patch("subprocess.run", return_value=_completed("bandit 1.7.5  \n")):
            assert parse_tool_version(["bandit", "--version"], r"^bandit (\S+)") == "1.7.5"

    def test_multiline_anchor_works(self):
        # Trivy emits a multi-line banner; the helper passes re.MULTILINE so
        # ^Version: matches at start of any line. The first line is the CLI
        # version we want; later lines are DB metadata we don't.
        output = "Version: 0.58.1\nVulnerability DB:\n  Version: 2"
        with patch("subprocess.run", return_value=_completed(output)):
            assert parse_tool_version(["trivy", "--version"], r"^Version: (\S+)") == "0.58.1"

    def test_falls_back_to_stderr(self):
        # Some Java tools emit version strings to stderr.
        with patch("subprocess.run", return_value=_completed(stdout="", stderr="checkov 3.2.0")):
            assert parse_tool_version(["checkov", "--version"], r"^checkov (\S+)") == "3.2.0"

    def test_optional_v_prefix(self):
        # Gitleaks emits vX.Y.Z; the captured group should not include the v.
        with patch("subprocess.run", return_value=_completed("v8.18.4")):
            assert parse_tool_version(["gitleaks", "version"], r"v?([0-9]\S*)") == "8.18.4"

    def test_pattern_can_be_compiled_regex(self):
        compiled = re.compile(r"^bandit (\S+)", re.MULTILINE)
        with patch("subprocess.run", return_value=_completed("bandit 1.7.5")):
            assert parse_tool_version(["bandit", "--version"], compiled) == "1.7.5"

    def test_custom_group_index(self):
        with patch("subprocess.run", return_value=_completed("name=trivy ver=0.58.1")):
            assert parse_tool_version(
                ["trivy", "--version"],
                r"name=(\S+) ver=(\S+)",
                group=2,
            ) == "0.58.1"


class TestParseToolVersionFailures:
    """Anything we narrowly expect returns None — never raises.

    Per ADR-016 the broader Exception catch is the anti-pattern;
    only missing binary, timeout, and OS errors are translated.
    """

    def test_no_match_returns_none(self):
        with patch("subprocess.run", return_value=_completed("unknown")):
            assert parse_tool_version(["x", "--version"], r"^expected (\S+)") is None

    def test_missing_binary_returns_none(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert parse_tool_version(["nope", "--version"], r"(\S+)") is None

    def test_timeout_returns_none(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("x", 5)):
            assert parse_tool_version(["x", "--version"], r"(\S+)") is None

    def test_oserror_returns_none(self):
        with patch("subprocess.run", side_effect=OSError("permission denied")):
            assert parse_tool_version(["x", "--version"], r"(\S+)") is None

    def test_empty_output_returns_none(self):
        with patch("subprocess.run", return_value=_completed("")):
            assert parse_tool_version(["x", "--version"], r"(\S+)") is None

    def test_does_not_swallow_unexpected_exceptions(self):
        # Bugs inside subprocess.run shouldn't be silently translated to None.
        with patch("subprocess.run", side_effect=ValueError("unexpected")):
            with pytest.raises(ValueError):
                parse_tool_version(["x", "--version"], r"(\S+)")
