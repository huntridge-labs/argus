"""Tests for --version flag and version consistency."""

import subprocess
import sys

import pytest

from argus import __version__
from argus.cli import build_parser, _get_version


class TestVersionFlag:
    """Test --version outputs the correct version string."""

    def test_version_string_format(self):
        version = _get_version()
        assert version.startswith("argus ")
        assert __version__ in version

    def test_version_matches_module(self):
        assert isinstance(__version__, str)
        assert len(__version__.split(".")) >= 2  # at least major.minor

    def test_version_flag_output(self):
        result = subprocess.run(
            [sys.executable, "-m", "argus", "--version"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert __version__ in result.stdout

    def test_version_flag_exits_zero(self):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0

    def test_version_yaml_consistency(self):
        """Version in __init__.py should match version.yaml."""
        from pathlib import Path

        version_yaml = Path(__file__).parent.parent.parent / "version.yaml"
        if version_yaml.exists():
            raw = version_yaml.read_text().strip()
            # version.yaml is "0.7.0 # x-release-it-version" — extract the version
            yaml_version = raw.split()[0] if raw else ""
            assert __version__ == yaml_version, (
                f"__version__ ({__version__}) != version.yaml ({yaml_version})"
            )
