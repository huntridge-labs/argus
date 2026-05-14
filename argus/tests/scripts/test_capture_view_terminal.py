"""Tests for ``scripts/docsite/capture_view_terminal.py``.

Build-tool tests, not production-code tests: verify the script's
control flow + subprocess invocation shape without actually pulling
container images, calling ``argus scan``, or rendering Textual. The
end-to-end "did the pipeline produce SVGs" check is the script
itself — re-running it after a UI change is the regression test.

Skipped wholesale in environments without the ``[terminal]`` extra
since the script imports ``argus.viewers.terminal`` at module level.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("textual")  # the script imports BrowseApp at top level


SCRIPT_PATH = (
    Path(__file__).resolve().parents[3]
    / "scripts" / "docsite" / "capture_view_terminal.py"
)


@pytest.fixture(scope="module")
def script():
    """Import the script as a module so its helpers are testable."""
    spec = importlib.util.spec_from_file_location(
        "capture_view_terminal", SCRIPT_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["capture_view_terminal"] = module
    spec.loader.exec_module(module)
    return module


class TestModuleConstants:
    """Sanity checks on the script's public surface."""

    def test_image_refs_are_pinned(self, script):
        """Image refs should be pinned tags, not floating ``latest``."""
        assert script.SCAN_A_IMAGE.startswith("nginx:")
        assert script.SCAN_B_IMAGE.startswith("redis:")
        for ref in (script.SCAN_A_IMAGE, script.SCAN_B_IMAGE):
            assert ":" in ref
            assert not ref.endswith(":latest")

    def test_term_size_seats_dashboard(self, script):
        """Capture viewport must be wide enough for the findings table."""
        width, height = script.TERM_SIZE
        # Findings table needs ~120 cols; dashboard needs ~40 rows.
        assert width >= 120
        assert height >= 36

    def test_scan_config_opts_out_of_cosign(self, script):
        """Inline scan config must disable cosign so the script runs
        on hosts without a cosign binary."""
        assert "verify_image_signatures: false" in script._SCAN_CONFIG
        assert "execution:" in script._SCAN_CONFIG


class TestRunScan:
    """``_run_scan`` is the subprocess wrapper around ``argus scan``."""

    def test_invokes_argus_scan_container_with_image(
        self, script, tmp_path,
    ):
        output_dir = tmp_path / "out"
        config_file = tmp_path / "argus.yml"
        config_file.write_text("execution:\n  verify_image_signatures: false\n")

        completed = MagicMock(returncode=0, stdout="", stderr="")
        with patch.object(script.subprocess, "run", return_value=completed) as run:
            script._run_scan("nginx:1.27-alpine", output_dir, config_file)

        argv = run.call_args.args[0]
        # The script must drive `argus` via `python -m argus` so it
        # uses whichever interpreter ran the script (matters in
        # ``pip install -e .`` setups where the entry point may lag).
        assert argv[0] == sys.executable
        assert argv[1:4] == ["-m", "argus", "scan"]
        assert "container" in argv
        assert "--image" in argv
        assert "nginx:1.27-alpine" in argv
        assert "--config" in argv
        assert str(config_file) in argv
        assert "--output-dir" in argv
        assert str(output_dir) in argv
        # Output formatting flags the screenshot pipeline depends on.
        assert "--no-timestamp" in argv
        assert "--severity-threshold" in argv
        assert "none" in argv
        assert "--format" in argv
        assert "json" in argv
        # Don't poison the test environment with the upgrade-check ping.
        assert "--no-update-check" in argv

    def test_creates_output_dir_before_scanning(self, script, tmp_path):
        """``argus scan`` writes into ``--output-dir`` directly; the
        directory must exist before subprocess fires."""
        output_dir = tmp_path / "deep" / "nested" / "out"
        config_file = tmp_path / "argus.yml"
        config_file.write_text("")

        completed = MagicMock(returncode=0, stdout="", stderr="")
        with patch.object(script.subprocess, "run", return_value=completed):
            script._run_scan("redis:7-alpine", output_dir, config_file)

        assert output_dir.is_dir()

    def test_raises_systemexit_on_nonzero_returncode(
        self, script, tmp_path,
    ):
        output_dir = tmp_path / "out"
        config_file = tmp_path / "argus.yml"
        config_file.write_text("")

        failed = MagicMock(
            returncode=2, stdout="", stderr="image pull failed",
        )
        with patch.object(script.subprocess, "run", return_value=failed):
            with pytest.raises(SystemExit) as exc_info:
                script._run_scan(
                    "nginx:does-not-exist", output_dir, config_file,
                )

        # Surfacing the image ref + exit code in the error message
        # keeps debugging painless when a regen fails in CI/locally.
        message = str(exc_info.value)
        assert "nginx:does-not-exist" in message
        assert "2" in message
