"""Argv construction for the terminal viewer's in-app scan runner.

The TUI can kick off ``argus scan`` without dropping back to the shell:
press ``R``, confirm a target, and the scan streams into an overlay,
then the results reload in place. This module owns the *pure* pieces of
that flow — building the subprocess argv and deciding where output
lands — so they're unit-testable without Textual or a live subprocess.
The Textual overlay that runs the command lives in ``app.py``.

We re-invoke the SAME interpreter (``sys.executable -m argus``) rather
than a bare ``argus`` on PATH so a scan launched from a venv'd TUI runs
in that venv — no surprise about which argus / which scanners resolve.
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path

from argus.core.run_discovery import RESULTS_FILENAME


def resolve_output_base(results_dir: str | None) -> Path:
    """Return the directory new scans should write into.

    Mirrors ``discover_runs``' notion of a "runs parent" so a scan
    launched from the TUI lands as a sibling of the runs already in the
    sidebar:

    - ``None`` → ``./argus-results`` (argus scan's own default home).
    - a dir that *is* a single run (holds ``argus-results.json``) →
      its parent, so the new timestamped run sits beside it.
    - any other dir → itself (it's already a runs parent).
    """
    if results_dir is None:
        return Path("argus-results")
    base = Path(results_dir)
    if (base / RESULTS_FILENAME).is_file():
        return base.parent
    return base


def build_scan_argv(
    *,
    scanner: str | None = None,
    path: str = ".",
    config: str | None = None,
    output_dir: str | Path | None = None,
    no_spinner: bool = True,
) -> list[str]:
    """Build the ``argus scan`` argv the runner overlay executes.

    Always requests the ``json`` format — the viewers consume
    ``argus-results.json``, so a scan that didn't emit it would leave
    nothing to reload — plus ``terminal`` so the streamed output stays
    human-readable. ``--no-spinner`` is on by default because the
    animated spinner's carriage returns render as garbage in a captured
    pipe; the phase-progress lines still stream.

    ``scanner`` (optional) runs a single scanner; omitted runs all
    enabled scanners from the resolved config. ``path`` defaults to the
    current directory. The argv is a list (never a shell string) so
    paths with spaces or quotes need no escaping.
    """
    argv = [sys.executable, "-m", "argus", "scan"]
    if scanner:
        argv.append(scanner)
    if path:
        argv += ["--path", path]
    if config:
        argv += ["--config", config]
    if output_dir is not None:
        argv += ["--output-dir", str(output_dir)]
    argv += ["--format", "json", "--format", "terminal"]
    if no_spinner:
        argv.append("--no-spinner")
    return argv


def format_command(argv: list[str]) -> str:
    """Render ``argv`` as a copy-pasteable shell line for the overlay header.

    The interpreter path is collapsed to ``argus`` so the displayed
    command reads like what a user would type, not the venv's python
    absolute path. Purely cosmetic — the real invocation uses ``argv``.
    """
    display = list(argv)
    if len(display) >= 3 and display[1] == "-m" and display[2] == "argus":
        display = ["argus", *display[3:]]
    return " ".join(shlex.quote(part) for part in display)
