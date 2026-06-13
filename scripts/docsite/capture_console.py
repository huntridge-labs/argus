"""Generate SVG screenshots of the Argus Console for the docsite.

Drives the ``ConsoleApp`` headlessly via Textual ``Pilot`` against a
deterministic synthetic two-run fixture (no Docker / network) and writes
SVGs into ``docs/images/console/``. Animations are forced off
(``ARGUS_NO_ANIMATION``) so the banner is a still frame.

Usage:
    python scripts/docsite/capture_console.py

Requirements:
    - ``pip install -e ".[terminal]"`` (Textual)
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path

os.environ.setdefault("ARGUS_NO_ANIMATION", "1")

from argus.core.models import Finding, ScanResult, ScanSummary, Severity
from argus.core.run_discovery import RESULTS_FILENAME
from argus.viewers.terminal.console import ConsoleApp

REPO_ROOT = Path(__file__).resolve().parents[2]
IMAGES_DIR = REPO_ROOT / "docs" / "images" / "console"
TERM_SIZE = (120, 40)


def _seed_runs(parent: Path) -> Path:
    """Write two sibling synthetic runs; return the newer one."""
    specs = {
        "2026-06-12T18-25Z": ([Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM], 2_000_000),
        "2026-06-11T09-14Z": ([Severity.HIGH], 1_000_000),
    }
    newer: Path | None = None
    for name, (sevs, mtime) in specs.items():
        run = parent / name
        run.mkdir(parents=True)
        findings = [
            Finding(id=f"CVE-2026-{i}", severity=s, title="t", scanner="trivy")
            for i, s in enumerate(sevs)
        ]
        results = run / RESULTS_FILENAME
        results.write_text(json.dumps(
            ScanSummary(results=[ScanResult(scanner="trivy", findings=findings)]).to_dict()
        ))
        os.utime(results, (mtime, mtime))
        if newer is None:
            newer = run
    return newer


async def _capture() -> None:
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="argus-console-shots-"))
    run = _seed_runs(work)

    app = ConsoleApp(results_dir=str(run))
    # Pretend a config exists so the status line shows the populated state.
    app.config_path = REPO_ROOT / "argus.example.yml"
    async with app.run_test(headless=True, size=TERM_SIZE) as pilot:
        await pilot.pause(0.2)
        if app.screen.__class__.__name__ == "HomeScreen":
            app.screen.refresh_status()
        await pilot.pause(0.1)
        out = IMAGES_DIR / "console-home.svg"
        app.save_screenshot(str(out))
        print(f"  wrote {out.relative_to(REPO_ROOT)}")

        app.dispatch_menu("settings")
        await pilot.pause(0.2)
        out = IMAGES_DIR / "console-settings.svg"
        app.save_screenshot(str(out))
        print(f"  wrote {out.relative_to(REPO_ROOT)}")


def main() -> None:
    print(f"Writing console screenshots to {IMAGES_DIR.relative_to(REPO_ROOT)}")
    asyncio.run(_capture())
    print("Done.")


if __name__ == "__main__":
    main()
