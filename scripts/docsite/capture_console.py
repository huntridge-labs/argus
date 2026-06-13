"""Generate PNG screenshots of the Argus Console for the docs / PRs.

Drives the ``ConsoleApp`` headlessly via Textual ``Pilot`` against a
deterministic synthetic two-run fixture (no Docker / network), captures
each state as an SVG, then rasterises to **PNG** in ``docs/images/console/``.
Animations are forced off (``ARGUS_NO_ANIMATION``) so the banner is a still
frame.

Why PNG (not the SVG the other viewer screenshots use): the ANSI block-art
wordmark relies on ``█`` glyphs tiling seamlessly, which GitHub's image
proxy doesn't honour when rendering an SVG (the rows strip apart). A raster
PNG renders pixel-identically everywhere.

Usage:
    python scripts/docsite/capture_console.py

Requirements:
    - ``pip install -e ".[terminal]"`` (Textual)
    - One SVG→PNG rasteriser on PATH: ``rsvg-convert`` (librsvg),
      ``cairosvg``, or macOS ``qlmanage``.
    - Pillow (optional) for trimming uniform padding.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
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


def _svg_to_png(svg: Path, png: Path) -> None:
    """Rasterise ``svg`` → ``png`` with the first available tool, then trim."""
    rasterisers = (
        ("rsvg-convert", ["rsvg-convert", "-o", str(png), str(svg)]),
        ("cairosvg", ["cairosvg", str(svg), "-o", str(png)]),
        ("qlmanage", ["qlmanage", "-t", "-s", "2000", "-o", str(png.parent), str(svg)]),
    )
    for name, cmd in rasterisers:
        if not shutil.which(name):
            continue
        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError:
            continue  # tool present but failed (e.g. missing libcairo) — try the next
        if name == "qlmanage":  # writes <svg name>.png in the out dir
            (png.parent / f"{svg.name}.png").replace(png)
        if not png.is_file():
            continue
        _trim(png)
        return
    raise SystemExit(
        "No working SVG→PNG rasteriser found. Install rsvg-convert, cairosvg, or use macOS qlmanage."
    )


def _trim(png: Path) -> None:
    """Best-effort crop of uniform padding (skipped if Pillow is absent)."""
    try:
        from PIL import Image, ImageChops
    except ImportError:
        return
    im = Image.open(png).convert("RGB")
    bbox = ImageChops.difference(im, Image.new("RGB", im.size, im.getpixel((0, 0)))).getbbox()
    if bbox:
        im.crop(bbox).save(png)


async def _capture() -> None:
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="argus-console-shots-"))
    run = _seed_runs(work)

    def _shot(name: str) -> None:
        svg = work / f"{name}.svg"
        app.save_screenshot(str(svg))
        out = IMAGES_DIR / f"{name}.png"
        _svg_to_png(svg, out)
        print(f"  wrote {out.relative_to(REPO_ROOT)}")

    app = ConsoleApp(results_dir=str(run))
    # Pretend a config exists so the status line shows the populated state.
    app.config_path = REPO_ROOT / "argus.example.yml"
    async with app.run_test(headless=True, size=TERM_SIZE) as pilot:
        await pilot.pause(0.2)
        if app.screen.__class__.__name__ == "HomeScreen":
            app.screen.refresh_status()
        await pilot.pause(0.1)
        _shot("console-home")

        app.dispatch_menu("settings")
        await pilot.pause(0.2)
        _shot("console-settings")


def main() -> None:
    print(f"Writing console screenshots to {IMAGES_DIR.relative_to(REPO_ROOT)}")
    asyncio.run(_capture())
    print("Done.")


if __name__ == "__main__":
    main()
