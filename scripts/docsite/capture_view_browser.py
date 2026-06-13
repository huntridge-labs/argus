#!/usr/bin/env python3
"""Regenerate the ``argus view browser`` docs screenshots.

Mirrors ``capture_view_terminal.py`` for the browser viewer: it starts the
local FastAPI server against a results directory, then drives **headless
Chrome** (already on the machine — no Playwright / extra dependency) to
screenshot each page into ``docs/images/browser/``.

Screenshots are captured with ``--force-prefers-reduced-motion`` so they're
deterministic: the count-up snaps to its final value and the chart draw-on
settles, rather than catching an animation mid-frame. That also means the
images show the accessible, reduced-motion rendering.

Usage::

    python scripts/docsite/capture_view_browser.py [RESULTS_DIR]

``RESULTS_DIR`` defaults to ``argus-results`` (a specific run dir, or a
parent containing timestamped runs — the newest is used). Requires the
``[browser]`` extra installed and Google Chrome / Chromium present.

NOTE: the dashboard/findings header shows the *resolved* scan path, so
capture from a **neutral location** (e.g. copy a run under
``/Users/Shared/argus-demo`` or ``/srv/argus``) — never straight from a
personal home directory — or the committed docs screenshots will embed your
username. The shipped images are captured this way.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = REPO_ROOT / "docs" / "images" / "browser"
PORT = 8799
WINDOW = "1440,1180"
VIRTUAL_TIME_MS = 5000

# Pages to capture: (filename stem, path).
PAGES = [
    ("dashboard", "/"),
    ("findings", "/findings"),
]

_CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    shutil.which("google-chrome-stable") or "",
    shutil.which("chromium") or "",
    shutil.which("chromium-browser") or "",
]


def _find_chrome() -> str:
    for candidate in _CHROME_CANDIDATES:
        if candidate and Path(candidate).exists():
            return candidate
    raise SystemExit("No Chrome/Chromium binary found — install one to capture screenshots.")


def _wait_for_server(url: str, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:  # noqa: S310
                if resp.status == 200:
                    return
        except Exception:
            time.sleep(0.3)
    raise SystemExit(f"Server did not come up at {url}")


def main() -> int:
    results = sys.argv[1] if len(sys.argv) > 1 else "argus-results"
    chrome = _find_chrome()
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    server = subprocess.Popen(
        [sys.executable, "-m", "argus", "view", "--interface=browser",
         results, "--port", str(PORT), "--no-open"],
        cwd=REPO_ROOT,
    )
    try:
        _wait_for_server(f"http://127.0.0.1:{PORT}/healthz")
        for stem, path in PAGES:
            profile = REPO_ROOT / ".cache" / f"chrome-{stem}"
            shutil.rmtree(profile, ignore_errors=True)
            subprocess.run(
                [chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                 "--force-color-profile=srgb", "--force-prefers-reduced-motion",
                 f"--user-data-dir={profile}", f"--window-size={WINDOW}",
                 f"--virtual-time-budget={VIRTUAL_TIME_MS}",
                 f"--screenshot={OUT_DIR / (stem + '.png')}",
                 f"http://127.0.0.1:{PORT}{path}"],
                check=False, capture_output=True,
            )
            shutil.rmtree(profile, ignore_errors=True)
            print(f"captured {stem}.png")
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
