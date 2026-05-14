"""Generate SVG screenshots of ``argus view terminal`` for the docsite.

End-to-end automation: runs ``argus scan container`` against two pinned
images, drives the Textual ``BrowseApp`` headlessly via ``Pilot`` against
the fresh scan output, and writes one SVG per UI state into
``docs/images/view-terminal/``.

The scan output JSON is **not** committed — it lives in a tempdir for
the duration of the script and is discarded on exit. Re-running this
script regenerates both the data and the screenshots, so the committed
artifacts can never drift out of sync with the current argus output
shape, the current CVE database, or the current image contents.

The committed SVGs themselves are vector and render natively in the
MkDocs build.

Two pinned images power the dataset:

  nginx:1.27-alpine  →  scan A (97-ish findings spread across every
                        severity including INFO from the new exposure /
                        services sub-scanners; declared EXPOSE 80/tcp
                        and nginx init.d units provide the Info column
                        marquee shots).
  redis:7-alpine     →  scan B (handful of findings including the
                        MEDIUM EXPOSE-6379-tcp from the RISKY_PORTS
                        watchlist; provides the second results set for
                        the scan-over-scan diff overlay).

Image refs intentionally use slightly-floating tags
(``nginx:1.27-alpine`` / ``redis:7-alpine``) so the script keeps
working for years without manual touch. Bump them when they 404.

Usage:
    python scripts/docsite/capture_view_terminal.py

Requirements:
    - ``pip install -e ".[terminal]"`` — Textual is needed for capture
    - Docker (or a podman / nerdctl alias) — argus pulls scanner images
    - Network access to docker.io for the pinned target images
    - Cosign is NOT required — the inline scan config opts out via
      ``execution.verify_image_signatures: false`` (the screenshot
      pipeline doesn't add to the supply-chain guarantees real users
      get; that's owned by the live scan path).
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

from argus.viewers.terminal.app import BrowseApp, DiffScreen
from argus.viewers.terminal.loader import flatten_findings, load_summary


REPO_ROOT = Path(__file__).resolve().parents[2]
IMAGES_DIR = REPO_ROOT / "docs" / "images" / "view-terminal"

TERM_SIZE = (160, 44)  # wide enough for the findings table, tall enough
                       # to seat the dashboard overlay without scroll

SCAN_A_IMAGE = "nginx:1.27-alpine"
SCAN_A_LABEL = "nginx:1.27-alpine"

SCAN_B_IMAGE = "redis:7-alpine"
SCAN_B_LABEL = "redis:7-alpine"

_DEMO_SUBTITLE = f"argus-results.json ({SCAN_A_LABEL})"

# Inline scan config — opts out of cosign verify so the script runs
# without a cosign binary on the contributor's host. The committed
# screenshots don't need the supply-chain guarantee; the screenshots
# are for showing the UI, not for attesting image provenance.
_SCAN_CONFIG = textwrap.dedent(
    """\
    execution:
      verify_image_signatures: false
    """
)


def _run_scan(image_ref: str, output_dir: Path, config_file: Path) -> None:
    """Invoke ``argus scan container --image`` as a subprocess."""
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, "-m", "argus", "scan", "container",
        "--image", image_ref,
        "--config", str(config_file),
        "--output-dir", str(output_dir),
        "--no-timestamp",
        "--severity-threshold", "none",
        "--format", "json",
        "--quiet", "--no-spinner", "--no-update-check",
    ]
    print(f"  scanning {image_ref}…", flush=True)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(
            f"argus scan exited {result.returncode} for {image_ref}"
        )


async def _capture(
    filename: str, keys: list[str], fixture_dir: Path, *,
    settle: float = 0.2,
) -> None:
    """Drive BrowseApp via Pilot and save an SVG.

    The app's ``sub_title`` is overridden with a friendly demo label so
    the title bar in committed images doesn't expose the contributor's
    absolute home directory.
    """
    app = BrowseApp(results_dir=str(fixture_dir))
    async with app.run_test(headless=True, size=TERM_SIZE) as pilot:
        await pilot.pause(settle)
        app.sub_title = _DEMO_SUBTITLE
        await pilot.pause(settle)  # let the reactive re-render
        for key in keys:
            await pilot.press(key)
            await pilot.pause(settle)
        out = IMAGES_DIR / filename
        app.save_screenshot(str(out))
        print(f"  wrote {out.relative_to(REPO_ROOT)}")


async def _capture_diff(
    filename: str, scan_a_dir: Path, scan_b_dir: Path, *,
    settle: float = 0.2,
) -> None:
    """Push DiffScreen directly with both fixtures' findings."""
    before_summary, _ = load_summary(str(scan_a_dir))
    after_summary, _ = load_summary(str(scan_b_dir))
    before = flatten_findings(before_summary)
    after = flatten_findings(after_summary)

    app = BrowseApp(results_dir=str(scan_a_dir))
    async with app.run_test(headless=True, size=TERM_SIZE) as pilot:
        await pilot.pause(settle)
        app.sub_title = _DEMO_SUBTITLE
        await pilot.pause(settle)
        await app.push_screen(
            DiffScreen(
                before, after,
                before_label=SCAN_A_LABEL,
                after_label=SCAN_B_LABEL,
            ),
        )
        await pilot.pause(settle)
        out = IMAGES_DIR / filename
        app.save_screenshot(str(out))
        print(f"  wrote {out.relative_to(REPO_ROOT)}")


async def _capture_all(scan_a_dir: Path, scan_b_dir: Path) -> None:
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Writing screenshots to {IMAGES_DIR.relative_to(REPO_ROOT)}")

    states: list[tuple[str, str, list[str]]] = [
        ("01-findings-list.svg",   "initial findings list",        []),
        ("02-filter-medium.svg",   "filter: medium and above",     ["3"]),
        ("03-filter-critical.svg", "filter: critical only",        ["1"]),
        ("04-dashboard.svg",       "executive dashboard overlay",  ["d"]),
        ("05-help.svg",            "help modal (key reference)",   ["question_mark"]),
        ("06-scanner-picker.svg",  "scanner picker (shift+n)",     ["N"]),
        ("07-product-picker.svg",  "product picker (p)",           ["p"]),
    ]

    for filename, description, keys in states:
        print(f"[{description}]")
        await _capture(filename, keys, scan_a_dir)

    print("[scan-over-scan diff overlay]")
    await _capture_diff("08-diff-overlay.svg", scan_a_dir, scan_b_dir)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="argus-screenshots-") as tmp:
        tmp_path = Path(tmp)
        config_file = tmp_path / "argus.yml"
        config_file.write_text(_SCAN_CONFIG)

        scan_a_dir = tmp_path / "scan-a"
        scan_b_dir = tmp_path / "scan-b"

        print("Running scans (this pulls scanner images on first run)…")
        _run_scan(SCAN_A_IMAGE, scan_a_dir, config_file)
        _run_scan(SCAN_B_IMAGE, scan_b_dir, config_file)

        # ``argus scan container`` writes into a timestamped subdir and
        # leaves a ``latest`` symlink even with --no-timestamp; the
        # viewer's loader follows the symlink, so point at it directly.
        scan_a_latest = scan_a_dir / "latest"
        scan_b_latest = scan_b_dir / "latest"

        print()
        asyncio.run(_capture_all(scan_a_latest, scan_b_latest))
        print("Done.")


if __name__ == "__main__":
    main()
