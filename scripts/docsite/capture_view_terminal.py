"""Generate SVG screenshots of ``argus view terminal`` for the docsite.

Drives the Textual ``BrowseApp`` headlessly via ``Pilot``, navigates to
each documented UI state, and writes one SVG per state into
``docs/images/view-terminal/``. SVGs are vector, render natively in the
MkDocs build, version cleanly in git, and the script is the single
source of truth — re-running regenerates the whole set after UI shifts.

Two real scan fixtures power the dataset:

  docs/images/view-terminal/fixtures/scan-a/argus-results.json
      nginx:1.27-alpine — INFO-severity exposed ports (80/tcp), low-
      severity Alpine + nginx CVEs. Demonstrates the new Info column.

  docs/images/view-terminal/fixtures/scan-b/argus-results.json
      redis:7-alpine — MEDIUM 6379/tcp (Redis is on RISKY_PORTS),
      different CVE set. Drives the scan-over-scan diff overlay.

Regenerate fixtures by running the canonical CLI command — see
``scripts/docsite/README.md`` for the exact invocation.

Usage:
    python scripts/docsite/capture_view_terminal.py

Requires the ``[terminal]`` extra (``pip install -e ".[terminal]"``).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from argus.viewers.terminal.app import BrowseApp, DiffScreen
from argus.viewers.terminal.loader import flatten_findings, load_summary


REPO_ROOT = Path(__file__).resolve().parents[2]
IMAGES_DIR = REPO_ROOT / "docs" / "images" / "view-terminal"
FIXTURES_DIR = IMAGES_DIR / "fixtures"
FIXTURE_A = FIXTURES_DIR / "scan-a"
FIXTURE_B = FIXTURES_DIR / "scan-b"

TERM_SIZE = (160, 44)  # wide enough for the findings table, tall enough
                       # to seat the dashboard overlay without scroll


_DEMO_SUBTITLE = "argus-results.json (nginx:1.27-alpine)"


async def _capture(filename: str, keys: list[str], *, settle: float = 0.2) -> None:
    """Drive BrowseApp via a Pilot, save an SVG to IMAGES_DIR/filename.

    The app's sub_title is overridden with a friendly demo label so the
    title bar in the committed screenshot doesn't expose whoever ran
    the capture script's absolute home directory.
    """
    app = BrowseApp(results_dir=str(FIXTURE_A))
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


async def _capture_diff(filename: str, *, settle: float = 0.2) -> None:
    """Push DiffScreen directly with both fixtures' findings."""
    before_summary, _ = load_summary(str(FIXTURE_A))
    after_summary, _ = load_summary(str(FIXTURE_B))
    before = flatten_findings(before_summary)
    after = flatten_findings(after_summary)

    app = BrowseApp(results_dir=str(FIXTURE_A))
    async with app.run_test(headless=True, size=TERM_SIZE) as pilot:
        await pilot.pause(settle)
        app.sub_title = _DEMO_SUBTITLE
        await pilot.pause(settle)
        await app.push_screen(
            DiffScreen(
                before, after,
                before_label="nginx:1.27-alpine",
                after_label="redis:7-alpine",
            ),
        )
        await pilot.pause(settle)
        out = IMAGES_DIR / filename
        app.save_screenshot(str(out))
        print(f"  wrote {out.relative_to(REPO_ROOT)}")


async def main() -> None:
    if not (FIXTURE_A / "argus-results.json").exists():
        raise SystemExit(
            f"Missing fixture: {FIXTURE_A / 'argus-results.json'}\n"
            "Regenerate by running the scan commands documented in "
            "scripts/docsite/README.md."
        )

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
        await _capture(filename, keys)

    print("[scan-over-scan diff overlay]")
    await _capture_diff("08-diff-overlay.svg")

    print("Done.")


if __name__ == "__main__":
    asyncio.run(main())
