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
import json
import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

from argus.core.config import ViewConfig
from argus.core.models import Finding, ScanResult, ScanSummary, Severity
from argus.core.run_discovery import RESULTS_FILENAME
from argus.viewers.terminal import scan_runner
from argus.viewers.terminal.app import (
    BrowseApp,
    ContextMenuScreen,
    DiffScreen,
    OpenLocationPromptScreen,
    RunScanPromptScreen,
    RunScanScreen,
)
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


async def _capture(  # pragma: no cover — integration-tested by running the script
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


async def _capture_diff(  # pragma: no cover — integration-tested by running the script
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


async def _capture_context_menu(  # pragma: no cover — integration-tested by running the script
    filename: str, scan_a_dir: Path, *, settle: float = 0.2,
) -> None:
    """Push ContextMenuScreen with a synthesized finding that exercises
    every menu item, then snapshot the result.

    A real scan finding usually has *either* a CVE *or* a file:line
    location, not both — so the context menu in production scans
    shows a subset of items per row. For documentation we want all
    menu items visible at once, so we construct a deliberately-rich
    "demo" finding rather than picking one from the scan output.
    """
    demo_finding = Finding(
        id="CVE-2026-12345",
        severity=Severity.HIGH,
        title="Demo finding for screenshot — every menu item visible",
        description="Constructed for the docs context-menu screenshot.",
        location="src/argus/cli.py:142",
        cve="CVE-2026-12345",
        scanner="bandit",
    )

    app = BrowseApp(results_dir=str(scan_a_dir))
    async with app.run_test(headless=True, size=TERM_SIZE) as pilot:
        await pilot.pause(settle)
        app.sub_title = _DEMO_SUBTITLE
        await pilot.pause(settle)
        await app.push_screen(ContextMenuScreen(demo_finding, ViewConfig()))
        await pilot.pause(settle)
        out = IMAGES_DIR / filename
        app.save_screenshot(str(out))
        print(f"  wrote {out.relative_to(REPO_ROOT)}")


async def _capture_open_location_prompt(  # pragma: no cover — integration-tested by running the script
    filename: str, scan_a_dir: Path, *, settle: float = 0.2,
) -> None:
    """Push OpenLocationPromptScreen (the 'local or remote?' modal that
    appears in ``view.open_location: ask`` mode) and snapshot it."""
    app = BrowseApp(results_dir=str(scan_a_dir))
    async with app.run_test(headless=True, size=TERM_SIZE) as pilot:
        await pilot.pause(settle)
        app.sub_title = _DEMO_SUBTITLE
        await pilot.pause(settle)
        await app.push_screen(OpenLocationPromptScreen("src/argus/cli.py:142"))
        await pilot.pause(settle)
        out = IMAGES_DIR / filename
        app.save_screenshot(str(out))
        print(f"  wrote {out.relative_to(REPO_ROOT)}")


def _synth_runs(parent: Path) -> Path:  # pragma: no cover — integration-tested by running the script
    """Write two sibling synthetic runs under ``parent``; return the newer.

    The runs sidebar only earns its keep with more than one run to switch
    between, and a deterministic two-run fixture keeps the screenshot
    stable across regenerations (the real container scans land in
    separate parents, so they don't exercise the sidebar's "siblings"
    discovery on their own).
    """
    parent.mkdir(parents=True, exist_ok=True)
    specs = {
        "2026-06-12T18-25Z": ([
            (Severity.CRITICAL, "CVE-2026-12345", "libxml2", "2.11.5-r0", "Heap overflow in xmlParseDoc"),
            (Severity.HIGH, "CVE-2026-22222", "openssl", "3.1.4-r1", "Timing side-channel in RSA"),
            (Severity.HIGH, "CVE-2026-33333", "curl", "8.5.0-r0", "Use-after-free in connection reuse"),
            (Severity.MEDIUM, "CVE-2026-44444", "zlib", "1.3-r2", "Improper bounds check in inflate"),
            (Severity.LOW, "CVE-2026-55555", "busybox", "1.36.1-r5", "Info leak in applet parsing"),
        ], 2_000_000),
        "2026-06-11T09-14Z": ([
            (Severity.HIGH, "CVE-2026-22222", "openssl", "3.1.3-r0", "Timing side-channel in RSA"),
            (Severity.LOW, "CVE-2026-55555", "busybox", "1.36.1-r4", "Info leak in applet parsing"),
        ], 1_000_000),
    }
    newer: Path | None = None
    for name, (rows, mtime) in specs.items():
        run_dir = parent / name
        run_dir.mkdir()
        findings = [
            Finding(id=cve, severity=sev, title=title, scanner="trivy", cve=cve,
                    location=f"{pkg}@{ver}",
                    metadata={"package": pkg, "installed_version": ver,
                              "fixed_version": "—", "sbom_source": "nginx:1.27-alpine"})
            for sev, cve, pkg, ver, title in rows
        ]
        results = run_dir / RESULTS_FILENAME
        results.write_text(json.dumps(
            ScanSummary(results=[ScanResult(scanner="trivy", findings=findings)]).to_dict()
        ))
        os.utime(results, (mtime, mtime))
        if newer is None:
            newer = run_dir
    return newer


async def _capture_runs_sidebar(  # pragma: no cover — integration-tested by running the script
    filename: str, run_dir: Path, *, settle: float = 0.2,
) -> None:
    """Snapshot the runs sidebar (auto-revealed with two sibling runs)."""
    app = BrowseApp(results_dir=str(run_dir))
    async with app.run_test(headless=True, size=TERM_SIZE) as pilot:
        await pilot.pause(settle)
        app.sub_title = _DEMO_SUBTITLE
        await pilot.pause(settle)
        app.save_screenshot(str(IMAGES_DIR / filename))
        print(f"  wrote {(IMAGES_DIR / filename).relative_to(REPO_ROOT)}")


async def _capture_run_prompt(  # pragma: no cover — integration-tested by running the script
    filename: str, run_dir: Path, *, settle: float = 0.2,
) -> None:
    """Snapshot the 'Run a scan' prompt overlay."""
    app = BrowseApp(results_dir=str(run_dir))
    async with app.run_test(headless=True, size=TERM_SIZE) as pilot:
        await pilot.pause(settle)
        app.sub_title = _DEMO_SUBTITLE
        await pilot.pause(settle)
        await app.push_screen(RunScanPromptScreen(default_path="."))
        await pilot.pause(settle)
        app.save_screenshot(str(IMAGES_DIR / filename))
        print(f"  wrote {(IMAGES_DIR / filename).relative_to(REPO_ROOT)}")


async def _capture_run_output(  # pragma: no cover — integration-tested by running the script
    filename: str, run_dir: Path, *, settle: float = 0.2,
) -> None:
    """Snapshot the scan-runner output overlay.

    The real subprocess stream is stubbed and replaced with curated
    lines so the committed screenshot is deterministic — the point is to
    show the overlay's shape, not a specific scan's output.
    """
    async def _noop() -> None:
        return None

    app = BrowseApp(results_dir=str(run_dir))
    async with app.run_test(headless=True, size=TERM_SIZE) as pilot:
        await pilot.pause(settle)
        app.sub_title = _DEMO_SUBTITLE
        await pilot.pause(settle)
        argv = scan_runner.build_scan_argv(scanner=None, path=".", output_dir=str(run_dir.parent))
        screen = RunScanScreen(argv, launch_root=run_dir.parent)
        screen._stream = _noop  # type: ignore[method-assign]  # don't spawn a real scan
        await app.push_screen(screen)
        await pilot.pause(settle)
        for line in [
            "argus scan — 6 scanners enabled", "",
            "[1/6] bandit      ✓  0 findings", "[2/6] gitleaks    ✓  0 findings",
            "[3/6] osv         ✓  12 findings", "[4/6] trivy       ✓  47 findings",
            "[5/6] checkov     ✓  3 findings", "[6/6] opengrep    ✓  1 finding", "",
            "Wrote argus-results/2026-06-12T18-40Z/argus-results.json  (63 findings)",
        ]:
            screen._append(line)
        screen._mark_done(success=True, code=0)
        await pilot.pause(settle)
        app.save_screenshot(str(IMAGES_DIR / filename))
        print(f"  wrote {(IMAGES_DIR / filename).relative_to(REPO_ROOT)}")


async def _capture_anchored_menu(  # pragma: no cover — integration-tested by running the script
    filename: str, run_dir: Path, *, settle: float = 0.2,
) -> None:
    """Snapshot a context menu anchored at a right-click position."""
    app = BrowseApp(results_dir=str(run_dir))
    async with app.run_test(headless=True, size=TERM_SIZE) as pilot:
        await pilot.pause(settle)
        app.sub_title = _DEMO_SUBTITLE
        await pilot.pause(settle)
        if app.all_findings:
            app._push_context_menu(app.all_findings[min(1, len(app.all_findings) - 1)], anchor=(104, 9))
        await pilot.pause(settle)
        app.save_screenshot(str(IMAGES_DIR / filename))
        print(f"  wrote {(IMAGES_DIR / filename).relative_to(REPO_ROOT)}")


async def _capture_all(  # pragma: no cover — integration-tested by running the script
    scan_a_dir: Path, scan_b_dir: Path,
) -> None:
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

    print("[context menu — every menu item visible]")
    await _capture_context_menu("09-context-menu.svg", scan_a_dir)

    print("[open-location prompt — ask mode modal]")
    await _capture_open_location_prompt(
        "10-open-location-prompt.svg", scan_a_dir,
    )

    # Runs sidebar + scan runner states use a deterministic two-run
    # synthetic fixture (see _synth_runs) rather than the real container
    # scans, which land in separate parents and don't exercise sibling
    # discovery. The runner-output state is stubbed for determinism.
    with tempfile.TemporaryDirectory(prefix="argus-runs-") as runs_tmp:
        run_dir = _synth_runs(Path(runs_tmp))
        print("[runs sidebar — switch between runs]")
        await _capture_runs_sidebar("11-runs-sidebar.svg", run_dir)
        print("[scan runner — prompt]")
        await _capture_run_prompt("12-scan-runner-prompt.svg", run_dir)
        print("[scan runner — streamed output]")
        await _capture_run_output("13-scan-runner-output.svg", run_dir)
        print("[context menu — anchored at the cursor]")
        await _capture_anchored_menu("14-context-menu-anchored.svg", run_dir)


def main() -> None:  # pragma: no cover — integration-tested by running the script
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
