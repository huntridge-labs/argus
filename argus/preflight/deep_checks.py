"""Live config validation — registry reachability + path existence.

Extracted from `argus validate --deep` so the same probes can be reused
by `argus doctor`-style workflows and end-of-init smoke tests. Pure
logic + a single `docker manifest inspect` subprocess call per image —
no print statements, no I/O on the config itself, callers own formatting.

The probes here are **always optional**: failures are reported as
results, never raised. A missing Docker daemon yields `skip` results
rather than aborting the run, so an offline developer can still run
`argus validate --deep` and get the path-existence half of the report.
"""

from __future__ import annotations

import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal


Status = Literal["ok", "fail", "skip", "warn"]
Severity = Literal["error", "warning", "info"]


def short_ref(image_ref: str, verbose: bool = False, digest_chars: int = 6) -> str:
    """Truncate a ``tag@sha256:...`` reference for display.

    The 64-character digest tail dominates terminal output and isn't
    actionable to read in full — the operator wants the tag + a hint
    of which digest, not the whole hash. ``verbose=True`` returns the
    untruncated ref so ``argus validate --deep -v`` can dump the
    canonical form for copy-paste / escalation.
    """
    if verbose or "@sha256:" not in image_ref:
        return image_ref
    head, _, digest = image_ref.partition("@sha256:")
    if len(digest) <= digest_chars * 2 + 1:
        return image_ref
    return f"{head}@sha256:{digest[:digest_chars]}…{digest[-digest_chars:]}"


@dataclass(frozen=True)
class DeepCheckResult:
    """One row in the `--deep` output table.

    `name` identifies the subject (an image ref, a path, a config key).
    `status` is the machine-readable outcome the caller uses for
    pass/fail accounting. `message` is the human-readable detail line
    shown after the status indicator.
    """

    name: str
    status: Status
    severity: Severity
    message: str


def manifest_probe(image_ref: str, timeout: int = 30) -> tuple[bool, str]:
    """Probe `image_ref` via `docker manifest inspect`.

    Returns (success, detail). `success=False` with detail "no docker"
    when the binary is missing — callers should map that to a `skip`
    result, not an error, because it means the probe couldn't run, not
    that the image is broken.
    """
    if not shutil.which("docker"):
        return False, "no docker"
    try:
        result = subprocess.run(
            ["docker", "manifest", "inspect", image_ref],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"timeout after {timeout}s"
    except OSError as exc:
        return False, f"could not invoke docker: {exc}"

    if result.returncode == 0:
        return True, "manifest resolved"
    # Trim the first stderr line — Docker's errors are typically a
    # single ~80-char string ("no such manifest", "unauthorized",
    # "manifest unknown") with stack-trace garbage after.
    err = (result.stderr or result.stdout).strip().split("\n", 1)[0][:120]
    return False, err or "manifest inspect failed"


def check_registry_reachability(
    images: list[str],
    registry: str = "",
    registry_map: dict | None = None,
    *,
    max_workers: int = 8,
    progress: Callable[[int, "DeepCheckResult"], None] | None = None,
) -> list[DeepCheckResult]:
    """For each image, apply registry rewriting then probe the manifest.

    Empty image list returns []. Each image emits exactly one result
    with the rewritten ref as the ``name`` (so the output shows what
    was actually probed, not just the upstream).

    Probes run concurrently in a ``ThreadPoolExecutor`` — six independent
    ``docker manifest inspect`` calls take ~3s wall-clock instead of
    ~15s sequential. Results are returned in **input order** (not
    finish order) so the operator sees the same row layout as the
    config.

    ``progress(idx, result)`` is invoked once per completion in
    finish-order — useful for streaming a live progress display while
    keeping the final return value stably ordered. The callback runs
    on a worker thread; format-only callers can ignore thread-safety,
    but anyone touching mutable state should serialize the update.
    """
    if not images:
        return []

    # Import here so a missing engine import (unusual but possible
    # during partial test runs) doesn't break the rest of the validate
    # pipeline.
    from argus.core.engine import resolve_image_ref

    resolved = [
        resolve_image_ref(img, registry or None, registry_map or None)
        for img in images
    ]

    # Short-circuit before spinning up the pool: if Docker is missing,
    # every probe will say so identically. One explanation + N quiet
    # skip rows reads better than N identical Docker-missing lines.
    if not shutil.which("docker"):
        results: list[DeepCheckResult] = []
        for i, ref in enumerate(resolved):
            r = DeepCheckResult(
                name=ref,
                status="skip",
                severity="info",
                message=(
                    "Docker not on PATH — install Docker to probe registries"
                    if i == 0
                    else "(skipped — no Docker)"
                ),
            )
            results.append(r)
            if progress is not None:
                progress(i, r)
        return results

    # Concurrent execution. The slot list keeps input order; futures
    # write into their own index. `as_completed` drives the progress
    # callback in finish-order so the operator sees results trickle
    # in rather than blocking on the slowest probe.
    slots: list[DeepCheckResult | None] = [None] * len(resolved)
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_to_idx = {
            ex.submit(manifest_probe, ref): (i, ref)
            for i, ref in enumerate(resolved)
        }
        for future in as_completed(future_to_idx):
            i, ref = future_to_idx[future]
            success, detail = future.result()
            if success:
                r = DeepCheckResult(name=ref, status="ok", severity="info", message=detail)
            else:
                r = DeepCheckResult(name=ref, status="fail", severity="error", message=detail)
            slots[i] = r
            if progress is not None:
                progress(i, r)

    # `slots` is fully populated by the time the executor exits.
    return [r for r in slots if r is not None]


def check_paths(
    config_data: dict,
    base_dir: Path | None = None,
) -> list[DeepCheckResult]:
    """Verify on-disk paths in the config against the real argus schema.

    Top-level keys that hold paths (per ``argus-config.schema.json``):
      - ``containers.search_paths`` — list of dirs for Dockerfile discovery.
        Missing dir is an **error** (scan-time discovery would surface
        no results from that path anyway, but flagging up-front saves
        debugging "why didn't argus find my Dockerfile" later).
      - ``containers.output_dir`` and ``reporting.output_dir`` — output
        dirs argus creates lazily. Missing is a **warning** because
        the scan will create them; non-writable parent is the real
        error case (caught at scan time).
      - Per-scanner ``exclude`` — comma-separated paths or patterns
        under each ``scanners.{name}``. Glob entries are skipped on
        purpose; concrete-path entries that don't exist emit info-level
        warnings so a typo is visible without failing the run.
    """
    base = base_dir or Path.cwd()
    results: list[DeepCheckResult] = []

    def _resolve(p: str) -> Path:
        return Path(p) if Path(p).is_absolute() else (base / p).resolve()

    # containers.search_paths — list of dirs
    containers = config_data.get("containers") or {}
    if isinstance(containers, dict):
        search_paths = containers.get("search_paths") or []
        if isinstance(search_paths, list):
            for sp in search_paths:
                if not isinstance(sp, str) or not sp:
                    continue
                rp = _resolve(sp)
                if rp.exists():
                    results.append(DeepCheckResult(
                        name=f"containers.search_paths[{sp}]",
                        status="ok",
                        severity="info",
                        message=f"exists at {rp}",
                    ))
                else:
                    results.append(DeepCheckResult(
                        name=f"containers.search_paths[{sp}]",
                        status="fail",
                        severity="error",
                        message=f"path does not exist: {rp}",
                    ))

        # containers.output_dir — created at scan time, missing is warn
        c_out = containers.get("output_dir")
        if isinstance(c_out, str) and c_out:
            rp = _resolve(c_out)
            if rp.exists():
                results.append(DeepCheckResult(
                    name=f"containers.output_dir={c_out}",
                    status="ok",
                    severity="info",
                    message=f"exists at {rp}",
                ))
            else:
                results.append(DeepCheckResult(
                    name=f"containers.output_dir={c_out}",
                    status="warn",
                    severity="info",
                    message="does not exist — will be created at scan time",
                ))

    # reporting.output_dir — created at scan time, missing is warn
    reporting = config_data.get("reporting") or {}
    if isinstance(reporting, dict):
        r_out = reporting.get("output_dir")
        if isinstance(r_out, str) and r_out:
            rp = _resolve(r_out)
            if rp.exists():
                results.append(DeepCheckResult(
                    name=f"reporting.output_dir={r_out}",
                    status="ok",
                    severity="info",
                    message=f"exists at {rp}",
                ))
            else:
                results.append(DeepCheckResult(
                    name=f"reporting.output_dir={r_out}",
                    status="warn",
                    severity="info",
                    message="does not exist — will be created at scan time",
                ))

    # Per-scanner exclude — comma-separated; concrete-path entries
    # that don't exist emit info warnings (likely typos).
    scanners = config_data.get("scanners") or {}
    if isinstance(scanners, dict):
        for sname, scfg in scanners.items():
            if not isinstance(scfg, dict):
                continue
            excl_raw = scfg.get("exclude")
            if not isinstance(excl_raw, str) or not excl_raw:
                continue
            for piece in excl_raw.split(","):
                excl = piece.strip()
                if not excl:
                    continue
                # Skip glob entries — they're patterns, not paths.
                if any(ch in excl for ch in "*?["):
                    continue
                rp = _resolve(excl)
                if not rp.exists():
                    results.append(DeepCheckResult(
                        name=f"scanners.{sname}.exclude[{excl}]",
                        status="warn",
                        severity="info",
                        message="path does not exist (still valid as a defensive entry)",
                    ))

    return results
