"""Shared template for subprocess-based scanners.

Every scanner that wraps a CLI tool used to repeat the same shape:

    with tempfile.TemporaryDirectory() as tmp_dir:
        output_file = Path(tmp_dir) / "results.json"
        cmd = self._build_command(path, output_file, config)
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0 and ...:
            return ScanResult(error=...)
        if not output_file.exists():
            return ScanResult(error=...)
        findings = self.parse_results(output_file)
        return ScanResult(findings=findings, ...)

…and a *parallel* ``container_args(config)`` method that built the
same args but with ``/workspace`` and ``/output/results.json`` in place
of the local paths. The two methods drifted (different ``--output`` vs
``--output-file`` flag names; different exit-code handling) and the
boilerplate hid the per-scanner intent — what command to run, how to
parse — under 30+ lines of plumbing.

This module collapses that into:

* :class:`ScanPaths` — the file paths a scanner operates on, in whatever
  execution environment is current. Local execution sets absolute host
  paths; container execution sets ``/workspace`` and ``/output/...``.

* :func:`run_subprocess_scan` — runs ``scanner.build_args(paths)``,
  handles the exit code, reads back the output file, and produces a
  uniform :class:`ScanResult`. The scanner only declares *what command
  to run* (``build_args``) and *how to parse output* (``parse_results``).

Scanners with structurally-different flows (Grype JSON-stdout, ClamAV
text-output, ZAP Docker-only, the container orchestrator) keep custom
``scan()`` implementations — the template is a tool for the common
case, not a forced abstraction.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from argus.core.models import Finding, ScanResult


logger = logging.getLogger("argus.scanner")


@dataclass(frozen=True)
class ScanPaths:
    """File-system paths the scanner operates on, in the *current* execution environment.

    Local execution: absolute host paths.
    Container execution: paths inside the container (``/workspace``,
    ``/output/<filename>``).

    Deliberately narrow — only what the scanner needs to wire up
    ``input → tool → output`` plumbing. Tool-specific knobs (lockfile
    selection, recursive flag, exclusions, config-file paths) live in
    the ``config`` dict that ``build_args`` also receives, so each
    scanner declares its own config schema instead of pushing every
    option through this dataclass.
    """

    workspace: str
    output: str


class _SubprocessScanner(Protocol):
    """Structural protocol the template expects of the scanner argument."""

    name: str

    def build_args(self, paths: ScanPaths, config: dict) -> list[str]:
        ...  # pragma: no cover

    def parse_results(self, output_path: Path) -> list[Finding] | tuple:
        ...  # pragma: no cover


def run_subprocess_scan(
    scanner: _SubprocessScanner,
    path: str,
    config: dict | None = None,
    *,
    output_filename: str = "results.json",
    timeout: float | None = None,
) -> ScanResult:
    """Run *scanner*'s CLI in a tempdir and return a :class:`ScanResult`.

    The scanner declares the command via ``build_args(paths)`` and the
    parser via ``parse_results(output_path)``. Most security tools
    intentionally exit non-zero when findings exist — that's the *happy
    path*, not an error — so the template only treats a missing/empty
    output file as a failure. ``parse_results`` may also legitimately
    fall back to stdout for tools that don't write to disk; the
    template captures stdout when no output file is produced.

    Args:
        scanner: Scanner instance with ``name``, ``build_args``,
            ``parse_results``.
        path: Workspace path passed through to ``build_args`` as
            ``ScanPaths.workspace``.
        config: Per-scanner config dict (e.g. SBOM path, custom
            config-file path). Forwarded as ``ScanPaths.config_file`` /
            ``ScanPaths.sbom`` when present.
        output_filename: Name of the output file inside the tempdir.
            Most scanners emit ``results.json``; SARIF emitters override
            (e.g. ``"results.sarif"``).
        timeout: Optional subprocess timeout in seconds. Default: no
            timeout (most scanners self-cap).

    Returns:
        A :class:`ScanResult` with ``findings`` populated on success or
        ``metadata["execution_failed"] = True`` when the underlying
        tool failed to run. The terminal reporter, viewers, and
        ``--fail-on-scanner-error`` all key off ``execution_failed``;
        using the same metadata shape that the engine's container path
        emits (see ``argus/core/engine.py::_run_in_container``) keeps
        local-execution and container-execution failures uniformly
        visible without per-path special-casing.
    """
    config = config or {}

    with tempfile.TemporaryDirectory() as tmp_dir:
        output_file = Path(tmp_dir) / output_filename
        paths = ScanPaths(workspace=path, output=str(output_file))

        cmd = scanner.build_args(paths, config)
        logger.debug("[%s] running: %s", scanner.name, " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError as exc:
            return ScanResult(
                scanner=scanner.name,
                metadata={
                    "execution_failed": True,
                    "execution_failure_reason": (
                        f"Tool not found: {exc.filename or cmd[0]}"
                    ),
                },
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                scanner=scanner.name,
                metadata={
                    "execution_failed": True,
                    "execution_failure_reason": (
                        f"Scanner timed out after {timeout}s"
                    ),
                },
            )

        if not output_file.exists():
            # Some scanners emit findings to stdout (no -o flag). When
            # the planned output file isn't there but stdout has content,
            # fall back to stdout — parse_results decides what to do.
            stdout = (result.stdout or "").strip()
            if stdout:
                output_file.write_text(stdout)
            else:
                return ScanResult(
                    scanner=scanner.name,
                    metadata={
                        "execution_failed": True,
                        "execution_failure_reason": (
                            f"No output produced (exit={result.returncode}). "
                            f"stderr: {(result.stderr or '').strip()[:400]}"
                        ),
                    },
                )

        parsed = scanner.parse_results(output_file)
        # ``parse_results`` may return ``list[Finding]`` (most scanners),
        # a ``(list, int)`` tuple (linter passed-count channel — used by
        # checkov), or a ``(list, dict)`` tuple (extra metadata). Engine
        # also unpacks all three; we mirror that here so callers see the
        # same shape regardless of which path produced it.
        metadata: dict = {}
        if isinstance(parsed, tuple):
            findings = parsed[0]
            extra = parsed[1] if len(parsed) > 1 else {}
            if isinstance(extra, int):
                metadata["passed_count"] = extra
            elif isinstance(extra, dict):
                metadata.update(extra)
        else:
            findings = parsed

        return ScanResult(
            scanner=scanner.name,
            findings=list(findings),
            raw_report=output_file,
            metadata=metadata,
        )
