"""Shared helpers for linter implementations.

Consolidates three concerns that were duplicated across the linter
adapters:

1. **File discovery** — walking the workspace for files matching a glob
   pattern (originally re-implemented in `HadolintLinter._find_dockerfiles`,
   `JsonlintLinter`'s inline `rglob`, etc.).
2. **Docker fallback** — building the `docker run -v ws:/workspace ...`
   command line when the local binary isn't installed (originally
   duplicated across `HadolintLinter._build_docker_command`,
   `EslintLinter._build_docker_command`, `TerraformLinter._docker_command`).
3. **UTF-8 subprocess** — `subprocess.run(text=True)` falls back to the
   platform default encoding (cp1252 on Windows), which breaks on
   non-ASCII output. The shared helper pins `encoding='utf-8'` +
   `errors='replace'` everywhere.

Two consumption shapes:

* **Helper functions** (`discover_files`, `build_docker_command`,
  `run_utf8`) — for linters that have a custom `scan()` flow but want
  to use the shared building blocks. Most existing linters use this
  pattern.

* **`FileDiscoveryScanner` base class** — for linters whose flow is
  "walk for files matching a glob, run the tool against the file list
  in one batched subprocess, parse the output." Subclasses declare
  `name`, `file_glob`, `container_image` (optional),
  `_build_local_args`, `_build_container_args`, `_parse_results`. The
  base does discovery, dispatch (local → container), error handling,
  and the engine-compatible `ScanResult` shape.

The base is intentionally distinct from `argus.core.scanner_template`'s
`run_subprocess_scan` (which targets security scanners writing to an
output file). Linters typically write findings to stdout and don't
need a tempdir.

Reference: `docs/developer/SDK-ROADMAP.md` "FileDiscoveryScanner
Template" section + ADR-020 in `.ai/decisions.yaml`.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Sequence

from argus.core.models import Finding, ScanResult


logger = logging.getLogger("argus.scanner")


# --------------------------------------------------------------------- #
# Helper functions                                                      #
# --------------------------------------------------------------------- #


def discover_files(
    target: Path,
    patterns: Sequence[str],
    *,
    exclusions: set[str] | None = None,
) -> list[Path]:
    """Walk *target* recursively for files matching any of *patterns*.

    Returns the union of matches, sorted and deduplicated. When
    *target* is itself a file, returns ``[target]`` regardless of the
    pattern (the caller asked us to lint that exact file).

    *exclusions* is a set of *path substrings* — any path containing
    one is dropped. The default ``None`` performs no filtering. The
    engine's full exclusion set lives in ``argus.core.exclusions``;
    callers can build a substring set from it when finer-grained
    filtering is needed.
    """
    if target.is_file():
        return [target]

    found: set[Path] = set()
    for pattern in patterns:
        for p in target.rglob(pattern):
            if not p.is_file():
                continue
            if exclusions and any(ex in str(p) for ex in exclusions):
                continue
            found.add(p)
    return sorted(found)


def build_docker_command(
    image: str,
    workspace: Path | str,
    container_args: Sequence[str],
    *,
    mount_rw: bool = False,
    ws_mount: str = "/workspace",
    workdir: str | None = None,
) -> list[str]:
    """Build a ``docker run --rm -v <workspace>:<ws_mount>[:ro] <image>
    <container_args>`` command line.

    Used as the container-fallback dispatch when the local linter
    binary isn't installed but a ``container_image`` is declared on
    the scanner class.

    *workspace* is bind-mounted at *ws_mount* (default
    ``/workspace``). *mount_rw* controls read-only vs read-write —
    most linters need only read access, but ``terraform init`` writes
    to ``.terraform/`` and ``tflint --init`` writes to ``.tflint.d/``,
    so those need ``mount_rw=True``.

    *workdir* sets the container's working directory via ``-w``. Most
    linters don't need it; terraform does.

    Returns the full argv list ready to pass to ``subprocess.run``.
    The caller appends to *container_args* whatever args their linter
    expects (the binary name, flags, file paths translated to
    container-side equivalents). This builder doesn't try to do path
    translation — that's caller-specific.
    """
    workspace_abs = str(Path(workspace).resolve())
    mount_spec = f"{workspace_abs}:{ws_mount}" + ("" if mount_rw else ":ro")
    cmd = ["docker", "run", "--rm", "-v", mount_spec]
    if workdir:
        cmd.extend(["-w", workdir])
    cmd.append(image)
    cmd.extend(container_args)
    return cmd


def run_utf8(
    cmd: Sequence[str],
    *,
    cwd: str | Path | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess:
    """``subprocess.run`` with explicit UTF-8 + ``errors='replace'``.

    The platform default encoding (cp1252 on Windows) raises
    ``UnicodeDecodeError`` on non-ASCII output (CVE descriptions, file
    paths with unicode segments, scanner banners with arrows). This
    helper pins UTF-8 so every linter handles non-ASCII identically.

    ``errors='replace'`` is intentional: a security/lint tool showing
    ``\\ufffd`` is better than crashing on otherwise-usable output.
    """
    return subprocess.run(
        list(cmd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=cwd,
        timeout=timeout,
    )


# --------------------------------------------------------------------- #
# FileDiscoveryScanner base class                                       #
# --------------------------------------------------------------------- #


class FileDiscoveryScanner:
    """Base for linters that walk the workspace then batch-invoke a tool.

    Two shapes a subclass declares:

    * Class attributes: ``name``, ``file_glob`` (str or list[str]),
      and optionally ``container_image``.
    * Methods: ``_build_local_args(files, config)``,
      ``_build_container_args(container_files, config)`` (only when a
      container fallback is wanted), and ``_parse_results(stdout,
      result)``.

    The base implements ``scan()``: it discovers files matching
    ``file_glob`` under the target path, builds the local command (or
    falls back to container if the binary is missing and
    ``container_image`` is declared), runs it via ``run_utf8``, and
    hands the output to ``_parse_results`` for finding extraction.
    Empty output with a non-zero exit code becomes
    ``execution_failed`` metadata in the same shape the engine's
    container path emits — reporters render the two paths
    identically.

    Subclasses still own ``is_available()``, ``install_command()``,
    and ``tool_version()`` — the base doesn't try to dictate those
    because the variation across linters (binary check vs. always-
    available stdlib fallbacks like jsonlint) doesn't fit one shape.
    """

    # --- class-level configuration the subclass must declare ---
    name: str = ""
    file_glob: str | Sequence[str] = ()
    container_image: str | None = None
    binary: str = ""  # the local binary name; set so the base can shutil.which it

    # --- subprocess behavior knobs ---
    accept_returncodes: tuple[int, ...] = (0, 1)
    """Exit codes treated as success. Most linters: 0 (clean) and 1
    (findings). Override per-tool when the convention differs (e.g.,
    yamllint uses ``> 1`` as the failure threshold)."""

    require_stdout_on_failure: bool = True
    """When the exit code is outside ``accept_returncodes`` AND
    stdout is empty, treat as a real failure (set
    ``execution_failed``). Override to ``False`` for tools that emit
    findings only via stderr."""

    # --- public API ---

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        config = config or {}
        target = Path(path)
        patterns = (
            [self.file_glob] if isinstance(self.file_glob, str) else list(self.file_glob)
        )

        files = discover_files(target, patterns)
        if not files:
            return ScanResult(
                scanner=self.name,
                metadata={"info": f"No files matching {patterns} found"},
            )

        cmd, mode = self._dispatch_command(target, files, config)
        if cmd is None:
            return ScanResult(
                scanner=self.name,
                metadata={
                    "execution_failed": True,
                    "execution_failure_reason": (
                        f"{self.binary or self.name} not installed and Docker "
                        f"not available. Install the binary or install Docker "
                        f"to use the container backend."
                    ),
                },
            )

        try:
            result = run_utf8(cmd)
        except FileNotFoundError as exc:
            return ScanResult(
                scanner=self.name,
                metadata={
                    "execution_failed": True,
                    "execution_failure_reason": (
                        f"{exc.filename or self.binary or self.name} not found "
                        f"(race between is_available() and exec)."
                    ),
                },
            )

        stdout = (result.stdout or "").strip()
        if (
            result.returncode not in self.accept_returncodes
            and (self.require_stdout_on_failure and not stdout)
        ):
            return ScanResult(
                scanner=self.name,
                metadata={
                    "mode": mode,
                    "execution_failed": True,
                    "execution_failure_reason": (
                        f"{self.name} exited {result.returncode}. "
                        f"stderr: {(result.stderr or '').strip()[:400]}"
                    ),
                },
            )

        try:
            findings = self._parse_results(stdout, result)
        except Exception as exc:
            return ScanResult(
                scanner=self.name,
                metadata={
                    "mode": mode,
                    "parse_failed": True,
                    "parse_failure_reason": (
                        f"{type(exc).__name__}: {exc}. "
                        f"output head: {stdout[:200]!r}"
                    ),
                },
            )

        return ScanResult(
            scanner=self.name,
            findings=list(findings),
            metadata={"mode": mode, "file_count": len(files)},
        )

    # --- subclass extension points ---

    def _build_local_args(
        self, files: Sequence[Path], config: dict
    ) -> list[str]:
        """Build the local-invocation argv (binary + flags + files).

        Subclasses MUST override.
        """
        raise NotImplementedError

    def _build_container_args(
        self,
        container_files: Sequence[str],
        config: dict,
    ) -> list[str]:
        """Build the in-container argv to pass after ``docker run ... <image>``.

        *container_files* are paths translated to their container-side
        equivalents under ``/workspace``. Subclasses override this when
        they want a container fallback. The default raises so a
        subclass without ``container_image`` doesn't accidentally hit
        the docker dispatch.
        """
        raise NotImplementedError(
            f"{type(self).__name__} did not declare a container fallback "
            f"(no ``container_image`` or no ``_build_container_args`` override)."
        )

    def _parse_results(
        self, stdout: str, completed: subprocess.CompletedProcess
    ) -> list[Finding]:
        """Convert the linter's stdout into a list of :class:`Finding`.

        Subclasses MUST override. The full ``CompletedProcess`` is
        passed for cases where stderr or returncode also informs
        parsing.
        """
        raise NotImplementedError

    # --- internals ---

    def _dispatch_command(
        self,
        target: Path,
        files: Sequence[Path],
        config: dict,
    ) -> tuple[list[str] | None, str]:
        """Pick local-binary vs docker dispatch. Returns ``(cmd, mode)``.

        ``mode`` is ``"local"`` or ``"container"`` — surfaced in the
        returned ``ScanResult.metadata`` so the user can see which
        path executed.
        """
        if self.binary and shutil.which(self.binary):
            return self._build_local_args(files, config), "local"

        if self.container_image and shutil.which("docker"):
            target_abs = target.resolve()
            container_files = [
                f"/workspace/{f.resolve().relative_to(target_abs).as_posix()}"
                for f in files
                # If a discovered file isn't under target_abs (rare —
                # symlinks pointing outside), skip it: the container
                # mount only covers the workspace.
                if _is_under(f.resolve(), target_abs)
            ]
            container_args = self._build_container_args(container_files, config)
            return (
                build_docker_command(
                    self.container_image,
                    target_abs,
                    container_args,
                ),
                "container",
            )

        return None, "unavailable"


def _is_under(path: Path, root: Path) -> bool:
    """Return True if *path* is under *root* (inclusive)."""
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
