"""Shell script linter wrapping shellcheck.

Built on :class:`argus.core.linter_template.FileDiscoveryScanner` like
:class:`argus.linters.hadolint.HadolintLinter`, but shell files can't be
found by a single filename glob the way ``Dockerfile*`` can — a shell
script may have any name and be identified only by its ``#!`` shebang.
So this linter overrides ``scan()`` to substitute richer discovery
(extension match + shebang sniff) while reusing the base's local→
container dispatch, UTF-8 subprocess, and ``execution_failed`` /
``parse_failed`` metadata shapes.

shellcheck CLI: ``shellcheck -f json <files>`` emits a JSON array of
``{file, line, endLine, column, level, code, message}`` objects where
``level`` is one of ``error`` / ``warning`` / ``info`` / ``style``.
Per the Argus linter convention all findings map to ``Severity.INFO``;
the upstream level is preserved in ``Finding.metadata['level']``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from argus.containers import get_image
from argus.core.linter_template import FileDiscoveryScanner, discover_files
from argus.core.models import Finding, ScanResult, Severity
from argus.core.version import parse_tool_version

# Extensions that identify a shell script by name alone.
SHELL_EXTENSIONS = (".sh", ".bash", ".zsh", ".ksh")

# Interpreter basenames in a ``#!`` line that mark a file as a shell
# script even when it has no shell extension (e.g. ``configure``,
# ``install``). Matched against the shebang's interpreter token and the
# ``env`` argument (``#!/usr/bin/env bash`` → ``bash``).
SHELL_INTERPRETERS = frozenset({"sh", "bash", "dash", "ksh", "zsh"})

# Cap shebang sniffing so we never read a multi-megabyte binary that
# happens to be executable and extension-less. A shebang must be the
# first line; 256 bytes is generous for the longest realistic one.
_SHEBANG_READ_LIMIT = 256


def _has_shell_shebang(file_path: Path) -> bool:
    """Return True if *file_path*'s first line is a shell shebang.

    Reads at most :data:`_SHEBANG_READ_LIMIT` bytes. Unreadable files
    (permissions, binary decode errors) return False rather than
    raising — discovery should never crash on one odd file.
    """
    try:
        with file_path.open("r", encoding="utf-8", errors="replace") as handle:
            first_line = handle.readline(_SHEBANG_READ_LIMIT)
    except OSError:
        return False

    if not first_line.startswith("#!"):
        return False

    # Tokens after stripping ``#!``: the interpreter path, then any args.
    # ``#!/bin/sh`` → ["/bin/sh"]; ``#!/usr/bin/env bash`` → ["/usr/bin/env", "bash"].
    tokens = first_line[2:].strip().split()
    if not tokens:
        return False

    interpreter = Path(tokens[0]).name
    if interpreter in SHELL_INTERPRETERS:
        return True
    # ``env`` indirection: the real interpreter is the next token.
    if interpreter == "env" and len(tokens) > 1:
        return Path(tokens[1]).name in SHELL_INTERPRETERS
    return False


def discover_shell_files(target: Path) -> list[Path]:
    """Find shell scripts under *target* by extension or shebang.

    When *target* is itself a file, returns ``[target]`` (the caller
    asked us to lint that exact file). Otherwise walks recursively,
    collecting files whose suffix is in :data:`SHELL_EXTENSIONS` plus any
    extension-less (or differently-named) file whose first line is a
    shell shebang. The result is sorted and deduplicated.
    """
    if target.is_file():
        return [target]

    # Extension matches via the shared glob walker (one rglob per ext).
    patterns = [f"*{ext}" for ext in SHELL_EXTENSIONS]
    by_extension = set(discover_files(target, patterns))

    # Shebang sniff for everything else. Skip files already matched by
    # extension to avoid re-reading them.
    by_shebang: set[Path] = set()
    for candidate in target.rglob("*"):
        if not candidate.is_file() or candidate in by_extension:
            continue
        if candidate.suffix.lower() in SHELL_EXTENSIONS:
            continue
        if _has_shell_shebang(candidate):
            by_shebang.add(candidate)

    return sorted(by_extension | by_shebang)


class ShellcheckLinter(FileDiscoveryScanner):
    """Wraps shellcheck to lint shell scripts for bugs and bad practices."""

    name = "lint-shell"
    description = "Shell script linter (shellcheck)"
    category = "linter"
    languages = ["shell"]
    container_image = get_image("shellcheck")
    binary = "shellcheck"
    # ``file_glob`` is declared for symmetry with the base class, but the
    # overridden ``scan()`` uses :func:`discover_shell_files` instead so
    # shebang-only scripts are also covered.
    file_glob = tuple(f"*{ext}" for ext in SHELL_EXTENSIONS)

    # shellcheck: 0 = clean, 1 = findings (happy path); we accept both.
    accept_returncodes = (0, 1)

    def is_available(self) -> bool:
        return shutil.which("shellcheck") is not None

    def install_command(self) -> str | None:
        return "Install from https://github.com/koalaman/shellcheck#installing"

    def tool_version(self) -> str | None:
        if not self.is_available():
            return None
        return parse_tool_version(
            ["shellcheck", "--version"], r"version:\s*(\d+\.\d+\.\d+)"
        )

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Discover shell scripts then delegate to the base dispatch.

        Mirrors :meth:`FileDiscoveryScanner.scan` but swaps the glob-only
        discovery for :func:`discover_shell_files` so files identified by
        a ``#!`` shebang (no shell extension) are linted too.
        """
        config = config or {}
        target = Path(path)

        files = discover_shell_files(target)
        if not files:
            return ScanResult(
                scanner=self.name,
                metadata={"info": "No shell scripts found"},
            )

        cmd, mode = self._dispatch_command(target, files, config)
        if cmd is None:
            return ScanResult(
                scanner=self.name,
                metadata={
                    "execution_failed": True,
                    "execution_failure_reason": (
                        f"{self.binary} not installed and Docker not "
                        f"available. Install the binary or install Docker "
                        f"to use the container backend."
                    ),
                },
            )

        try:
            result = self._run(cmd)
        except FileNotFoundError as exc:
            return ScanResult(
                scanner=self.name,
                metadata={
                    "execution_failed": True,
                    "execution_failure_reason": (
                        f"{exc.filename or self.binary} not found "
                        f"(race between is_available() and exec)."
                    ),
                },
            )

        stdout = (result.stdout or "").strip()
        if result.returncode not in self.accept_returncodes and not stdout:
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

    def _run(self, cmd: list[str]) -> subprocess.CompletedProcess:
        """Indirection point so ``scan()`` can be tested via the same
        ``argus.core.linter_template.subprocess.run`` patch the base uses."""
        from argus.core.linter_template import run_utf8

        return run_utf8(cmd)

    def _build_local_args(self, files: list[Path], config: dict) -> list[str]:
        cmd = ["shellcheck", "-f", "json"]
        shell = config.get("shell")
        if shell:
            cmd.extend(["--shell", shell])
        severity = config.get("severity")
        if severity:
            cmd.extend(["--severity", severity])
        for code in config.get("exclude_codes", []) or []:
            cmd.extend(["--exclude", str(code)])
        cmd.extend(str(p) for p in files)
        return cmd

    def _build_container_args(
        self, container_files: list[str], config: dict
    ) -> list[str]:
        # koalaman/shellcheck-alpine's ENTRYPOINT is shellcheck, so the
        # args passed after the image are shellcheck's own flags. Include
        # the binary name explicitly to match the hadolint pattern and
        # stay robust if the image's entrypoint changes.
        args = ["shellcheck", "-f", "json"]
        shell = config.get("shell")
        if shell:
            args.extend(["--shell", shell])
        severity = config.get("severity")
        if severity:
            args.extend(["--severity", severity])
        for code in config.get("exclude_codes", []) or []:
            args.extend(["--exclude", str(code)])
        args.extend(container_files)
        return args

    def _parse_results(
        self, stdout: str, completed: subprocess.CompletedProcess
    ) -> list[Finding]:
        if not stdout:
            return []
        data = json.loads(stdout)
        return [self._parse_item(item) for item in data]

    def _parse_item(self, item: dict) -> Finding:
        code = item.get("code")
        rule_id = f"SC{code}" if code is not None else "shellcheck"
        line_num = item.get("line", 0)
        shell_file = item.get("file", "")
        location = f"{shell_file}:{line_num}" if shell_file else None
        message = item.get("message", "")

        return Finding(
            id=rule_id,
            severity=Severity.INFO,
            title=message,
            description=message,
            location=location,
            scanner=self.name,
            metadata={
                "level": item.get("level", ""),
                "column": item.get("column", 0),
                "file": shell_file,
            },
        )
