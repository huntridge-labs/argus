"""Argus CLI — command-line interface for security scanning."""

import argparse
import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import TextIO

# Exit codes
EXIT_SUCCESS = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

SEVERITY_CHOICES = ["critical", "high", "medium", "low", "none"]


# Curated display order for the seven user-facing built-ins. ``terminal``
# leads because it's the default and most users only ever pass that one;
# the rest follow in roughly the order users encounter them in CI configs
# (file artifacts → SARIF → JSON → CI integrations). Third-party plugins
# discovered via the entry-point group are appended after the built-ins.
_BUILTIN_FORMAT_ORDER = (
    "terminal",
    "markdown",
    "sarif",
    "json",
    "github",
    "gitlab",
    "junit",
)


def _build_format_choices() -> list[str]:
    """Build the ``--format`` choice list from the live reporter registry.

    Recomputed at parser-construction time so any third-party reporter
    plugin installed alongside Argus shows up in
    ``argus scan --format <name>`` and ``argus scan --help`` without a
    code change here. ``container_markdown`` is registered for internal
    use (the container-scan flow constructs it directly) so it's
    filtered out of the user-facing list. Failure to import the
    registry falls back to the historical built-ins so a misconfigured
    environment doesn't kill the CLI.
    """
    try:
        from argus.reporters import available_reporters

        registered = [
            name for name in available_reporters() if name != "container_markdown"
        ]
    except Exception:  # noqa: BLE001 — fall back, never crash the CLI
        return list(_BUILTIN_FORMAT_ORDER)

    # Built-ins keep their curated order; plugins follow in
    # ``available_reporters`` order (already sorted, so deterministic).
    builtin_set = set(_BUILTIN_FORMAT_ORDER)
    head = [name for name in _BUILTIN_FORMAT_ORDER if name in registered]
    tail = [name for name in registered if name not in builtin_set]
    return head + tail


FORMAT_CHOICES = _build_format_choices()
_SPINNER_STYLES = [
    ["⠁", "⠂", "⠄", "⡀", "⢀", "⠠", "⠐", "⠈"],
    ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
    ["⠿", "⣟", "⣯", "⣷", "⣾", "⣽", "⣻", "⢿"],
]


class _TerminalSpinner:
    """Minimal terminal spinner for long-running CLI operations."""

    def __init__(
        self,
        message: str,
        enabled: bool,
        stream: TextIO | None = None,
        interval: float = 0.08,
    ):
        self._message = message
        self._enabled = enabled
        self._stream = stream or sys.stderr
        self._interval = interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._start_ts = 0.0

    def __enter__(self):
        self._start_ts = time.monotonic()
        if self._enabled:
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, exc_type, _exc, _tb):
        elapsed = time.monotonic() - self._start_ts
        if self._enabled:
            self._stop_event.set()
            if self._thread:
                self._thread.join(timeout=0.2)
            self._clear_line()

        status = "done" if exc_type is None else "failed"
        print(f"{self._message} [{status} in {elapsed:.1f}s]", file=self._stream)
        return False

    def _spin(self) -> None:
        style_index = 0
        frame_index = 0

        while not self._stop_event.is_set():
            frames = _SPINNER_STYLES[style_index]
            frame = frames[frame_index]
            self._stream.write(f"\r{self._message} {frame}")
            self._stream.flush()

            frame_index += 1
            if frame_index >= len(frames):
                frame_index = 0
                style_index = (style_index + 1) % len(_SPINNER_STYLES)

            self._stop_event.wait(self._interval)

    def _clear_line(self) -> None:
        self._stream.write("\r" + (" " * 80) + "\r")
        self._stream.flush()

    @property
    def enabled(self) -> bool:
        """True when the spinner thread is actively drawing."""
        return self._enabled

    def update_message(self, message: str) -> None:
        """Replace the spinner's status text in place.

        Called from progress callbacks at phase transitions so the
        user sees ``[2/4] scanner-opengrep — trivy (12s)`` updating
        instead of a static "Running container scan". No-op when the
        spinner isn't drawing — callers can pass through unconditionally.
        """
        # Pad with trailing spaces to overwrite any longer previous
        # message without leaving stale characters on the line.
        prev = self._message
        self._message = message
        if self._enabled and len(prev) > len(message):
            self._stream.write("\r" + (" " * len(prev)) + "\r")
            self._stream.flush()


def _canonical_container_metadata(result) -> dict:
    """Build the metadata dict for a container ScanResult row.

    Surfaces the originating Dockerfile + context for build-mode
    targets so security reviewers and audit archives can trace any
    finding back to its source. Empty dockerfile/context fields
    (remote-pull entries) are *omitted* rather than written as empty
    strings so downstream readers don't have to special-case them.

    Extracted from the inline list comprehension that builds
    ``canonical_results`` in ``_cmd_container_scan`` so the dict
    shape is unit-testable without spinning up the full container
    engine.
    """
    metadata: dict = {
        "image_ref": result.image_ref,
        "build_success": result.build_success,
    }
    if getattr(result, "dockerfile", ""):
        metadata["dockerfile_path"] = result.dockerfile
    if getattr(result, "context", ""):
        metadata["context_path"] = result.context
    if getattr(result, "scanner_errors", None):
        metadata["scanner_errors"] = dict(result.scanner_errors)
    if getattr(result, "scan_error", None):
        metadata["scan_error"] = result.scan_error
    return metadata


def _configure_logger(args: argparse.Namespace, output_dir: str | None = None):
    """Set up the ``argus`` logger at the level the user's flags imply.

    Mapping:
      * ``--verbose`` / ``--debug``: DEBUG (full firehose)
      * ``--quiet``: WARNING (suppress INFO lines from the engine)
      * default:    INFO (per-phase status, no DEBUG noise)

    Returns the configured logger so callers can also use it directly.
    """
    import logging
    from argus.audit import get_logger

    log = get_logger(
        "argus",
        output_dir=output_dir,
        verbose=_verbose_enabled(args),
    )
    if _quiet_enabled(args):
        for handler in log.handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(
                handler, logging.FileHandler,
            ):
                handler.setLevel(logging.WARNING)
    return log


def _verbose_enabled(args: argparse.Namespace) -> bool:
    """``--verbose`` / ``--debug`` — full firehose mode.

    The two are aliases: ``--verbose`` is preserved for backward
    compatibility, ``--debug`` is the clearer name new users learn.
    """
    return getattr(args, "verbose", False) or getattr(args, "debug", False)


def _quiet_enabled(args: argparse.Namespace) -> bool:
    """``--quiet`` / ``-q`` — suppress per-phase INFO lines.

    Spinner stays drawing (just doesn't update its message) unless
    ``--no-spinner`` is also passed. Composes with ``--no-spinner``:
    ``--quiet --no-spinner`` means fully silent (CI exit-code-only).
    """
    return getattr(args, "quiet", False)


def _spinner_enabled(args: argparse.Namespace) -> bool:
    """Enable spinner for interactive terminals unless explicitly disabled."""
    if getattr(args, "no_spinner", False):
        return False
    if _verbose_enabled(args):
        return False
    return sys.stderr.isatty()


def _make_progress_emitter(
    args: argparse.Namespace,
    spinner: "_TerminalSpinner | None",
):
    """Return a progress callback that routes phase events to the right surface.

    Output target depends on the flag combination:
      * ``--quiet`` or ``--verbose``: no-op (logger handles verbose; quiet
        suppresses progress on purpose).
      * Spinner is drawing: update its message in place.
      * No spinner (``--no-spinner`` or non-TTY): print a persistent
        INFO line to stderr per phase event so CI logs and step-away
        terminals get scrollback.
    """
    if _quiet_enabled(args) or _verbose_enabled(args):
        return lambda *a, **kw: None

    if spinner is not None and spinner.enabled:
        def update_spinner(idx: int, total: int, name: str, phase: str, elapsed_ms: int):
            elapsed_s = elapsed_ms // 1000
            spinner.update_message(
                f"[{idx}/{total}] {name} — {phase} ({elapsed_s}s)"
            )
        return update_spinner

    def print_line(idx: int, total: int, name: str, phase: str, elapsed_ms: int):
        elapsed_s = elapsed_ms // 1000
        print(
            f"[{idx}/{total}] {name} — {phase} ({elapsed_s}s)",
            file=sys.stderr,
            flush=True,
        )
    return print_line


def _make_run_dir(base_dir: str) -> str:
    """Create a timestamped subdirectory for this scan run.

    Each run gets its own directory so previous results are never
    overwritten. A 'latest' symlink points to the newest run.

    Structure:
        argus-results/
        ├── 2026-04-12T07-24-50Z/
        │   ├── argus.log
        │   ├── argus-audit.json
        │   └── ...
        └── latest -> 2026-04-12T07-24-50Z/
    """
    from datetime import datetime, timezone

    base = Path(base_dir)
    base.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    run_dir = base / ts
    run_dir.mkdir(parents=True, exist_ok=True)

    # Update 'latest' symlink
    latest = base / "latest"
    try:
        if latest.is_symlink() or latest.exists():
            latest.unlink()
        latest.symlink_to(ts)
    except OSError:
        pass  # Symlinks may not work on all platforms

    return str(run_dir)


def _build_common_parent() -> argparse.ArgumentParser:
    """Flags shared across every subcommand.

    Currently just ``--no-update-check``. Per issue #174, users
    invoked ``argus report --no-update-check`` and hit
    ``unrecognized arguments: --no-update-check`` because the flag
    was previously only on ``scan``. The update-check itself only
    fires from scan paths today, but the flag should be accepted
    everywhere so the suppression contract isn't subcommand-specific
    (and so future subcommands that opt into the check don't need a
    second round of UX cleanup).
    """
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "--no-update-check",
        action="store_true",
        help="Skip the once-per-day check for a newer argus release. The "
             "check runs in the background (zero latency cost) and prints "
             "a soft notice at the end of the command when an upgrade is "
             "available. Also disabled by setting the "
             "ARGUS_NO_UPDATE_CHECK environment variable, which is the "
             "right move for CI / air-gapped environments. Override the "
             "PyPI URL via ARGUS_UPDATE_CHECK_URL for TestPyPI or "
             "private mirrors.",
    )
    return parent


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser with scan and report subcommands."""
    parser = argparse.ArgumentParser(
        prog="argus",
        description="Argus Security Scanner — comprehensive security scanning for your codebase",
        epilog="Run 'argus <command> --help' for subcommand-specific options.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=_get_version(),
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    common = _build_common_parent()
    _build_init_parser(subparsers, common)
    _build_scan_parser(subparsers, common)
    _build_classify_parser(subparsers, common)
    _build_collect_parser(subparsers, common)
    _build_report_parser(subparsers, common)
    _build_validate_parser(subparsers, common)
    _build_mcp_parser(subparsers, common)
    _build_completion_parser(subparsers, common)
    _build_cache_parser(subparsers, common)
    _build_view_parser(subparsers, common)

    return parser


VIEW_INTERFACES = ("terminal", "browser")


def _build_view_parser(subparsers: argparse._SubParsersAction, parent: argparse.ArgumentParser) -> None:
    """Add the 'view' subcommand — open a viewer on existing scan results.

    Replaces the old ``browse`` and ``serve`` commands with a single entry
    point. The interface is selected positionally (``argus view terminal``)
    or via ``--interface=`` (``argus view --interface=browser``); both
    forms are accepted for ergonomics.
    """
    view_parser = subparsers.add_parser(
        "view",
        parents=[parent],
        help="Open a viewer (terminal UI or browser) on existing scan results",
        description=(
            "Open a human-readable view of argus-results.json:\n"
            "  argus view                                  # terminal interface, ./argus-results/\n"
            "  argus view terminal                         # explicit terminal\n"
            "  argus view browser                          # local web UI (127.0.0.1)\n"
            "  argus view --interface=terminal             # flag form\n"
            "  argus view browser ./run-2026-04-24/        # interface + path\n"
            "  argus view --interface=browser --port 9090\n"
            "  argus view browser --no-open      # don't auto-open the browser\n\n"
            "Terminal interface keyboard shortcuts:\n"
            "  / search · 1/2/3/4 filter by severity · s sort · e export CSV · q quit\n\n"
            "Browser interface is bound to 127.0.0.1 only — no auth, no mutations.\n\n"
            "Install:\n"
            "  pip install 'argus-security[terminal]'      # terminal interface\n"
            "  pip install 'argus-security[browser]'       # browser interface"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Two positionals where the first is *either* an interface keyword
    # (terminal|browser) *or* a results path. We can't put choices=
    # on the first positional because it would reject path-shaped
    # values when the user passes --interface separately. Instead we
    # accept any string and sort it out in _resolve_view_args.
    #
    # Argparse can't bind the second positional when a flag-with-value
    # sits between the two positionals on some Python versions (issue
    # #168-D5 reproduced ``argus view browser --port 18081 ./results/``
    # → "unrecognized arguments: ./results/"). When that happens, the
    # ``--path / -p`` flag below is the explicit workaround. Two
    # workable shapes:
    #
    #     argus view browser ./results/ --port 18081     # path before flags
    #     argus view browser --port 18081 --path ./results/  # explicit --path
    view_parser.add_argument(
        "interface_or_path",
        nargs="?",
        default=None,
        metavar="INTERFACE|PATH",
        help="Either an interface keyword (terminal | browser) or a "
             "results path. If a path is given here without an interface "
             "keyword, the interface defaults to terminal.",
    )
    view_parser.add_argument(
        "path_arg",
        nargs="?",
        default=None,
        metavar="PATH",
        help="Results directory or argus-results.json path when the first "
             "positional is an interface keyword (default: ./argus-results/)",
    )
    view_parser.add_argument(
        "--path", "-p",
        dest="path_flag",
        default=None,
        metavar="PATH",
        help="Results directory or argus-results.json path. Equivalent "
             "to the positional form ``argus view <iface> <path>`` but "
             "robust to argparse's ordering quirks — use this when a "
             "flag-with-value (e.g. ``--port``) sits between the "
             "interface keyword and the path (issue #168-D5).",
    )
    view_parser.add_argument(
        "--interface", "-i",
        dest="interface_flag",
        choices=VIEW_INTERFACES,
        default=None,
        help="Interface to open: terminal | browser (alternative to positional)",
    )
    view_parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="TCP port for the browser interface (default: 8080)",
    )
    view_parser.add_argument(
        "--no-open",
        dest="no_open",
        action="store_true",
        help="Don't auto-open the default web browser after startup "
             "(browser interface only). By default, the browser opens when "
             "stdout is a TTY; CI and other non-interactive contexts already "
             "skip auto-open without this flag.",
    )
    view_parser.add_argument(
        "--check",
        action="store_true",
        help="Validate that the resolved scan directory contains "
             "argus-results.json and print actionable remediation if not. "
             "Doesn't launch the viewer — useful in CI and pre-flight checks.",
    )


def _resolve_view_args(args: argparse.Namespace) -> tuple[str, str | None] | None:
    """Sort positionals + flags into (interface, path).

    The first positional can be either an interface keyword
    (``terminal``/``browser``) or a path. We only know which by looking
    at its value, so the disambiguation lives here rather than in the
    parser.

    ``--path / -p`` provides an explicit-flag escape hatch when
    argparse refuses to bind the second positional (issue #168-D5).

    Returns ``(interface, path)`` on success, or ``None`` if the
    arguments are inconsistent (the caller has already printed an
    error to stderr).
    """
    pos1 = getattr(args, "interface_or_path", None)
    pos2 = getattr(args, "path_arg", None)
    flag = getattr(args, "interface_flag", None)
    path_flag = getattr(args, "path_flag", None)

    pos_interface: str | None = None
    pos_path: str | None = None

    if pos1 in VIEW_INTERFACES:
        pos_interface = pos1
        if pos2 in VIEW_INTERFACES:
            print(
                f"Error: got two interface keywords ('{pos1}', '{pos2}'). "
                "Pass at most one interface (positional or --interface).",
                file=sys.stderr,
            )
            return None
        pos_path = pos2
    elif pos1 is not None:
        # First positional is path-shaped — there shouldn't be a second.
        if pos2 is not None:
            print(
                f"Error: got two paths ('{pos1}', '{pos2}') but no interface "
                "keyword. Pass at most one path.",
                file=sys.stderr,
            )
            return None
        pos_path = pos1

    if pos_interface and flag and pos_interface != flag:
        print(
            f"Error: conflicting interfaces — positional '{pos_interface}' vs "
            f"--interface '{flag}'. Pass only one.",
            file=sys.stderr,
        )
        return None

    # ``--path`` overrides the positional path. Conflict between the
    # two surfaces is an error — the user passed both forms and we
    # can't know which they meant.
    if path_flag is not None and pos_path is not None and path_flag != pos_path:
        print(
            f"Error: conflicting paths — positional '{pos_path}' vs "
            f"--path '{path_flag}'. Pass only one.",
            file=sys.stderr,
        )
        return None
    resolved_path = path_flag if path_flag is not None else pos_path

    interface = flag or pos_interface or "terminal"
    return interface, resolved_path


def cmd_view(args: argparse.Namespace) -> int:
    """Execute the view subcommand — dispatch to terminal or browser viewer."""
    resolved = _resolve_view_args(args)
    if resolved is None:
        return EXIT_ERROR
    interface, path = resolved

    # --check short-circuits before launching the viewer: validate that
    # argus-results.json is reachable from the supplied path and print
    # remediation guidance if not. Useful in CI and as a pre-flight
    # check before a maintainer hands off "open this scan in argus
    # view" to a less-technical stakeholder.
    if getattr(args, "check", False):
        return _check_view_artifact(path)

    return _launch_view(
        interface,
        path=path,
        port=args.port,
        open_browser=_should_open_browser(args),
    )


def _check_view_artifact(path: str | None) -> int:
    """Resolve ``path`` to an argus-results.json without launching the viewer.

    Reuses the terminal loader's resolver so the success / failure
    message matches what a real ``argus view`` would surface. On
    success, prints the resolved path; on failure, prints the
    diagnoser's remediation output (config-aware hint identifying the
    likely root cause) to stderr.
    """
    from argus.viewers.terminal.loader import locate_results
    try:
        resolved = locate_results(path)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR
    print(f"OK: {resolved} is readable.")
    return EXIT_SUCCESS


def _should_open_browser(args: argparse.Namespace) -> bool:
    """Default to auto-opening the browser when stdout is a TTY.

    Headless / CI / piped-output contexts already shouldn't trigger
    ``webbrowser.open`` (it would either fail noisily or block), so the
    TTY check gives us a sensible default without needing the user to
    flag every interactive run. ``--no-open`` overrides regardless.
    """
    if getattr(args, "no_open", False):
        return False
    return sys.stdout.isatty()


def _launch_view(
    interface: str,
    *,
    path: str | None,
    port: int = 8080,
    open_browser: bool = False,
) -> int:
    """Dispatch to the chosen viewer, surfacing missing-extra hints cleanly."""
    if interface == "terminal":
        try:
            from argus.viewers.terminal import launch, ViewerUnavailable
        except ImportError as exc:  # pragma: no cover — defensive
            print(f"Error: could not import argus.viewers.terminal: {exc}", file=sys.stderr)
            return EXIT_ERROR
        try:
            return launch(path)
        except ViewerUnavailable as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return EXIT_ERROR

    if interface == "browser":
        try:
            from argus.viewers.browser import launch, ViewerUnavailable
        except ImportError as exc:  # pragma: no cover — defensive
            print(f"Error: could not import argus.viewers.browser: {exc}", file=sys.stderr)
            return EXIT_ERROR
        try:
            return launch(root=path, port=port, open_browser=open_browser)
        except ViewerUnavailable as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return EXIT_ERROR

    print(f"Error: unknown interface '{interface}'", file=sys.stderr)
    return EXIT_ERROR


def _build_init_parser(subparsers: argparse._SubParsersAction, parent: argparse.ArgumentParser) -> None:
    """Add the 'init' subcommand for project initialization."""
    init_parser = subparsers.add_parser(
        "init",
        parents=[parent],
        help="Initialize argus.yml for the current project",
        description=(
            "Detect your project's languages, frameworks, and infrastructure,\n"
            "then generate a tailored argus.yml with the right scanners enabled.\n\n"
            "Examples:\n"
            "  argus init                # auto-detect and generate argus.yml\n"
            "  argus init --force        # overwrite existing argus.yml\n"
            "  argus init --no-detect    # generate with defaults only\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing argus.yml file",
    )
    init_parser.add_argument(
        "--no-detect",
        action="store_true",
        help="Skip auto-detection and generate a config with defaults only",
    )


def cmd_init(args: argparse.Namespace) -> int:
    """Execute the init subcommand — generate argus.yml for a project."""
    from argus.init import run_init
    return run_init(
        force=args.force,
        detect=not args.no_detect,
    )


def _build_scan_parser(subparsers: argparse._SubParsersAction, parent: argparse.ArgumentParser) -> None:
    """Add the 'scan' subcommand."""
    scan_parser = subparsers.add_parser(
        "scan",
        parents=[parent],
        help="Run security scanners against a target path or container images",
        description=(
            "Run one or more security scanners and generate results.\n\n"
            "For source code scanning:\n"
            "  argus scan                    # all enabled scanners\n"
            "  argus scan bandit             # specific scanner\n\n"
            "For container image scanning:\n"
            "  argus scan container --image nginx:latest\n"
            "  argus scan container --discover ./\n"
            "  argus scan container --discover docker/\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scanner_arg = scan_parser.add_argument(
        "scanner",
        nargs="?",
        default=None,
        help="Specific scanner to run (omit to run all enabled scanners). "
             "Use 'container' with --discover or --image for container scanning.",
    )
    # Tab completion for scanner names (requires argcomplete)
    try:
        import argcomplete
        from argus.scanners import SCANNER_REGISTRY
        scanner_arg.completer = argcomplete.completers.ChoicesCompleter(
            sorted(SCANNER_REGISTRY.keys()),
        )
    except ImportError:
        pass
    scan_parser.add_argument(
        "--path", "-p",
        default=".",
        help="Path to scan (default: current directory)",
    )
    scan_parser.add_argument(
        "--config", "-c",
        default=None,
        help="Path to argus.yml config file",
    )
    scan_parser.add_argument(
        "--output-dir", "-o",
        default=None,
        help="Output directory for results (default: ./argus-results)",
    )
    scan_parser.add_argument(
        "--severity-threshold", "-s",
        choices=SEVERITY_CHOICES,
        default=None,
        help="Fail threshold severity level (default: from config)",
    )
    scan_parser.add_argument(
        "--format", "-f",
        action="append",
        choices=FORMAT_CHOICES,
        dest="formats",
        help="Output format (can be repeated; default: terminal)",
    )
    scan_parser.add_argument(
        "--list",
        action="store_true",
        help="List available scanners and exit",
    )
    scan_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Alias for --debug. Full firehose: subprocess output, "
             "vulnerability-DB updates, every engine log line.",
    )
    scan_parser.add_argument(
        "--debug",
        action="store_true",
        help="Full firehose: subprocess output, vulnerability-DB updates, "
             "every engine log line. Use when troubleshooting; the default "
             "phase-aware progress is enough for normal scans.",
    )
    scan_parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress per-phase progress lines. The spinner still draws "
             "(use --no-spinner to suppress that too). Final summary "
             "still prints. Compose with --no-spinner for fully silent "
             "CI exit-code-only mode.",
    )
    scan_parser.add_argument(
        "--no-spinner",
        action="store_true",
        help="Disable animated spinner output",
    )
    scan_parser.add_argument(
        "--no-timestamp",
        action="store_true",
        help="Write output directly to --output-dir without a timestamped subdirectory. "
             "Useful in CI where a predictable output path is needed.",
    )
    scan_parser.add_argument(
        "--output-vars",
        default=None,
        metavar="FILE",
        help="Write scan result counts as key=value pairs to FILE. "
             "Useful in CI: cat FILE >> $GITHUB_OUTPUT. "
             "Keys: critical_count, high_count, medium_count, low_count, info_count, total_count, passed.",
    )
    scan_parser.add_argument(
        "--exclude", "-e",
        default="",
        metavar="PATTERNS",
        help="Comma-separated paths or patterns to exclude from scanning. "
             "Added on top of .gitignore, .dockerignore, and built-in defaults.",
    )
    scan_parser.add_argument(
        "--no-default-excludes",
        action="store_true",
        help="Drop built-in exclusions (node_modules, .git, ...) and "
             ".gitignore / .dockerignore patterns. Only --exclude and "
             "argus.yml exclude: take effect. Use when you explicitly want "
             "to scan what the defaults would normally skip.",
    )
    scan_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Resolve config and print the planned scanner invocations "
             "without executing them. Useful for verifying which per-scanner "
             "config files, paths, and excludes Argus will use.",
    )
    scan_parser.add_argument(
        "--sbom",
        default=None,
        metavar="PATH",
        help="Scan a pre-built SBOM or directory of SBOMs (CycloneDX "
             "JSON/XML, SPDX JSON/tag-value, or Syft JSON). When PATH is "
             "a directory, argus walks it recursively, sniffs each file, "
             "and scans every SBOM it finds. Auto-enables all SBOM-capable "
             "scanners (osv, grype, trivy) regardless of argus.yml. "
             "Filesystem scanners (bandit, gitleaks, ...) are skipped "
             "since they have nothing to scan.",
    )
    scan_parser.add_argument(
        "--interface", "-i",
        dest="view_interface",
        choices=VIEW_INTERFACES,
        default=None,
        help="After the scan completes, open a viewer on the just-written "
             "results. 'terminal' launches the TUI (requires "
             "'argus-security[terminal]'); 'browser' launches the local web "
             "UI (requires 'argus-security[browser]').",
    )
    scan_parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Abort immediately if any scanner fails instead of continuing.",
    )
    scan_parser.add_argument(
        "--fail-on-scanner-error",
        action="store_true",
        help="Exit non-zero when any scanner produced no output (typically "
             "a uid-mismatch on /output, container crash, or wrong "
             "entrypoint). Default behavior treats these as warnings so "
             "partial scans still surface findings; opt in for hard CI "
             "gates that require every configured scanner to actually run.",
    )
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        metavar="SECONDS",
        help="Per-scanner timeout in seconds. Scanners exceeding this limit are killed.",
    )
    scan_parser.add_argument(
        "--no-parallel",
        action="store_true",
        help="Run scanners sequentially instead of concurrently.",
    )
    scan_parser.add_argument(
        "--allow-local-versions",
        action="store_true",
        help="Allow local tool versions that differ from argus-pinned versions. "
             "Use in airgapped environments where tool updates are constrained.",
    )
    scan_parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable DB cache volume mounts. Forces scanners to re-download "
             "vulnerability databases on every container run.",
    )
    scan_parser.add_argument(
        "--keep-raw",
        action=argparse.BooleanOptionalAction,
        default=None,
        dest="keep_raw",
        help="Persist each scanner's raw output files (results.json / "
             "*.sarif / stdout.txt) under <output_dir>/raw/<scanner>/ "
             "alongside the canonical argus-results.json. Container "
             "scans drop trivy-results.json / grype-results.json / "
             "syft-sbom.json under <output_dir>/raw/<image>/. Default "
             "OFF — scanners like gitleaks write the literal matched "
             "secret bytes into raw output, so persisting raw by "
             "default turned argus-results into a secret-leak vector. "
             "The canonical argus-results.json is always written and "
             "is pattern-redacted. Pass --keep-raw for forensic / "
             "triage workflows that need the unredacted per-scanner "
             "artifacts. The same effect is available via "
             "'reporting.keep_raw: true' in argus.yml. Use "
             "--no-keep-raw to explicitly override a config-file "
             "opt-in.",
    )

    # Credential stdin flags — read a password from stdin and use it
    # as the highest-precedence credential for the named slot. Mirrors
    # ``docker login --password-stdin``: keeps the value off the
    # process argv (no ``ps``/``docker inspect`` exposure), off the
    # shell history, and out of the config file. At most one stdin
    # flag may be used per invocation (stdin is a single stream).
    scan_parser.add_argument(
        "--registry-password-stdin",
        action="store_true",
        dest="registry_password_stdin",
        help="Read the private-registry password from stdin and use it "
             "for any scanner that needs registry auth (container, zap "
             "with app_image_ref). Overrides registry_password / "
             "registry_password_env in argus.yml.",
    )
    scan_parser.add_argument(
        "--zap-auth-password-stdin",
        action="store_true",
        dest="zap_auth_password_stdin",
        help="Read the ZAP web-app authentication password from stdin. "
             "Overrides scanners.zap.auth.password / password_env in "
             "argus.yml.",
    )

    # Container-specific flags (used with: argus scan container)
    container_group = scan_parser.add_argument_group(
        "container scanning",
        "Flags for container image scanning (use with: argus scan container)",
    )
    container_group.add_argument(
        "--discover",
        nargs="?",
        const=".",
        default=None,
        metavar="PATH",
        help="Discover Dockerfiles in PATH (default: current directory)",
    )
    container_group.add_argument(
        "--image",
        action="append",
        dest="images",
        metavar="REF",
        help="Container image to scan (can be repeated)",
    )
    container_group.add_argument(
        "--scanners",
        default=None,
        help="Sub-scanners for container scanning: trivy,grype,syft (default: trivy,grype)",
    )

    # ZAP DAST flags (used with: argus scan zap)
    dast_group = scan_parser.add_argument_group(
        "DAST scanning",
        "Flags for dynamic application security testing (use with: argus scan zap)",
    )
    dast_group.add_argument(
        "--target",
        default=None,
        metavar="URL",
        help="URL of a running target to scan (e.g., http://localhost:3000)",
    )
    dast_group.add_argument(
        "--port",
        type=int,
        default=None,
        help="Override the exposed port when using --image with zap",
    )
    dast_group.add_argument(
        "--env",
        action="append",
        dest="env_vars",
        metavar="KEY=VALUE",
        help="Environment variable for the target container (can be repeated)",
    )
    dast_group.add_argument(
        "--scan-type",
        choices=["baseline", "full"],
        default="baseline",
        help="ZAP scan type (default: baseline)",
    )
    dast_group.add_argument(
        "--startup-timeout",
        type=int,
        default=60,
        help="Seconds to wait for target container to become healthy (default: 60)",
    )


def _build_classify_parser(subparsers: argparse._SubParsersAction, parent: argparse.ArgumentParser) -> None:
    """Add the 'classify' subcommand for SCN change classification."""
    classify_parser = subparsers.add_parser(
        "classify",
        parents=[parent],
        help="Classify IaC changes for compliance reporting (FedRAMP SCN)",
        description=(
            "Analyze infrastructure-as-code changes between two git refs\n"
            "and classify them according to compliance rules (FedRAMP SCN).\n\n"
            "Examples:\n"
            "  argus classify                              # compare HEAD vs main\n"
            "  argus classify --base main --head HEAD      # explicit refs\n"
            "  argus classify --config .github/scn.yml     # custom profile\n"
            "  argus classify --format json                # JSON output\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    classify_parser.add_argument(
        "--base",
        default="main",
        help="Base git ref for comparison (default: main)",
    )
    classify_parser.add_argument(
        "--head",
        default="HEAD",
        help="Head git ref for comparison (default: HEAD)",
    )
    classify_parser.add_argument(
        "--config", "-c",
        default=None,
        help="Path to SCN configuration/profile file",
    )
    classify_parser.add_argument(
        "--format", "-f",
        choices=["terminal", "markdown", "json"],
        default="terminal",
        dest="output_format",
        help="Output format (default: terminal)",
    )
    classify_parser.add_argument(
        "--output-dir", "-o",
        default=None,
        help="Output directory for report files",
    )
    classify_parser.add_argument(
        "--output-vars",
        default=None,
        metavar="FILE",
        help="Write classification counts as key=value pairs to FILE",
    )
    classify_parser.add_argument(
        "--enable-ai",
        action="store_true",
        help="Use AI for ambiguous change classification (requires API key)",
    )
    classify_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )


def cmd_classify(args: argparse.Namespace) -> int:
    """Execute the classify subcommand — SCN change classification."""
    import subprocess as _subprocess

    try:
        from argus.scn import ChangeClassifier, load_scn_config, generate_report
        from argus.scn.diff import analyze_iac_changes
    except ImportError as exc:
        print(f"Error: failed to import SCN modules: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Load config
    config = {}
    if args.config:
        try:
            config = load_scn_config(args.config)
        except Exception as exc:
            print(f"Error: failed to load SCN config: {exc}", file=sys.stderr)
            return EXIT_ERROR

    # Analyze IaC changes between refs and classify
    try:
        iac_analysis = analyze_iac_changes(args.base, args.head)

        if not iac_analysis.get("changes"):
            print("No IaC changes detected between refs.")
            return EXIT_SUCCESS

        classifier = ChangeClassifier(
            config=config,
            enable_ai=args.enable_ai,
        )
        result = classifier.classify_all_changes(iac_analysis)
        classifications = result.get("classifications", [])
    except Exception as exc:
        # GitDiffError (git command failed — unknown ref, not a repo,
        # etc.) must NOT be confused with "git diff produced 0 changed
        # files". The pre-1.0.2 path silently returned ``EXIT_SUCCESS``
        # whenever git diff blew up, which made every CI gate built
        # around classify trivially pass on repos missing the base
        # ref. Issue #168-J.
        from argus.scn.diff import GitDiffError
        if isinstance(exc, GitDiffError):
            print(f"Error: classify could not run git diff: {exc}", file=sys.stderr)
        else:
            print(f"Error: classification failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Count categories
    category_counts = {}
    for c in classifications:
        cat = c.get("category", "UNKNOWN")
        category_counts[cat] = category_counts.get(cat, 0) + 1

    # Output
    if args.output_format == "json":
        import json
        output = json.dumps({
            "base_ref": args.base,
            "head_ref": args.head,
            "total_changes": len(classifications),
            "categories": category_counts,
            "classifications": classifications,
        }, indent=2)
        if args.output_dir:
            Path(args.output_dir).mkdir(parents=True, exist_ok=True)
            (Path(args.output_dir) / "scn-report.json").write_text(output)
        else:
            print(output)
    elif args.output_format == "markdown":
        try:
            output_md = None
            if args.output_dir:
                Path(args.output_dir).mkdir(parents=True, exist_ok=True)
                output_md = str(Path(args.output_dir) / "scn-report.md")

            report_data = generate_report(
                classifications_data=result,
                output_md=output_md,
            )

            if not output_md:
                # Print the markdown content to stdout
                md = report_data.get("markdown", "")
                if md:
                    print(md)
        except Exception as exc:
            print(f"Error: report generation failed: {exc}", file=sys.stderr)
            return EXIT_ERROR
    else:
        # Terminal
        print(f"\nSCN Classification: {args.base}...{args.head}")
        print(f"{'=' * 50}")
        print(f"Total changes: {len(classifications)}")
        for cat, count in sorted(category_counts.items()):
            print(f"  {cat}: {count}")
        print()

    # Write output vars for CI
    if args.output_vars:
        lines = [f"total_changes={len(classifications)}"]
        for cat, count in sorted(category_counts.items()):
            lines.append(f"{cat.lower()}_count={count}")
        Path(args.output_vars).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output_vars).write_text("\n".join(lines) + "\n")

    return EXIT_SUCCESS


def _build_collect_parser(subparsers: argparse._SubParsersAction, parent: argparse.ArgumentParser) -> None:
    """Add the 'collect' subcommand for aggregating multi-job results."""
    collect_parser = subparsers.add_parser(
        "collect",
        parents=[parent],
        help="Collect and merge results from parallel CI scanner jobs",
        description=(
            "Aggregate per-scanner results into a unified audit package.\n\n"
            "In CI, each scanner job produces its own argus-results/ directory.\n"
            "This command merges them into one structured directory with:\n"
            "  - Combined JSONL log (sorted by timestamp)\n"
            "  - Combined audit manifest (all provenance and findings)\n"
            "  - Per-scanner subdirectories with individual results\n\n"
            "Example:\n"
            "  argus collect ./downloaded-artifacts/ -o ./argus-audit-package/\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    collect_parser.add_argument(
        "input_dir",
        help="Directory containing per-scanner result directories (argus-results-*)",
    )
    collect_parser.add_argument(
        "--output-dir", "-o",
        default="./argus-audit-package",
        help="Output directory for the combined audit package (default: ./argus-audit-package)",
    )
    collect_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )


def _build_validate_parser(subparsers: argparse._SubParsersAction, parent: argparse.ArgumentParser) -> None:
    """Add the 'validate' subcommand for config validation."""
    validate_parser = subparsers.add_parser(
        "validate",
        parents=[parent],
        help="Validate an argus.yml configuration file",
        description=(
            "Check an argus.yml config file for errors and warnings.\n"
            "Catches typos, invalid values, and unknown keys before scanning."
        ),
    )
    validate_parser.add_argument(
        "--config", "-c",
        default=None,
        help="Path to argus.yml config file (default: auto-detect)",
    )
    validate_parser.add_argument(
        "--check-tools",
        action="store_true",
        default=False,
        help="Also check scanner tool availability (local + Docker)",
    )
    validate_parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Treat warnings as errors (exit non-zero). Useful in CI.",
    )
    validate_parser.add_argument(
        "--report-issue",
        action="store_true",
        default=False,
        help="Create or update a living issue on GitHub/GitLab with validation "
             "results. Requires GITHUB_TOKEN or CI_JOB_TOKEN.",
    )


def _build_mcp_parser(subparsers: argparse._SubParsersAction, parent: argparse.ArgumentParser) -> None:
    """Add the 'mcp' subcommand to start the MCP server."""
    subparsers.add_parser(
        "mcp",
        parents=[parent],
        help="Start the MCP server for AI assistant integration",
        description=(
            "Start the Argus MCP (Model Context Protocol) server.\n\n"
            "The server communicates via stdio and provides tools for\n"
            "AI assistants (Claude, Copilot, Cursor) to run security scans,\n"
            "validate configs, and detect project characteristics.\n\n"
            "Setup in Claude Code:\n"
            '  Add to .claude/settings.json mcpServers:\n'
            '    "argus": {"command": "argus", "args": ["mcp"]}\n'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )


def _build_completion_parser(subparsers: argparse._SubParsersAction, parent: argparse.ArgumentParser) -> None:
    """Add the 'completion' subcommand for shell completion scripts."""
    completion_parser = subparsers.add_parser(
        "completion",
        parents=[parent],
        help="Generate shell completion script",
        description=(
            "Generate a shell completion script for argus.\n\n"
            "Once installed, pressing <Tab> will complete:\n"
            "  - subcommands (scan, view, report, classify, cache, ...)\n"
            "  - scanner and linter names (bandit, gitleaks, lint-yaml, ...)\n"
            "  - common flags (--config, --scanners, --severity, ...)\n\n"
            "Install (persistent — remember to reload your shell):\n"
            "  argus completion zsh  >> ~/.zshrc  && source ~/.zshrc\n"
            "  argus completion bash >> ~/.bashrc && source ~/.bashrc\n\n"
            "Activate for current session only:\n"
            "  eval \"$(argus completion zsh)\"\n\n"
            "Completions are generated from the live scanner registry, so\n"
            "newly added scanners appear after re-running this command.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    completion_parser.add_argument(
        "shell",
        choices=["bash", "zsh"],
        help="Shell type to generate completions for",
    )


def _build_cache_parser(subparsers: argparse._SubParsersAction, parent: argparse.ArgumentParser) -> None:
    """Add the 'cache' subcommand for managing scanner DB caches."""
    cache_parser = subparsers.add_parser(
        "cache",
        parents=[parent],
        help="Manage scanner database caches",
        description=(
            "Manage cached vulnerability databases used by container-based scanners.\n\n"
            "Argus caches scanner databases (Trivy, Grype, Checkov, etc.) in the system\n"
            "temp directory so container runs don't re-download hundreds of MB each time.\n"
            "The cache persists across runs within a session but is cleaned on reboot.\n\n"
            "Cache location: $TMPDIR/argus-cache (override with ARGUS_CACHE_DIR)\n"
            "For persistent caching: export ARGUS_CACHE_DIR=~/.argus/cache"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    cache_sub = cache_parser.add_subparsers(dest="cache_action")

    cache_sub.add_parser(
        "info",
        help="Show cache location and size per scanner",
    )
    cache_sub.add_parser(
        "clean",
        help="Remove all cached scanner databases",
    )


def _build_report_parser(subparsers: argparse._SubParsersAction, parent: argparse.ArgumentParser) -> None:
    """Add the 'report' subcommand."""
    report_parser = subparsers.add_parser(
        "report",
        parents=[parent],
        help="Generate reports from existing scan results",
        description="Generate formatted reports from previously captured scan results.",
    )
    report_parser.add_argument(
        "format",
        choices=FORMAT_CHOICES,
        help="Output format for the report",
    )
    report_parser.add_argument(
        "--results-dir", "-r",
        default="./argus-results",
        help="Directory containing scan results JSON (default: ./argus-results)",
    )
    report_parser.add_argument(
        "--output-dir", "-o",
        default=None,
        help="Output directory for generated reports (default: same as results-dir)",
    )
    report_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )


_STDIN_PASSWORD_FLAGS = {
    # CLI flag attr name on argparse.Namespace -> credential slot
    "registry_password_stdin": "registry_password",
    "zap_auth_password_stdin": "zap_auth_password",
}


def _consume_stdin_password_flags(args: argparse.Namespace) -> int:
    """Read a password from stdin for any ``--*-password-stdin`` flag.

    Mirrors ``docker login --password-stdin``: the value is read once,
    stored in ``argus.core.secrets`` under a named slot, and consumed
    by scanner modules via ``get_stdin_override(slot)`` at scan time.
    The value never reaches the per-scanner config dict, so it can't
    leak into argus-audit.json / argus.log.

    Returns ``EXIT_SUCCESS`` on success (including when no stdin flag was
    provided) or ``EXIT_ERROR`` on a usage / TTY violation. Logs no
    secret material.
    """
    active = [
        slot for attr, slot in _STDIN_PASSWORD_FLAGS.items()
        if getattr(args, attr, False)
    ]
    if not active:
        return EXIT_SUCCESS

    if len(active) > 1:
        print(
            f"Error: only one stdin password flag may be used per "
            f"invocation (got: {', '.join(sorted(active))}). "
            f"stdin is a single stream — pass other credentials via "
            f"<field>_env config keys instead.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    if sys.stdin.isatty():
        print(
            "Error: --*-password-stdin requires piped input.\n"
            "Example:\n"
            "  echo \"$REGISTRY_TOKEN\" | "
            "argus scan --registry-password-stdin --config argus.yml",
            file=sys.stderr,
        )
        return EXIT_ERROR

    raw = sys.stdin.read()
    # Strip a single trailing newline if present (matches
    # ``docker login --password-stdin`` behavior — handles
    # ``echo $X | ...`` cleanly without eating multi-line tokens).
    if raw.endswith("\n"):
        raw = raw[:-1]
    if not raw:
        print(
            "Error: stdin was empty. The password must be supplied "
            "as the body of the pipe.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    from argus.core.secrets import set_stdin_override
    set_stdin_override(active[0], raw)
    return EXIT_SUCCESS


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute the scan subcommand.

    Routes to specialized lifecycle engines based on scanner name
    and flags:
      - container + --discover/--image → container lifecycle
      - zap + --image/--target → DAST lifecycle
      - everything else → source code scanning
    """
    # Consume any --*-password-stdin flags before further dispatch.
    # Done first so a usage error surfaces before the scanner-registry
    # import (which is slower) and so the stdin value is in place for
    # both the container and DAST lifecycle paths below.
    rc = _consume_stdin_password_flags(args)
    if rc != EXIT_SUCCESS:
        return rc

    # Validate scanner name against registry
    if args.scanner and not args.list:
        try:
            from argus.scanners import SCANNER_REGISTRY
            if args.scanner not in SCANNER_REGISTRY:
                available = sorted(SCANNER_REGISTRY.keys())
                # Simple "did you mean?" — check for close matches
                import difflib
                close = difflib.get_close_matches(args.scanner, available, n=1, cutoff=0.6)
                hint = f" Did you mean '{close[0]}'?" if close else ""
                print(
                    f"Error: unknown scanner '{args.scanner}'.{hint}\n\n"
                    f"Available scanners:\n"
                    + "\n".join(f"  - {name}" for name in available)
                    + "\n\nRun 'argus scan --list' for details.",
                    file=sys.stderr,
                )
                return EXIT_ERROR
        except ImportError:
            pass

    # Container lifecycle — activated by EITHER CLI flags OR a config
    # file with a populated ``containers:`` block. Load config first
    # so a config-only invocation (``argus scan container --config
    # argus.yml`` with no --image/--discover) reaches the lifecycle
    # path; the previous gate looked at CLI flags only and shipped a
    # confusing usage error before config was even consulted.
    if args.scanner == "container":
        try:
            container_config = _load_container_config(args)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return EXIT_ERROR

        if (
            _is_container_lifecycle(args)
            or _container_config_has_targets(container_config)
        ):
            return _cmd_container_scan(args, container_config=container_config)

        print(
            "Usage: argus scan container "
            "[--config FILE | --discover PATH | --image REF]\n\n"
            "Container image scanning needs at least one source of targets:\n"
            "  --image REF      Scan a specific image (CLI, repeatable)\n"
            "  --discover PATH  Discover Dockerfiles in PATH\n"
            "  --config FILE    Load `containers.images` and/or "
            "`containers.discover`\n"
            "                   from a YAML config file (e.g. argus.yml).\n\n"
            "Examples:\n"
            "  argus scan container --image nginx:latest\n"
            "  argus scan container --discover ./docker/\n"
            "  argus scan container --config argus.yml\n"
            "  argus scan container --config argus.yml --image extra:tag\n",
            file=sys.stderr,
        )
        return EXIT_ERROR

    # DAST lifecycle — needs --target or --image
    if args.scanner == "zap":
        if _is_dast_lifecycle(args):
            return _cmd_dast_scan(args)
        print(
            "Usage: argus scan zap [--target URL | --image REF]\n\n"
            "DAST scanning requires one of:\n"
            "  --target URL   Scan an already-running web application\n"
            "  --image REF    Start container, discover ports, scan, stop\n\n"
            "Examples:\n"
            "  argus scan zap --target http://localhost:3000\n"
            "  argus scan zap --image myapp:latest\n"
            "  argus scan zap --image myapp:latest --port 8080\n"
            "  argus scan zap --image myapp:latest --env DB_HOST=localhost\n",
            file=sys.stderr,
        )
        return EXIT_ERROR

    return _cmd_source_scan(args)


def _is_container_lifecycle(args: argparse.Namespace) -> bool:
    """Check if container lifecycle CLI flags are present.

    Note: this is the CLI-only signal. Config-defined targets in
    ``argus.yml`` (a ``containers.images`` list or
    ``containers.discover`` flag) also activate the container lifecycle —
    that path goes through ``_load_container_config`` /
    ``_container_config_has_targets``, which the dispatcher consults
    alongside this CLI-flag check before deciding whether to fall
    back to the usage-error gate.
    """
    return bool(
        getattr(args, "discover", None) is not None
        or getattr(args, "images", None)
    )


def _load_container_config(args: argparse.Namespace) -> dict:
    """Build the container-scan config from --config + CLI overrides.

    The caller can supply targets one of three ways (or any
    combination): an explicit ``--config FILE`` (top-level
    ``containers:`` block), repeated ``--image REF`` flags, or
    ``--discover PATH``. CLI flags take precedence over config-file
    values for the keys they touch — explicit > implicit.

    Raises ``ValueError`` with an actionable message when the config
    file is unreadable, isn't a YAML mapping, or has a malformed
    ``containers`` section. The dispatcher catches this and prints
    the message before exiting EXIT_ERROR — users see one clean
    diagnostic instead of an opaque traceback from deep in the
    YAML/engine path.
    """
    config: dict = {}
    config_path = getattr(args, "config", None)

    # When --config wasn't supplied, auto-detect argus.yml the same way
    # ``argus scan`` (source) does. Source scans have always done this;
    # the container subcommand used to require an explicit --config,
    # which made config-driven container scans feel inconsistent with
    # the rest of the CLI. Search the project root for the canonical
    # filenames; if none exist, fall through with no config (CLI flags
    # alone may still supply targets).
    if not config_path:
        from argus.core.config import _DEFAULT_CONFIG_NAMES
        for candidate in _DEFAULT_CONFIG_NAMES:
            if Path(candidate).is_file():
                config_path = candidate
                break

    if config_path:
        try:
            import yaml
            from argus.core.config import load_strict_yaml
            with open(config_path, "r", encoding="utf-8") as fh:
                file_config = load_strict_yaml(fh) or {}
        except FileNotFoundError as exc:
            raise ValueError(f"Config file not found: {config_path}") from exc
        except yaml.YAMLError as exc:
            raise ValueError(
                f"Config file YAML parse error in {config_path}: {exc}"
            ) from exc

        if not isinstance(file_config, dict):
            raise ValueError(
                f"{config_path} is not a YAML mapping; expected an object "
                "at the top level."
            )
        containers_section = file_config.get("containers", {})
        if not isinstance(containers_section, dict):
            raise ValueError(
                f"{config_path}: 'containers' must be a mapping, got "
                f"{type(containers_section).__name__}. Expected: "
                "containers:\n  images:\n    - image: <ref>\n  discover: true"
            )
        config = dict(containers_section)

        # Pull ``reporting.keep_raw`` from the same file so the
        # container handler honors the unified config knob — same
        # default-True semantics as ``_cmd_source_scan``. Stashed
        # under a synthetic underscore key so it doesn't collide
        # with any future ``containers:`` field a user might add.
        reporting_section = file_config.get("reporting", {})
        if isinstance(reporting_section, dict) and "keep_raw" in reporting_section:
            config["_reporting_keep_raw"] = bool(reporting_section["keep_raw"])

        # Plumb ``execution.registry`` and ``execution.registry_map``
        # through to the container engine so the Trivy/Grype/Syft sub-
        # scanner image pulls honor the operator's mirror policy. Same
        # synthetic-key pattern as ``_reporting_keep_raw`` above.
        # Without this, the source-scan path correctly routes through
        # ArgusEngine._resolve_image but ``argus scan container`` pulls
        # raw upstream refs regardless of config (#186).
        execution_section = file_config.get("execution", {})
        if isinstance(execution_section, dict):
            if execution_section.get("registry"):
                config["_execution_registry"] = str(execution_section["registry"])
            raw_map = execution_section.get("registry_map") or {}
            if isinstance(raw_map, dict) and raw_map:
                config["_execution_registry_map"] = {
                    str(k): str(v) for k, v in raw_map.items() if v
                }

        # Back-compat: registry credentials are documented under
        # ``scanners.container.*`` in argus.example.yml and were the
        # only home for them before container-scan grew first-class
        # auth support. The canonical location going forward is the
        # top-level ``containers:`` block, but a user who already
        # configured creds under ``scanners.container.*`` shouldn't
        # have their config silently stop authenticating to private
        # registries. Promote each credential field into the
        # container config when the canonical key isn't already set —
        # ``containers.*`` wins when both are present.
        scanners_section = file_config.get("scanners", {})
        if isinstance(scanners_section, dict):
            sc = scanners_section.get("container") or {}
            if isinstance(sc, dict):
                for key in (
                    "registry_username", "registry_username_env",
                    "registry_password", "registry_password_env",
                ):
                    if key in sc and key not in config:
                        config[key] = sc[key]

    # CLI overrides — explicit > implicit. --image and --discover both
    # OVERWRITE the corresponding config keys so the user's intent is
    # unambiguous (and so we don't accidentally double-scan an image
    # the user passed on the CLI to *replace* a stale config entry).
    if getattr(args, "images", None):
        config["images"] = [
            {"image": img, "name": img.split(":")[0].split("/")[-1]}
            for img in args.images
        ]
    if getattr(args, "discover", None) is not None:
        config["discover"] = True
        config["search_paths"] = [args.discover]
    if getattr(args, "scanners", None):
        config["scanners"] = [s.strip() for s in args.scanners.split(",")]

    return config


def _container_config_has_targets(config: dict) -> bool:
    """Return True if the merged container config has any way to resolve targets.

    Used by the dispatcher to decide whether ``argus scan container``
    can proceed without explicit ``--discover``/``--image`` flags.
    Mirrors the semantics of ``parse_container_config``: images list
    non-empty, ``discover: true``, or an explicit ``search_paths``
    list — any one is enough.
    """
    if not isinstance(config, dict):
        return False
    images = config.get("images")
    if isinstance(images, list) and len(images) > 0:
        return True
    if config.get("discover"):
        return True
    search_paths = config.get("search_paths")
    if isinstance(search_paths, list) and len(search_paths) > 0:
        return True
    return False


def _is_dast_lifecycle(args: argparse.Namespace) -> bool:
    """Check if DAST lifecycle flags are present."""
    return bool(
        getattr(args, "target", None)
        or getattr(args, "images", None)
    )


def _cmd_source_scan(args: argparse.Namespace) -> int:
    """Run source code scanning with registered scanner modules."""
    from argus.audit import get_logger, create_manifest, finalize_manifest

    try:
        from argus.core import ArgusConfig, ArgusEngine, Severity
    except ImportError as exc:
        print(f"Error: failed to import argus core modules: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Load config
    try:
        config = ArgusConfig.load(args.config)
    except FileNotFoundError:
        print(f"Error: config file not found: {args.config}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:
        print(f"Error: failed to load config: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Override config with CLI arguments
    if args.severity_threshold:
        if args.severity_threshold == "none":
            config.reporting.severity_threshold = None
        else:
            config.reporting.severity_threshold = Severity.from_string(
                args.severity_threshold
            )
    if args.output_dir:
        config.reporting.output_dir = args.output_dir
    if args.formats:
        config.reporting.formats = args.formats

    # Dry-run short-circuit: resolve scanners, configs, exclusions — then
    # print the plan and exit without invoking any scanner. Short-circuits
    # BEFORE creating output dirs, opening log files, or writing a run
    # manifest so the dry run stays read-only. We still need an engine +
    # registered scanners for `--list` parity, so build those lazily below.
    if getattr(args, "dry_run", False):
        engine = ArgusEngine(config)
        try:
            from argus.scanners import get_available_scanners
            for scanner_cls in get_available_scanners():
                engine.register_scanner(scanner_cls())
        except ImportError:
            pass
        return _dry_run(engine=engine, config=config, args=args)

    # Initialize output directory — timestamped subdirectory by default,
    # flat directory when --no-timestamp is set (CI/action use case).
    if getattr(args, "no_timestamp", False):
        output_dir = config.reporting.output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    else:
        output_dir = _make_run_dir(config.reporting.output_dir)
    config.reporting.output_dir = output_dir
    log = get_logger(
        "argus",
        output_dir=output_dir,
        verbose=args.verbose,
        quiet=getattr(args, "quiet", False),
    )

    # Kick off the update check in a daemon thread now so it runs in
    # parallel with the scan — by end-of-command it's already done.
    # Returns ``None`` when suppressed (env var, --no-update-check,
    # --quiet, or dev install); callers must null-check.
    from argus.update_check import start_background_check
    update_check = start_background_check(args)

    manifest = create_manifest(
        config_path=args.config,
        scan_targets=[args.path],
    )
    manifest.execution_backend = config.execution.backend

    log.info("Argus scan starting")

    # Decide whether to persist raw per-scanner outputs alongside the
    # canonical argus-results.json. Default OFF — scanners like
    # gitleaks emit the literal matched secret bytes into raw output;
    # persisting those by default turned argus-results into a leak
    # vector. The canonical argus-results.json is always written and
    # is pattern-redacted. Forensic / triage users opt in via
    # ``--keep-raw`` (CLI) or ``reporting.keep_raw: true``
    # (argus.yml). CLI flag wins on conflict — ``--no-keep-raw``
    # explicitly overrides a config-file opt-in. ``args.keep_raw`` is
    # tri-state: True / False / None (not specified).
    keep_raw_config = getattr(config.reporting, "keep_raw", False)
    cli_keep_raw = getattr(args, "keep_raw", None)
    keep_raw = cli_keep_raw if cli_keep_raw is not None else bool(keep_raw_config)
    raw_output_root = str(Path(output_dir) / "raw") if keep_raw else None

    # Build engine and register scanners
    engine = ArgusEngine(config)

    try:
        from argus.scanners import get_available_scanners
        for scanner_cls in get_available_scanners():
            engine.register_scanner(scanner_cls())
    except ImportError:
        if args.verbose:
            log.warning("argus.scanners module not found; no scanners registered")

    # List mode
    if args.list:
        return _list_scanners(engine)

    # Dry-run guard — should never be reached because we short-circuited
    # above. Keep a tripwire here so accidental refactors fail fast rather
    # than silently fall through into the real scan.
    if getattr(args, "dry_run", False):
        return _dry_run(
            engine=engine,
            config=config,
            args=args,
        )

    # SBOM mode: validate input (file OR directory), discover every SBOM
    # present, and record formats up front. Failing here — before spinning
    # up any scanner — keeps errors actionable.
    sbom_path = getattr(args, "sbom", None)
    sbom_files: list = []
    if sbom_path:
        from argus.core.sbom import (
            analyze_sbom_quality,
            discover_sbom_files,
            SbomDetectionError,
        )
        try:
            sbom_files = discover_sbom_files(sbom_path)
        except SbomDetectionError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        if not sbom_files:
            print(
                f"Error: no SBOM files found in {sbom_path}. Supported: "
                "CycloneDX (JSON/XML), SPDX (JSON/tag-value), Syft JSON.",
                file=sys.stderr,
            )
            return EXIT_ERROR
        if len(sbom_files) == 1:
            log.info(
                "SBOM input: %s (%s)",
                sbom_files[0].path,
                sbom_files[0].display_format,
            )
        else:
            log.info(
                "SBOM batch: %d files found under %s",
                len(sbom_files), sbom_path,
            )
            for info in sbom_files:
                log.info("  - %s (%s)", info.path, info.display_format)
        # Warn on known-scan-hostile SBOMs (SPDX-2.1, purl-less). We
        # still scan — the user may want the few findings we can get
        # — but they get a heads-up before the silence.
        for info in sbom_files:
            for msg in analyze_sbom_quality(info):
                log.warning("%s: %s", info.path.name, msg)

    # Run the scan
    sbom_batch_failures: list[tuple[str, str]] = []
    try:
        scanner_names = [args.scanner] if args.scanner else None
        log.info("Running scanners: %s", scanner_names or "all enabled")
        if sbom_files:
            # SBOM mode: run the engine once per discovered SBOM, then
            # merge the per-file ScanSummary objects into one so the rest
            # of the pipeline (reporters, output vars, nudge) sees a
            # single aggregated view.
            #
            # Each per-SBOM scan is wrapped in its own try/except so a
            # single failing SBOM (corrupt file, crashed scanner, docker
            # daemon glitch) never aborts the batch — users running a
            # directory of vendor SBOMs depend on partial results, not
            # an all-or-nothing exit. Failures are recorded and the exit
            # code accounts for them only AFTER every SBOM has been tried.
            per_file_summaries = []
            with _TerminalSpinner(
                message=f"Scanning {len(sbom_files)} SBOM(s)",
                enabled=_spinner_enabled(args),
            ):
                for info in sbom_files:
                    try:
                        per_summary = engine.run(
                            scanner_names=scanner_names,
                            path=args.path,
                            fail_fast=getattr(args, "fail_fast", False),
                            timeout=getattr(args, "timeout", None),
                            exclude=getattr(args, "exclude", ""),
                            parallel=not getattr(args, "no_parallel", False),
                            allow_local_versions=getattr(args, "allow_local_versions", False),
                            no_cache=getattr(args, "no_cache", False),
                            use_default_excludes=not getattr(args, "no_default_excludes", False),
                            sbom_path=str(info.path),
                            sbom_format=info.format,
                            raw_output_dir=raw_output_root,
                        )
                    except Exception as exc:
                        log.error(
                            "Scan failed for %s: %s — continuing batch",
                            info.path, exc,
                        )
                        sbom_batch_failures.append((str(info.path), str(exc)))
                        # Insert an empty summary so per-file bookkeeping
                        # still reflects that we tried this SBOM.
                        from argus.core.models import ScanSummary as _ScanSummary
                        per_summary = _ScanSummary(
                            results=[],
                            severity_threshold=config.reporting.severity_threshold,
                        )
                    per_file_summaries.append((info, per_summary))
            summary = _merge_sbom_summaries(
                per_file_summaries,
                severity_threshold=config.reporting.severity_threshold,
            )
            if sbom_batch_failures:
                log.warning(
                    "%d of %d SBOM(s) failed during batch: %s",
                    len(sbom_batch_failures), len(sbom_files),
                    ", ".join(p for p, _ in sbom_batch_failures),
                )
        else:
            with _TerminalSpinner(
                message="Running scanners",
                enabled=_spinner_enabled(args),
            ):
                summary = engine.run(
                    scanner_names=scanner_names,
                    path=args.path,
                    fail_fast=getattr(args, "fail_fast", False),
                    timeout=getattr(args, "timeout", None),
                    exclude=getattr(args, "exclude", ""),
                    parallel=not getattr(args, "no_parallel", False),
                    allow_local_versions=getattr(args, "allow_local_versions", False),
                    no_cache=getattr(args, "no_cache", False),
                    use_default_excludes=not getattr(args, "no_default_excludes", False),
                    raw_output_dir=raw_output_root,
                )
        if args.verbose and getattr(engine, "_last_resolutions", None):
            from argus.core.tool_config import format_resolutions_for_display
            log.info(
                "%s",
                format_resolutions_for_display(engine._last_resolutions),
            )
        log.info(
            "Scan complete: %d scanner(s), %d finding(s)",
            len(summary.results),
            summary.total_count,
        )
    except Exception as exc:
        log.error("Scan failed: %s", exc)
        finalize_manifest(manifest, exit_code=EXIT_ERROR, output_dir=output_dir)
        return EXIT_ERROR

    # Generate reports.
    #
    # ``ensure_canonical_json`` guarantees the source-of-truth artifact
    # (``argus-results.json``) is always written, regardless of what
    # the user listed in ``reporting.formats``. The viewers, the audit
    # manifest, and the ``argus report`` subcommand all consume that
    # file — keeping it implicitly mandatory means a config like
    # ``formats: [terminal, sarif]`` no longer silently breaks
    # ``argus view`` (the diagnoser still helps for legacy result dirs
    # produced before this contract was in place).
    # Surface the --fail-on-scanner-error state to reporters so the
    # terminal report can suppress its "Pass --fail-on-scanner-error
    # to fail the scan when this happens" advice when the flag is
    # already on (issue #168-D).
    summary.fail_on_scanner_error_set = bool(getattr(args, "fail_on_scanner_error", False))

    try:
        from argus.reporters import ensure_canonical_json, get_reporter
        for fmt in ensure_canonical_json(config.reporting.formats):
            reporter = get_reporter(fmt)
            reporter.report(summary, output_dir)
            log.debug("Generated %s report", fmt)
    except ImportError:
        if args.verbose:
            log.warning("argus.reporters module not found; skipping report generation")

    # Write machine-readable output vars (for CI integration)
    output_vars_path = getattr(args, "output_vars", None)
    if output_vars_path:
        _write_output_vars(summary, output_vars_path)
        log.debug("Output vars written to %s", output_vars_path)

    # Nudge when scanners ran but produced no results — this is the
    # "silent empty scan" failure mode users hit on machines without
    # Docker or the native tools installed. Point them at --check-tools
    # so they get actionable install suggestions instead of nothing.
    if sbom_path:
        # In SBOM mode the engine auto-picks supports_sbom scanners;
        # the requested set should mirror that logic so the nudge
        # doesn't falsely report "bandit skipped" on an SBOM scan.
        requested_for_nudge = [
            name for name, scanner in engine._scanners.items()
            if getattr(scanner, "supports_sbom", False)
        ]
        if args.scanner:
            requested_for_nudge = [args.scanner] if args.scanner in requested_for_nudge else []
    else:
        requested_for_nudge = scanner_names or [
            name for name in engine._scanners
            if config.get_scanner_config(name).enabled
        ]
    _print_missing_scanner_nudge(
        requested=requested_for_nudge,
        summary=summary,
    )

    # Finalize audit trail.
    #
    # Exit policy (in priority order):
    #   1. Findings over the severity threshold → EXIT_FINDINGS.
    #   2. Otherwise, if any SBOM failed hard during a batch → EXIT_ERROR.
    #      This always fires AFTER every SBOM in the batch was attempted;
    #      we never abort the loop on the first failure.
    #   3. Otherwise, if --fail-on-scanner-error is set AND any scanner
    #      produced no output → EXIT_ERROR. Opt-in so existing default
    #      "warn but pass" behavior stays unchanged.
    #   4. Otherwise → EXIT_SUCCESS.
    scanner_execution_failures = [
        r.scanner for r in summary.results
        if r.metadata.get("execution_failed")
    ]
    scanner_parse_failures = [
        r.scanner for r in summary.results
        if r.metadata.get("parse_failed")
    ]
    # Multi-phase scanners (lint-terraform, container) that ran but had
    # one or more phases fail. ``partial_failure`` is True iff at least
    # one PhaseResult has status="failed" — issues #169 / #170. Gating
    # this with --fail-on-scanner-error matches the
    # execution_failed / parse_failed shape; the engine and terminal
    # reporter likewise fold partial-failure scanners into the same
    # "did not run cleanly" bucket.
    scanner_partial_failures = [
        r.scanner for r in summary.results
        if getattr(r, "partial_failure", False)
    ]
    if not summary.passed:
        exit_code = EXIT_FINDINGS
    elif sbom_batch_failures:
        exit_code = EXIT_ERROR
    elif (
        getattr(args, "fail_on_scanner_error", False)
        and (
            scanner_execution_failures
            or scanner_parse_failures
            or scanner_partial_failures
        )
    ):
        # All three states represent "the scan didn't fully succeed":
        # execution_failed = couldn't run; parse_failed = ran but
        # output unintelligible; partial_failure = ran some phases
        # but at least one phase couldn't complete. From a CI gating
        # perspective they're equivalent — the user asked for a hard
        # fail when scanners don't deliver clean results.
        if scanner_execution_failures:
            log.error(
                "Exiting non-zero: %d scanner(s) did not run cleanly "
                "(%s) and --fail-on-scanner-error is set.",
                len(scanner_execution_failures),
                ", ".join(scanner_execution_failures),
            )
        if scanner_parse_failures:
            log.error(
                "Exiting non-zero: %d scanner(s) produced unparsable "
                "output (%s) and --fail-on-scanner-error is set.",
                len(scanner_parse_failures),
                ", ".join(scanner_parse_failures),
            )
        if scanner_partial_failures:
            log.error(
                "Exiting non-zero: %d scanner(s) ran with phase "
                "failures (%s) and --fail-on-scanner-error is set.",
                len(scanner_partial_failures),
                ", ".join(scanner_partial_failures),
            )
        exit_code = EXIT_ERROR
    else:
        exit_code = EXIT_SUCCESS
    finalize_manifest(manifest, summary=summary, exit_code=exit_code, output_dir=output_dir)
    log.info("Audit manifest written to %s/argus-audit.json", output_dir)

    # --interface: hand off to the chosen viewer against the
    # just-written results. Intentionally AFTER finalize_manifest so
    # the manifest always lands regardless of whether the viewer
    # succeeds (or whether the user has the matching extra installed).
    view_interface = getattr(args, "view_interface", None)
    if view_interface:
        _launch_view_after_scan(view_interface, output_dir)

    # Surface the update notice as the very last thing — past PASS/FAIL
    # status, past viewer launch, so it never hides scan results behind
    # version chatter. ``None`` when suppressed or when up-to-date.
    if update_check is not None:
        notice = update_check.notice()
        if notice:
            print(notice, file=sys.stderr)

    return exit_code


def _launch_view_after_scan(interface: str, results_dir: str) -> None:
    """Dispatch to ``argus view`` after ``argus scan --interface=...``.

    Extracted from ``cmd_scan`` so it's unit-testable without running
    a full scan plan. Failures here are non-fatal: the manifest and
    results file are already on disk, so the user loses the viewer
    convenience but nothing else. Both the friendly
    ``ViewerUnavailable`` / ``ViewerUnavailable`` (missing optional
    extra) and a bare ``ImportError`` (something weirder in the
    import chain) are caught so the scan exit code isn't affected
    either way.
    """
    if interface == "terminal":
        try:
            from argus.viewers.terminal import launch as terminal_launch, ViewerUnavailable
            try:
                terminal_launch(results_dir)
            except ViewerUnavailable as exc:
                print(f"\n{exc}", file=sys.stderr)
        except ImportError as exc:  # pragma: no cover — defensive
            print(f"\nCould not launch terminal interface: {exc}", file=sys.stderr)
        return

    if interface == "browser":
        try:
            from argus.viewers.browser import launch as browser_launch, ViewerUnavailable
            try:
                # Match `argus view --interface=browser` semantics: auto-open
                # the user's default browser when stdout is a TTY (interactive
                # invocation), skip in CI / piped contexts where webbrowser.open
                # would fail or hang.
                browser_launch(root=results_dir, open_browser=sys.stdout.isatty())
            except ViewerUnavailable as exc:
                print(f"\n{exc}", file=sys.stderr)
        except ImportError as exc:  # pragma: no cover — defensive
            print(f"\nCould not launch browser interface: {exc}", file=sys.stderr)
        return

    # Defensive: unknown interface should never reach here because argparse
    # restricts --interface to VIEW_INTERFACES.
    print(f"\nUnknown interface '{interface}'", file=sys.stderr)  # pragma: no cover


def _dry_run(engine, config, args) -> int:
    """Resolve the scan plan and print it without executing scanners.

    Exits with EXIT_SUCCESS after printing. The point of --dry-run is to
    show the user exactly which scanners will run, which config file each
    will use, and the final exclusion pattern set — so CI debugging and
    "is my .bandit being picked up?" investigations don't require an
    actual scan cycle.
    """
    from argus.core.exclusions import build_exclusion_set
    from argus.core.tool_config import (
        format_resolutions_for_display,
        resolve_config,
    )

    sbom_path = getattr(args, "sbom", None)
    sbom_files = []

    if sbom_path:
        from argus.core.sbom import discover_sbom_files, SbomDetectionError
        try:
            sbom_files = discover_sbom_files(sbom_path)
        except SbomDetectionError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        if not sbom_files:
            print(
                f"Error: no SBOM files found in {sbom_path}.",
                file=sys.stderr,
            )
            return EXIT_ERROR
        # SBOM mode: only scanners declaring supports_sbom run; argus.yml
        # `enabled:` flags are ignored by design (the user explicitly asked
        # for full SBOM coverage by passing --sbom).
        capable = [
            name for name, scanner in engine._scanners.items()
            if getattr(scanner, "supports_sbom", False)
        ]
        scanner_names = [args.scanner] if args.scanner else sorted(capable)
        # Filter a named request down to capable scanners so the dry-run
        # plan matches what a real run would do.
        scanner_names = [n for n in scanner_names if n in capable]
    else:
        scanner_names = [args.scanner] if args.scanner else [
            name for name in engine._scanners
            if config.get_scanner_config(name).enabled
        ]
    use_defaults = not getattr(args, "no_default_excludes", False)

    print("Argus dry-run — no scanners will execute.\n")
    if sbom_files:
        if len(sbom_files) == 1:
            print(f"SBOM input:  {sbom_files[0].path} ({sbom_files[0].display_format})")
        else:
            print(f"SBOM batch:  {len(sbom_files)} files under {sbom_path}")
            for info in sbom_files:
                print(f"  - {info.path} ({info.display_format})")
    print(f"Scan path:   {args.path}")
    print(f"Backend:     {config.execution.backend}")
    print(f"Scanners:    {', '.join(scanner_names) if scanner_names else '(none)'}")
    print()

    # Exclusion set with the same inputs a real run would use
    patterns = build_exclusion_set(
        scan_path=args.path,
        cli_excludes=getattr(args, "exclude", ""),
        use_defaults=use_defaults,
    )
    print(f"Exclusion patterns ({len(patterns)}, use_defaults={use_defaults}):")
    for p in patterns:
        print(f"  - {p}")
    print()

    # Per-scanner config resolution
    resolutions = []
    for name in scanner_names:
        scanner_config = config.get_scanner_config(name)
        explicit = scanner_config.config_file
        resolutions.append(resolve_config(name, args.path, explicit))
    print(format_resolutions_for_display(resolutions))

    return EXIT_SUCCESS


def _merge_sbom_summaries(per_file_summaries, severity_threshold):
    """Collapse per-SBOM ScanSummary objects into a single ScanSummary.

    For each scanner we end up with one ScanResult whose findings span
    every SBOM file. Each finding is annotated via metadata['sbom_source']
    so downstream reporters / audit consumers can tell which SBOM a
    vulnerability came from without losing per-scanner grouping.
    """
    from argus.core.models import ScanResult, ScanSummary

    by_scanner: dict[str, list] = {}
    metadata_by_scanner: dict[str, dict] = {}
    for info, summary in per_file_summaries:
        source = str(info.path)
        for result in summary.results:
            # Annotate without mutating shared finding objects in place:
            # metadata is a per-finding dict so assignment is safe, but
            # we still want to avoid clobbering an sbom_source set by an
            # earlier iteration (shouldn't happen, but defensive).
            for f in result.findings:
                f.metadata.setdefault("sbom_source", source)
            by_scanner.setdefault(result.scanner, []).extend(result.findings)
            # Preserve the first metadata dict we see per scanner for
            # the execution/tool-version bookkeeping the audit trail
            # relies on; append the new SBOM source to a list.
            meta = metadata_by_scanner.setdefault(result.scanner, dict(result.metadata))
            meta.setdefault("sbom_sources", []).append(source)

    merged_results = [
        ScanResult(
            scanner=name,
            findings=findings,
            metadata=metadata_by_scanner.get(name, {}),
        )
        for name, findings in by_scanner.items()
    ]
    from argus.core.models import ScanContext as _ScanContext
    return ScanSummary(
        results=merged_results,
        severity_threshold=severity_threshold,
        scan_context=_ScanContext.capture(),
    )


def _print_missing_scanner_nudge(requested: list[str], summary) -> None:
    """Tell the user how to diagnose scanners that produced no results."""
    completed = {r.scanner for r in summary.results}
    missing = [name for name in requested if name not in completed]
    if not missing:
        return
    print(
        f"\n💡 {len(missing)} scanner(s) produced no results: {', '.join(missing)}",
        file=sys.stderr,
    )
    print(
        "   Run 'argus validate --check-tools' for install suggestions.",
        file=sys.stderr,
    )


def _cmd_container_scan(
    args: argparse.Namespace,
    container_config: dict | None = None,
) -> int:
    """Run container image scanning lifecycle (discover, build, scan, report).

    ``container_config`` is the merged config the dispatcher pre-loaded
    via ``_load_container_config``. When ``None`` (e.g. a direct
    test-side call), this function falls back to loading it locally —
    that path is kept for backward compatibility with any caller that
    still bypasses ``cmd_scan``.
    """
    from argus.container import ContainerEngine
    from argus.reporters.container_markdown import ContainerMarkdownReporter

    # Configure the ``argus`` logger at the user's chosen level —
    # default INFO, --quiet WARNING, --verbose/--debug DEBUG. Without
    # this the container engine's logger.info() calls would go
    # nowhere even under --verbose.
    _configure_logger(args)

    if container_config is None:
        try:
            container_config = _load_container_config(args)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return EXIT_ERROR

    # Defensive: a config that resolves to zero targets after merging
    # CLI overrides should hit a clear error before the engine spins
    # up, not deep inside it. The dispatcher gates this in the normal
    # flow; this branch covers tests / direct-callers + protects
    # against a regression where the gate stops covering a case.
    if not _container_config_has_targets(container_config):
        print(
            "Error: container scan has no targets to run. Provide one of:\n"
            "  --image REF        (CLI)\n"
            "  --discover PATH    (CLI)\n"
            "  containers.images  (in --config FILE)\n"
            "  containers.discover: true + containers.search_paths  (in --config FILE)",
            file=sys.stderr,
        )
        return EXIT_ERROR

    config = container_config
    base_dir = args.output_dir or config.get("output_dir", "./argus-results")
    output_dir = _make_run_dir(base_dir)
    formats = args.formats or ["terminal", "markdown"]

    # Now that we know the output dir, re-attach the logger's file
    # handler so engine logs land in <output_dir>/argus.log alongside
    # the rest of the audit trail — same shape as the source-scan
    # path. ``_configure_logger`` is idempotent on the stream handler;
    # passing output_dir adds the file handler when it's missing.
    log = _configure_logger(args, output_dir=output_dir)

    # Audit manifest — captures the exact targets, config path, and
    # outcome so a security reviewer (or CI archive) can trace any
    # finding back to its inputs without cross-referencing the
    # workflow. Source scans have always done this; container scans
    # used to skip it entirely. ``scan_targets`` lists the originating
    # source per target — Dockerfile path for build-mode entries,
    # image ref for remote-pull entries — so the audit manifest
    # answers "which container produced this artifact?" by name.
    from argus.audit import create_manifest, finalize_manifest
    from argus.container.discovery import parse_container_config
    _audit_targets = [
        str(t.dockerfile) if t.dockerfile else t.image_ref
        for t in parse_container_config(config)
    ]
    manifest = create_manifest(
        config_path=getattr(args, "config", None),
        scan_targets=_audit_targets,
    )
    manifest.execution_backend = config.get("backend", "auto")

    # Kick off the update check in a daemon thread now so it runs in
    # parallel with the (typically multi-minute) container scan. By
    # end-of-command the result is already cached in memory.
    from argus.update_check import start_background_check
    update_check = start_background_check(args)

    # Decide whether to persist raw per-scanner outputs alongside the
    # canonical argus-results.json. Default is OFF — scanners write
    # literal matched content (image-layer scan hits) into raw output,
    # so persisting raw by default leaks data the canonical
    # argus-results.json pattern-redacts. Forensic / triage users opt
    # in with ``--keep-raw`` (CLI) or ``reporting.keep_raw: true``
    # (argus.yml). The legacy ``containers.keep_raw`` is still read
    # as a fallback for argus.yml files from before the unified
    # ``reporting.keep_raw`` shape. CLI ``--no-keep-raw`` explicitly
    # overrides a config-file opt-in. ``args.keep_raw`` is tri-state:
    # True / False / None (not specified).
    keep_raw_config = config.get(
        "_reporting_keep_raw", config.get("keep_raw", False),
    )
    cli_keep_raw = getattr(args, "keep_raw", None)
    keep_raw = cli_keep_raw if cli_keep_raw is not None else bool(keep_raw_config)
    if keep_raw:
        config["_raw_output_root"] = str(Path(output_dir) / "raw")

    # Run
    try:
        # Build the spinner first so the engine's progress callback
        # can update its message in place. ``_make_progress_emitter``
        # picks the right routing (spinner vs persistent INFO line vs
        # no-op) based on the user's --quiet/--debug/--no-spinner mix.
        with _TerminalSpinner(
            message="Running container scan",
            enabled=_spinner_enabled(args),
        ) as spinner:
            engine = ContainerEngine(
                config,
                progress_callback=_make_progress_emitter(args, spinner),
            )
            summary = engine.run()
    except Exception as exc:
        print(f"Error: container scan failed: {exc}", file=sys.stderr)
        finalize_manifest(manifest, exit_code=EXIT_ERROR, output_dir=output_dir)
        return EXIT_ERROR

    # Build a canonical ScanSummary view of the container results so
    # the standard reporters (json → argus-results.json, sarif) and
    # ``argus view`` can consume container scans the same way they
    # consume source scans. Each container target becomes a
    # ScanResult; the per-image domain metadata (image_ref, build
    # status, scanner_errors) lifts onto ScanResult.metadata so the
    # browser dashboard and exporters surface it.
    from argus.core.models import ScanResult, ScanSummary
    canonical_results = [
        ScanResult(
            scanner=f"container/{r.name}",
            findings=list(r.combined_findings),
            metadata=_canonical_container_metadata(r),
        )
        for r in summary.results
    ]
    from argus.core.models import ScanContext as _ScanContext
    canonical_summary = ScanSummary(
        results=canonical_results,
        scan_context=_ScanContext.capture(),
    )

    # Always emit argus-results.json — same canonical-artifact
    # contract the source-scan flow established. ``argus view`` and
    # the audit manifest both consume this regardless of what the
    # user listed in ``formats``.
    from argus.reporters import get_reporter
    get_reporter("json").report(canonical_summary, output_dir)

    # Reports
    for fmt in formats:
        if fmt == "markdown":
            reporter = ContainerMarkdownReporter()
            filepath = reporter.report(summary, output_dir)
            if args.verbose:
                print(f"Markdown report: {filepath}")
        elif fmt == "terminal":
            _print_container_terminal(summary)
        elif fmt == "json":
            # Domain-shaped per-image summary (container_count etc.)
            # lives at container-scan.json. The canonical
            # argus-results.json was already written above; this
            # is the supplementary domain artifact for tooling that
            # wants per-image stats without parsing findings.
            _write_container_json(summary, output_dir)
        elif fmt == "sarif":
            sarif_reporter = get_reporter("sarif")
            sarif_reporter.report(canonical_summary, output_dir)

    # Exit code — scanner failures are always non-zero
    scan_failures = getattr(summary, "scan_failures", 0)
    if scan_failures:
        print(
            f"\n{scan_failures} scanner failure(s) — results are incomplete",
            file=sys.stderr,
        )
        exit_code = EXIT_ERROR
    elif args.severity_threshold and args.severity_threshold != "none":
        from argus.core.models import Severity
        threshold = Severity.from_string(args.severity_threshold)
        exit_code = EXIT_SUCCESS
        for r in summary.results:
            if any(f.severity >= threshold for f in r.combined_findings):
                exit_code = EXIT_FINDINGS
                break
    else:
        exit_code = EXIT_SUCCESS

    # Finalize the audit manifest with the canonical summary so the
    # archived ``argus-audit.json`` reflects what actually ran. Same
    # shape as the source-scan flow.
    finalize_manifest(
        manifest,
        summary=canonical_summary,
        exit_code=exit_code,
        output_dir=output_dir,
    )
    log.info("Audit manifest written to %s/argus-audit.json", output_dir)

    # Surface the update notice last — past PASS/FAIL, past audit
    # finalize — so it never hides scan results behind version chatter.
    if update_check is not None:
        notice = update_check.notice()
        if notice:
            print(notice, file=sys.stderr)

    return exit_code


def _cmd_dast_scan(args: argparse.Namespace) -> int:
    """Run DAST scanning lifecycle (start target, scan with ZAP, cleanup)."""
    from argus.dast import DastEngine

    base_dir = args.output_dir or "./argus-results"
    if getattr(args, "no_timestamp", False):
        output_dir = base_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    else:
        output_dir = _make_run_dir(base_dir)
    formats = args.formats or ["terminal", "markdown"]

    # Parse env vars from --env KEY=VALUE flags
    env = {}
    for item in (args.env_vars or []):
        if "=" in item:
            key, _, val = item.partition("=")
            env[key] = val

    # Build config
    if args.target:
        # Scan an already-running target
        config = {
            "targets": [{"url": args.target, "name": "target"}],
            "scan_type": args.scan_type,
        }
    elif args.images:
        # Auto-discover ports, start containers, scan
        config = {
            "targets": [
                {
                    "image": img,
                    "name": img.split(":")[0].split("/")[-1],
                    "port": args.port,
                    "env": env,
                }
                for img in args.images
            ],
            "scan_type": args.scan_type,
            "startup_timeout": args.startup_timeout,
        }
    else:
        print("Error: argus scan zap requires --target or --image", file=sys.stderr)
        return EXIT_ERROR

    try:
        engine = DastEngine(config)
        with _TerminalSpinner(
            message="Running DAST scan",
            enabled=_spinner_enabled(args),
        ):
            summary = engine.run()
    except Exception as exc:
        print(f"Error: DAST scan failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Reports
    for fmt in formats:
        if fmt == "terminal":
            _print_dast_terminal(summary)
        elif fmt == "markdown":
            _write_dast_markdown(summary, output_dir)
        elif fmt == "json":
            _write_dast_json(summary, output_dir)
        elif fmt == "sarif":
            from argus.core.models import ScanResult, ScanSummary
            from argus.reporters import get_reporter
            results = [
                ScanResult(scanner=f"zap/{r.name}", findings=r.findings)
                for r in summary.results
            ]
            get_reporter("sarif").report(ScanSummary(results=results), output_dir)

    # Exit code
    if args.severity_threshold and args.severity_threshold != "none":
        from argus.core.models import Severity
        threshold = Severity.from_string(args.severity_threshold)
        for r in summary.results:
            for f in r.findings:
                if f.severity >= threshold:
                    return EXIT_FINDINGS
    return EXIT_SUCCESS


def _print_dast_terminal(summary) -> None:
    """Print DAST scan results to terminal."""
    print("\n" + "=" * 50)
    print("  DAST Security Scan Results")
    print("=" * 50 + "\n")
    print(f"Targets scanned: {summary.target_count}")
    print(f"Healthy targets: {summary.healthy_count}")
    print(f"Total findings:  {summary.total_count}")
    print()
    for r in summary.results:
        if not r.healthy:
            status = "NOT HEALTHY"
        elif r.scan_error:
            status = f"SCAN ERROR: {r.scan_error}"
        else:
            status = f"{len(r.findings)} findings"
        print(f"  {r.name:<20} {r.target_url:<30} {status}")
    print()


def _write_dast_markdown(summary, output_dir) -> None:
    """Write DAST scan markdown report."""
    import json
    dest = Path(output_dir)
    dest.mkdir(parents=True, exist_ok=True)

    lines = ["# DAST Security Scan Results", ""]
    lines.append(f"**Targets:** {summary.target_count} | "
                 f"**Healthy:** {summary.healthy_count} | "
                 f"**Findings:** {summary.total_count}")
    lines.append("")

    for r in summary.results:
        if not r.healthy:
            lines.append(f"### {r.name} — Target not healthy")
            lines.append(f"URL: `{r.target_url}`")
            lines.append("")
            continue

        lines.append(f"### {r.name} — {len(r.findings)} finding(s)")
        lines.append(f"URL: `{r.target_url}`")
        lines.append("")
        if r.findings:
            lines.append("| Severity | Finding | Location | CWE |")
            lines.append("|----------|---------|----------|-----|")
            for f in sorted(r.findings, key=lambda x: -x.severity._order):
                sev = f.severity.value.upper()
                lines.append(f"| {sev} | {f.title} | {f.location or '-'} | {f.cwe or '-'} |")
            lines.append("")

    (dest / "dast-scan.md").write_text("\n".join(lines))


def _write_dast_json(summary, output_dir) -> None:
    """Write DAST scan JSON report."""
    import json
    dest = Path(output_dir)
    dest.mkdir(parents=True, exist_ok=True)
    data = {
        "target_count": summary.target_count,
        "healthy_count": summary.healthy_count,
        "total_findings": summary.total_count,
        "critical_count": summary.critical_count,
        "high_count": summary.high_count,
        "medium_count": summary.medium_count,
        "low_count": summary.low_count,
        "info_count": summary.info_count,
        "results": [
            {
                "name": r.name,
                "target_url": r.target_url,
                "healthy": r.healthy,
                "finding_count": len(r.findings),
                "critical_count": r.critical_count,
                "high_count": r.high_count,
                "medium_count": r.medium_count,
                "low_count": r.low_count,
                "info_count": r.info_count,
            }
            for r in summary.results
        ],
    }
    (dest / "dast-scan.json").write_text(json.dumps(data, indent=2))


def _print_container_terminal(summary) -> None:
    """Print container scan results to terminal."""
    print("\n" + "=" * 50)
    print("  Container Security Scan Results")
    print("=" * 50 + "\n")
    print(f"Containers scanned:  {summary.container_count}")
    print(f"Build failures:      {summary.build_failures}")
    scan_failures = getattr(summary, "scan_failures", 0)
    if scan_failures:
        print(f"Scanner failures:    {scan_failures}")
    print(f"Total findings:      {summary.total_count}")
    print(f"Unique findings:     {summary.unique_count}")
    print()
    for r in summary.results:
        if not r.build_success:
            status = "BUILD FAILED"
        elif getattr(r, "scanner_errors", {}):
            failed = ", ".join(r.scanner_errors.keys())
            status = f"SCAN FAILED ({failed})"
        else:
            status = f"{r.total_count} findings"
        print(f"  {r.name:<20} {status}")
        for tool, err in getattr(r, "scanner_errors", {}).items():
            # Truncate long error messages for terminal readability
            short = err[:120] + "..." if len(err) > 120 else err
            print(f"    {tool}: {short}")
    print()


def _write_container_json(summary, output_dir) -> None:
    """Write container scan results as JSON."""
    import json
    dest = Path(output_dir)
    dest.mkdir(parents=True, exist_ok=True)
    data = {
        "container_count": summary.container_count,
        "build_failures": summary.build_failures,
        "total_findings": summary.total_count,
        "unique_findings": summary.unique_count,
        "results": [
            {
                "name": r.name,
                "image_ref": r.image_ref,
                "build_success": r.build_success,
                "critical": r.critical_count,
                "high": r.high_count,
                "medium": r.medium_count,
                "low": r.low_count,
                "total": r.total_count,
                "unique": r.unique_count,
            }
            for r in summary.results
        ],
    }
    filepath = dest / "container-scan.json"
    filepath.write_text(json.dumps(data, indent=2))


def cmd_report(args: argparse.Namespace) -> int:
    """Execute the report subcommand."""
    results_dir = Path(args.results_dir)
    if not results_dir.is_dir():
        print(f"Error: results directory not found: {results_dir}", file=sys.stderr)
        return EXIT_ERROR

    output_dir = Path(args.output_dir) if args.output_dir else results_dir

    try:
        from argus.reporters import get_reporter
        reporter = get_reporter(args.format)
    except (ImportError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        import json
        # ``argus scan`` writes to ``<results_dir>/<timestamp>/argus-
        # results.json`` and updates a ``latest`` symlink. The previous
        # default lookup looked at ``<results_dir>/argus-results.json``
        # directly, which never existed for fresh scans (issue #168-K).
        # Try the flat layout first (back-compat with CI matrix output
        # and explicit ``-r`` pointing at a run dir) then fall back to
        # following the ``latest`` symlink.
        json_file = results_dir / "argus-results.json"
        if not json_file.exists():
            latest = results_dir / "latest" / "argus-results.json"
            if latest.exists():
                json_file = latest
            else:
                print(
                    f"Error: no argus-results.json found at {results_dir!s} "
                    f"or {results_dir / 'latest'!s}/. Did you run "
                    f"`argus scan` first?",
                    file=sys.stderr,
                )
                return EXIT_ERROR

        from argus.core.models import ScanSummary
        data = json.loads(json_file.read_text())
        summary = ScanSummary.from_dict(data) if hasattr(ScanSummary, "from_dict") else None
        if summary is None:
            print("Error: cannot reconstruct ScanSummary from JSON", file=sys.stderr)
            return EXIT_ERROR
        reporter.report(summary, str(output_dir))
    except Exception as exc:
        print(f"Error: report generation failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.verbose:
        print(f"Report generated: {output_dir}")

    return EXIT_SUCCESS


def cmd_completion(args: argparse.Namespace) -> int:
    """Generate shell completion script, printed to stdout."""
    try:
        from argus.scanners import SCANNER_REGISTRY
        scanners = " ".join(sorted(SCANNER_REGISTRY.keys()))
    except ImportError:
        scanners = "bandit checkov clamav gitleaks opengrep osv trivy-iac"

    if args.shell == "zsh":
        print(_generate_zsh_completion(scanners))
    elif args.shell == "bash":
        print(_generate_bash_completion(scanners))
    return EXIT_SUCCESS


def cmd_cache(args: argparse.Namespace) -> int:
    """Manage scanner database caches."""
    from argus.containers import CACHE_MOUNTS, _default_cache_root

    cache_root = _default_cache_root()
    action = getattr(args, "cache_action", None)

    if action == "clean":
        if cache_root.exists():
            import shutil
            shutil.rmtree(cache_root)
            print(f"Removed cache directory: {cache_root}")
        else:
            print("No cache directory found.")
        return EXIT_SUCCESS

    # Default: info
    print(f"Cache directory: {cache_root}")
    if os.environ.get("ARGUS_CACHE_DIR"):
        print(f"  (set by ARGUS_CACHE_DIR)")
    print()

    total_size = 0
    empty_existing = 0
    for scanner_key in sorted(CACHE_MOUNTS):
        scanner_dir = cache_root / scanner_key
        if not scanner_dir.exists():
            print(f"  {scanner_key:<15} (not cached)")
            continue
        size = sum(f.stat().st_size for f in scanner_dir.rglob("*") if f.is_file())
        total_size += size
        if size == 0:
            # The directory was created by ``get_cache_mount`` (so the
            # mount could be wired up) but the scanner wrote nothing
            # into it. Distinguishing this from "not cached" gives the
            # user a hint that the mount happened but the scanner
            # isn't using it — see issue #168-M.
            print(f"  {scanner_key:<15} 0 B (mount empty)")
        else:
            print(f"  {scanner_key:<15} {_format_size(size)}")

    print(f"\n  {'Total':<15} {_format_size(total_size)}")
    if total_size == 0 and empty_existing == 0:
        # Inspect whether any of the dirs exist at all — if they do,
        # the scanner ran with the mount but didn't write to it.
        empty_dirs = [k for k in CACHE_MOUNTS if (cache_root / k).exists()]
        if empty_dirs:
            print(
                f"\nNote: directories exist for {', '.join(empty_dirs)} but "
                "are empty. Three possibilities, in order of likelihood: "
                "(1) the scanner didn't trigger a cache-populating operation "
                "during the recent run — e.g. ``trivy-iac`` scans config files "
                "without touching the vuln DB so /root/.cache/trivy stays empty; "
                "(2) the scanner stores its cache at a path argus doesn't mount; "
                "(3) the container process runs as a non-root user and can't write "
                "to the host-owned mount. Run a vuln-DB-driven scan (``argus scan "
                "grype --sbom <sbom>``) to verify the cache surfaces are wired. "
                "Tracked in issue #168-M."
            )
    return EXIT_SUCCESS


def _format_size(size_bytes: int) -> str:
    """Format byte count as human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    if size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def cmd_mcp(args: argparse.Namespace) -> int:
    """Start the MCP server for AI assistant integration.

    The server speaks JSON-RPC over stdin/stdout (the standard MCP
    stdio transport), so anything written to stdout would corrupt
    the protocol. Startup feedback goes to stderr instead — visible
    to humans running ``argus mcp`` directly, captured in MCP
    clients' subprocess logs, never seen by the protocol parser.
    """
    try:
        from argus.mcp import create_server
    except ImportError:
        print(
            "Error: MCP dependencies not installed.\n"
            "Install with: pip install argus-security[mcp]",
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Always log the startup line — MCP clients pipe stderr to their
    # logs, so it's useful as a "server started" marker there too.
    print(
        "argus MCP server starting on stdio transport — awaiting client messages...",
        file=sys.stderr,
        flush=True,
    )
    if sys.stderr.isatty():
        # Interactive invocation: explain what to do next so the user
        # doesn't think the command has hung.
        print(
            "\n  This is correct behavior. The server reads JSON-RPC messages from"
            "\n  stdin and writes responses to stdout — that's how MCP clients"
            "\n  (Claude Desktop, Cursor, Claude Code, etc.) talk to it."
            "\n"
            "\n  Configure your client to launch:  argus mcp"
            "\n  Press Ctrl+C to exit.",
            file=sys.stderr,
            flush=True,
        )

    server = create_server()
    try:
        server.run(transport="stdio")
    except KeyboardInterrupt:
        # Clean exit on Ctrl+C — only meaningful when run interactively;
        # MCP clients close the subprocess via stdin EOF instead.
        print("\nargus MCP server stopped.", file=sys.stderr, flush=True)
    return EXIT_SUCCESS


def _generate_zsh_completion(scanners: str) -> str:
    """Generate zsh completion script from current scanner registry."""
    return f'''#compdef argus
# Generated by: argus completion zsh

_argus() {{
    local -a commands scanners severity formats

    commands=(
        'init:Initialize argus.yml for the current project'
        'scan:Run security scanners against a target'
        'classify:Classify IaC changes for compliance reporting'
        'collect:Collect and merge results from parallel CI jobs'
        'report:Generate reports from existing scan results'
        'validate:Validate an argus.yml configuration file'
        'mcp:Start the MCP server for AI assistant integration'
        'completion:Generate shell completion script'
        'cache:Manage scanner database caches'
        'view:Open a viewer (terminal UI or browser) on existing scan results'
    )

    scanners=({scanners})
    severity=(critical high medium low none)
    formats=(terminal markdown sarif json github gitlab junit)
    interfaces=(terminal browser)

    _arguments -C \\
        '--version[Show version]' \\
        '--help[Show help]' \\
        '1:command:->command' \\
        '*::arg:->args'

    case "$state" in
        command)
            _describe 'command' commands
            ;;
        args)
            case "${{words[1]}}" in
                scan)
                    local -a scan_common scan_container scan_dast scan_args

                    scan_common=(
                        '1:scanner:($scanners)'
                        '(-p --path)'{{-p,--path}}'[Path to scan]:path:_files -/'
                        '(-c --config)'{{-c,--config}}'[Path to argus.yml]:config:_files'
                        '(-o --output-dir)'{{-o,--output-dir}}'[Output directory]:dir:_files -/'
                        '(-s --severity-threshold)'{{-s,--severity-threshold}}'[Fail threshold]:severity:($severity)'
                        '(-f --format)'{{-f,--format}}'[Output format]:format:($formats)'
                        '--output-vars[Write counts to file]:file:_files'
                        '--list[List available scanners]'
                        '(-v --verbose)'{{-v,--verbose}}'[Enable verbose output]'
                        '--no-spinner[Disable spinner]'
                        '--no-timestamp[Flat output directory]'
                        '--fail-fast[Abort on first failure]'
                        '--fail-on-scanner-error[Exit non-zero if any scanner produced no output]'
                        '--timeout[Per-scanner timeout]:seconds:'
                        '--no-parallel[Run scanners sequentially]'
                        '--allow-local-versions[Skip version enforcement]'
                        '--no-cache[Disable DB cache volume mounts]'
                        '(-i --interface)'{{-i,--interface}}'[Open viewer after scan]:interface:($interfaces)'
                    )

                    scan_container=(
                        '--image[Container image to scan]:image:'
                        '--discover[Discover Dockerfiles]:path:_files -/'
                        '--scanners[Sub-scanners (trivy,grype,syft)]:scanners:'
                    )

                    scan_dast=(
                        '--target[URL to scan]:url:'
                        '--image[Container image to scan]:image:'
                        '--port[Override exposed port]:port:'
                        '--env[Environment variable]:env:'
                        '--scan-type[ZAP scan type]:type:(baseline full)'
                        '--startup-timeout[Target startup timeout]:seconds:'
                    )

                    scan_args=("${{scan_common[@]}}")
                    case "${{words[2]}}" in
                        container) scan_args+=("${{scan_container[@]}}") ;;
                        zap)       scan_args+=("${{scan_dast[@]}}") ;;
                    esac

                    _arguments "${{scan_args[@]}}"
                    ;;
                report)
                    _arguments \\
                        '1:format:($formats)' \\
                        '(-r --results-dir)'{{-r,--results-dir}}'[Results directory]:dir:_files -/' \\
                        '(-o --output-dir)'{{-o,--output-dir}}'[Output directory]:dir:_files -/' \\
                        '(-v --verbose)'{{-v,--verbose}}'[Enable verbose output]'
                    ;;
                validate)
                    _arguments \\
                        '(-c --config)'{{-c,--config}}'[Path to argus.yml]:config:_files' \\
                        '--check-tools[Check scanner availability]' \\
                        '--strict[Treat warnings as errors]'
                    ;;
                init)
                    _arguments \\
                        '--platform[Generate CI workflow]:platform:(github gitlab jenkins none)' \\
                        '--force[Overwrite existing config]' \\
                        '--no-detect[Skip auto-detection]'
                    ;;
                collect)
                    _arguments \\
                        '1:input directory:_files -/' \\
                        '(-o --output-dir)'{{-o,--output-dir}}'[Output directory]:dir:_files -/' \\
                        '(-v --verbose)'{{-v,--verbose}}'[Enable verbose output]'
                    ;;
                completion)
                    _arguments '1:shell:(bash zsh)'
                    ;;
                view)
                    _arguments \\
                        '1:interface:($interfaces)' \\
                        '2:path:_files -/' \\
                        '(-i --interface)'{{-i,--interface}}'[Interface to open]:interface:($interfaces)' \\
                        '--port[TCP port for browser interface]:port:' \\
                        '--no-open[Skip auto-opening the default web browser]'
                    ;;
            esac
            ;;
    esac
}}

compdef _argus argus 2>/dev/null'''


def _generate_bash_completion(scanners: str) -> str:
    """Generate bash completion script from current scanner registry."""
    return f'''#!/bin/bash
# Generated by: argus completion bash

_argus_completions() {{
    local cur prev commands scanners severity formats
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"

    commands="init scan classify collect report validate mcp completion cache view"
    scanners="{scanners}"
    severity="critical high medium low none"
    formats="terminal markdown sarif json github gitlab junit"
    interfaces="terminal browser"

    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=($(compgen -W "$commands --version --help" -- "$cur"))
        return
    fi

    local subcmd="${{COMP_WORDS[1]}}"

    case "$subcmd" in
        scan)
            if [ "$COMP_CWORD" -eq 2 ] && [[ "$cur" != -* ]]; then
                COMPREPLY=($(compgen -W "$scanners --list --help" -- "$cur"))
                return
            fi
            case "$prev" in
                --severity-threshold|-s) COMPREPLY=($(compgen -W "$severity" -- "$cur")); return ;;
                --format|-f) COMPREPLY=($(compgen -W "$formats" -- "$cur")); return ;;
                --interface|-i) COMPREPLY=($(compgen -W "$interfaces" -- "$cur")); return ;;
                --scan-type) COMPREPLY=($(compgen -W "baseline full" -- "$cur")); return ;;
                --path|-p|--output-dir|-o|--config|-c|--output-vars) COMPREPLY=($(compgen -d -- "$cur")); return ;;
            esac
            COMPREPLY=($(compgen -W "--path --config --output-dir --severity-threshold --format --interface --output-vars --list --verbose --no-spinner --no-timestamp --fail-fast --fail-on-scanner-error --timeout --no-cache --no-parallel --allow-local-versions" -- "$cur"))
            ;;
        report)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=($(compgen -W "$formats" -- "$cur")); return
            fi
            COMPREPLY=($(compgen -W "--results-dir --output-dir --verbose" -- "$cur"))
            ;;
        validate) COMPREPLY=($(compgen -W "--config --check-tools --strict" -- "$cur")) ;;
        init)
            case "$prev" in
                --platform) COMPREPLY=($(compgen -W "github gitlab jenkins none" -- "$cur")); return ;;
            esac
            COMPREPLY=($(compgen -W "--platform --force --no-detect" -- "$cur"))
            ;;
        collect) COMPREPLY=($(compgen -W "--output-dir --verbose" -- "$cur")) ;;
        completion) COMPREPLY=($(compgen -W "bash zsh" -- "$cur")) ;;
        view)
            if [ "$COMP_CWORD" -eq 2 ] && [[ "$cur" != -* ]]; then
                COMPREPLY=($(compgen -W "$interfaces --help" -- "$cur"))
                return
            fi
            case "$prev" in
                --interface|-i) COMPREPLY=($(compgen -W "$interfaces" -- "$cur")); return ;;
                --port) return ;;
            esac
            COMPREPLY=($(compgen -W "--interface --port --no-open" -- "$cur"))
            ;;
    esac
}}

complete -F _argus_completions argus'''


def _write_output_vars(summary, filepath: str) -> None:
    """Write scan result counts as key=value pairs to a file.

    Format is compatible with GitHub Actions ($GITHUB_OUTPUT),
    GitLab CI (dotenv artifacts), and shell `source`.
    """
    lines = [
        f"critical_count={summary.critical_count}",
        f"high_count={summary.high_count}",
        f"medium_count={summary.medium_count}",
        f"low_count={summary.low_count}",
        f"info_count={summary.info_count}",
        f"total_count={summary.total_count}",
        f"issue_count={summary.total_count}",
        f"findings_count={summary.total_count}",
        f"passed={'true' if summary.passed else 'false'}",
    ]

    # Per-scanner counts when running a single scanner
    if len(summary.results) == 1:
        r = summary.results[0]
        lines.append(f"scanner={r.scanner}")

    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    Path(filepath).write_text("\n".join(lines) + "\n")


def _list_scanners(engine) -> int:
    """Print registered scanners with availability status."""
    import shutil
    from argus.containers import get_image

    scanners = getattr(engine, "_scanners", {})
    if not scanners:
        print("No scanners registered.")
        print(
            "\nInstall scanner plugins or check your configuration.\n"
            "See: https://github.com/huntridge-labs/argus#supported-scanners"
        )
        return EXIT_SUCCESS

    container_ok = any(shutil.which(r) for r in ("docker", "podman", "nerdctl"))
    backend = engine.config.execution.backend

    print("Available scanners:\n")
    for name, scanner in sorted(scanners.items()):
        local = scanner.is_available()
        image = get_image(name) or getattr(scanner, "container_image", "")

        if local:
            status = "local"
        elif image and container_ok and backend != "local":
            status = "container"
        elif image and not container_ok:
            status = "no docker"
        else:
            status = "not found"

        description = getattr(scanner, "description", "")
        print(f"  {name:<20} [{status:<10}]  {description}")

    print()
    if not container_ok and backend != "local":
        print("  No container runtime found (docker, podman, or nerdctl) — container-only scanners will be unavailable.")
    print(f"  Backend: {backend}")

    return EXIT_SUCCESS


_SCHEMA_DIRECTIVE_RE = re.compile(
    r"^\s*#\s*yaml-language-server\s*:\s*\$schema\s*=", re.IGNORECASE,
)


def _has_schema_directive(raw_text: str, head_lines: int = 5) -> bool:
    """Return True if the raw YAML has a ``# yaml-language-server:`` directive near the top.

    Editors recognize the directive only when it sits in the first
    handful of lines, so we don't bother scanning the entire file.
    Tolerant about leading blank lines and a possible UTF-8 BOM.
    """
    for line in raw_text.splitlines()[:head_lines]:
        if _SCHEMA_DIRECTIVE_RE.match(line):
            return True
    return False


def cmd_validate(args: argparse.Namespace) -> int:
    """Execute the validate subcommand — check config file."""
    import yaml
    from argus.core.schema import validate_config, ConfigError

    # Find config file
    config_path = args.config
    if config_path is None:
        for name in ["argus.yml", "argus.yaml", ".argus.yml", ".argus.yaml"]:
            if Path(name).exists():
                config_path = name
                break

    if config_path is None:
        print("No argus.yml found. Create one or specify with --config.", file=sys.stderr)
        return EXIT_ERROR

    if not Path(config_path).exists():
        print(f"Config file not found: {config_path}", file=sys.stderr)
        return EXIT_ERROR

    # Load and validate. Also peek at the raw text first so we can
    # check the schema-directive comment that yaml.safe_load discards
    # (it's a YAML comment, not a key).
    try:
        with open(config_path, "r") as fh:
            raw_text = fh.read()
    except OSError as exc:
        print(f"Could not read {config_path}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        from argus.core.config import load_strict_yaml
        data = load_strict_yaml(raw_text)
    except yaml.YAMLError as exc:
        print(f"Invalid YAML in {config_path}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not isinstance(data, dict):
        print(f"Config must be a YAML mapping, got {type(data).__name__}", file=sys.stderr)
        return EXIT_ERROR

    errors = validate_config(data)
    warnings = [e for e in errors if e.level == "warning"]
    fatal = [e for e in errors if e.level == "error"]

    # IDE-schema directive — check the first few lines for the
    # ``# yaml-language-server: $schema=...`` comment that drives
    # in-editor validation in VS Code, IntelliJ, and other tools that
    # speak the language-server-protocol YAML spec. Soft warning so a
    # user editing argus.yml without an IDE isn't penalized.
    if not _has_schema_directive(raw_text):
        warnings.append(ConfigError(
            "",
            "Missing IDE schema directive. Add this as the first line "
            "of your argus.yml so editors get inline validation: "
            "# yaml-language-server: $schema="
            "https://raw.githubusercontent.com/huntridge-labs/argus/main/argus-config.schema.json",
            level="warning",
        ))

    strict = getattr(args, "strict", False)
    report_issue = getattr(args, "report_issue", False)

    if not warnings and not fatal:
        print(f"✅ {config_path} is valid")
    else:
        for w in warnings:
            print(f"⚠️  {w}")
        for e in fatal:
            print(f"❌ {e}")

        if fatal:
            print(f"\n{len(fatal)} error(s), {len(warnings)} warning(s). Fix and retry.")
        elif strict and warnings:
            print(f"\n❌ {len(warnings)} warning(s) treated as errors (--strict)")
        else:
            print(f"\n✅ {config_path} is valid ({len(warnings)} warning(s))")

    # Show summary with enabled/disabled breakdown
    scanners = data.get("scanners", {})
    enabled_names = []
    disabled_names = []
    for name, cfg in scanners.items():
        if isinstance(cfg, dict) and not cfg.get("enabled", True):
            disabled_names.append(name)
        else:
            enabled_names.append(name)
    print(f"   Scanners: {len(enabled_names)} enabled, {len(disabled_names)} disabled")
    if enabled_names:
        print(f"     enabled:  {', '.join(enabled_names)}")
    if disabled_names:
        print(f"     disabled: {', '.join(disabled_names)}")
    fmt = data.get("reporting", {}).get("formats", ["terminal"])
    print(f"   Formats: {', '.join(fmt) if isinstance(fmt, list) else fmt}")
    backend = data.get("execution", {}).get("backend", "auto")
    print(f"   Backend: {backend}")

    # Containers: only printed when the block exists and is structurally
    # sound (validate already surfaced any errors above). The line gives
    # the user a "yes, your containers config was inspected" signal that
    # was missing — without it, a typo'd top-level key like ``containerz``
    # used to fail silently here too.
    containers = data.get("containers")
    if isinstance(containers, dict):
        images = containers.get("images") or []
        discover = containers.get("discover", False)
        search_paths = containers.get("search_paths") or []
        parts = []
        if isinstance(images, list) and images:
            parts.append(f"{len(images)} image(s)")
        if discover:
            paths_str = ", ".join(search_paths) if search_paths else "."
            parts.append(f"discover from {paths_str}")
        summary = " + ".join(parts) if parts else "no targets"
        print(f"   Containers: {summary}")
        if isinstance(images, list) and images:
            for entry in images:
                if not isinstance(entry, dict):
                    continue
                ref = entry.get("image") or entry.get("dockerfile") or "<unknown>"
                print(f"     - {ref}")

    # Tool readiness check
    unavailable = []
    tool_statuses = []
    if getattr(args, "check_tools", False) and enabled_names:
        registry = data.get("execution", {}).get("registry", "")
        unavailable, tool_statuses = _check_tool_readiness(enabled_names, backend, registry)
        if unavailable and strict:
            print(f"\n❌ {len(unavailable)} scanner(s) unavailable (--strict)")

    # Living issue reporting (runs before exit so the issue captures full state)
    if report_issue:
        _report_issue(
            config_path=config_path,
            errors=[str(e) for e in fatal],
            warnings=[str(w) for w in warnings],
            tool_statuses=tool_statuses,
            unavailable=unavailable,
            strict=strict,
        )

    if fatal:
        return EXIT_ERROR
    if strict and warnings:
        return EXIT_ERROR
    if unavailable and strict:
        return EXIT_ERROR
    return EXIT_SUCCESS


def _check_tool_readiness(
    enabled_names: list[str], backend: str, registry: str = ""
) -> tuple[list[str], list]:
    """Check whether enabled scanners can actually run.

    Returns (unavailable_names, tool_statuses). Pure detection lives in
    `argus.preflight.tool_check`; this wrapper handles the detailed
    per-scanner output specific to `argus validate --check-tools`.
    """
    from argus.scanners import SCANNER_REGISTRY
    from argus.preflight.tool_check import (
        check_scanner_readiness,
        container_runtime_available,
        unavailable_names,
    )

    statuses = check_scanner_readiness(enabled_names, backend=backend, registry=registry)

    if registry:
        print(f"\n   Registry: {registry}")
    print("\n   Tool readiness:")
    for status in statuses:
        name = status.name
        cls = SCANNER_REGISTRY.get(name)
        if cls is None:
            print(f"     {name}: ⚠️  unknown scanner (not in registry)")
        elif status.available and status.method == "local":
            print(f"     {name}: ✅ installed locally")
        elif status.available and status.method == "container":
            print(f"     {name}: 🐳 will use container ({status.image})")
        else:
            install_cmd = cls().install_command() or "see docs"
            if backend == "local":
                print(f"     {name}: ❌ not found (install: {install_cmd})")
            elif not container_runtime_available():
                print(f"     {name}: ❌ not found, Docker not available (install: {install_cmd})")
            else:
                print(f"     {name}: ❌ not found, no container image (install: {install_cmd})")

        for dep in status.network_deps:
            print(f"             ℹ️  Requires network: {dep}")

    if not container_runtime_available() and backend != "local":
        print(
            "\n   ⚠️  No container runtime found (docker, podman, or nerdctl) — "
            "scanners without local installs will fail"
        )
        print(
            "      Install Docker, Podman, or nerdctl — or set execution.backend: local in argus.yml"
        )

    return unavailable_names(statuses), statuses


def _report_issue(
    config_path: str,
    errors: list[str],
    warnings: list[str],
    tool_statuses: list,
    unavailable: list[str],
    strict: bool,
) -> None:
    """Create, update, or close a living issue on GitHub/GitLab.

    Never raises — all failures are logged as warnings.
    """
    from argus.preflight.ci_provider import detect_ci_provider
    from argus.preflight.issue_reporter import get_issue_reporter
    from argus.preflight.report_body import build_issue_body, is_all_healthy

    ctx = detect_ci_provider()
    reporter = get_issue_reporter(ctx)
    if reporter is None:
        return

    healthy = is_all_healthy(errors, warnings, unavailable, strict=strict)
    existing = reporter.find_issue()

    if healthy:
        if existing:
            if reporter.close_issue(existing["number"]):
                print(f"\n   ✅ Closed issue #{existing['number']} — all checks pass")
            else:
                print(f"\n   ⚠️  Failed to close issue #{existing['number']}", file=sys.stderr)
        else:
            print("\n   ✅ All checks pass — no issue to report")
    else:
        body = build_issue_body(config_path, errors, warnings, tool_statuses)
        if existing:
            if reporter.update_issue(existing["number"], body):
                print(f"\n   📝 Updated issue #{existing['number']}: {existing.get('url', '')}")
            else:
                print(f"\n   ⚠️  Failed to update issue #{existing['number']}", file=sys.stderr)
        else:
            result = reporter.create_issue(body)
            if result:
                print(f"\n   📝 Created issue #{result['number']}: {result.get('url', '')}")
            else:
                print("\n   ⚠️  Failed to create issue", file=sys.stderr)


def cmd_collect(args: argparse.Namespace) -> int:
    """Execute the collect subcommand — merge parallel CI results."""
    from argus.collect import collect_results
    from argus.audit import get_logger

    log = get_logger("argus.collect", verbose=args.verbose)
    log.info("Collecting results from %s", args.input_dir)

    try:
        output = collect_results(
            input_dir=args.input_dir,
            output_dir=args.output_dir,
        )
        log.info("Audit package written to %s", output)
        return EXIT_SUCCESS
    except Exception as exc:
        log.error("Collection failed: %s", exc)
        return EXIT_ERROR


def _get_version() -> str:
    """Return the package version string."""
    try:
        from argus import __version__
        return f"argus {__version__}"
    except ImportError:
        return "argus (unknown version)"


def _show_scanner_help(scanner_name: str) -> None:
    """Print scanner-specific help by introspecting the scanner module."""
    try:
        from argus.scanners import SCANNER_REGISTRY
        cls = SCANNER_REGISTRY.get(scanner_name)
        if cls is None:
            print(f"Unknown scanner: {scanner_name}")
            print(f"Available scanners: {', '.join(sorted(SCANNER_REGISTRY))}")
            sys.exit(EXIT_ERROR)

        scanner = cls()
        print(f"argus scan {scanner_name}")
        print(f"{'=' * (len(scanner_name) + 11)}")
        print()

        # Description from docstring
        doc = (cls.__doc__ or "").strip()
        if doc:
            print(doc)
            print()

        # Key info
        print(f"  Tool:           {scanner_name}")
        available = scanner.is_available()
        print(f"  Installed:      {'yes' if available else 'no'}")

        install = scanner.install_command()
        if install and not available:
            print(f"  Install:        {install}")

        image = getattr(scanner, "container_image", "")
        if image:
            print(f"  Container:      {image}")

        print()
        print("Usage:")
        print(f"  argus scan {scanner_name}                    # scan current directory")
        print(f"  argus scan {scanner_name} --path src/        # scan specific path")
        print(f"  argus scan {scanner_name} --config argus.yml # use config file")
        print(f"  argus scan {scanner_name} --verbose          # debug output")
        print()
        print("Common options:")
        print("  --path, -p PATH                 Path to scan (default: .)")
        print("  --config, -c FILE               Path to argus.yml config")
        print("  --output-dir, -o DIR            Output directory (default: ./argus-results)")
        print("  --severity-threshold, -s LEVEL  Fail threshold (critical/high/medium/low/none)")
        print("  --format, -f FORMAT             Output format (terminal/markdown/sarif/json)")
        print("  --verbose, -v                   Enable debug output")

    except ImportError:
        print(f"Scanner '{scanner_name}' — unable to load scanner module")

    sys.exit(EXIT_SUCCESS)


def _show_logo_easter_egg() -> int:
    """Render the Argus logo banner with a scroll effect.

    Hidden trigger: `argus __logo`
    Not part of argparse, so it stays out of generated docs/help text.
    """
    try:
        from argus.init import _load_banner
        lines = _load_banner().splitlines()
    except Exception:
        lines = [
            "\033[1;32mA R G U S\033[0m",
            "\033[90mPerception is Protection\033[0m",
        ]

    for line in lines:
        print(line, file=sys.stderr)
        time.sleep(0.06 if line.strip() else 0.15)
    print(file=sys.stderr)

    return EXIT_SUCCESS


def main(argv: list[str] | None = None) -> None:
    """CLI entry point. Parse arguments and dispatch to the appropriate subcommand."""
    # Intercept `argus scan <name> --help` before argparse exits
    raw_args = list(argv) if argv is not None else list(sys.argv[1:])
    if len(raw_args) >= 1 and raw_args[0] == "__logo":
        sys.exit(_show_logo_easter_egg())

    # Hidden inline trigger: allow `argus <command> ... __logo`.
    # Keep this out of argparse so it remains undocumented.
    if "__logo" in raw_args[1:]:
        _show_logo_easter_egg()
        raw_args = [
            token for i, token in enumerate(raw_args)
            if not (i > 0 and token == "__logo")
        ]

    if (len(raw_args) >= 3
        and raw_args[0] == "scan"
        and raw_args[-1] in ("--help", "-h")
        and raw_args[1] not in ("--help", "-h", "--list")):
        scanner_name = raw_args[1]
        _show_scanner_help(scanner_name)

    parser = build_parser()

    # Enable shell tab completion (requires: pip install argcomplete)
    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    args = parser.parse_args(raw_args)

    if args.command is None:
        parser.print_help()
        sys.exit(EXIT_SUCCESS)

    handlers = {
        "init": cmd_init,
        "scan": cmd_scan,
        "classify": cmd_classify,
        "collect": cmd_collect,
        "report": cmd_report,
        "validate": cmd_validate,
        "mcp": cmd_mcp,
        "completion": cmd_completion,
        "cache": cmd_cache,
        "view": cmd_view,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(EXIT_ERROR)

    sys.exit(handler(args))
