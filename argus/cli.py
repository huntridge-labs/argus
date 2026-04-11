"""Argus CLI — command-line interface for security scanning."""

import argparse
import sys
from pathlib import Path

# Exit codes
EXIT_SUCCESS = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

SEVERITY_CHOICES = ["critical", "high", "medium", "low", "none"]
FORMAT_CHOICES = ["terminal", "markdown", "sarif", "json"]


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

    _build_scan_parser(subparsers)
    _build_report_parser(subparsers)

    return parser


def _build_scan_parser(subparsers: argparse._SubParsersAction) -> None:
    """Add the 'scan' subcommand."""
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run security scanners against a target path",
        description="Run one or more security scanners and generate results.",
    )
    scan_parser.add_argument(
        "scanner",
        nargs="?",
        default=None,
        help="Specific scanner to run (omit to run all enabled scanners)",
    )
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
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )


def _build_report_parser(subparsers: argparse._SubParsersAction) -> None:
    """Add the 'report' subcommand."""
    report_parser = subparsers.add_parser(
        "report",
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


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute the scan subcommand."""
    try:
        from argus.core import ArgusConfig, ArgusEngine, Severity
    except ImportError as exc:
        print(f"Error: failed to import argus core modules: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Load config
    try:
        config = ArgusConfig.load(args.config)
    except FileNotFoundError:
        print(
            f"Error: config file not found: {args.config}",
            file=sys.stderr,
        )
        return EXIT_ERROR
    except Exception as exc:
        print(f"Error: failed to load config: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Override config with CLI arguments
    if args.severity_threshold:
        config.reporting.severity_threshold = Severity.from_string(
            args.severity_threshold
        )
    if args.output_dir:
        config.reporting.output_dir = args.output_dir
    if args.formats:
        config.reporting.formats = args.formats

    # Build engine and register scanners
    engine = ArgusEngine(config)

    try:
        from argus.scanners import get_available_scanners
        for scanner_cls in get_available_scanners():
            engine.register_scanner(scanner_cls())
    except ImportError:
        if args.verbose:
            print("Warning: argus.scanners module not found; no scanners registered")

    # List mode — print scanners and exit
    if args.list:
        return _list_scanners(engine)

    # Run the scan
    try:
        scanner_names = [args.scanner] if args.scanner else None
        summary = engine.run(scanner_names=scanner_names, path=args.path)
    except Exception as exc:
        print(f"Error: scan failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Generate reports
    try:
        from argus.reporters import get_reporter
        for fmt in config.reporting.formats:
            reporter = get_reporter(fmt)
            reporter.report(summary, config.reporting.output_dir)
    except ImportError:
        if args.verbose:
            print("Warning: argus.reporters module not found; skipping report generation")

    return EXIT_SUCCESS if summary.passed else EXIT_FINDINGS


def cmd_report(args: argparse.Namespace) -> int:
    """Execute the report subcommand."""
    results_dir = Path(args.results_dir)
    if not results_dir.is_dir():
        print(
            f"Error: results directory not found: {results_dir}",
            file=sys.stderr,
        )
        return EXIT_ERROR

    output_dir = args.output_dir or args.results_dir

    try:
        from argus.reporters import get_reporter
    except ImportError:
        print(
            "Error: argus.reporters module not available",
            file=sys.stderr,
        )
        return EXIT_ERROR

    try:
        reporter = get_reporter(args.format)
        reporter.generate(results_dir=str(results_dir), output_dir=output_dir)
    except Exception as exc:
        print(f"Error: report generation failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.verbose:
        print(f"Report generated: {output_dir}")

    return EXIT_SUCCESS


def _list_scanners(engine) -> int:
    """Print registered scanners and return success."""
    scanners = getattr(engine, "_scanners", {})
    if not scanners:
        print("No scanners registered.")
        print(
            "\nInstall scanner plugins or check your configuration.\n"
            "See: https://github.com/huntridge-labs/argus#supported-scanners"
        )
        return EXIT_SUCCESS

    print("Available scanners:\n")
    for name, scanner in sorted(scanners.items()):
        description = getattr(scanner, "description", "")
        status = "enabled" if getattr(scanner, "enabled", True) else "disabled"
        print(f"  {name:<24} [{status}]  {description}")

    return EXIT_SUCCESS


def _get_version() -> str:
    """Return the package version string."""
    try:
        from argus import __version__
        return f"argus {__version__}"
    except ImportError:
        return "argus (unknown version)"


def main(argv: list[str] | None = None) -> None:
    """CLI entry point. Parse arguments and dispatch to the appropriate subcommand."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        sys.exit(EXIT_SUCCESS)

    handlers = {
        "scan": cmd_scan,
        "report": cmd_report,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(EXIT_ERROR)

    sys.exit(handler(args))
