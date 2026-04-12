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
    _build_container_parser(subparsers)
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


def _build_container_parser(subparsers: argparse._SubParsersAction) -> None:
    """Add the 'container' subcommand for container image scanning."""
    container_parser = subparsers.add_parser(
        "container",
        help="Scan container images for vulnerabilities",
        description=(
            "Discover Dockerfiles, build images, scan with Trivy + Grype, "
            "deduplicate findings, and generate reports."
        ),
    )
    container_parser.add_argument(
        "images",
        nargs="*",
        help="Image references to scan (e.g., nginx:latest myapp:v1). "
             "If omitted, discovers Dockerfiles or reads from config.",
    )
    container_parser.add_argument(
        "--discover",
        nargs="?",
        const=".",
        default=None,
        metavar="PATH",
        help="Discover Dockerfiles in PATH (default: current directory)",
    )
    container_parser.add_argument(
        "--config", "-c",
        default=None,
        help="Path to argus.yml config file",
    )
    container_parser.add_argument(
        "--output-dir", "-o",
        default=None,
        help="Output directory for reports (default: ./argus-results)",
    )
    container_parser.add_argument(
        "--format", "-f",
        dest="formats",
        action="append",
        choices=["terminal", "markdown", "sarif", "json"],
        help="Output format (can be repeated). Default: terminal + markdown",
    )
    container_parser.add_argument(
        "--severity-threshold", "-s",
        choices=SEVERITY_CHOICES,
        help="Fail threshold (default from config or none)",
    )
    container_parser.add_argument(
        "--scanners",
        default="trivy,grype",
        help="Comma-separated sub-scanners: trivy,grype,syft (default: trivy,grype)",
    )
    container_parser.add_argument(
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


def cmd_container(args: argparse.Namespace) -> int:
    """Execute the container subcommand."""
    from argus.container import ContainerEngine
    from argus.reporters.container_markdown import ContainerMarkdownReporter

    # Build config from args
    config = {}

    if args.config:
        try:
            import yaml
            with open(args.config, "r") as fh:
                file_config = yaml.safe_load(fh) or {}
            config = file_config.get("containers", {})
        except Exception as exc:
            print(f"Error loading config: {exc}", file=sys.stderr)
            return EXIT_ERROR

    # CLI overrides
    if args.images:
        config["images"] = [{"image": img, "name": img.split(":")[0].split("/")[-1]} for img in args.images]
    if args.discover is not None:
        config["discover"] = True
        config["search_paths"] = [args.discover]
    if args.scanners:
        config["scanners"] = [s.strip() for s in args.scanners.split(",")]

    output_dir = args.output_dir or config.get("output_dir", "./argus-results")
    formats = args.formats or ["terminal", "markdown"]

    # Run the container engine
    try:
        engine = ContainerEngine(config)
        summary = engine.run()
    except Exception as exc:
        print(f"Error: container scan failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Generate reports
    for fmt in formats:
        if fmt == "markdown":
            reporter = ContainerMarkdownReporter()
            filepath = reporter.report(summary, output_dir)
            if args.verbose:
                print(f"Markdown report: {filepath}")
        elif fmt == "terminal":
            _print_container_terminal(summary)
        elif fmt == "json":
            _write_container_json(summary, output_dir)
        elif fmt == "sarif":
            # Reuse the generic SARIF reporter with combined findings
            from argus.core.models import ScanResult, ScanSummary
            from argus.reporters import get_reporter
            results = []
            for r in summary.results:
                results.append(ScanResult(
                    scanner=f"container/{r.name}",
                    findings=r.combined_findings,
                ))
            scan_summary = ScanSummary(results=results)
            sarif_reporter = get_reporter("sarif")
            sarif_reporter.report(scan_summary, output_dir)

    # Exit code based on severity threshold
    if args.severity_threshold and args.severity_threshold != "none":
        from argus.core.models import Severity
        threshold = Severity.from_string(args.severity_threshold)
        for r in summary.results:
            for f in r.combined_findings:
                if f.severity >= threshold:
                    return EXIT_FINDINGS
    return EXIT_SUCCESS


def _print_container_terminal(summary) -> None:
    """Print container scan results to terminal."""
    print("\n" + "=" * 50)
    print("  Container Security Scan Results")
    print("=" * 50 + "\n")
    print(f"Containers scanned: {summary.container_count}")
    print(f"Build failures:     {summary.build_failures}")
    print(f"Total findings:     {summary.total_count}")
    print(f"Unique findings:    {summary.unique_count}")
    print()
    for r in summary.results:
        status = "BUILD FAILED" if not r.build_success else f"{r.total_count} findings"
        print(f"  {r.name:<20} {status}")
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
        "container": cmd_container,
        "report": cmd_report,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(EXIT_ERROR)

    sys.exit(handler(args))
