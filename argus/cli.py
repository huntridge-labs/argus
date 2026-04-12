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

    _build_init_parser(subparsers)
    _build_scan_parser(subparsers)
    _build_collect_parser(subparsers)
    _build_report_parser(subparsers)
    _build_validate_parser(subparsers)

    return parser


def _build_init_parser(subparsers: argparse._SubParsersAction) -> None:
    """Add the 'init' subcommand for project initialization."""
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize argus.yml for the current project",
        description=(
            "Detect your project's languages, frameworks, and infrastructure,\n"
            "then generate a tailored argus.yml with the right scanners enabled.\n\n"
            "Examples:\n"
            "  argus init                          # auto-detect and generate argus.yml\n"
            "  argus init --platform github        # also generate GitHub Actions workflow\n"
            "  argus init --force                   # overwrite existing argus.yml\n"
            "  argus init --no-detect               # generate with defaults only\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    init_parser.add_argument(
        "--platform",
        choices=["github", "gitlab", "jenkins", "none"],
        default="none",
        help="Generate a CI workflow file for the specified platform (default: none)",
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
        platform=args.platform,
        force=args.force,
        detect=not args.no_detect,
    )


def _build_scan_parser(subparsers: argparse._SubParsersAction) -> None:
    """Add the 'scan' subcommand."""
    scan_parser = subparsers.add_parser(
        "scan",
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
    scan_parser.add_argument(
        "scanner",
        nargs="?",
        default=None,
        help="Specific scanner to run (omit to run all enabled scanners). "
             "Use 'container' with --discover or --image for container scanning.",
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


def _build_collect_parser(subparsers: argparse._SubParsersAction) -> None:
    """Add the 'collect' subcommand for aggregating multi-job results."""
    collect_parser = subparsers.add_parser(
        "collect",
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


def _build_validate_parser(subparsers: argparse._SubParsersAction) -> None:
    """Add the 'validate' subcommand for config validation."""
    validate_parser = subparsers.add_parser(
        "validate",
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
    """Execute the scan subcommand.

    Routes to specialized lifecycle engines based on scanner name
    and flags:
      - container + --discover/--image → container lifecycle
      - zap + --image/--target → DAST lifecycle
      - everything else → source code scanning
    """
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

    # Container lifecycle — needs --discover or --image
    if args.scanner == "container":
        if _is_container_lifecycle(args):
            return _cmd_container_scan(args)
        print(
            "Usage: argus scan container [--discover PATH | --image REF]\n\n"
            "Container image scanning requires one of:\n"
            "  --discover PATH   Discover Dockerfiles and scan all images\n"
            "  --image REF       Scan a specific image (can be repeated)\n\n"
            "Examples:\n"
            "  argus scan container --discover ./\n"
            "  argus scan container --discover docker/\n"
            "  argus scan container --image nginx:latest\n"
            "  argus scan container --image myapp:v1 --image worker:v1\n",
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
    """Check if container lifecycle flags are present."""
    return bool(
        getattr(args, "discover", None) is not None
        or getattr(args, "images", None)
    )


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
        config.reporting.severity_threshold = Severity.from_string(
            args.severity_threshold
        )
    if args.output_dir:
        config.reporting.output_dir = args.output_dir
    if args.formats:
        config.reporting.formats = args.formats

    # Initialize audit trail — each run gets a timestamped subdirectory
    output_dir = _make_run_dir(config.reporting.output_dir)
    config.reporting.output_dir = output_dir
    log = get_logger("argus", output_dir=output_dir, verbose=args.verbose)
    manifest = create_manifest(
        config_path=args.config,
        scan_targets=[args.path],
    )
    manifest.execution_backend = config.execution.backend

    log.info("Argus scan starting")

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

    # Run the scan
    try:
        scanner_names = [args.scanner] if args.scanner else None
        log.info("Running scanners: %s", scanner_names or "all enabled")
        summary = engine.run(scanner_names=scanner_names, path=args.path)
        log.info(
            "Scan complete: %d scanner(s), %d finding(s)",
            len(summary.results),
            summary.total_count,
        )
    except Exception as exc:
        log.error("Scan failed: %s", exc)
        finalize_manifest(manifest, exit_code=EXIT_ERROR, output_dir=output_dir)
        return EXIT_ERROR

    # Generate reports
    try:
        from argus.reporters import get_reporter
        for fmt in config.reporting.formats:
            reporter = get_reporter(fmt)
            reporter.report(summary, output_dir)
            log.debug("Generated %s report", fmt)
    except ImportError:
        if args.verbose:
            log.warning("argus.reporters module not found; skipping report generation")

    # Finalize audit trail
    exit_code = EXIT_SUCCESS if summary.passed else EXIT_FINDINGS
    finalize_manifest(manifest, summary=summary, exit_code=exit_code, output_dir=output_dir)
    log.info("Audit manifest written to %s/argus-audit.json", output_dir)

    return exit_code


def _cmd_container_scan(args: argparse.Namespace) -> int:
    """Run container image scanning lifecycle (discover, build, scan, report)."""
    from argus.container import ContainerEngine
    from argus.reporters.container_markdown import ContainerMarkdownReporter

    # Build container config from args and config file
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
        config["images"] = [
            {"image": img, "name": img.split(":")[0].split("/")[-1]}
            for img in args.images
        ]
    if args.discover is not None:
        config["discover"] = True
        config["search_paths"] = [args.discover]
    if args.scanners:
        config["scanners"] = [s.strip() for s in args.scanners.split(",")]

    base_dir = args.output_dir or config.get("output_dir", "./argus-results")
    output_dir = _make_run_dir(base_dir)
    formats = args.formats or ["terminal", "markdown"]

    # Run
    try:
        engine = ContainerEngine(config)
        summary = engine.run()
    except Exception as exc:
        print(f"Error: container scan failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

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
            _write_container_json(summary, output_dir)
        elif fmt == "sarif":
            from argus.core.models import ScanResult, ScanSummary
            from argus.reporters import get_reporter
            results = [
                ScanResult(scanner=f"container/{r.name}", findings=r.combined_findings)
                for r in summary.results
            ]
            sarif_reporter = get_reporter("sarif")
            sarif_reporter.report(ScanSummary(results=results), output_dir)

    # Exit code
    if args.severity_threshold and args.severity_threshold != "none":
        from argus.core.models import Severity
        threshold = Severity.from_string(args.severity_threshold)
        for r in summary.results:
            for f in r.combined_findings:
                if f.severity >= threshold:
                    return EXIT_FINDINGS
    return EXIT_SUCCESS


def _cmd_dast_scan(args: argparse.Namespace) -> int:
    """Run DAST scanning lifecycle (start target, scan with ZAP, cleanup)."""
    from argus.dast import DastEngine

    base_dir = args.output_dir or "./argus-results"
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
        "results": [
            {
                "name": r.name,
                "target_url": r.target_url,
                "healthy": r.healthy,
                "finding_count": len(r.findings),
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
        json_file = results_dir / "argus-results.json"
        if not json_file.exists():
            print(f"Error: {json_file} not found", file=sys.stderr)
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

    # Load and validate
    try:
        with open(config_path, "r") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        print(f"Invalid YAML in {config_path}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not isinstance(data, dict):
        print(f"Config must be a YAML mapping, got {type(data).__name__}", file=sys.stderr)
        return EXIT_ERROR

    errors = validate_config(data)
    warnings = [e for e in errors if e.level == "warning"]
    fatal = [e for e in errors if e.level == "error"]

    if not errors:
        print(f"✅ {config_path} is valid")
        # Show summary
        scanners = data.get("scanners", {})
        enabled = sum(1 for s in scanners.values() if isinstance(s, dict) and s.get("enabled", True))
        print(f"   Scanners: {len(scanners)} configured, {enabled} enabled")
        fmt = data.get("reporting", {}).get("formats", ["terminal"])
        print(f"   Formats: {', '.join(fmt) if isinstance(fmt, list) else fmt}")
        print(f"   Backend: {data.get('execution', {}).get('backend', 'auto')}")
        return EXIT_SUCCESS

    for w in warnings:
        print(f"⚠️  {w}")
    for e in fatal:
        print(f"❌ {e}")

    if fatal:
        print(f"\n{len(fatal)} error(s), {len(warnings)} warning(s). Fix and retry.")
        return EXIT_ERROR

    print(f"\n✅ {config_path} is valid ({len(warnings)} warning(s))")
    return EXIT_SUCCESS


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


def main(argv: list[str] | None = None) -> None:
    """CLI entry point. Parse arguments and dispatch to the appropriate subcommand."""
    # Intercept `argus scan <name> --help` before argparse exits
    raw_args = argv if argv is not None else sys.argv[1:]
    if (len(raw_args) >= 3
        and raw_args[0] == "scan"
        and raw_args[-1] in ("--help", "-h")
        and raw_args[1] not in ("--help", "-h", "--list")):
        scanner_name = raw_args[1]
        _show_scanner_help(scanner_name)

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        sys.exit(EXIT_SUCCESS)

    handlers = {
        "init": cmd_init,
        "scan": cmd_scan,
        "collect": cmd_collect,
        "report": cmd_report,
        "validate": cmd_validate,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(EXIT_ERROR)

    sys.exit(handler(args))
