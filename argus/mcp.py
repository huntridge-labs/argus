"""Argus MCP server — exposes security scanning tools via the Model Context Protocol.

Provides tools for running scans, listing scanners, validating config,
detecting project signals, and generating configuration. Also exposes
resources for reading the current config and latest scan results.
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "argus",
    instructions=(
        "Argus Security Scanner — comprehensive security scanning "
        "for your codebase. Use these tools to run security scans, "
        "validate configuration, detect project signals, and generate "
        "tailored scanner configurations."
    ),
)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def argus_scan(
    scanners: list[str] | None = None,
    path: str = ".",
    severity_threshold: str = "none",
) -> str:
    """Run security scanners against a codebase.

    Runs one or more security scanners and returns structured findings.
    If no scanners are specified, runs all enabled scanners from argus.yml
    (or auto-detects appropriate scanners if no config exists).

    Args:
        scanners: Optional list of scanner names to run (e.g. ["bandit", "gitleaks"]).
                  When omitted, runs all enabled scanners.
        path: Directory to scan. Defaults to current directory.
        severity_threshold: Minimum severity to fail on — "critical", "high",
                            "medium", "low", or "none" (never fail). Defaults to "none".

    Returns:
        JSON object with scanner results, severity counts, and passed/failed status.
    """
    import json

    try:
        from argus.core import ArgusConfig, ArgusEngine, Severity
        from argus.scanners import get_available_scanners

        config = ArgusConfig.load()

        if severity_threshold != "none":
            config.reporting.severity_threshold = Severity.from_string(
                severity_threshold,
            )

        engine = ArgusEngine(config)
        for scanner_cls in get_available_scanners():
            engine.register_scanner(scanner_cls())

        summary = engine.run(
            scanner_names=scanners,
            path=path,
        )

        return json.dumps(summary.to_dict(), indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
async def argus_list_scanners() -> str:
    """List all registered scanners with their availability status.

    Returns a JSON array of objects, each containing:
      - name: scanner registry name
      - available: whether the tool is installed locally
      - container_image: Docker image used for container execution (empty if none)
      - description: short description of the scanner
    """
    import json

    try:
        from argus.scanners import SCANNER_REGISTRY
        from argus.containers import get_image

        result = []
        for name, cls in sorted(SCANNER_REGISTRY.items()):
            scanner = cls()
            image = get_image(name) or getattr(scanner, "container_image", "")
            description = getattr(scanner, "description", "")
            result.append({
                "name": name,
                "available": scanner.is_available(),
                "container_image": image,
                "description": description,
            })

        return json.dumps(result, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
async def argus_validate(config_path: str | None = None) -> str:
    """Validate an argus.yml configuration file.

    Checks for schema errors, unknown keys, invalid values, and warnings.
    Returns structured validation results so an AI agent can decide what
    to fix.

    Args:
        config_path: Path to argus.yml. When omitted, auto-detects
                     from the current directory.

    Returns:
        JSON object with errors, warnings, enabled scanners, and overall validity.
    """
    import json
    from pathlib import Path

    try:
        import yaml
        from argus.core.schema import validate_config, ConfigError

        # Resolve config path
        resolved_path = config_path
        if resolved_path is None:
            for name in ["argus.yml", "argus.yaml", ".argus.yml", ".argus.yaml"]:
                if Path(name).exists():
                    resolved_path = name
                    break

        if resolved_path is None:
            return json.dumps({
                "valid": False,
                "errors": ["No argus.yml found. Create one with argus_init or specify a path."],
                "warnings": [],
                "scanners_enabled": [],
                "scanners_disabled": [],
            })

        if not Path(resolved_path).exists():
            return json.dumps({
                "valid": False,
                "errors": [f"Config file not found: {resolved_path}"],
                "warnings": [],
                "scanners_enabled": [],
                "scanners_disabled": [],
            })

        with open(resolved_path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)

        if not isinstance(data, dict):
            return json.dumps({
                "valid": False,
                "errors": [f"Config must be a YAML mapping, got {type(data).__name__}"],
                "warnings": [],
                "scanners_enabled": [],
                "scanners_disabled": [],
            })

        issues = validate_config(data)
        warnings = [str(e) for e in issues if e.level == "warning"]
        errors = [str(e) for e in issues if e.level == "error"]

        # Extract scanner status
        scanner_data = data.get("scanners", {})
        enabled = []
        disabled = []
        for name, cfg in scanner_data.items():
            if isinstance(cfg, dict) and not cfg.get("enabled", True):
                disabled.append(name)
            else:
                enabled.append(name)

        return json.dumps({
            "valid": len(errors) == 0,
            "config_path": resolved_path,
            "errors": errors,
            "warnings": warnings,
            "scanners_enabled": enabled,
            "scanners_disabled": disabled,
            "formats": data.get("reporting", {}).get("formats", ["terminal"]),
            "backend": data.get("execution", {}).get("backend", "auto"),
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
async def argus_detect(path: str = ".") -> str:
    """Detect project signals (languages, frameworks, IaC, CI/CD, etc.).

    Scans the project directory for language files, dependency manifests,
    Dockerfiles, Terraform configs, GitHub Actions workflows, and other
    indicators to determine which scanners are appropriate.

    Args:
        path: Root directory to analyze. Defaults to current directory.

    Returns:
        JSON object mapping signal names to lists of evidence file paths.
        Example: {"python": ["app.py", "utils.py"], "github-actions": [".github/workflows/ci.yml"]}
    """
    import json
    from pathlib import Path

    try:
        from argus.init import detect_project

        signals = detect_project(Path(path))
        return json.dumps(signals, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
async def argus_init(path: str = ".", force: bool = False) -> str:
    """Generate an argus.yml configuration based on project detection.

    Detects languages, frameworks, and infrastructure in the project,
    then generates tailored YAML configuration content. Does NOT write
    the file — returns the content so the AI agent can review or
    modify it before saving.

    Args:
        path: Root directory to analyze. Defaults to current directory.
        force: Included for API parity. Since this tool returns content
               rather than writing a file, it has no effect.

    Returns:
        JSON object with the generated YAML content and detected signals.
    """
    import json
    from pathlib import Path

    try:
        from argus.init import detect_project, generate_config

        signals = detect_project(Path(path))
        config_content = generate_config(signals)

        return json.dumps({
            "config_yaml": config_content,
            "signals": signals,
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------


@mcp.resource("argus://config")
async def read_config() -> str:
    """Read the current argus.yml configuration as structured JSON.

    Searches for argus.yml in the current directory (standard names),
    parses it, and returns the full configuration as JSON. If no config
    is found, returns the auto-detected default configuration.
    """
    import json

    try:
        import yaml
        from pathlib import Path

        # Try to find and read raw YAML first for fidelity
        for name in ["argus.yml", "argus.yaml", ".argus.yml", ".argus.yaml"]:
            if Path(name).exists():
                with open(name, "r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
                if isinstance(data, dict):
                    return json.dumps(data, indent=2)

        # No file found — return auto-detected config
        from argus.core import ArgusConfig
        config = ArgusConfig.load()
        # Serialize the dataclass to a dict manually
        scanners = {}
        for sname, scfg in config.scanners.items():
            entry = {"enabled": scfg.enabled, "path": scfg.path}
            if scfg.severity_threshold:
                entry["severity_threshold"] = scfg.severity_threshold.value
            if scfg.config_file:
                entry["config_file"] = scfg.config_file
            if scfg.extra:
                entry.update(scfg.extra)
            scanners[sname] = entry

        return json.dumps({
            "version": config.version,
            "scanners": scanners,
            "reporting": {
                "formats": config.reporting.formats,
                "severity_threshold": (
                    config.reporting.severity_threshold.value
                    if config.reporting.severity_threshold
                    else None
                ),
                "output_dir": config.reporting.output_dir,
            },
            "execution": {
                "backend": config.execution.backend,
                "registry": config.execution.registry,
                "pull_policy": config.execution.pull_policy,
            },
            "_source": "auto-detected (no argus.yml found)",
        }, indent=2)
    except Exception as exc:
        import json as _json
        return _json.dumps({"error": str(exc)})


@mcp.resource("argus://results/latest")
async def read_latest_results() -> str:
    """Read the most recent scan results.

    Looks for argus-results/latest/argus-results.json (the symlink
    created by each scan run). Falls back to argus-results.json in
    the default output directory.
    """
    import json
    from pathlib import Path

    try:
        # Check the 'latest' symlink first
        candidates = [
            Path("argus-results/latest/argus-results.json"),
            Path("argus-results/latest/argus-audit.json"),
            Path("argus-results/argus-results.json"),
            Path("argus-results/argus-audit.json"),
        ]

        for candidate in candidates:
            if candidate.exists():
                return candidate.read_text(encoding="utf-8")

        # Try to find any JSON result file in the latest run dir
        latest_link = Path("argus-results/latest")
        if latest_link.is_symlink() or latest_link.is_dir():
            json_files = sorted(latest_link.glob("*.json"))
            if json_files:
                return json_files[0].read_text(encoding="utf-8")

        return json.dumps({
            "error": "No scan results found. Run argus_scan first.",
        })
    except Exception as exc:
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# Server factory
# ---------------------------------------------------------------------------


def create_server() -> FastMCP:
    """Create and return the Argus MCP server instance."""
    return mcp
