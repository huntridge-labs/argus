"""Argus MCP server — exposes security scanning tools via the Model Context Protocol.

Provides tools for running scans, listing scanners, validating config,
detecting project signals, generating configuration, classifying IaC changes,
explaining findings, and summarizing results. Also exposes resources for
reading the current config, latest scan results, and the config schema.
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "argus",
    instructions="""
Argus Security Scanner — comprehensive security scanning for your codebase.

WHEN TO USE EACH TOOL:
- argus_detect: First step — understand what's in the project
- argus_scan: Run security scans (specify scanners or let auto-detect choose)
- argus_list_scanners: See what scanners are available and their categories
- argus_classify: Analyze IaC changes between git branches for compliance
- argus_validate: Check if argus.yml config is valid
- argus_init: Generate a tailored config for the project
- argus_explain_finding: Get remediation guidance for a specific finding
- argus_scan_summary: Quick check on latest scan status

COMMON WORKFLOWS:
1. New project setup: argus_detect -> argus_init -> save config -> argus_scan
2. Security review: argus_scan -> review findings -> argus_explain_finding for each
3. Quick check: argus_scan_summary to see latest results
4. Branch comparison: argus_classify to check IaC changes

SCANNER CATEGORIES:
- sast: Static analysis (bandit, opengrep)
- secrets: Credential detection (gitleaks)
- sca: Dependency vulnerabilities (osv)
- iac: Infrastructure misconfigurations (trivy-iac, checkov)
- dast: Web application testing (zap)
- container: Container image scanning (container)
- malware: File scanning (clamav)
- supply-chain: CI/CD security (supply-chain)
- linter: Code quality (lint-yaml, lint-json, lint-python, etc.)
""",
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
        path: File or directory to scan. Most scanners accept both.
              Defaults to current directory.
        severity_threshold: Minimum severity to fail on — "critical", "high",
                            "medium", "low", or "none" (never fail). Defaults to "none".

    Returns:
        JSON object with scanner results, severity counts, and passed/failed status.
    """
    import json

    summary = None
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
        error_response = {
            "error": str(exc),
            "error_type": type(exc).__name__,
        }
        if summary is not None:
            error_response["partial_results"] = summary.to_dict()
        return json.dumps(error_response, indent=2)


@mcp.tool()
async def argus_list_scanners() -> str:
    """List all registered scanners with their availability status.

    Returns a JSON array of objects, each containing:
      - name: scanner registry name
      - available: whether the tool is installed locally
      - container_image: Docker image used for container execution (empty if none)
      - description: short description of the scanner
      - category: scanner category (sast, secrets, sca, iac, dast, etc.)
      - languages: list of languages/targets supported
      - install_command: command to install the tool locally (if available)
    """
    import json

    try:
        from argus.scanners import SCANNER_REGISTRY
        from argus.containers import get_image

        result = []
        for name, cls in sorted(SCANNER_REGISTRY.items()):
            scanner = cls()
            image = get_image(name) or getattr(scanner, "container_image", "")
            result.append({
                "name": name,
                "available": scanner.is_available(),
                "container_image": image,
                "description": getattr(scanner, "description", ""),
                "category": getattr(scanner, "category", ""),
                "languages": getattr(scanner, "languages", []),
                "install_command": scanner.install_command() if hasattr(scanner, "install_command") else None,
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
async def argus_init(
    path: str = ".",
    force: bool = False,
    signals_override: dict | None = None,
) -> str:
    """Generate an argus.yml configuration based on project detection.

    Detects languages, frameworks, and infrastructure in the project,
    then generates tailored YAML configuration content. Does NOT write
    the file — returns the content so the AI agent can review or
    modify it before saving.

    Args:
        path: Root directory to analyze. Defaults to current directory.
        force: Included for API parity. Since this tool returns content
               rather than writing a file, it has no effect.
        signals_override: Optional dict of signals to merge with (or replace)
                          auto-detected signals. Keys are signal names, values
                          are lists of evidence paths.

    Returns:
        JSON object with the generated YAML content and detected signals.
    """
    import json
    from pathlib import Path

    try:
        from argus.init import detect_project, generate_config

        signals = detect_project(Path(path))

        if signals_override:
            signals.update(signals_override)

        config_content = generate_config(signals)

        return json.dumps({
            "config_yaml": config_content,
            "signals": signals,
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
async def argus_classify(
    base_ref: str = "main",
    head_ref: str = "HEAD",
    config_path: str | None = None,
    enable_ai: bool = False,
) -> str:
    """Classify infrastructure-as-code changes for compliance reporting.

    Analyzes git diff between two refs, classifies changes according to
    compliance rules (FedRAMP SCN categories: ROUTINE, ADAPTIVE,
    TRANSFORMATIVE, IMPACT).

    Args:
        base_ref: Base git ref for comparison (default: "main")
        head_ref: Head git ref for comparison (default: "HEAD")
        config_path: Path to SCN profile config file (optional)
        enable_ai: Use AI for ambiguous classifications (requires API key)

    Returns:
        JSON with classifications, category counts, and change details.
    """
    import json

    try:
        from argus.scn import ChangeClassifier, analyze_iac_changes

        analysis = analyze_iac_changes(base_ref, head_ref)

        config = None
        if config_path:
            classifier = ChangeClassifier(enable_ai=enable_ai)
            config = classifier.load_config_from_file(config_path)

        classifier = ChangeClassifier(config=config, enable_ai=enable_ai)
        result = classifier.classify_all_changes(analysis)

        return json.dumps(result, indent=2, default=str)
    except Exception as exc:
        return json.dumps({
            "error": str(exc),
            "error_type": type(exc).__name__,
        }, indent=2)


@mcp.tool()
async def argus_explain_finding(
    finding_id: str,
    scanner: str = "",
    location: str = "",
) -> str:
    """Get detailed explanation and remediation guidance for a security finding.

    Given a finding ID (e.g., "B301", "CWE-89", "CVE-2024-1234"), returns:
    - What the vulnerability is
    - Why it matters
    - How to fix it
    - Reference links

    Args:
        finding_id: The finding rule ID, CWE, or CVE identifier
        scanner: Which scanner produced the finding (helps with context)
        location: File path and line number (e.g., "app.py:42")
    """
    import json
    import re

    explanation = {
        "finding_id": finding_id,
        "scanner": scanner or "unknown",
        "location": location or "not specified",
        "references": [],
    }

    normalized = finding_id.upper().strip()

    # Bandit findings (B1xx-B7xx)
    if re.match(r"^B\d{3}$", normalized):
        explanation["source"] = "bandit"
        explanation["references"].append(
            f"https://bandit.readthedocs.io/en/latest/plugins/{finding_id.lower()}.html"
        )
        explanation["guidance"] = (
            f"Bandit rule {finding_id}: Review the flagged code for the specific "
            "security anti-pattern. Check the Bandit docs link for detailed "
            "explanation, examples of vulnerable code, and recommended fixes."
        )

    # CWE identifiers
    elif re.match(r"^CWE-\d+$", normalized):
        cwe_number = normalized.split("-")[1]
        explanation["source"] = "cwe"
        explanation["references"].append(
            f"https://cwe.mitre.org/data/definitions/{cwe_number}.html"
        )
        explanation["guidance"] = (
            f"CWE-{cwe_number}: Common Weakness Enumeration entry. "
            "Review the MITRE reference for detailed description, "
            "potential mitigations, and related weaknesses."
        )

    # CVE identifiers
    elif re.match(r"^CVE-\d{4}-\d+$", normalized):
        explanation["source"] = "cve"
        explanation["references"].extend([
            f"https://nvd.nist.gov/vuln/detail/{normalized}",
            f"https://www.cvedetails.com/cve/{normalized}/",
            f"https://github.com/advisories?query={normalized}",
        ])
        explanation["guidance"] = (
            f"{normalized}: Check the NVD and GitHub Advisory links for "
            "affected versions, CVSS score, and available patches. "
            "Update the affected dependency to a fixed version."
        )

    # Checkov check IDs (CKV_*)
    elif normalized.startswith("CKV"):
        explanation["source"] = "checkov"
        explanation["references"].append(
            f"https://www.checkov.io/5.Policy%20Index/{finding_id}.html"
        )
        explanation["guidance"] = (
            f"Checkov policy {finding_id}: Infrastructure-as-code policy violation. "
            "Review the Checkov docs for the specific misconfiguration "
            "and recommended remediation."
        )

    # Trivy / AVDID
    elif re.match(r"^AVD-\w+-\d+$", normalized):
        explanation["source"] = "trivy"
        explanation["references"].append(
            f"https://avd.aquasec.com/misconfig/{finding_id.lower()}"
        )
        explanation["guidance"] = (
            f"Aqua Vulnerability Database entry {finding_id}: "
            "Review the AVD reference for misconfiguration details and fix guidance."
        )

    # Semgrep / Opengrep rule IDs
    elif "." in finding_id and not finding_id.startswith("CVE"):
        explanation["source"] = "opengrep/semgrep"
        explanation["references"].append(
            f"https://semgrep.dev/r?q={finding_id}"
        )
        explanation["guidance"] = (
            f"Rule {finding_id}: Pattern-based finding. "
            "Review the rule definition for the specific vulnerability pattern, "
            "true/false positive indicators, and suggested fix."
        )

    # Gitleaks
    elif scanner.lower() in ("gitleaks", "secrets"):
        explanation["source"] = "gitleaks"
        explanation["references"].append(
            "https://github.com/gitleaks/gitleaks#readme"
        )
        explanation["guidance"] = (
            f"Secret detection rule {finding_id}: A potential credential or secret "
            "was found. Rotate the secret immediately, remove it from git history "
            "(use git-filter-repo or BFG), and store secrets in a vault or "
            "environment variables."
        )

    else:
        explanation["source"] = "generic"
        explanation["guidance"] = (
            f"Finding {finding_id}: Review the scanner output for context. "
            "If this is a dependency vulnerability, update to a patched version. "
            "If this is a code issue, review the flagged location and apply "
            "the suggested remediation."
        )

    if location:
        explanation["next_steps"] = (
            f"1. Read the source file at {location}\n"
            "2. Understand the context of the flagged code\n"
            "3. Apply the fix described in the references\n"
            "4. Re-run the scanner to verify the fix"
        )

    return json.dumps(explanation, indent=2)


@mcp.tool()
async def argus_scan_summary() -> str:
    """Get a quick summary of the most recent scan results.

    Returns severity counts, scanner breakdown, and top findings
    without the full payload. Use this for a quick "how bad is it?"
    check before diving into details with argus://results/latest.
    """
    import json
    from pathlib import Path

    try:
        candidates = [
            Path("argus-results/latest/argus-results.json"),
            Path("argus-results/latest/argus-audit.json"),
            Path("argus-results/argus-results.json"),
            Path("argus-results/argus-audit.json"),
        ]

        results_data = None
        source_path = None
        for candidate in candidates:
            if candidate.exists():
                raw = candidate.read_text(encoding="utf-8")
                results_data = json.loads(raw)
                source_path = str(candidate)
                break

        if results_data is None:
            latest_link = Path("argus-results/latest")
            if latest_link.is_symlink() or latest_link.is_dir():
                json_files = sorted(latest_link.glob("*.json"))
                if json_files:
                    raw = json_files[0].read_text(encoding="utf-8")
                    results_data = json.loads(raw)
                    source_path = str(json_files[0])

        if results_data is None:
            return json.dumps({
                "error": "No scan results found. Run argus_scan first.",
            })

        # Extract summary counts
        summary = {
            "source": source_path,
            "passed": results_data.get("passed"),
            "severity_threshold": results_data.get("severity_threshold"),
            "counts": {
                "critical": results_data.get("critical_count", 0),
                "high": results_data.get("high_count", 0),
                "medium": results_data.get("medium_count", 0),
                "low": results_data.get("low_count", 0),
                "total": results_data.get("total_count", 0),
            },
        }

        # Scanner breakdown
        scanner_breakdown = []
        for result in results_data.get("results", []):
            scanner_breakdown.append({
                "scanner": result.get("scanner", "unknown"),
                "total": result.get("total_count", 0),
                "critical": result.get("critical_count", 0),
                "high": result.get("high_count", 0),
            })
        summary["scanners"] = scanner_breakdown

        # Top critical/high findings (up to 5)
        top_findings = []
        for result in results_data.get("results", []):
            for finding in result.get("findings", []):
                sev = finding.get("severity", "unknown")
                if sev in ("critical", "high"):
                    top_findings.append({
                        "id": finding.get("id", ""),
                        "severity": sev,
                        "title": finding.get("title", ""),
                        "location": finding.get("location", ""),
                        "scanner": finding.get("scanner", result.get("scanner", "")),
                    })
        top_findings.sort(key=lambda f: 0 if f["severity"] == "critical" else 1)
        summary["top_findings"] = top_findings[:5]

        return json.dumps(summary, indent=2)
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


@mcp.resource("argus://config/schema")
async def read_config_schema() -> str:
    """Return the JSON Schema for argus.yml configuration.

    Reads the argus-config.schema.json from the repository root or
    the package directory. Useful for understanding valid configuration
    keys, types, and defaults.
    """
    from pathlib import Path

    try:
        # Check repo root first, then package directory
        candidates = [
            Path("argus-config.schema.json"),
            Path(__file__).resolve().parent.parent / "argus-config.schema.json",
        ]

        for candidate in candidates:
            if candidate.exists():
                return candidate.read_text(encoding="utf-8")

        import json
        return json.dumps({
            "error": "Schema file not found. Expected argus-config.schema.json in repo root.",
        })
    except Exception as exc:
        import json
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------


@mcp.prompt()
async def security_review() -> str:
    """Comprehensive security review prompt for a codebase."""
    return (
        "Perform a security review of this project:\n"
        "1. Run argus_detect to understand the project\n"
        "2. Run argus_scan to find vulnerabilities\n"
        "3. For each HIGH or CRITICAL finding, explain the risk and suggest a fix\n"
        "4. Summarize the overall security posture\n"
        "5. Recommend additional scanners if appropriate"
    )


@mcp.prompt()
async def fix_findings() -> str:
    """Fix security findings from the latest scan."""
    return (
        "Review the latest argus scan results and fix the findings:\n"
        "1. Read argus://results/latest for the scan data\n"
        "2. For each finding, use argus_explain_finding to understand it\n"
        "3. Read the source file at the finding's location\n"
        "4. Apply the fix\n"
        "5. Re-run argus_scan to verify the fix"
    )


@mcp.prompt()
async def setup_scanning() -> str:
    """Set up security scanning for a new project."""
    return (
        "Set up Argus security scanning for this project:\n"
        "1. Run argus_detect to analyze the project\n"
        "2. Run argus_init to generate a config\n"
        "3. Review the generated config and adjust if needed\n"
        "4. Save it as argus.yml\n"
        "5. Run argus_validate to verify\n"
        "6. Run argus_scan for the initial baseline"
    )


# ---------------------------------------------------------------------------
# Server factory
# ---------------------------------------------------------------------------


def create_server() -> FastMCP:
    """Create and return the Argus MCP server instance."""
    return mcp
