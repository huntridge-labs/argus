"""Argus MCP server — exposes security scanning tools via the Model Context Protocol.

Provides tools for running scans, listing scanners, validating config,
detecting project signals, generating configuration, classifying IaC changes,
explaining findings, and summarizing results. Also exposes resources for
reading the current config, latest scan results, and the config schema.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp.server import MCPServer

from argus import __version__ as _ARGUS_VERSION

# A scan older than this is considered stale and should be re-run for
# accurate posture answers. 24 hours is the default because most code
# review questions ("is this repo secure?") only need same-day data;
# older snapshots can miss recent changes or new disclosures.
DEFAULT_FRESH_THRESHOLD_SECONDS = 86400

mcp = MCPServer(
    "argus",
    version=_ARGUS_VERSION,
    instructions="""
Argus Security Scanner — comprehensive security scanning for your codebase.

QUICK PATH (RECOMMENDED FOR NATURAL-LANGUAGE QUERIES):
- argus_security_review: ONE-CALL entry point for "what's my security posture?",
  "is this repo secure?", "what should I fix?" — orchestrates detect + scan
  (or fresh-cache reuse) + returns a stable JSON envelope. Use this first
  when the user asks an open-ended security question.

WHEN TO USE INDIVIDUAL TOOLS:
- argus_detect: Understand what's in the project (languages, IaC, CI/CD)
- argus_scan: Run security scans (specify scanners or let auto-detect choose)
- argus_list_scanners: See what scanners are available and their categories
- argus_classify: Analyze IaC changes between git branches for compliance
- argus_validate: Check if argus.yml config is valid
- argus_init: Generate a tailored config for the project
- argus_explain_finding: Get remediation guidance for a specific finding
- argus_scan_summary: Quick check on latest scan results (returns cache age —
  if cache_age_seconds > 86400, prefer argus_scan for fresh results)

CACHE FRESHNESS:
- argus_scan_summary and argus://results/latest both report cache_age_seconds.
- Treat results > 24h old as stale; re-run argus_scan or argus_security_review
  rather than answering from a stale snapshot.

COMMON WORKFLOWS:
1. Open-ended posture question: argus_security_review (handles everything)
2. New project setup: argus_detect -> argus_init -> save config -> argus_scan
3. Targeted re-scan: argus_scan with specific scanners
4. Branch comparison: argus_classify to check IaC changes
5. Fix triage: argus_scan_summary -> argus_explain_finding per finding

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

# The server version is passed to the constructor above. MCP clients read
# it from the initialize response to disambiguate compatible argus
# releases, so it must be the argus version and not the SDK's own
# (issue #168-O). Under mcp 1.x this needed a write through to the private
# ``_mcp_server`` attribute because FastMCP's constructor did not accept
# ``version``; MCPServer takes it directly and exposes a read-only
# ``.version`` property.


# ---------------------------------------------------------------------------
# Internal helpers — cache freshness + results loading
# ---------------------------------------------------------------------------


# Search order for cached scan results. The 'latest' symlink is canonical;
# the unprefixed paths are legacy fallbacks from older argus runs.
_RESULTS_CANDIDATES: tuple[str, ...] = (
    "argus-results/latest/argus-results.json",
    "argus-results/latest/argus-audit.json",
    "argus-results/argus-results.json",
    "argus-results/argus-audit.json",
)


def _freshness_for(path: Path, threshold_seconds: int = DEFAULT_FRESH_THRESHOLD_SECONDS) -> dict[str, Any]:
    """Compute cache-freshness metadata for a results file.

    Returns a dict with:
      - cache_age_seconds: int — seconds since file mtime (>=0)
      - cached_at: str — ISO-8601 UTC timestamp of file mtime
      - is_stale: bool — True if older than threshold_seconds

    Stale results are still returned to the caller; this metadata lets the
    LLM decide whether to re-run the scan rather than answering from old data.
    """
    mtime = path.stat().st_mtime
    cached_at = datetime.fromtimestamp(mtime, tz=timezone.utc)
    age_seconds = max(0, int((datetime.now(timezone.utc) - cached_at).total_seconds()))
    return {
        "cache_age_seconds": age_seconds,
        "cached_at": cached_at.isoformat(),
        "is_stale": age_seconds > threshold_seconds,
    }


def _find_latest_results_file() -> Path | None:
    """Locate the most recent scan-results JSON file, or None if absent.

    Tries the canonical candidates first, then falls back to globbing the
    'latest' run directory for any *.json. Mirrors the discovery used by
    argus_scan_summary and the argus://results/latest resource so they
    stay in agreement.
    """
    for name in _RESULTS_CANDIDATES:
        candidate = Path(name)
        if candidate.exists():
            return candidate

    latest_link = Path("argus-results/latest")
    if latest_link.is_symlink() or latest_link.is_dir():
        json_files = sorted(latest_link.glob("*.json"))
        if json_files:
            return json_files[0]

    return None


def _stale_warning(age_seconds: int) -> str:
    """Render a human-readable freshness warning for stale results."""
    if age_seconds < 3600:
        age_str = f"{age_seconds // 60}m"
    elif age_seconds < 86400:
        age_str = f"{age_seconds // 3600}h"
    else:
        age_str = f"{age_seconds // 86400}d"
    return (
        f"Results are {age_str} old. For current security state, "
        "re-run argus_scan or argus_security_review."
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


def _summarize_results(results_data: dict) -> dict[str, Any]:
    """Build the standard summary envelope from a parsed results blob.

    Shared by argus_scan_summary and argus_security_review so they emit
    the same shape (counts, scanner breakdown, top findings).
    """
    summary: dict[str, Any] = {
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

    scanner_breakdown = []
    for result in results_data.get("results", []):
        scanner_breakdown.append({
            "scanner": result.get("scanner", "unknown"),
            "total": result.get("total_count", 0),
            "critical": result.get("critical_count", 0),
            "high": result.get("high_count", 0),
        })
    summary["scanners"] = scanner_breakdown

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
    return summary


@mcp.tool()
async def argus_scan_summary() -> str:
    """Get a quick summary of the most recent scan results.

    Returns severity counts, scanner breakdown, top findings, and **cache
    freshness metadata** (cache_age_seconds, cached_at). If cache_age_seconds
    exceeds 86400 (24h), the response includes a freshness_warning and you
    should prefer running argus_scan (or argus_security_review) for current
    posture rather than answering from this snapshot.

    Use this for a quick "how bad is it?" check before diving into details
    with argus://results/latest.
    """
    try:
        results_path = _find_latest_results_file()
        if results_path is None:
            return json.dumps({
                "error": "No scan results found. Run argus_scan first.",
            })

        results_data = json.loads(results_path.read_text(encoding="utf-8"))

        summary = _summarize_results(results_data)
        summary["source"] = str(results_path)

        freshness = _freshness_for(results_path)
        summary["cache_age_seconds"] = freshness["cache_age_seconds"]
        summary["cached_at"] = freshness["cached_at"]
        if freshness["is_stale"]:
            summary["freshness_warning"] = _stale_warning(
                freshness["cache_age_seconds"],
            )

        return json.dumps(summary, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
async def argus_security_review(
    path: str = ".",
    use_cached_if_fresh: bool = True,
    fresh_threshold_seconds: int = DEFAULT_FRESH_THRESHOLD_SECONDS,
) -> str:
    """One-call security posture review — the canonical entry point.

    USE THIS WHEN the user asks open-ended security questions like:
      - "What's my security posture?"
      - "Is this repo secure?"
      - "What should I fix?"
      - "Run a security review"
      - "Are there any vulnerabilities?"

    Orchestrates the full workflow in a single call:
      1. Detect project signals (languages, IaC, CI/CD)
      2. Reuse cached scan results if fresher than ``fresh_threshold_seconds``
         (default 24h) and ``use_cached_if_fresh`` is True; otherwise run a
         new scan via the engine.
      3. Return a stable JSON envelope so repeated invocations of the same
         question produce the same shape — no tool-routing variance.

    Args:
        path: Project root to analyze. Defaults to current directory.
        use_cached_if_fresh: When True (default), reuse the latest cached
            scan if it's fresher than the threshold. Set False to force a
            new scan.
        fresh_threshold_seconds: Cache freshness cutoff in seconds.
            Defaults to 86400 (24h).

    Returns:
        JSON envelope with stable shape:
          {
            "version": "1",
            "cache_used": bool,           // True if served from cache
            "cache_age_seconds": int,     // 0 for a fresh scan
            "cached_at": str,             // ISO-8601 UTC timestamp
            "is_stale": bool,             // age > threshold
            "freshness_warning": str?,    // present only if is_stale
            "signals": dict,              // from argus_detect
            "summary": dict,              // counts + scanners + top_findings
            "next_steps": list[str]       // recommended follow-ups
          }
    """
    try:
        from argus.init import detect_project

        signals = detect_project(Path(path))

        results_path: Path | None = None
        results_data: dict | None = None
        cache_used = False
        freshness: dict[str, Any] | None = None

        if use_cached_if_fresh:
            cached_path = _find_latest_results_file()
            if cached_path is not None:
                cached_freshness = _freshness_for(cached_path, fresh_threshold_seconds)
                if not cached_freshness["is_stale"]:
                    results_path = cached_path
                    results_data = json.loads(cached_path.read_text(encoding="utf-8"))
                    cache_used = True
                    freshness = cached_freshness

        if results_data is None:
            from argus.core import ArgusConfig
            from argus.core.engine import ArgusEngine
            from argus.scanners import get_available_scanners

            config = ArgusConfig.load()
            engine = ArgusEngine(config)
            for scanner_cls in get_available_scanners():
                engine.register_scanner(scanner_cls())

            scan_summary = engine.run(scanner_names=None, path=path)
            results_data = scan_summary.to_dict()
            now = datetime.now(timezone.utc)
            freshness = {
                "cache_age_seconds": 0,
                "cached_at": now.isoformat(),
                "is_stale": False,
            }

        envelope: dict[str, Any] = {
            "version": "1",
            "cache_used": cache_used,
            "cache_age_seconds": freshness["cache_age_seconds"],
            "cached_at": freshness["cached_at"],
            "is_stale": freshness["is_stale"],
            "signals": signals,
            "summary": _summarize_results(results_data),
        }
        if freshness["is_stale"]:
            envelope["freshness_warning"] = _stale_warning(
                freshness["cache_age_seconds"],
            )
        if results_path is not None:
            envelope["source"] = str(results_path)

        next_steps: list[str] = []
        counts = envelope["summary"]["counts"]
        if counts.get("critical", 0) > 0:
            next_steps.append(
                "Triage critical findings first — call argus_explain_finding "
                "for each top_finding with severity=critical."
            )
        if counts.get("high", 0) > 0:
            next_steps.append(
                "Address high-severity findings — call argus_explain_finding "
                "for each top_finding with severity=high."
            )
        if envelope["is_stale"]:
            next_steps.append(
                "Cache is stale — re-run with use_cached_if_fresh=False for "
                "current results."
            )
        if not next_steps:
            next_steps.append(
                "No critical or high findings. Review medium/low findings "
                "in argus://results/latest as time permits."
            )
        envelope["next_steps"] = next_steps

        return json.dumps(envelope, indent=2)
    except Exception as exc:
        return json.dumps({
            "error": str(exc),
            "error_type": type(exc).__name__,
        }, indent=2)


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

    Looks for argus-results/latest/argus-results.json (the symlink created
    by each scan run). Falls back to argus-results.json in the default
    output directory. When the underlying file is a JSON object, the
    response is augmented with ``_cache_age_seconds`` and ``_cached_at``
    fields (underscore-prefixed because they're MCP envelope metadata,
    not part of the scan-results schema). Use these to decide whether to
    re-run the scan instead of trusting a stale snapshot.
    """
    try:
        results_path = _find_latest_results_file()
        if results_path is None:
            return json.dumps({
                "error": "No scan results found. Run argus_scan first.",
            })

        raw = results_path.read_text(encoding="utf-8")
        freshness = _freshness_for(results_path)

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # Non-JSON or malformed file — return raw bytes unchanged
            # rather than swallowing the original content.
            return raw

        if isinstance(data, dict):
            data["_cache_age_seconds"] = freshness["cache_age_seconds"]
            data["_cached_at"] = freshness["cached_at"]
            if freshness["is_stale"]:
                data["_freshness_warning"] = _stale_warning(
                    freshness["cache_age_seconds"],
                )
            return json.dumps(data, indent=2)

        # Not a JSON object (e.g. a list at the top level) — return raw
        # text since we have no envelope to inject metadata into.
        return raw
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


@mcp.resource("argus://architecture")
async def read_architecture() -> str:
    """Return the SDK architecture map as JSON.

    Byte-identical to what the docsite build inlines into
    ``architecture/index.html`` and what the FastAPI viewer's
    ``/architecture`` route hydrates from. The transformer is a pure
    function from ``.ai/architecture.yaml`` + ``.ai/decisions.yaml``
    + ``argus-config.schema.json`` + ``version.yaml`` + the running
    SDK's registries — same inputs ⇒ byte-identical output.

    AI assistants picking up Argus work read this resource to learn
    the SDK's component layout, scanner / linter / reporter
    inventory, data flows, and the ADRs that justify the structure,
    without having to walk the YAML files themselves.
    """
    import json
    from pathlib import Path

    try:
        from argus.architecture_map import build_view_model_from_repo

        # Find the repo containing .ai/architecture.yaml. Try cwd
        # first (most contributor scenarios), then walk up from this
        # file (covers editable installs).
        repo_root = _find_architecture_repo_root()
        view_model = build_view_model_from_repo(repo_root)
        return json.dumps(view_model, indent=2)
    except ImportError as exc:
        return json.dumps({
            "error": str(exc),
            "hint": (
                "Install argus in editable mode "
                "(``pip install -e .`` from the argus repo root) "
                "to make the architecture map available."
            ),
        })
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def _find_architecture_repo_root() -> Path:
    """Locate the project repo that owns ``.ai/architecture.yaml``."""
    from pathlib import Path as _Path
    for start in (_Path.cwd(),):
        for parent in (start, *start.parents):
            if (parent / ".ai" / "architecture.yaml").exists():
                return parent
    here = _Path(__file__).resolve()
    for parent in here.parents:
        if (parent / ".ai" / "architecture.yaml").exists():
            return parent
    return _Path.cwd()


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------


@mcp.prompt()
async def security_review() -> str:
    """Run a comprehensive security review of the current codebase.

    Trigger phrases (use this prompt when the user says any of):
      - "what's my security posture?"
      - "is this repo secure?"
      - "what should I fix?"
      - "run a security review"
      - "are there any vulnerabilities?"
      - "check this project for security issues"
    """
    return (
        "Perform a security review of this project. Prefer the one-call\n"
        "tool argus_security_review for the orchestration; the explicit\n"
        "steps below are the breakdown it performs.\n"
        "\n"
        "1. Call argus_security_review (handles detect + scan-or-cached\n"
        "   reuse + stable JSON envelope). If cache_age_seconds > 86400,\n"
        "   re-call with use_cached_if_fresh=False for fresh results.\n"
        "2. From the response, list each CRITICAL and HIGH finding by\n"
        "   id, severity, location, and scanner.\n"
        "3. For each top finding, call argus_explain_finding with the\n"
        "   finding id and scanner; report the remediation guidance.\n"
        "4. Summarize the overall posture: total counts by severity,\n"
        "   whether the scan passed the threshold, and which scanners\n"
        "   produced the most findings.\n"
        "5. Recommend any uninstalled scanners that would add coverage\n"
        "   based on the detected signals (use argus_list_scanners)."
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


def create_server() -> MCPServer:
    """Create and return the Argus MCP server instance."""
    return mcp
