"""argus init — project detection and config generation.

Detects project languages, frameworks, and infrastructure to generate
a tailored argus.yml with the right scanners enabled.
"""

import sys
from pathlib import Path

# Banner displayed on init.
# Source of truth: img/argus_logo.txt (editable without code changes).
_LOGO_PATH = Path(__file__).resolve().parent.parent / "img" / "argus_logo.txt"
_BANNER_FALLBACK = (
    "\033[1;32m                                   A R G U S\033[0m\n"
    "\033[90m                          Perception is Protection\033[0m\n"
)


def _load_banner() -> str:
    """Load banner art from img/argus_logo.txt with a safe fallback."""
    if _LOGO_PATH.is_file():
        return _LOGO_PATH.read_text(encoding="utf-8")
    return _BANNER_FALLBACK


# Backward-compat alias for ad-hoc preview commands that import _BANNER.
_BANNER = _load_banner()


# Schema URL version is derived from the installed argus version so
# ``argus init`` always writes a schema pin that matches the wheel the
# user is running. Previously this was a hardcoded string that release-it
# never bumped — every 1.0.x install was writing ``0.7.0`` URLs into
# user argus.yml files (see issue #168-A).
from argus import __version__ as _SCHEMA_VERSION  # noqa: E402
_SCHEMA_URL = (
    "https://raw.githubusercontent.com/huntridge-labs/argus/"
    f"{_SCHEMA_VERSION}/argus-config.schema.json"
)
_DOCS_URL = "https://huntridge-labs.github.io/argus/"

# Exit codes (mirrors cli.py)
EXIT_SUCCESS = 0
EXIT_ERROR = 2


def run_init(
    force: bool = False,
    detect: bool = True,
    target_dir: str = ".",
) -> int:
    """Run the init workflow: detect project and generate argus.yml.

    Returns an exit code (0 = success, 2 = error).
    """
    root = Path(target_dir)
    config_path = root / "argus.yml"

    if sys.stderr.isatty():
        print(_load_banner(), file=sys.stderr)
        print(file=sys.stderr)

    if config_path.exists() and not force:
        print(
            f"argus.yml already exists at {config_path}.\n"
            "Use --force to overwrite.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Detect project signals
    signals = detect_project(root) if detect else {}

    # Generate config content
    config_content = generate_config(signals)
    config_path.write_text(config_content, encoding="utf-8")

    enabled_scanners = _extract_enabled_scanners(config_content)
    readiness = _check_local_readiness(enabled_scanners)

    _print_summary(signals, config_path, readiness=readiness)

    return EXIT_SUCCESS


def _extract_enabled_scanners(config_content: str) -> list[str]:
    """Parse scanners out of the just-generated argus.yml content.

    We parse the string we just wrote instead of re-reading the file so
    tests stay deterministic across filesystems, and we avoid importing
    the full config loader here just for a name list.
    """
    import yaml
    try:
        data = yaml.safe_load(config_content) or {}
    except yaml.YAMLError:
        return []
    scanners = data.get("scanners", {})
    if not isinstance(scanners, dict):
        return []
    enabled = []
    for name, cfg in scanners.items():
        if isinstance(cfg, dict) and cfg.get("enabled", True):
            enabled.append(name)
    return enabled


def _check_local_readiness(scanner_names: list[str]) -> dict[str, int] | None:
    """Return a {local, container, missing} bucket summary, or None when unavailable.

    Catches ImportError only — readiness check is best-effort and an
    optional preflight import (the [preflight] extra is not always
    installed) shouldn't fail init. Bugs inside the readiness logic
    itself should surface, not get silently swallowed.
    """
    if not scanner_names:
        return None
    try:
        from argus.preflight.tool_check import check_scanner_readiness, summarize
    except ImportError:
        return None
    statuses = check_scanner_readiness(scanner_names, backend="auto")
    return summarize(statuses)


def detect_project(root: Path) -> dict[str, list[str]]:
    """Scan the project directory for language, framework, and tool signals.

    Returns a dict mapping signal names to lists of evidence paths.
    Skips node_modules, .git, __pycache__, .venv, and other build dirs.
    """
    signals: dict[str, list[str]] = {}
    _skip = {"node_modules", ".git", "__pycache__", ".venv", "venv",
             ".tox", "htmlcov", "coverage", "dist", "build", ".eggs"}

    def _rglob_safe(pattern: str, limit: int = 5) -> list[Path]:
        """rglob that skips ignored directories."""
        results = []
        for p in root.rglob(pattern):
            if any(skip in p.parts for skip in _skip):
                continue
            results.append(p)
            if len(results) >= limit:
                break
        return results

    def _rel(p: Path) -> str:
        return str(p.relative_to(root))

    # ── Languages ──────────────────────────────────────────
    python_files = _rglob_safe("*.py")
    if python_files:
        signals["python"] = [_rel(p) for p in python_files]

    js_files = _rglob_safe("*.js") + _rglob_safe("*.ts")
    if js_files:
        signals["javascript"] = [_rel(p) for p in js_files[:5]]

    go_files = _rglob_safe("*.go")
    if go_files:
        signals["go"] = [_rel(p) for p in go_files]

    java_files = _rglob_safe("*.java")
    if java_files:
        signals["java"] = [_rel(p) for p in java_files]

    # ── Package managers / dependencies ────────────────────
    for manifest in ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"]:
        for p in root.glob(manifest):
            signals.setdefault("node", []).append(_rel(p))

    dep_files = [
        "requirements.txt", "requirements-*.txt", "poetry.lock",
        "Pipfile.lock", "go.sum", "Cargo.lock", "Gemfile.lock",
        "composer.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    ]
    for pattern in dep_files:
        for p in root.glob(pattern):
            rel = _rel(p)
            if rel not in signals.get("dependencies", []):
                signals.setdefault("dependencies", []).append(rel)

    # ── Containers ─────────────────────────────────────────
    dockerfiles = _rglob_safe("Dockerfile*")
    compose_files = _rglob_safe("docker-compose*.yml") + _rglob_safe("docker-compose*.yaml")
    if dockerfiles or compose_files:
        signals["container"] = [_rel(p) for p in (dockerfiles + compose_files)[:5]]

    # ── Infrastructure as code ─────────────────────────────
    tf_files = _rglob_safe("*.tf")
    k8s_dirs = [
        d for d in root.iterdir()
        if d.is_dir() and d.name in ("infrastructure", "terraform", "k8s", "kubernetes", "deploy")
    ]
    if tf_files or k8s_dirs:
        evidence = [_rel(p) for p in tf_files[:3]]
        evidence.extend(_rel(d) for d in k8s_dirs)
        signals["iac"] = evidence

    # ── CI/CD ──────────────────────────────────────────────
    gh_workflows = root / ".github" / "workflows"
    if gh_workflows.is_dir():
        wf = list(gh_workflows.glob("*.yml")) + list(gh_workflows.glob("*.yaml"))
        if wf:
            signals["github-actions"] = [_rel(p) for p in wf[:5]]

    gl_ci = root / ".gitlab-ci.yml"
    if gl_ci.is_file():
        signals["gitlab-ci"] = [_rel(gl_ci)]

    jenkinsfile = root / "Jenkinsfile"
    if jenkinsfile.is_file():
        signals["jenkins"] = [_rel(jenkinsfile)]

    # ── Existing tool configs (reference in generated argus.yml) ──
    # Keep this list aligned with argus.core.tool_config.DISCOVERY_RULES so
    # the signals "argus init detected" line reflects what will actually be
    # auto-picked-up at scan time.
    tool_configs = {
        "pyproject.toml": "python-config",
        ".bandit": "bandit-config",
        "bandit.yaml": "bandit-config",
        "bandit.yml": "bandit-config",
        ".gitleaks.toml": "gitleaks-config",
        ".gitleaksignore": "gitleaks-config",
        ".semgrepignore": "opengrep-config",
        "semgrep.yml": "opengrep-config",
        "semgrep.yaml": "opengrep-config",
        ".trivyignore": "trivy-config",
        "trivy.yaml": "trivy-config",
        "trivy.yml": "trivy-config",
        ".checkov.yaml": "checkov-config",
        ".checkov.yml": "checkov-config",
        "osv-scanner.toml": "osv-config",
        ".flake8": "flake8-config",
        "setup.cfg": "python-config",
        ".hadolint.yaml": "hadolint-config",
        ".yamllint.yml": "yamllint-config",
        ".eslintrc.json": "eslint-config",
        ".eslintrc.js": "eslint-config",
        "eslint.config.js": "eslint-config",
        "eslint.config.mjs": "eslint-config",
        "tflint.hcl": "tflint-config",
        ".tflint.hcl": "tflint-config",
    }
    for filename, signal_key in tool_configs.items():
        p = root / filename
        if p.is_file():
            signals.setdefault("tool-configs", []).append(f"{filename} ({signal_key})")

    return signals


def generate_config(signals: dict[str, list[str]]) -> str:
    """Generate argus.yml content based on detected signals."""
    lines = [
        # The schema URL is longer than yamllint's default 80-char
        # cap and can't be shortened (it's the pinned raw.github
        # path). Suppress the rule on just this line so the
        # generated argus.yml passes its own ``lint-yaml`` check
        # (issue #168-I).
        "# yamllint disable-line rule:line-length",
        f"# yaml-language-server: $schema={_SCHEMA_URL}",
        "# Argus Security Scanner Configuration",
        f"# Docs: {_DOCS_URL}",
        "# Generated by: argus init",
        "",
        'version: "1.0"',
        "",
        "scanners:",
    ]

    # Always-enabled scanners
    lines.append("  # Secret detection — always recommended")
    lines.append("  gitleaks:")
    lines.append("    enabled: true")
    lines.append("")

    # Python detection
    if "python" in signals:
        evidence = signals["python"][0]
        lines.append(f"  # Detected: Python files found ({evidence})")
        lines.append("  bandit:")
        lines.append("    enabled: true")
        lines.append('    path: "."')
        lines.append("")
    else:
        lines.append("  # bandit:")
        lines.append("  #   enabled: true  # Enable for Python projects")
        lines.append('  #   path: "."')
        lines.append("")

    # Dependency scanning
    if "dependencies" in signals or "node" in signals:
        dep_evidence = (
            signals.get("dependencies", []) + signals.get("node", [])
        )
        evidence = dep_evidence[0] if dep_evidence else "manifests"
        lines.append(f"  # Detected: dependency manifests found ({evidence})")
        lines.append("  osv:")
        lines.append("    enabled: true")
        lines.append("")
    else:
        lines.append("  # osv:")
        lines.append("  #   enabled: true  # Enable for dependency vulnerability scanning")
        lines.append("")

    # Multi-language SAST
    lines.append("  # Multi-language pattern-based SAST")
    lines.append("  opengrep:")
    lines.append("    enabled: true")
    lines.append('    path: "."')
    lines.append("")

    # Supply chain
    if "github-actions" in signals:
        evidence = signals["github-actions"][0]
        lines.append(f"  # Detected: GitHub Actions workflows ({evidence})")
        lines.append("  supply-chain:")
        lines.append("    enabled: true")
        lines.append("")
    else:
        lines.append("  # supply-chain:")
        lines.append("  #   enabled: true  # Enable if using GitHub Actions")
        lines.append("")

    # IaC scanning
    if "iac" in signals:
        evidence = signals["iac"][0]
        lines.append(f"  # Detected: infrastructure-as-code files ({evidence})")
        lines.append("  trivy-iac:")
        lines.append("    enabled: true")
        lines.append(f'    path: "{_guess_iac_path(signals)}"')
        lines.append("")
        lines.append("  checkov:")
        lines.append("    enabled: true")
        lines.append(f'    path: "{_guess_iac_path(signals)}"')
        lines.append("")
    else:
        lines.append("  # trivy-iac:")
        lines.append("  #   enabled: true  # Enable for Terraform/Kubernetes")
        lines.append('  #   path: "infrastructure"')
        lines.append("")
        lines.append("  # checkov:")
        lines.append("  #   enabled: true  # Enable for infrastructure policy checks")
        lines.append('  #   path: "infrastructure"')
        lines.append("")

    # Container scanning
    if "container" in signals:
        evidence = signals["container"][0]
        lines.append(f"  # Detected: container files ({evidence})")
        lines.append("  # Run with: argus scan container --discover")
        lines.append("  container:")
        lines.append("    enabled: true")
        lines.append("")
    else:
        lines.append("  # container:")
        lines.append("  #   enabled: true  # Enable for Docker image scanning")
        lines.append("  #   image_ref: \"myapp:latest\"")
        lines.append("")

    # DAST (always commented — requires target)
    lines.append("  # zap:")
    lines.append("  #   enabled: true  # Enable for web application DAST")
    lines.append("  #   target_url: \"http://localhost:3000\"")
    lines.append("")

    # Malware (always commented — opt-in)
    lines.append("  # clamav:")
    lines.append("  #   enabled: true  # Enable for malware scanning")
    lines.append('  #   path: "."')
    lines.append("")

    # ── Linters ────────────────────────────────────────────
    lines.append("  # ── Linters ──")
    lines.append("")

    if "python" in signals:
        lines.append("  lint-python:")
        lines.append("    enabled: true")
        lines.append("")
    else:
        lines.append("  # lint-python:")
        lines.append("  #   enabled: true")
        lines.append("")

    if "javascript" in signals or "node" in signals:
        lines.append("  lint-javascript:")
        lines.append("    enabled: true")
        lines.append("")
    else:
        lines.append("  # lint-javascript:")
        lines.append("  #   enabled: true")
        lines.append("")

    if "container" in signals:
        lines.append("  lint-dockerfile:")
        lines.append("    enabled: true")
        lines.append("")

    if "iac" in signals:
        lines.append("  lint-terraform:")
        lines.append("    enabled: true")
        lines.append(f'    path: "{_guess_iac_path(signals)}"')
        lines.append("")

    lines.append("  lint-yaml:")
    lines.append("    enabled: true")
    lines.append("")

    lines.append("  # lint-json:")
    lines.append("  #   enabled: true")
    lines.append("")

    # ── Tool config references ─────────────────────────────
    tool_configs = signals.get("tool-configs", [])
    if tool_configs:
        lines.append("# Detected tool configs (referenced automatically by scanners):")
        for cfg in tool_configs:
            lines.append(f"#   {cfg}")
        lines.append("")

    # Reporting section
    lines.extend([
        "reporting:",
        "  formats:",
        "    - terminal",
        "    - sarif",
        "  severity_threshold: high",
        '  output_dir: "./argus-results"',
        "",
        "execution:",
        "  backend: auto",
        "  pull_policy: if-not-present",
        "",
    ])

    return "\n".join(lines)


def _guess_iac_path(signals: dict[str, list[str]]) -> str:
    """Guess the IaC root path from detected signals."""
    iac_evidence = signals.get("iac", [])
    for path_str in iac_evidence:
        parts = Path(path_str).parts
        if parts and parts[0] in (
            "infrastructure", "terraform", "k8s", "kubernetes", "deploy"
        ):
            return parts[0]
    return "."


def _print_summary(
    signals: dict[str, list[str]],
    config_path: Path,
    readiness: dict[str, int] | None = None,
) -> None:
    """Print a polished summary of what was created and next steps."""
    G = "\033[32m"
    B = "\033[1;32m"
    D = "\033[90m"
    Y = "\033[33m"
    R = "\033[0m"

    print(f"\n{B}  Initialized!{R}  {D}Created {config_path}{R}")

    if signals:
        print(f"\n{G}  Detected:{R}")
        signal_labels = {
            "python": "Python source files",
            "javascript": "JavaScript/TypeScript files",
            "go": "Go source files",
            "java": "Java source files",
            "node": "Node.js project",
            "dependencies": "Dependency manifests",
            "container": "Container/Docker files",
            "iac": "Infrastructure as code",
            "github-actions": "GitHub Actions workflows",
            "gitlab-ci": "GitLab CI configuration",
            "jenkins": "Jenkinsfile",
            "tool-configs": "Existing tool configurations",
        }
        for key, evidence in signals.items():
            label = signal_labels.get(key, key)
            print(f"    {D}-{R} {label} {D}({evidence[0]}){R}")

    if readiness is not None:
        local = readiness["local"]
        container = readiness["container"]
        missing = readiness["missing"]
        print(f"\n{G}  Tool readiness on this machine:{R}")
        print(
            f"    {D}-{R} {local} ready locally, {container} via container, "
            f"{Y if missing else G}{missing} missing{R}"
        )
        if missing:
            print(
                f"    {D}-{R} {Y}Run {G}argus validate --check-tools{Y} "
                f"for per-scanner install suggestions.{R}"
            )

    print(f"\n{G}  Next steps:{R}")
    print(f"    {B}1.{R} Review argus.yml and adjust scanner settings")
    print(f"    {B}2.{R} Run: {G}argus validate{R}")
    print(f"    {B}3.{R} Run: {G}argus scan{R}")
    print(f"    {B}4.{R} AI integration: {G}pip install argus-security[mcp]{R} + {G}argus mcp{R}")

    # Shareable install hint — argus init runs once locally but the
    # config it just wrote is typically committed and used by
    # teammates / CI. Surface the canonical install command here so
    # the operator can paste it into a teammate's onboarding message
    # or a CI workflow without hunting for the right invocation.
    print(f"\n{G}  Share with your team:{R}")
    print(f"    {G}pip install argus-security{R}")

    print(f"\n  {D}{_DOCS_URL}{R}")
    print()
