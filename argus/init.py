"""argus init — project detection and config generation.

Detects project languages, frameworks, and infrastructure to generate
a tailored argus.yml with the right scanners enabled.
"""

import sys
from pathlib import Path

# Banner displayed on init — generated from the Argus logo.
# Static string, no runtime dependency on ascii_magic.
_BANNER = """\
\033[32m                 gXXXPGGGGGGGGZZX\033[0m
\033[32m             h44EEXbbPPGGGGPGGGGGZZZZ\033[0m
\033[32m          ShVV4PPEEgXPZ        QddEGG\033[0m
\033[32m        Vhhh4Ed444     PGGG     pqmmm66p\033[0m
\033[32m      VghdVhhVV    GZGGGYYGGGZX    6mmqpppp2\033[0m
\033[32m     hh4hghhh      GGOYZGGZYOGG      m6mmmppF\033[0m
\033[32m     hhhVVVhg       GZYZGGGYbP       mm6pmmpF\033[0m
\033[32m       hhhhhVhh5     XGGYYZGG      mmmmqm6pF\033[0m
\033[32m          dhhhhhhh     GZbb     Sqqqhgmmm5\033[0m
\033[32m           EXXg4dd44Vph2 nVhggSSqVVqqmm\033[0m
\033[32m            4EEE444dVVVhhhhhd4VSSSqmh\033[0m
\033[32m                PE44VVVhhhhhggSgV\033[0m

\033[1;32m  █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗\033[0m
\033[1;32m  ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝\033[0m
\033[1;32m  ███████║██████╔╝██║  ███╗██║   ██║███████╗\033[0m
\033[1;32m  ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║\033[0m
\033[1;32m  ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║\033[0m
\033[1;32m  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝\033[0m
\033[90m  Security Scanner — See Everything\033[0m
"""

# Schema URL version is managed by release-it during releases
_SCHEMA_VERSION = "0.7.0"
_SCHEMA_URL = (
    "https://raw.githubusercontent.com/huntridge-labs/argus/"
    f"{_SCHEMA_VERSION}/argus-config.schema.json"
)
_DOCS_URL = "https://huntridge-labs.github.io/argus/"

# Exit codes (mirrors cli.py)
EXIT_SUCCESS = 0
EXIT_ERROR = 2


def run_init(
    platform: str = "none",
    force: bool = False,
    detect: bool = True,
    target_dir: str = ".",
) -> int:
    """Run the init workflow: detect, generate config, optionally generate CI.

    Returns an exit code (0 = success, 2 = error).
    """
    root = Path(target_dir)
    config_path = root / "argus.yml"

    # Show banner on interactive terminals
    if sys.stderr.isatty():
        print(_BANNER, file=sys.stderr)

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
    print(f"Created {config_path}")

    # Generate CI workflow if requested
    ci_created = False
    if platform == "github":
        ci_created = _generate_github_workflow(root)

    # Print summary
    _print_summary(signals, config_path, platform, ci_created)

    return EXIT_SUCCESS


def detect_project(root: Path) -> dict[str, list[str]]:
    """Scan the project directory for language and framework signals.

    Returns a dict mapping signal names to lists of evidence paths.
    """
    signals: dict[str, list[str]] = {}

    python_patterns = list(root.rglob("*.py"))
    if python_patterns:
        signals["python"] = [str(p.relative_to(root)) for p in python_patterns[:5]]

    for manifest in ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"]:
        matches = list(root.glob(manifest))
        if matches:
            signals.setdefault("node", []).extend(
                str(p.relative_to(root)) for p in matches
            )

    for lockfile in [
        "requirements.txt", "requirements-*.txt", "poetry.lock",
        "Pipfile.lock", "go.sum", "Cargo.lock", "Gemfile.lock",
        "composer.lock",
    ]:
        matches = list(root.glob(lockfile))
        if matches:
            signals.setdefault("dependencies", []).extend(
                str(p.relative_to(root)) for p in matches
            )

    # Also check for package-lock.json as a dependency signal
    for manifest in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]:
        matches = list(root.glob(manifest))
        if matches:
            signals.setdefault("dependencies", []).extend(
                str(p.relative_to(root)) for p in matches
                if str(p.relative_to(root)) not in signals.get("dependencies", [])
            )

    dockerfile_patterns = list(root.rglob("Dockerfile*"))
    compose_patterns = list(root.rglob("docker-compose*.yml")) + list(
        root.rglob("docker-compose*.yaml")
    )
    if dockerfile_patterns or compose_patterns:
        signals["container"] = [
            str(p.relative_to(root))
            for p in (dockerfile_patterns + compose_patterns)[:5]
        ]

    tf_files = list(root.rglob("*.tf"))
    k8s_dirs = [
        d for d in root.iterdir()
        if d.is_dir() and d.name in ("infrastructure", "terraform", "k8s", "kubernetes", "deploy")
    ]
    if tf_files or k8s_dirs:
        evidence = [str(p.relative_to(root)) for p in tf_files[:3]]
        evidence.extend(str(d.relative_to(root)) for d in k8s_dirs)
        signals["iac"] = evidence

    gh_workflows = root / ".github" / "workflows"
    if gh_workflows.is_dir():
        workflow_files = list(gh_workflows.glob("*.yml")) + list(
            gh_workflows.glob("*.yaml")
        )
        if workflow_files:
            signals["github-actions"] = [
                str(p.relative_to(root)) for p in workflow_files[:5]
            ]

    return signals


def generate_config(signals: dict[str, list[str]]) -> str:
    """Generate argus.yml content based on detected signals."""
    lines = [
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


def _generate_github_workflow(root: Path) -> bool:
    """Generate a minimal GitHub Actions security scanning workflow.

    Returns True if the file was created, False if it already exists.
    Never overwrites an existing workflow file.
    """
    workflows_dir = root / ".github" / "workflows"
    workflow_path = workflows_dir / "security-scan.yml"

    if workflow_path.exists():
        print(f"  Skipped: {workflow_path} already exists")
        return False

    workflows_dir.mkdir(parents=True, exist_ok=True)

    content = """\
# Argus Security Scanning
# Generated by: argus init
# Docs: https://huntridge-labs.github.io/argus/
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Argus
        run: pip install pyyaml

      - name: Run security scan
        run: python -m argus scan --severity-threshold high
"""
    workflow_path.write_text(content, encoding="utf-8")
    print(f"Created {workflow_path}")
    return True


def _print_summary(
    signals: dict[str, list[str]],
    config_path: Path,
    platform: str,
    ci_created: bool,
) -> None:
    """Print a summary of what was created and next steps."""
    print()
    print("Argus initialized!")
    print()

    if signals:
        print("Detected:")
        signal_labels = {
            "python": "Python source files",
            "node": "Node.js project",
            "dependencies": "Dependency manifests",
            "container": "Container/Docker files",
            "iac": "Infrastructure as code",
            "github-actions": "GitHub Actions workflows",
        }
        for key, evidence in signals.items():
            label = signal_labels.get(key, key)
            print(f"  - {label} ({evidence[0]})")
        print()

    print("Next steps:")
    print(f"  1. Review {config_path} and adjust scanner settings")
    print("  2. Run: argus validate")
    print("  3. Run: argus scan")
    if platform == "github" and ci_created:
        print("  4. Commit .github/workflows/security-scan.yml")
    elif platform == "github" and not ci_created:
        print("  4. Review existing .github/workflows/security-scan.yml")
    print()
    print(f"Docs: {_DOCS_URL}")
