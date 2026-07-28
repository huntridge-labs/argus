# Contributing to Argus

Welcome! This guide covers how to contribute scanners to the security scanning toolkit.

> **Architecture Note**: The **argus Python SDK** (`argus/` package) is the primary way to add and run scanners. Each scanner is a single Python module implementing the `Scanner` protocol. **Composite actions** (`.github/actions/`) remain available as a secondary path for GitHub Actions users who need direct workflow integration.

## Table of Contents

- [Getting Started](#getting-started)
- [Adding a Scanner via the SDK](#adding-a-scanner-via-the-sdk)
- [Adding a Linter via the SDK](#adding-a-linter-via-the-sdk)
- [Adding a Composite Action (GitHub Actions)](#adding-a-composite-action-github-actions)
- [Testing Your Changes](#testing-your-changes)
- [Documentation Requirements](#documentation-requirements)
- [Pull Request Process](#pull-request-process)
- [Best Practices](#best-practices)

---

## Getting Started

### Prerequisites

- Git
- GitHub account
- Python 3.11+
- Familiarity with the `Scanner` protocol (`argus/core/scanner.py`)
- Knowledge of the scanner tool you're integrating
- Basic understanding of GitHub Actions (for composite action contributions)

### Project Structure

```
argus/                            # Python SDK (primary interface)
├── core/                         # Models, engine, config, scanner protocol
│   ├── scanner.py               # Scanner protocol definition
│   ├── models.py                # Finding, ScanResult, Severity
│   └── engine.py                # Scan orchestration engine
├── scanners/                     # Scanner modules (one .py per scanner)
│   ├── __init__.py              # Scanner registry (includes linters via auto-merge)
│   ├── bandit.py                # Example: Bandit SAST scanner
│   └── ...                      # One module per scanner
├── linters/                      # Linter modules (one .py per linter)
│   ├── __init__.py              # LINTER_REGISTRY (auto-merges into SCANNER_REGISTRY)
│   ├── yamllint.py              # Example: YAML linter
│   └── ...                      # One module per linter
├── reporters/                    # Output: terminal, markdown, SARIF, JSON
├── containers.py                 # Container image manifest
└── tests/                        # SDK unit tests
    ├── scanners/                # Per-scanner test files
    └── ...

.github/actions/                  # Composite actions (GitHub Actions integration)
├── scanner-*/                    # Scanner composite actions
│   ├── action.yml               # Action definition
│   ├── .docsite.yml             # Docsite category declaration
│   ├── README.md                # Action documentation
│   ├── scripts/                 # Bundled Python scripts
│   │   ├── parse-results.py     # Parse scanner output → JSON
│   │   └── generate-summary.py  # Generate markdown summary
│   └── tests/                   # Co-located pytest tests
│       ├── test_parse_results.py
│       ├── test_generate_summary.py
│       └── conftest.py (optional)
├── linter-*/                    # Linter composite actions
├── parse-container-config/      # Config parser actions
├── security-summary/            # Summary aggregators
└── README.md                    # Actions catalog

examples/
├── workflows/
│   ├── composite-actions-example.yml     # Complete security workflow
│   └── actions-linting-example.yml       # Complete linting workflow
└── README.md

tests/
├── fixtures/                    # Shared mock data and test apps
│   └── scanner-outputs/         # Pre-captured scanner results
└── unit/actions/                # Action schema validation
```

### Key Concepts

**Argus SDK** (primary path):
- Single Python module per scanner implementing the `Scanner` protocol
- SDK handles tool execution, Docker fallback, result parsing, and reporting
- Register once in `argus/scanners/__init__.py` and the scanner is available everywhere

**Composite Actions** (GitHub Actions integration):
- Self-contained with bundled scripts
- Works on GHES with github.com access
- Easier to compose in workflow files
- Optional wrapper around SDK scanners

---

## Adding a Scanner via the SDK

This is the primary way to add a new scanner. Each scanner is a single Python module that implements the `Scanner` protocol defined in `argus/core/scanner.py`.

### Step 1: Create the Scanner Module

Create `argus/scanners/my_scanner.py`. The SDK provides two helpers — `parse_tool_version` (for `tool_version()`) and `run_subprocess_scan` (for `scan()`) — so a typical scanner is ~50 lines:

```python
"""My Scanner - brief description of what it scans."""

import json
import shutil
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity
from argus.core.scanner_template import ScanPaths, run_subprocess_scan
from argus.core.version import parse_tool_version


class MyScanner:
    """Wraps MyTool to scan for security issues."""

    name = "my-scanner"
    description = "What it scans, in one line"
    category = "sast"  # or "secrets", "iac", "sca", "container", "linter", ...
    container_image = get_image("my-scanner")
    # Set this if your container image declares ``ENTRYPOINT ["my-tool"]``.
    # The engine drops argv[0] when this attr is present, so build_args
    # can return the same argv shape for both local and container paths.
    container_entrypoint = "my-tool"

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """One-line wrapper — the template handles tempdir, subprocess, errors."""
        return run_subprocess_scan(self, path, config)

    def build_args(self, paths: ScanPaths, config: dict) -> list[str]:
        """Build the FULL argv (binary name as args[0]).

        Single source of truth for both local and container execution.
        Local path: ``paths.workspace`` is the host path the user gave;
        container path: ``paths.workspace`` is ``/workspace`` and
        ``paths.output`` is ``/output/results.json``. The engine handles
        the path translation; this method just consumes whatever paths
        it's handed.
        """
        args = [
            "my-tool", "scan",
            paths.workspace,
            "--format", "json",
            "--output", paths.output,
        ]
        if config.get("exclude"):
            args.extend(["--exclude", config["exclude"]])
        return args

    def is_available(self) -> bool:
        return shutil.which("my-tool") is not None

    def install_command(self) -> str | None:
        return "pip install my-tool"

    def tool_version(self) -> str | None:
        if not self.is_available():
            return None
        # Tool output: "my-tool X.Y.Z (build info)"
        return parse_tool_version(["my-tool", "--version"], r"^my-tool (\S+)")

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse tool output into normalized Finding objects."""
        data = json.loads(raw_output_path.read_text())
        return [
            Finding(
                id=item.get("rule_id", "UNKNOWN"),
                severity=Severity.from_string(item.get("severity", "UNKNOWN")),
                title=item.get("message", ""),
                description=item.get("message", ""),
                location=item.get("file", ""),
                scanner=self.name,
            )
            for item in data.get("results", [])
        ]
```

**Why this shape**: `build_args(paths, config)` replaces the historical pair of `_build_command(path, output, config)` (local) + `container_args(config)` (container). The two used to drift — different `--output` vs `--output-file` flag names, different exit-code handling — and the engine had to know about both. With one method that takes a `ScanPaths` value object, local and container execution share the same definition; the engine builds the right `ScanPaths` for the context (host paths locally, `/workspace` + `/output/...` in containers) and the scanner stays oblivious.

**When to skip the template**: if your tool emits results to stdout instead of a file (`grype version -o json`, ClamAV's text output) or runs an orchestration of multiple binaries (`supply_chain` → zizmor + actionlint), write a custom `scan()`. The template doesn't fit every shape and shouldn't be forced — see `grype.py`, `clamav.py`, `supply_chain.py` for examples.

**Scanner protocol requirements** (from `argus/core/scanner.py`):

| Attribute/Method | Required | Description |
|---|---|---|
| `name: str` | Yes | Unique scanner identifier (e.g., `"bandit"`) |
| `scan(path, config) -> ScanResult` | Yes | Run the scanner and return normalized results |
| `is_available() -> bool` | Yes | Check if the tool is installed locally |
| `install_command() -> str \| None` | Yes | Shell command to install the tool |
| `tool_version() -> str \| None` | Recommended | Installed tool version. Use `parse_tool_version()` from `argus.core.version` for the common case (regex match against `<tool> --version` output) — see `bandit.py`, `clamav.py`, `trivy.py`, `gitleaks.py` for examples. Only fall back to custom parsing for tools with structured output (JSON, etc.) — see `grype.py` |
| `build_args(paths, config) -> list[str]` | Yes (subprocess scanners) | Build the full argv for the tool. Used by both local and container execution paths — single source of truth. `paths` is a `ScanPaths(workspace, output)` value object. Drop `argv[0]` automatically when the image has an `ENTRYPOINT` — declare `container_entrypoint = "<bin>"` on the class |
| `container_image: str` | Optional | Docker image for container fallback |
| `container_entrypoint: str` | Optional | Set when the container image has `ENTRYPOINT ["<bin>"]`; engine drops `argv[0]` from `build_args` output |
| `parse_results(path) -> list[Finding]` | Yes | Parse raw output file into findings. May return `(list[Finding], dict)` to attach scanner-level metadata (e.g. `passed_count` for linters) |

**Reference implementation**: See `argus/scanners/bandit.py` for a complete, well-documented example.

### Step 2: Register in the Scanner Registry

Add your scanner to `argus/scanners/__init__.py`:

```python
from .my_scanner import MyScanner

# Add to __all__
__all__ = [
    # ... existing scanners
    "MyScanner",
]

# Add to SCANNER_REGISTRY
SCANNER_REGISTRY = {
    # ... existing entries
    "my-scanner": MyScanner,
}
```

### Step 3: Add Container Image (if applicable)

If your scanner uses a container image, add it to `argus/containers.py`:

```python
# In OFFICIAL_IMAGES (for upstream images) or CUSTOM_IMAGES (for argus-built images)
OFFICIAL_IMAGES = {
    # ... existing entries
    "my-scanner": "author/my-tool:version",
}
```

### Step 4: Add Test Fixtures

Add pre-captured scanner output to `tests/fixtures/scanner-outputs/my-scanner/`:

```bash
mkdir -p tests/fixtures/scanner-outputs/my-scanner
# Add sample output files (clean scan, findings, error cases)
```

### Step 5: Add Tests

Create `argus/tests/scanners/test_my_scanner.py`:

```python
"""Tests for MyScanner."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from argus.scanners.my_scanner import MyScanner


class TestMyScanner:
    def setup_method(self):
        self.scanner = MyScanner()

    def test_name(self):
        assert self.scanner.name == "my-scanner"

    def test_is_available_when_installed(self):
        with patch("shutil.which", return_value="/usr/bin/my-tool"):
            assert self.scanner.is_available() is True

    def test_is_available_when_missing(self):
        with patch("shutil.which", return_value=None):
            assert self.scanner.is_available() is False

    def test_parse_results(self, tmp_path):
        output_file = tmp_path / "results.json"
        output_file.write_text(json.dumps({
            "results": [
                {"rule_id": "R001", "severity": "HIGH", "message": "Issue found"}
            ]
        }))
        findings = self.scanner.parse_results(output_file)
        assert len(findings) == 1
        assert findings[0].id == "R001"

    def test_install_command(self):
        assert self.scanner.install_command() is not None
```

### Step 6 (Optional): Create Composite Action Wrapper

If GitHub Actions users need a workflow-level integration, create a composite action wrapper. See [Adding a Composite Action](#adding-a-composite-action-github-actions) below.

---

## Adding a Linter via the SDK

Linters implement the same `Scanner` protocol as security scanners but live in the `argus/linters/` package. They produce findings with `Severity.INFO` and are registered in `LINTER_REGISTRY`, which auto-merges into `SCANNER_REGISTRY` at import time.

### Step 1: Create the Linter Module

Create `argus/linters/my_linter.py` implementing the `Scanner` protocol:

```python
"""My Linter - brief description of what it lints."""

import shutil
import subprocess
from pathlib import Path

from argus.core.models import Finding, ScanResult, Severity


class MyLinter:
    """Wraps my-tool to lint files for style and syntax issues."""

    name = "lint-my-tool"

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run the linter against the given path and return results."""
        config = config or {}
        cmd = self._build_command(path, config)

        result = subprocess.run(cmd, capture_output=True, text=True)

        findings = self._parse_output(result.stdout)
        return ScanResult(
            scanner=self.name,
            findings=findings,
            metadata={"returncode": result.returncode},
        )

    def is_available(self) -> bool:
        """Check if the linting tool is installed."""
        return shutil.which("my-tool") is not None

    def install_command(self) -> str | None:
        """Return the shell command to install the tool, or None."""
        return "pip install my-tool"

    def _build_command(self, path: str, config: dict) -> list[str]:
        """Build the CLI command."""
        return ["my-tool", "--format", "parsable", path]

    def _parse_output(self, output: str) -> list[Finding]:
        """Parse tool output into findings with Severity.INFO."""
        findings = []
        for line in output.strip().splitlines():
            if not line.strip():
                continue
            finding = self._parse_line(line)
            if finding:
                findings.append(finding)
        return findings

    def _parse_line(self, line: str) -> Finding | None:
        """Parse a single output line into a Finding."""
        # Adapt parsing logic for your linter's output format
        return Finding(
            id="my-tool",
            severity=Severity.INFO,
            title=line.strip(),
            description=line.strip(),
            location="",
            scanner=self.name,
        )
```

**Key differences from security scanners:**
- Linter names are prefixed with `lint-` (e.g., `lint-yaml`, `lint-python`)
- Findings use `Severity.INFO` rather than security severity levels
- No container image is needed (linters run locally)

**Reference implementation**: See `argus/linters/yamllint.py` for a complete, well-documented example.

### Step 2: Register in the Linter Registry

Add your linter to `argus/linters/__init__.py`:

```python
from .my_linter import MyLinter

# Add to __all__
__all__ = [
    # ... existing linters
    "MyLinter",
]

# Add to LINTER_REGISTRY
LINTER_REGISTRY = {
    # ... existing entries
    "lint-my-tool": MyLinter,
}
```

The `LINTER_REGISTRY` auto-merges into `SCANNER_REGISTRY` (see `argus/scanners/__init__.py`), so `argus scan lint-my-tool` works immediately after registration. Shell completions (`argus completion zsh`) update automatically since they are generated dynamically from the registry.

### Step 3: Add Tests

Create `argus/tests/linters/test_my_linter.py`:

```python
"""Tests for MyLinter."""

from unittest.mock import patch

import pytest

from argus.linters.my_linter import MyLinter
from argus.core.models import Severity


class TestMyLinter:
    def setup_method(self):
        self.linter = MyLinter()

    def test_name(self):
        assert self.linter.name == "lint-my-tool"

    def test_is_available_when_installed(self):
        with patch("shutil.which", return_value="/usr/bin/my-tool"):
            assert self.linter.is_available() is True

    def test_is_available_when_missing(self):
        with patch("shutil.which", return_value=None):
            assert self.linter.is_available() is False

    def test_findings_use_info_severity(self):
        finding = self.linter._parse_line("some lint warning")
        assert finding is not None
        assert finding.severity == Severity.INFO

    def test_install_command(self):
        assert self.linter.install_command() is not None
```

### Step 4: Update Documentation

1. Update `.ai/architecture.yaml` (linters list)
2. Update `CLAUDE.md` if the linter introduces a new category

### Validation Checklist (Linters)

- [ ] Linter implements all required protocol methods (`scan`, `is_available`, `install_command`)
- [ ] Linter registered in `argus/linters/__init__.py`
- [ ] Linter name uses `lint-` prefix
- [ ] Findings use `Severity.INFO`
- [ ] `argus scan lint-<name>` works after registration
- [ ] Unit tests in `argus/tests/linters/`
- [ ] All tests pass: `pytest argus/tests/`

---

## Adding a Composite Action (GitHub Actions)

### Step 1: Create Action Structure

Create the directory structure for your scanner:

```bash
mkdir -p .github/actions/scanner-example/scripts
touch .github/actions/scanner-example/action.yml
touch .github/actions/scanner-example/.docsite.yml
touch .github/actions/scanner-example/README.md
touch .github/actions/scanner-example/scripts/parse-results.py
touch .github/actions/scanner-example/scripts/generate-summary.py
```

### Step 2: Define action.yml

See existing scanner actions for reference patterns (e.g., `scanner-bandit/action.yml`, `scanner-checkov/action.yml`).

**Standard structure**:
```yaml
name: 'Example Scanner'
description: |
  Run Example security scanner and generate reports.

inputs:
  scan_path:                  # What to scan
  fail_on_severity:          # Threshold (none/low/medium/high/critical)
  enable_code_security:      # Upload SARIF boolean
  post_pr_comment:          # Post PR comment boolean
  job_id:                   # For artifact naming

outputs:
  critical_count:           # Number of findings by severity
  high_count:
  medium_count:
  low_count:
  total_count:
  scan_status:             # passed/failed/skipped

runs:
  using: 'composite'
  steps:
    - name: Validate inputs
    - name: Run scanner
    - name: Parse results (using scripts/parse-results.sh)
    - name: Upload SARIF (if enabled)
    - name: Upload reports artifact
    - name: Generate summary (using scripts/generate-summary.sh)
    - name: Upload summary artifact
    - name: Comment PR (if enabled)
```

**Key patterns to follow**:
- Use `${{ github.action_path }}/scripts/` to reference bundled scripts
- Set `if: always()` on result processing steps
- Use `continue-on-error: true` for optional steps (SARIF, PR comments)
- Follow naming conventions for artifacts: `{scanner}-reports-{job_id}`

**Install the Argus SDK from the composite checkout, not from PyPI.**
Every SDK-using wrapper installs the SDK with this exact step (see
ADR-019 in `.ai/decisions.yaml` for the full rationale):

```yaml
- name: Install Argus SDK
  shell: bash
  # Install the SDK from the checked-out composite source. This matches
  # the consumer-scoped intent of composite actions (``uses: .../<wrapper>@tag``
  # implicitly pins the SDK version to the same tag) and sidesteps the
  # PyPI-release lag that would break ``pip install argus-security>=X``
  # for consumers until after the release ships.
  run: pip install "${{ github.action_path }}/../../.."
```

When `uses: org/argus/.github/actions/<wrapper>@<ref>` resolves on a
runner, GitHub clones the entire repo at `<ref>` into
`_actions/.../<ref>/`. `${{ github.action_path }}/../../..` is that
clone root, which contains `pyproject.toml` and the `argus/` package —
pip-installable directly. Don't replace this with `pip install
argus-security==<X>`: action releases would block on the PyPI publish
landing first, and air-gapped GHES setups would also need a private
PyPI mirror in addition to the repo mirror.

A CI guard (`validate-install-from-source` in `.github/workflows/test-actions.yml`)
fails the build if any SDK-using wrapper drifts back to `pip install
pyyaml` or any other shape.

### Step 3: Create Parser Script

Create `scripts/parse-results.py`:

```python
#!/usr/bin/env python3
"""
Example Scanner Results Parser
Usage: parse-results.py counts <report_file>
"""

import json
import sys
from pathlib import Path

def parse_counts(report_file):
    """Extract severity counts from scanner report."""
    if report_file == '-':
        data = json.load(sys.stdin)
    else:
        try:
            with open(report_file) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return 0, 0, 0, 0

    # Adjust parsing logic for your scanner's output format
    critical = len([r for r in data.get('results', []) if r.get('severity') == 'CRITICAL'])
    high = len([r for r in data.get('results', []) if r.get('severity') == 'HIGH'])
    medium = len([r for r in data.get('results', []) if r.get('severity') == 'MEDIUM'])
    low = len([r for r in data.get('results', []) if r.get('severity') == 'LOW'])

    return critical, high, medium, low

if __name__ == '__main__':
    command = sys.argv[1] if len(sys.argv) > 1 else None
    report_file = sys.argv[2] if len(sys.argv) > 2 else None

    if command == 'counts':
        c, h, m, l = parse_counts(report_file)
        print(f"{c} {h} {m} {l}")
    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        sys.exit(1)
```

**Parser requirements**:
- Must handle missing files gracefully (return 0 counts)
- Must handle malformed JSON (catch exceptions)
- Must map scanner's severity levels to standard: CRITICAL, HIGH, MEDIUM, LOW
- Output format: space-separated counts for environment variable assignment
- Support reading from stdin with `-` argument

### Step 4: Create Summary Generator

Create `scripts/generate-summary.py`:

```python
#!/usr/bin/env python3
"""
Example Scanner Summary Generator
Usage: generate-summary.py <output_file> <is_pr_comment>
"""

import os
import sys
from pathlib import Path

def generate_summary(output_file, is_pr_comment=False):
    """Generate markdown summary from severity counts."""

    # Get counts from environment
    critical = os.environ.get('CRITICAL', '0')
    high = os.environ.get('HIGH', '0')
    medium = os.environ.get('MEDIUM', '0')
    low = os.environ.get('LOW', '0')
    total = os.environ.get('TOTAL', '0')

    lines = []

    if is_pr_comment:
        lines.append('<details>')
        lines.append('<summary>🔍 Example Scanner</summary>')
    else:
        lines.append('## 🔍 Example Scanner Results')

    lines.append('')
    lines.append('| 🚨 Critical | ⚠️ High | 🟡 Medium | 🔵 Low | ❌ Total |')
    lines.append('|-------------|---------|-----------|--------|----------|')
    lines.append(f'| **{critical}** | **{high}** | **{medium}** | **{low}** | **{total}** |')
    lines.append('')

    # Add artifacts link
    github_url = os.environ.get('GITHUB_SERVER_URL', 'https://github.com')
    repo = os.environ.get('GITHUB_REPOSITORY', '')
    run_id = os.environ.get('GITHUB_RUN_ID', '')
    artifacts_url = f"{github_url}/{repo}/actions/runs/{run_id}#artifacts"
    lines.append(f'**📁 Artifacts:** [View Reports]({artifacts_url})')

    if is_pr_comment:
        lines.append('</details>')

    # Write to file
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        f.write('\n'.join(lines) + '\n')

if __name__ == '__main__':
    output_file = sys.argv[1] if len(sys.argv) > 1 else 'scanner-summaries/example.md'
    is_pr_comment = sys.argv[2].lower() == 'true' if len(sys.argv) > 2 else False
    generate_summary(output_file, is_pr_comment)
```

**Summary requirements**:
- Use consistent emoji and formatting
- Support both PR comment and job summary modes
- Include artifacts link
- Keep it concise but informative
- Create output directory if it doesn't exist

### Step 5: Create Documentation

Create `README.md` for your action:

```markdown
# Example Scanner Composite Action

Brief description of what this scanner detects.

## Usage

### Basic Example
\`\`\`yaml
- uses: huntridge-labs/argus/.github/actions/scanner-example@1.11.0
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    scan_path: 'src'
    fail_on_severity: 'high'
\`\`\`

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `scan_path` | Path to scan | No | `.` |
| `fail_on_severity` | Fail threshold | No | `none` |
| `enable_code_security` | Upload SARIF | No | `false` |
| `post_pr_comment` | Post PR comment | No | `true` |

## Outputs

| Output | Description |
|--------|-------------|
| `critical_count` | Critical findings |
| `high_count` | High findings |
| `total_count` | Total findings |
| `scan_status` | Status (passed/failed/skipped) |

## Requirements

- Scanner tool version requirements
- Supported file types
- Dependencies
```

### Step 6: Register with the Documentation Site

Create `.github/actions/scanner-example/.docsite.yml` to declare the action's category:

```yaml
category: sast  # Must match a category defined in docsite.yml
```

Available categories are defined in `docsite.yml` at the repo root (e.g., `sast`, `secrets`, `container`, `dast`, `infrastructure`, `malware`, `dependencies`, `linting`, `compliance`, `ai`, `utility`).

To validate your configuration:

```bash
cd scripts && python -m docsite --validate
```

This ensures your `.docsite.yml` exists, references a valid category, and that the site will build correctly.

To preview the documentation site locally:

```bash
cd scripts && python -m docsite --output-dir /tmp/argus-docs
cd /tmp/argus-docs && mkdocs serve
```

### Step 7: Update Actions Catalog

Add to `.github/actions/README.md`:

```markdown
| [scanner-example](scanner-example/) | Example scanner description | Languages | [README](scanner-example/README.md) |
```

### Step 8: Add to Example Workflows

Add your scanner to `examples/workflows/composite-actions-example.yml`:

```yaml
  example-scanner:
    name: Example Scanner
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: huntridge-labs/argus/.github/actions/scanner-example@1.11.0
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          scan_path: 'src'
          post_pr_comment: false  # Let security-summary handle comments

  security-summary:
    needs:
      - example-scanner  # Add to needs array
      - bandit
      # ... other scanners
```

---

## Testing Your Changes

### Testing Approach

**SDK tests** live in the `argus/tests/` package:
```
argus/tests/
├── scanners/                   # Per-scanner unit tests
│   ├── test_bandit.py
│   ├── test_my_scanner.py
│   └── ...
├── reporters/                  # Reporter tests
├── test_cli.py                 # CLI tests
├── test_engine.py              # Engine tests
├── test_models.py              # Model tests
└── conftest.py
```

**Action tests** are co-located with the composite actions they validate:
```
.github/actions/scanner-myScanner/
├── action.yml
├── scripts/
│   ├── parse-results.py
│   └── generate-summary.py
└── tests/                      # Action-level tests
    ├── test_parse_results.py
    ├── test_generate_summary.py
    └── conftest.py (optional)
```

**Shared fixtures** - mock data centralized for reuse:
```
tests/fixtures/
├── scanner-outputs/            # Pre-captured scanner results
├── test-apps/                  # Minimal test apps
└── configs/                    # Test configurations
```

**Run tests**:
```bash
pytest                                    # All tests with coverage
pytest --no-cov -q                        # Fast mode (no coverage)
pytest argus/tests/                       # SDK tests only
pytest argus/tests/ --no-cov -q           # Fast SDK tests
pytest argus/tests/scanners/test_bandit.py  # Single scanner
pytest .github/actions/scanner-x/tests/  # Single action tests
```

**Key principles**:
1. SDK scanners tested in `argus/tests/scanners/`
2. Action scripts tested co-located with their action
3. Fixtures shared across both SDK and action tests (avoid duplication)
4. Use synthetic data, not real vulnerabilities
5. Measure coverage with pytest-cov

See `tests/CONTRIBUTING.md` for detailed pytest guide.

### Manual Testing

Create a test workflow:

```yaml
name: Test Example Scanner

on:
  workflow_dispatch:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: ./.github/actions/scanner-example
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          scan_path: 'tests/fixtures/test-apps/example-app'
```

### Automated Testing ✅

Test infrastructure is complete:

- ✅ Unit tests for parser scripts (co-located in `.github/actions/*/tests/`)
- ✅ Unit tests for summary generators (co-located)
- ✅ Integration tests for full actions (`.github/workflows/test-actions*.yml`)
- ✅ Coverage reporting via Codecov
- ✅ 174+ tests running in CI/CD

### Validation Checklist

**SDK scanners:**
- [ ] Scanner implements all required protocol methods
- [ ] Scanner registered in `argus/scanners/__init__.py`
- [ ] Container image added to `argus/containers.py` (if applicable)
- [ ] `parse_results` handles various input formats
- [ ] `is_available` correctly detects tool presence
- [ ] Unit tests in `argus/tests/scanners/`
- [ ] Test fixtures in `tests/fixtures/scanner-outputs/`
- [ ] All tests pass: `pytest argus/tests/`

**Composite actions:**
- [ ] Action runs without errors
- [ ] All outputs are set correctly
- [ ] Parser handles various input formats
- [ ] Summary markdown is valid
- [ ] `.docsite.yml` created with valid category
- [ ] Docsite validation passes: `cd scripts && python -m docsite --validate`
- [ ] Unit tests added in `.github/actions/*/tests/`
- [ ] Tests use shared fixtures from `tests/fixtures/`
- [ ] All tests pass: `pytest`
- [ ] SARIF upload works (if applicable)
- [ ] Artifacts upload with correct names
- [ ] PR comments work
- [ ] Severity thresholds fail appropriately

---

## Documentation Requirements

### For SDK Scanners

Every SDK scanner must include:

1. **Module docstring** in `argus/scanners/my_scanner.py` describing what the scanner detects
2. **Container image entry** in `argus/containers.py` (if the scanner supports container execution)
3. **Registry entry** in `argus/scanners/__init__.py`
4. **Test file** in `argus/tests/scanners/test_my_scanner.py`
5. **Test fixtures** in `tests/fixtures/scanner-outputs/my-scanner/`
6. **Changelog** entry in `CHANGELOG.md`

### For Composite Actions

Every composite action must include:

1. **Action README.md**
   - Purpose and capabilities
   - Usage examples
   - Complete inputs/outputs tables
   - Requirements

2. **Docsite Registration**
   - `.docsite.yml` with valid category (see composite action Step 6 above)
   - Validate with `cd scripts && python -m docsite --validate`

3. **Inline Documentation**
   - Comments in action.yml
   - Comments in scripts
   - Helpful error messages

4. **Catalog Entry**
   - Add to `.github/actions/README.md`

5. **Usage Example**
   - Add to `examples/composite-actions-example.yml`

6. **Changelog**
   - Update `CHANGELOG.md`

---

## Pull Request Process

### Before Submitting

- [ ] Manual testing complete
- [ ] Documentation complete
- [ ] SDK scanner tests added in `argus/tests/scanners/` (if SDK scanner)
- [ ] Action tests added in `.github/actions/*/tests/` (if composite action)
- [ ] All tests pass: `pytest`
- [ ] Coverage meets 80% threshold
- [ ] Follows existing patterns (see `argus/scanners/bandit.py` for SDK reference)
- [ ] Automated tests pass in CI

### PR Template

```markdown
## Add Example Scanner Composite Action

### Summary
Brief description of the scanner.

### Scanner Details
- **Tool**: Example Scanner v1.0
- **Languages**: Python, JavaScript
- **Output Formats**: SARIF, JSON

### Changes
- ✅ Created scanner-example action
- ✅ Added parser and summary scripts
- ✅ Updated actions catalog
- ✅ Added examples
- ✅ Documentation complete

### Testing
- [x] Tested manually
- [x] Verified outputs
- [x] Confirmed artifacts
- [ ] TODO: Unit tests
- [ ] TODO: Integration tests

### Usage
\`\`\`yaml
- uses: huntridge-labs/argus/.github/actions/scanner-example@1.11.0
\`\`\`
```

---

## Best Practices

### Naming Conventions

- **SDK scanner modules**: `argus/scanners/{tool}.py` (snake_case, e.g., `trivy_iac.py`, `supply_chain.py`)
- **SDK scanner classes**: `PascalCase` + `Scanner` suffix (e.g., `BanditScanner`, `TrivyIacScanner`)
- **Scanner registry names**: kebab-case (e.g., `"trivy-iac"`, `"supply-chain"`)
- **SDK linter modules**: `argus/linters/{tool}.py` (snake_case, e.g., `yamllint.py`, `python_lint.py`)
- **SDK linter classes**: `PascalCase` + `Linter` suffix (e.g., `YamllintLinter`, `HadolintLinter`)
- **Linter registry names**: `lint-` prefix + kebab-case (e.g., `"lint-yaml"`, `"lint-python"`)
- **Actions**: `scanner-{tool}` or `linter-{tool}`
- **Scripts**: `parse_results.py`, `generate_summary.py`
- **Artifacts**: `{tool}-reports-{job_id}`, `scanner-summary-{tool}-{job_id}`

### Script Guidelines

1. Validate inputs before processing
2. Handle missing files gracefully
3. Provide default values
4. Use descriptive error messages
5. Use `pathlib` for file operations

### Security

- Never hardcode secrets
- Validate all inputs
- Use `continue-on-error` for optional steps
- Pin action versions
- Minimize required permissions

### Performance

- Set reasonable timeouts
- Cache dependencies
- Minimize scan scope
- Generate only necessary formats

---

## Architecture Migration Complete

- Argus Python SDK (`argus/`) is the primary scanner interface
- 22 reusable workflow wrappers (`scanner-*.yml`) have been removed
- All scanner logic consolidated into SDK modules implementing the `Scanner` protocol
- SDK handles tool execution, Docker container fallback, result parsing, and reporting
- Composite actions remain for direct GitHub Actions integration
- All scripts and tests are Python with pytest
- Unified coverage with pytest-cov

---

## Getting Help

- 📋 See `argus/scanners/bandit.py` for the SDK reference implementation
- 📋 Check existing composite actions for action-level patterns
- 📖 Review `CLAUDE.md` for architecture
- 📝 See `tests/TODO.md` for testing
- 💬 Open a [Discussion](https://github.com/huntridge-labs/argus/discussions)
- 🐛 Report via [Issues](https://github.com/huntridge-labs/argus/issues)

---

**Thank you for contributing! 🎉**
