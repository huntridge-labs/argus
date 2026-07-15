# Argus

Python SDK and GitHub Actions toolkit for comprehensive security scanning. The **Argus SDK** (`argus/` package) is the primary interface for running scans locally or in CI. **Composite actions** (`.github/actions/`) remain available for GitHub Actions users, designed for GitHub Enterprise Server (GHES) with github.com access.

---

## Project Vision & Goals

**Primary Vision**: Make it as easy as possible for users to employ a hardening pipeline on their projects to gain insights into their security footprint and current vulnerabilities.

### Core Principles

1. **Documentation serves both humans and AI**: Concise, clear, on point. Structured context in `.ai/` for machine-readability.
2. **Code must be simple and maintainable**: Minimize complexity, maximize clarity. Easy for anyone to understand and extend.
3. **Dependabot is foundational**: Automated dependency updates are critical to the pipeline's value.
4. **Trust is everything**: The pipeline must earn trust in PRs through extremely robust testing. Only then can it auto-merge and auto-release.
5. **Automation end-state**:
   - Dependabot dependency updates arrive in PRs
   - Pipeline runs automatically
   - Green test results = trusted
   - Auto-merge enabled
   - Auto-release to users

---

## Testing Philosophy

**Python everywhere: SDK, action scripts, and all tests are Python.**

### Standards

- **Single Language**: Python for the SDK, all action scripts, and tests (not Bash, not Node.js for actions)
- **Single Test Framework**: pytest (not jest, mocha, or other)
- **Single Coverage Tool**: pytest-cov (with `--cov-fail-under=80` in pytest.ini)
- **Minimum Coverage**: 80% enforced at all times

### Test Structure

```
argus/                                 # SDK package
├── tests/
│   ├── conftest.py
│   ├── test_cli.py                   # CLI tests
│   ├── test_config.py                # Config loading tests
│   ├── test_containers.py            # Docker execution tests
│   ├── test_engine.py                # Scan engine tests
│   ├── test_models.py                # Data model tests
│   ├── scanners/                     # Per-scanner unit tests
│   │   ├── test_bandit.py
│   │   ├── test_gitleaks.py
│   │   └── ...                       # One test file per scanner
│   └── reporters/                    # Reporter tests
│       ├── test_terminal.py
│       ├── test_markdown.py
│       ├── test_sarif.py
│       └── test_json_report.py

.github/actions/scanner-{name}/       # Composite action tests
├── scripts/
│   ├── parse-results.py              # Scanner output → JSON
│   └── generate-summary.py           # JSON → Markdown
└── tests/
    ├── test_parse_results.py
    ├── test_generate_summary.py
    └── conftest.py (optional)

tests/
├── fixtures/
│   └── scanner-outputs/              # Pre-captured real scanner results
└── (integration tests)
```

### Test Execution

```bash
# Full run with coverage (enforced: ≥80%)
pytest

# Fast validation (no coverage)
pytest --no-cov -q

# SDK tests only
pytest argus/tests/

# Specific SDK scanner
pytest argus/tests/scanners/test_bandit.py

# Specific composite action
pytest .github/actions/scanner-clamav/tests/
```

### Reference Implementations

**SDK scanner**: Any scanner in `argus/scanners/` (e.g., `bandit.py`) — implements the `Scanner` protocol with `scan()`, `is_available()`, and `install_command()` methods.

**Composite action**: `scanner-clamav` remains the reference pattern for:
- Python action script structure
- Test organization and fixtures
- Coverage targets (80%+)
- How to test scanner parsing and summary generation

---

## Project Conventions

### Versioning & Release

- **Single Version Source**: `version.yaml` (prevents drift)
- **Release Command**: `npm run release` (manages all version updates and tags)
- **Version Tags**: Release workflow auto-tags and publishes

### Commit Messages

Follow **Conventional Commits**:
```
feat(scanner-name): add support for X
fix(parser): handle empty results
docs: update scanner reference
test(bandit): add edge case coverage
refactor: simplify parse logic
```

### Release Process

Users depend on you auto-releasing after dependency updates pass. The testing pipeline must be bulletproof for this trust.

---

## AI Context Ecosystem

This project uses **AI Context as Code (AICaC)** - structured, machine-readable context in `.ai/`:

| File | Purpose |
|------|---------|
| `.ai/context.yaml` | Project metadata and entry points |
| `.ai/architecture.yaml` | Component relationships and dependencies |
| `.ai/workflows.yaml` | Common tasks with exact commands |
| `.ai/decisions.yaml` | Architectural Decision Records (ADRs) |
| `.ai/errors.yaml` | Error patterns and solutions |
**Reading order**: `.ai/context.yaml` → relevant module files → source code

### CRITICAL: Maintain .ai/ Files

**After making changes to this project, you MUST update the relevant `.ai/` files.**

| When you change... | Update... |
|--------------------|-----------|
| Components/structure | `.ai/architecture.yaml` |
| Commands/tasks | `.ai/workflows.yaml` |
| Make design decisions | `.ai/decisions.yaml` |
| Fix common errors | `.ai/errors.yaml` |
| Project metadata | `.ai/context.yaml` |
| Scanners or actions | `.ai/architecture.yaml` (scanners list + components) |
| Version number | `.ai/context.yaml` (version field) |

**Before completing any task**, verify:
```
[ ] Relevant .ai/ files updated (or confirmed not needed)
```

---

## AI Assistant Configuration

### Global Standards (Claude Code)

Claude Code users: Global rules, skills, and agents from `~/.claude/` are automatically applied. These include:

- **Rules**: coding-style, git-workflow, testing, security, performance, refactor-clean
- **Skills**: security-skills, documentation-skills, data-analysis-skills
- **Agents**: planner, security-reviewer, technical-docs-writer

Source: [huntridge-labs/cheat-codes](https://github.com/huntridge-labs/cheat-codes)

### Project Overrides

To override global settings for this project, create `.claude/settings.json`:

```json
{
  "rules": {
    "disabled": ["performance"],
    "project_specific": true
  }
}
```

Or add project-specific rules in `.claude/rules/`.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CLAUDE_SKIP_GLOBAL_RULES` | Skip loading ~/.claude/rules/ | `false` |
| `CLAUDE_VERBOSE` | Show which rules are being applied | `false` |

### GitHub Copilot Users

Copilot reads only this file (via `.github/copilot-instructions.md` symlink). Global `~/.claude/` config does not apply. Key standards to follow:

- **Commits**: Conventional commits (`feat:`, `fix:`, `refactor:`, etc.)
- **Testing**: 80%+ coverage, TDD for new features
- **Security**: No hardcoded secrets, validate inputs, use parameterized queries
- **Code Style**: Functional patterns, immutability, early returns

---

## Architecture

The project has two interfaces: the **Argus SDK** (primary) and **composite actions** (for GitHub Actions users).

### Argus SDK (`argus/` package)

The SDK is the primary interface. Users run `argus scan --config argus.yml` to execute scans locally or in CI. The engine handles tool installation via Docker containers or local execution.

```
argus/                                 # Python SDK package
├── __init__.py                       # Version (0.1.0)
├── __main__.py                       # Entry point: argus
├── cli.py                            # CLI (click-based): scan, list, version
├── containers.py                     # Docker execution backend
├── core/
│   ├── config.py                     # YAML config loading (argus.yml)
│   ├── engine.py                     # Scan orchestration engine
│   ├── exclusions.py                 # Path exclusion set + **-glob matcher
│   ├── findings_view.py              # Shared UI-free view logic (ViewState, compute_summary) — consumed by both viewer interfaces
│   ├── models.py                     # Finding, ScanResult, Severity
│   ├── sbom.py                       # SBOM format detection (CycloneDX, SPDX, Syft)
│   ├── scanner.py                    # Scanner protocol definition
│   └── tool_config.py                # Per-scanner canonical config auto-discovery
├── scanners/                         # Scanner modules (one per tool)
│   ├── __init__.py                   # SCANNER_REGISTRY + get_scanner()
│   ├── bandit.py                     # Python SAST
│   ├── checkov.py                    # IaC scanning
│   ├── clamav.py                     # Malware scanning
│   ├── container.py                  # Container image scanning
│   ├── gitleaks.py                   # Secret detection
│   ├── opengrep.py                   # Pattern-based SAST
│   ├── osv.py                        # Dependency vulnerability scanning
│   ├── supply_chain.py               # GitHub Actions security
│   ├── trivy_iac.py                  # IaC scanning (Trivy)
│   └── zap.py                        # DAST web scanning
├── linters/                          # Linter modules (one per tool)
│   ├── __init__.py                   # LINTER_REGISTRY (auto-merges into SCANNER_REGISTRY)
│   ├── yamllint.py                   # YAML linting
│   ├── jsonlint.py                   # JSON linting
│   ├── python_lint.py                # Python linting
│   ├── jshint.py                     # JavaScript linting
│   ├── hadolint.py                   # Dockerfile linting
│   └── terraform.py                  # Terraform linting
├── reporters/                        # Output format handlers
│   ├── __init__.py                   # REPORTER_REGISTRY
│   ├── terminal.py                   # Rich terminal output
│   ├── markdown.py                   # Markdown summary
│   ├── sarif.py                      # SARIF format
│   └── json_report.py               # JSON format
├── viewers/                          # `argus view` interfaces (optional extras)
│   ├── __init__.py                   # ViewerUnavailable shared exception
│   ├── terminal/                     # `argus view --interface=terminal` — Textual TUI ([terminal] extra)
│   │   ├── app.py                    # Textual App, HelpScreen, DashboardScreen, PickerScreens
│   │   ├── loader.py                 # argus-results.json → ScanSummary
│   │   └── export.py                 # CSV / JSON / Markdown / SARIF writers
│   └── browser/                      # `argus view --interface=browser` — FastAPI web UI, 127.0.0.1 only ([browser] extra)
│       ├── app.py                    # FastAPI routes: /, /findings, /picker, /healthz
│       ├── templates/                # Jinja2: base, summary (dashboard), findings, picker
│       └── static/                   # argus.css + auto-filter.js (vanilla, no framework)
└── tests/                            # 20 test files, comprehensive coverage
```

### Composite Actions (for GitHub Actions users)

Composite actions remain for users who consume Argus directly in GitHub Actions workflows.

```
.github/actions/
├── scanner-*/                         # Individual scanner actions
│   ├── action.yml                    # Action definition
│   ├── .docsite.yml                  # Docsite category declaration
│   ├── scripts/                      # Supporting Python scripts
│   │   ├── parse-results.py         # Result parsing
│   │   └── generate-summary.py      # Summary generation
│   ├── tests/                        # Co-located pytest tests
│   └── README.md                     # Action documentation
├── parse-container-config/           # Config-driven container scanning
├── comment-pr/                       # PR comment utility
├── security-summary/                 # Aggregate security results
└── linting-summary/                  # Aggregate linting results

examples/workflows/                   # User-facing workflow examples
```

**Why Composite Actions?**
- Works on any GHES with github.com access (no reusable workflow restrictions)
- Self-contained with scripts and dependencies
- Easier to compose and customize
- Faster execution (no cross-repo workflow calls)

## SDK Scan Flow

1. User runs `argus scan --config argus.yml` (or specifies scanners via CLI flags)
2. Config loaded by `argus.core.config` — resolves scanner list, paths, severity thresholds
3. Engine (`argus.core.engine`) iterates over requested scanners
4. Each scanner module implements the `Scanner` protocol: `scan()`, `is_available()`, `install_command()`
5. Engine checks `is_available()` — if the tool is missing, it can run via Docker container (`containers.py`)
6. Scanner runs the underlying tool, parses output into `Finding` / `ScanResult` objects
7. Results passed to reporters (terminal, markdown, SARIF, JSON) based on config
8. Exit code reflects severity threshold compliance

## Composite Action Flow

1. User configures action inputs (paths, severity thresholds, etc.)
2. Action runs scanner with appropriate configuration
3. Results parsed by action's `scripts/parse-results.py`
4. Summary generated by `scripts/generate-summary.py`
5. Artifacts uploaded (reports, SARIF, summaries)
6. Outputs set (counts, status) for downstream jobs
7. Optional: PR comment posted
8. Optional: SARIF uploaded to GitHub Security

## Adding a New Scanner

> **Some scanners stay composite-only by design.** If your tool's primary signal comes from the GitHub API (e.g. requires `GITHUB_TOKEN` + a `pull_request` event context to do anything useful), or its CLI is licence-restricted such that off-platform consumers can't legally run it, route it through a composite action under `.github/actions/scanner-<name>/` and skip the SDK port. The two existing instances are `scanner-codeql` (licence-encumbered CLI + bundle distribution cost) and `scanner-dependency-review` (thin client over GitHub's dependency-graph compare API). The full boundary rule, the test for future contributors, and the rationale for these two specifically lives in [`.ai/decisions.yaml` ADR-021](.ai/decisions.yaml).

### SDK Scanner Module (preferred)

Create a single Python file implementing the `Scanner` protocol:

1. **Create module** at `argus/scanners/{name}.py`:
   ```python
   from argus.core.scanner import Scanner
   from argus.core.models import ScanResult, Finding, Severity

   class MyScanner:
       name = "my-scanner"

       def scan(self, path: str, config: dict | None = None) -> ScanResult:
           # Run the tool, parse output, return ScanResult with findings
           ...

       def is_available(self) -> bool:
           # Check if the tool is installed
           ...

       def install_command(self) -> str | None:
           # Return install command, or None
           ...
   ```

2. **Register** in `argus/scanners/__init__.py`:
   ```python
   from .my_scanner import MyScanner
   # Add to SCANNER_REGISTRY:
   "my-scanner": MyScanner,
   ```

3. **Add tests** at `argus/tests/scanners/test_my_scanner.py`

4. **Audit for secret leaks.** If the scanner's raw output ever contains matched literals from source code (passwords, API keys, the `code` excerpt that triggered a finding), drop or redact those fields before building the `Finding`. Use `argus.core.redact.redact_secret(value)` for fields that hold the raw value, `redact_secret_in_message(msg, value)` to scrub interpolated descriptions. Add a test asserting the original literal never appears in `Finding.to_dict()` JSON output. Full audit checklist + rationale: [`docs/mcp.md` → Secrets handling](docs/mcp.md#secrets-handling). A pattern-based second pass runs in `Finding.__post_init__` as a backstop for known vendor-prefix tokens (GitHub PATs, AWS keys, Slack tokens, JWTs, PEM private keys, etc.) — it's defence-in-depth, not a replacement for the per-scanner audit. Anything without a recognizable prefix (raw passwords, custom tokens) still relies on the first pass.

5. **Update documentation** and `.ai/architecture.yaml`

## Adding a New Linter

Linters follow the same `Scanner` protocol as security scanners but live in the `argus/linters/` package and produce findings with `Severity.INFO`. The `LINTER_REGISTRY` auto-merges into `SCANNER_REGISTRY` at import time, so linters are immediately available via `argus scan lint-<name>`.

### SDK Linter Module

1. **Create module** at `argus/linters/{name}.py`:
   ```python
   from argus.core.models import Finding, ScanResult, Severity

   class MyLinter:
       name = "lint-my-tool"

       def scan(self, path: str, config: dict | None = None) -> ScanResult:
           # Run the linting tool, parse output, return ScanResult
           # Findings use Severity.INFO
           ...

       def is_available(self) -> bool:
           # Check if the tool is installed
           ...

       def install_command(self) -> str | None:
           # Return install command, or None
           ...
   ```

2. **Register** in `argus/linters/__init__.py`:
   ```python
   from .my_linter import MyLinter
   # Add to LINTER_REGISTRY:
   "lint-my-tool": MyLinter,
   ```
   The `LINTER_REGISTRY` auto-merges into `SCANNER_REGISTRY` (see `argus/scanners/__init__.py`), so `argus scan lint-my-tool` works immediately. Shell completions (`argus completion zsh`) update automatically since they are generated dynamically from the registry.

3. **Add tests** at `argus/tests/linters/test_my_linter.py`

4. **Update documentation** and `.ai/architecture.yaml`

**Key differences from security scanners:**
- Linters live in `argus/linters/`, not `argus/scanners/`
- Linter names are prefixed with `lint-` (e.g., `lint-yaml`, `lint-python`)
- Findings use `Severity.INFO` rather than security severity levels
- No container image is needed (linters run locally)

**Reference implementation**: See `argus/linters/yamllint.py` for a complete, well-documented example.

**Existing linters**: `lint-yaml`, `lint-json`, `lint-python`, `lint-javascript`, `lint-dockerfile`, `lint-terraform`, `lint-shell`

### Composite Action (for GitHub Actions users)

See `CONTRIBUTING.md` for the complete composite actions development guide. Key steps:

1. **Create action structure**:
   ```bash
   mkdir -p .github/actions/scanner-{name}/scripts
   ```

2. **Create action.yml** with standard inputs/outputs:
   ```yaml
   inputs:
     scan_path:              # What to scan
     fail_on_severity:       # Severity threshold
     enable_code_security:   # Upload SARIF
     post_pr_comment:        # Post PR comments
   outputs:
     critical_count:         # Number of critical findings
     high_count:            # Number of high findings
     # ... other severity counts
   ```

3. **Create scripts**:
   - `scripts/parse-results.py` - Parse scanner output, extract counts
   - `scripts/generate-summary.py` - Generate markdown summary

4. **Add tests**:
   - Co-located pytest tests in `tests/` directory
   - Use shared fixtures from `tests/fixtures/`

5. **Update documentation**:
   - Action README.md with usage examples
   - `.github/actions/README.md` catalog
   - `examples/workflows/composite-actions-example.yml`

## Supported Scanners

| Category | Actions | Documentation |
|----------|---------|---------------|
| **SAST** | scanner-codeql<br>scanner-bandit<br>scanner-gosec<br>scanner-opengrep<br>scanner-mumps | Multi-language<br>Python<br>Go<br>Pattern-based<br>MUMPS / M (28 rules: M001-M007 security, M101-M102 + M201-M219 diagnostics — mHawk taint-sink parity + 21 diagnostics) |
| **Secrets** | scanner-gitleaks | Git history & files |
| **Dependencies** | scanner-osv<br>scanner-dependency-review | OSV database<br>PR diff analysis & license compliance |
| **Infrastructure** | scanner-trivy-iac<br>scanner-checkov | Terraform, K8s, etc.<br>Multi-framework |
| **Container** | scanner-container | Trivy + Grype + Syft |
| **Malware** | scanner-clamav | File scanning |
| **Supply Chain** | scanner-supply-chain | GitHub Actions workflow security (zizmor + actionlint) |
| **DAST** | scanner-zap | Web applications |
| **Compliance** | scn-detector | FedRAMP SCN detection |
| **Linting** | linter-yaml<br>linter-json<br>linter-python<br>linter-javascript<br>linter-dockerfile<br>linter-terraform<br>lint-shell | Syntax & style |

## Testing

All tests are Python with pytest. Coverage enforced at 80% via pytest-cov.

```
argus/tests/                             # SDK unit tests (20 test files)
argus/tests/scanners/                    # Per-scanner tests (10 scanners)
argus/tests/reporters/                   # Reporter tests (4 reporters)
.github/actions/scanner-{name}/tests/    # Co-located with each action
tests/fixtures/                          # Shared mock data and test apps
```

**Coverage**: Python pytest-cov (80%+), reported via Codecov

## Key Inputs (Standard Across Actions)

Most scanner actions support these common inputs:

| Input | Description | Default |
|-------|-------------|---------|
| `scan_path` / `iac_path` / `target_url` | What to scan | Varies by scanner |
| `fail_on_severity` | Fail threshold | `none` |
| `enable_code_security` | Upload SARIF to Security tab | `false` |
| `post_pr_comment` | Post results as PR comment | `true` |
| `job_id` | Job ID for artifact naming | `${{ github.job }}` |

## Usage Examples

### SDK Usage (Primary)

```bash
# Run all scanners from config file
argus scan --config argus.yml

# Run specific scanners
argus scan --scanners bandit,gitleaks --path ./src

# List available scanners
argus scan --list

# Check version
argus --version
```

**Config file** (`argus.yml`):
```yaml
scanners:
  - bandit
  - gitleaks
  - osv
scan_path: "."
fail_on_severity: "high"
reporters:
  - terminal
  - sarif
```

See `argus.example.yml` for a quick-start template, or [Configuration Reference](docs/config-reference.md) for the full specification.

### Composite Action Usage (GitHub Actions)

#### Individual Scanner
```yaml
- name: Run Bandit Python Scanner
  uses: huntridge-labs/argus/.github/actions/scanner-bandit@1.9.1
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    scan_path: 'src'
    fail_on_severity: 'high'
    enable_code_security: true
```

#### Complete Security Workflow
See `examples/composite-actions-example.yml` for a full example with:
- Multiple scanners running in parallel
- security-summary aggregating results
- PR comments with findings
- SARIF uploads to GitHub Security

#### Config-Driven Container Scanning
```yaml
- uses: huntridge-labs/argus/.github/actions/parse-container-config@1.9.1
  id: parse
  with:
    config_file: 'container-config.yml'

- uses: huntridge-labs/argus/.github/actions/scanner-container@1.9.1
  strategy:
    matrix: ${{ fromJson(steps.parse.outputs.matrix) }}
  with:
    image_ref: ${{ matrix.image }}
    scanners: ${{ matrix.scanners }}
```

## Contributing

See `CONTRIBUTING.md` for:
- Composite action development guide (step-by-step)
- Parser and summary script templates
- Testing requirements (unit + integration)
- Code review checklist
- Best practices and patterns

## Example Workflow Validation

When creating or modifying example workflows in `examples/`, ensure they are valid and functional:

### Validation Requirements

All example workflows must:
1. ✅ Use valid YAML syntax
2. ✅ Reference existing action paths (paths must exist in `.github/actions/`)
3. ✅ Include all required action inputs
4. ✅ Have clear documentation and comments
5. ✅ Follow current conventions and best practices

**Note:** Version references (e.g., `@main`, `@0.6.5`) are managed by `release-it` during releases. Examples should use appropriate references that will be updated automatically.

### Testing Examples Locally

Before committing example changes, validate them:

```bash
# Validate YAML syntax for all examples
for example in examples/*.yml; do
  python -c "import yaml; yaml.safe_load(open('$example'))" || echo "❌ Invalid: $example"
done

# Validate config examples parse correctly
python -c "import yaml; yaml.safe_load(open('examples/container-config.example.yml'))"
python -c "import json; json.load(open('examples/container-config.example.json'))"

# Run full validation suite
npm test
```

### Example Quality Checklist

When adding/updating examples:
- [ ] YAML syntax is valid (run `python -c "import yaml; yaml.safe_load(open('example.yml'))"`)
- [ ] All action references point to existing actions in `.github/actions/`
- [ ] Required inputs are documented with clear comments
- [ ] Optional inputs show sensible defaults
- [ ] Has descriptive workflow name and job names
- [ ] Includes `on:` trigger section (even if just `workflow_dispatch`)
- [ ] Permissions are explicitly set (principle of least privilege)
- [ ] Comments explain the purpose and key configuration options
- [ ] Uses version references compatible with release-it (e.g., `@main`, `@0.6.5`)

### Automated Validation

Examples are automatically validated by `.github/workflows/test-examples-functional.yml`:
- Runs on PRs that modify `examples/` or `.github/actions/`
- Validates each example using a dynamic matrix strategy
- Checks syntax, action paths, and structure
- No duplication - validates the actual example files themselves

**Note**: Example validation focuses on documentation quality. Functional testing of actions themselves is handled by `test-actions.yml`. Version references are managed by release-it during the release process.

## Important Files

- `CLAUDE.md` - AI assistant reference guide (this file)
- `AGENTS.md` - Cross-tool AI entry point
- `argus/` - Python SDK package (primary interface)
- `argus/core/scanner.py` - Scanner protocol definition
- `argus/scanners/__init__.py` - Scanner registry (includes linters via auto-merge)
- `argus/linters/__init__.py` - Linter registry (auto-merges into SCANNER_REGISTRY)
- `argus/reporters/__init__.py` - Reporter registry
- `argus.yml` - Project scan configuration
- `argus.example.yml` - Quick-start configuration template
- `docs/config-reference.md` - Full `argus.yml` specification
- `version.yaml` - Single version source for releases
- `.github/renovate.json` - Dependency update configuration (Renovate)
- `CONTRIBUTING.md` - Composite actions contributor guide
- `tests/CONTRIBUTING.md` - How to add tests for actions
- `examples/README.md` - Example usage patterns and testing info
- `.ai/` - Structured AI context (AICaC) — keep in sync with code changes
- `examples/workflows/` - Usage examples for all actions
