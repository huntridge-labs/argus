# Argus Portability Research: Architecture Recommendation

## Context

Argus is a security scanning pipeline currently implemented as 31 GitHub composite actions (18 scanners, 6 linters, 7 utility actions) with 33 workflows. It works exclusively within GitHub Actions CI/CD pipelines. The goal is to make Argus fully functional in **any environment** — GitHub, GitLab, Jenkins, local Windows/Mac, Azure DevOps, etc. — while remaining scalable, maintainable, and easy to extend without tribal knowledge.

---

## Current Architecture Analysis

### What Each Scanner Actually Does (The Universal Pattern)

Every scanner follows the same 4-phase lifecycle:

```
1. INSTALL   → Install the scanner tool (apt-get, pip, curl)
2. SCAN      → Run the tool, produce raw output (JSON/SARIF/text)
3. ANALYZE   → Parse results, count severities, check thresholds
4. REPORT    → Surface results (artifacts, PR comments, summaries, SARIF upload)
```

**Phases 1-3 are already ~90% portable.** The scanner CLIs (bandit, trivy, clamscan, gitleaks, etc.) run on any Linux/Mac. The Python parsing scripts have zero GitHub dependencies — they read JSON files and produce counts/markdown.

**Phase 4 is 100% GitHub-coupled.** This is where all the platform lock-in lives.

### GitHub Coupling Inventory

| Coupling Point | Where Used | What It Does |
|---|---|---|
| `$GITHUB_OUTPUT` | Every scanner | Sets step output variables (severity counts) |
| `$GITHUB_STEP_SUMMARY` | Every scanner | Writes markdown to job summary panel |
| `actions/upload-artifact@v7` | Every scanner | Stores reports as workflow artifacts |
| `actions/download-artifact@v8` | security-summary, linting-summary | Retrieves reports for aggregation |
| `github/codeql-action/upload-sarif@v4` | 9 scanners | Uploads SARIF to GitHub Security tab |
| `actions/github-script@v8` | comment-pr | Posts/updates PR comments via REST API |
| `github.server_url`, `github.repository`, `github.run_id` | 15+ actions | Builds artifact/commit links in summaries |
| `github.event_name == 'pull_request'` | Every scanner | Conditional PR comment posting |
| `github.actor != 'nektos/act'` | 2 scanners | Excludes local testing framework |
| `actions/setup-python@v6` | 8 scanners | Installs Python runtime |
| `actions/checkout@v6` | 3 scanners | Clones repository |
| Third-party scanner actions | scanner-container | `aquasecurity/trivy-action`, `anchore/scan-action`, `anchore/sbom-action` |

### What's Already Portable

- **All Python parsers**: `parse_trivy_results.py`, `parse_grype_results.py`, `parse-clamav-report.py`, `parse_results.py` (supply-chain, osv, dependency-review) — pure file I/O, zero platform dependencies
- **Scanner CLI invocations**: `bandit -r . -f json`, `trivy config --format json`, `clamscan --recursive`, etc.
- **Severity threshold logic**: Already implemented in bash/Python, purely numerical comparisons
- **Markdown summary generation**: Most `generate_summary.py` scripts accept GitHub URLs as parameters — pass empty strings and they work fine
- **SARIF generation**: Scanners produce SARIF natively; it's an OASIS standard, not GitHub-specific

---

## Approaches Evaluated

### 1. Dagger.io (Portable CI Pipelines)

**What**: Container-based CI/CD engine that runs the same pipeline everywhere.

**Why rejected**: Adds heavy external dependency (Go runtime, Dagger engine), steep learning curve, less mature ecosystem. ADR-001 already rejected external CI tools. Overkill for this problem — Argus doesn't need a new CI engine, it needs to decouple its logic from one.

### 2. Docker-per-Scanner (Containerize Everything)

**What**: Package each scanner as a Docker image, orchestrate with docker-compose.

**Why rejected**: Adds Docker dependency everywhere (not always available in air-gapped GHES). Massive image sizes (ClamAV database alone is 300MB+). Slow startup. Some scanners already scan Docker images, creating confusing nesting. Doesn't help on local Windows/Mac without Docker Desktop.

### 3. Monolithic CLI (Single Binary/Package)

**What**: One `argus` CLI that bundles all scanners, all reporters, everything in a single package.

**Why rejected**: Violates the scalability requirement. Adding a scanner means modifying the monolith. Removing one means the same. Creates the tribal knowledge problem — you must understand the whole thing to change one part. Every contributor touches the same codebase for unrelated changes.

### 4. Rewrite in Go/Rust (Compiled Binaries)

**What**: Rewrite everything as compiled, distributable binaries.

**Why rejected**: Abandons the existing Python investment (ADR-009 just migrated everything to Python). Massive effort for unclear benefit. Go/Rust aren't as accessible to security practitioners who want to contribute scanners.

### 5. Python SDK + CLI + Thin CI Adapters (RECOMMENDED)

**What**: Extract core logic into a Python package, expose via CLI, keep CI-specific adapters thin.

**Why recommended**: See detailed breakdown below.

---

## Recommended Architecture: Python SDK with Plugin Scanners and CI Adapters

### Core Idea

Separate Argus into three clean layers:

```
┌─────────────────────────────────────────────────────┐
│              CI ADAPTERS (thin wrappers)             │
│  GitHub Actions │ GitLab CI │ Jenkins │ CLI/Local    │
├─────────────────────────────────────────────────────┤
│              REPORTERS (output plugins)              │
│  Terminal │ GitHub PR │ GitLab MR │ SARIF │ JSON     │
├─────────────────────────────────────────────────────┤
│              ARGUS CORE (Python SDK)                 │
│  Scanner Interface │ Result Model │ Config │ Engine  │
├─────────────────────────────────────────────────────┤
│              SCANNER MODULES (plugins)               │
│  bandit │ trivy │ clamav │ gitleaks │ osv │ ...     │
└─────────────────────────────────────────────────────┘
```

### Layer 1: Argus Core (`argus/core/`)

The engine. Zero CI dependencies. Pure Python.

```python
# argus/core/models.py — Universal result model
@dataclass
class Finding:
    id: str
    severity: Severity  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    location: Optional[str]  # file:line
    cwe: Optional[str]
    cve: Optional[str]

@dataclass
class ScanResult:
    scanner: str
    findings: list[Finding]
    raw_report: Path           # Original scanner output
    sarif_report: Optional[Path]
    metadata: dict             # Scanner-specific extras

@dataclass
class ScanSummary:
    results: list[ScanResult]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    passed: bool               # Based on severity threshold
```

```python
# argus/core/scanner.py — Scanner protocol
class Scanner(Protocol):
    name: str

    def install(self) -> None: ...
    def scan(self, config: ScannerConfig) -> ScanResult: ...
    def is_available(self) -> bool: ...  # Check if tool is installed
```

```python
# argus/core/engine.py — Orchestration
class ArgusEngine:
    def __init__(self, config: ArgusConfig): ...
    def run(self, scanners: list[str] = None) -> ScanSummary: ...
    def check_threshold(self, summary: ScanSummary) -> bool: ...
```

```python
# argus/core/config.py — Configuration
# Reads argus.yml, handles defaults, validates
```

### Layer 2: Scanner Modules (`argus/scanners/`)

Each scanner is a Python module implementing the `Scanner` protocol. **This is where the existing Python parsers migrate almost unchanged.**

```
argus/scanners/
├── __init__.py          # Scanner registry (auto-discovery)
├── bandit.py            # Wraps: pip install bandit -> bandit -r . -f json -> parse
├── trivy_iac.py         # Wraps: install trivy -> trivy config --format json -> parse
├── clamav.py            # Wraps: apt install clamav -> clamscan -> parse
├── gitleaks.py          # Wraps: install gitleaks -> gitleaks detect -> parse
├── osv.py               # Wraps: install osv-scanner -> osv-scanner -> parse
├── trivy_container.py   # Wraps: trivy image -> parse
├── grype.py             # Wraps: install grype -> grype -> parse
├── checkov.py
├── opengrep.py
├── supply_chain.py      # Wraps: zizmor + actionlint
├── container.py         # Orchestrates trivy_container + grype + syft
├── zap.py               # DAST scanner
└── dependency_review.py # PR-diff dependency analysis
```

Each scanner module reuses the existing `parse_*.py` logic. For example, `trivy_iac.py` calls `trivy config --format json`, then calls the same parsing functions currently in `.github/actions/scanner-trivy-iac/scripts/generate_summary.py`.

### Layer 3: Reporters (`argus/reporters/`)

Reporters consume a `ScanSummary` and output results in platform-appropriate ways.

```
argus/reporters/
├── __init__.py          # Reporter registry
├── terminal.py          # Rich console output (tables, colors)
├── markdown.py          # Generates .md files (reuses current summary logic)
├── sarif.py             # Writes SARIF files
├── json_report.py       # Machine-readable JSON
├── github.py            # GitHub-specific: PR comments, SARIF upload, step summary
├── gitlab.py            # GitLab-specific: MR comments, SAST report format
└── junit.py             # JUnit XML (Jenkins, Azure DevOps)
```

### Layer 4: CI Adapters (thin wrappers)

These are the **thinnest possible** integration points for each CI system.

**GitHub Actions** (preserves backward compatibility):
```yaml
# .github/actions/scanner-bandit/action.yml (simplified)
runs:
  using: 'composite'
  steps:
    - name: Setup Python
      uses: actions/setup-python@v6
    - name: Run Argus Bandit scan
      shell: bash
      run: |
        pip install argus-security
        argus scan bandit --path . --config argus.yml --output-dir ./results
    - name: Upload artifacts
      uses: actions/upload-artifact@v7
      with:
        path: ./results/
    - name: Post results
      run: argus report github --results ./results --pr-comment --step-summary
```

**GitLab CI** (new):
```yaml
# .gitlab-ci.d/argus-bandit.yml
bandit-scan:
  image: python:3.12
  script:
    - pip install argus-security
    - argus scan bandit --path . --output-dir ./results
    - argus report gitlab --results ./results
  artifacts:
    reports:
      sast: results/gl-sast-report.json
```

**Local / Jenkins / Any CI**:
```bash
pip install argus-security
argus scan --config argus.yml      # Run all configured scanners
argus report terminal               # Pretty-print to console
argus report sarif --output .       # Write SARIF files
```

### Configuration (`argus.yml`)

Single file drives everything:

```yaml
version: "1.0"

scanners:
  bandit:
    enabled: true
    path: "src"
    severity_threshold: high
    config_file: "pyproject.toml"

  trivy-iac:
    enabled: true
    path: "infrastructure"
    severity_threshold: medium

  clamav:
    enabled: true
    path: "."

  gitleaks:
    enabled: true

  osv:
    enabled: true

reporting:
  formats: [terminal, sarif]     # Which reporters to use
  severity_threshold: high        # Global fail threshold
  output_dir: "./argus-results"

# CI-specific overrides (optional)
github:
  pr_comment: true
  sarif_upload: true
  step_summary: true

gitlab:
  mr_comment: true
  sast_report: true
```

---

## Why This Architecture Wins

### Requirement: Works in Any Environment

- Core SDK is pure Python — runs anywhere Python runs (everywhere)
- CLI provides universal interface: `argus scan`, `argus report`
- No CI system assumptions in core logic

### Requirement: Fully Configurable

- `argus.yml` centralizes all scanner and reporting configuration
- Per-scanner overrides, global defaults, CI-specific sections
- Environment variables for secrets (API keys, tokens)

### Requirement: Easy to Add/Remove Capabilities

- **Add a scanner**: Create one Python file in `argus/scanners/`, implement the `Scanner` protocol (install, scan, is_available). Register it. Done.
- **Remove a scanner**: Delete the file. Or just set `enabled: false` in config.
- **Add a CI platform**: Create one file in `argus/reporters/` and a CI template. Core logic unchanged.
- **No tribal knowledge**: Each scanner is self-contained. The protocol is the contract.

### Requirement: No Extensive Refactors

- Existing Python parsers migrate ~as-is into scanner modules
- Existing summary generation becomes the `markdown` reporter
- GitHub composite actions become thin wrappers calling `argus scan` + `argus report github`
- Backward compatibility preserved — users see no change in their GitHub workflows

### Requirement: Scalable

- Plugin architecture means O(1) complexity to add scanners
- Parallel execution built into the engine (multiprocessing/asyncio)
- Each scanner is independently testable

---

## Migration Strategy (Incremental, Non-Breaking)

### Phase 1: Foundation (Core SDK + CLI)

- Create `argus/` package structure
- Define `Scanner` protocol and `ScanResult` model
- Implement `ArgusEngine` with config loading
- Build `argus` CLI entry point
- Port 2-3 scanners (bandit, clamav, trivy-iac) as proof of concept
- Add `terminal` and `sarif` reporters
- **Existing GitHub Actions untouched** — still work as before

### Phase 2: Scanner Migration

- Port remaining scanners one at a time
- Each port reuses existing `parse_*.py` logic
- Add tests for each scanner module (reuse existing test fixtures from `tests/fixtures/scanner-outputs/`)
- Build `github` reporter (PR comments, SARIF upload, step summary)

### Phase 3: GitHub Actions Thin Wrapper

- Refactor composite actions to call `argus scan` + `argus report github`
- Actions become ~15 lines of YAML instead of ~300
- **Backward compatible** — same inputs, same outputs, same behavior

### Phase 4: Multi-Platform

- Add `gitlab` reporter + GitLab CI templates
- Add `junit` reporter for Jenkins
- Add `json_report` reporter for custom integrations
- Publish `argus-security` to PyPI
- Create `argus init <platform>` to generate CI configs

---

## Package Structure

```
argus/                           # Python SDK
├── __init__.py
├── __main__.py                  # CLI entry point
├── cli.py                       # Click/argparse CLI
├── core/
│   ├── __init__.py
│   ├── config.py                # argus.yml loading
│   ├── engine.py                # Scan orchestration
│   ├── models.py                # Finding, ScanResult, ScanSummary
│   └── scanner.py               # Scanner protocol
├── scanners/
│   ├── __init__.py              # Registry + auto-discovery
│   ├── bandit.py
│   ├── clamav.py
│   ├── trivy_iac.py
│   └── ...                      # One file per scanner
├── reporters/
│   ├── __init__.py              # Reporter registry
│   ├── terminal.py
│   ├── markdown.py
│   ├── sarif.py
│   ├── json_report.py
│   ├── github.py
│   └── gitlab.py
└── tests/
    ├── test_engine.py
    ├── test_config.py
    ├── scanners/
    │   ├── test_bandit.py
    │   └── ...
    └── reporters/
        ├── test_terminal.py
        └── ...
```

### Existing Files to Modify (Phase 3 only)

- `.github/actions/scanner-*/action.yml` — Simplified to thin wrappers
- `pytest.ini` — Add `argus/` to test paths
- `pyproject.toml` — Package configuration for `argus-security`
- `.ai/architecture.yaml` — Updated architecture docs
- `.ai/decisions.yaml` — New ADR for portability architecture

### Existing Assets to Reuse

- `tests/fixtures/scanner-outputs/` — All existing test fixtures carry over
- `.github/actions/scanner-container/scripts/parse_trivy_results.py` — Core parsing logic migrates into `argus/scanners/trivy_container.py`
- `.github/actions/scanner-container/scripts/parse_grype_results.py` — Same pattern
- `.github/actions/scanner-container/scripts/generate_container_summary.py` — Becomes `argus/reporters/markdown.py` container section
- All other `scripts/parse_results.py` and `scripts/generate_summary.py` files

---

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Scanner tool installation differs per OS | Scanner modules handle OS detection; `is_available()` checks before running; skip gracefully |
| Breaking existing GitHub Actions users | Phases 1-2 don't touch actions at all; Phase 3 preserves same inputs/outputs |
| Python version compatibility | Target 3.11+ (pre-installed on ubuntu-latest, widely available) |
| Package distribution complexity | Start with `pip install` from git; PyPI comes in Phase 4 |
| Some scanners are GitHub-only (dependency-review) | Scanner's `is_available()` returns false outside GitHub; skip with clear message |
| Parallel scanner execution complexity | Start sequential; add parallel execution after core works |

---

## Decision Summary

The Python SDK + CLI + thin CI adapters approach is recommended because it:

1. **Maximizes reuse** of the ~90% of logic that's already portable
2. **Minimizes risk** via incremental, non-breaking migration phases
3. **Aligns with existing decisions** (ADR-009 Python standardization, ADR-002 SARIF as universal format)
4. **Solves the extensibility problem** — adding a scanner is creating one file, not understanding the whole system
5. **Delivers value early** — Phase 1 gives local CLI scanning; GitHub users unaffected

---

## Phase 3: Docker Execution Backend (Detailed Design)

### Problem

Running all 10 scanners requires installing trivy, grype, syft, gitleaks, clamscan, checkov, opengrep, zizmor, actionlint, bandit, osv-scanner, and ZAP. Users shouldn't need to install these on their host machine.

### Solution: Transparent Container Execution

The engine detects whether a tool is locally installed. If not, it transparently runs the scanner in its **official author-published container**. The user runs `argus scan` and it works regardless of what's installed.

```
argus scan trivy-iac --path ./infrastructure

Engine: is trivy installed locally?
  YES → subprocess.run(["trivy", "config", ...])
  NO  → docker run aquasec/trivy config --format json /workspace
```

### Official Tool Containers (Maximize Reuse)

We use official images published by tool authors wherever possible. Argus only builds custom images when no official image exists or when combining multiple tools.

| Scanner | Official Image | Custom Build? |
|---------|---------------|---------------|
| trivy | `aquasec/trivy` | No |
| grype | `anchore/grype` | No |
| syft | `anchore/syft` | No |
| gitleaks | `zricethezav/gitleaks` | No |
| clamav | `clamav/clamav` | No |
| checkov | `bridgecrew/checkov` | No |
| osv-scanner | `ghcr.io/google/osv-scanner` | No |
| zap | `ghcr.io/zaproxy/zaproxy` | No |
| bandit | — | Yes (`python:3.12-slim` + pip) |
| opengrep | — | Yes (binary from GitHub releases) |
| zizmor + actionlint | — | Yes (combined supply-chain image) |

**Principle**: Layer argus parsing requirements on top of official images only when necessary. Most scanners output JSON/SARIF that the host-side SDK parses directly — no argus code needs to run inside the container.

### Execution Flow

```
┌─────────────────────────────────┐
│  argus scan bandit --path ./src │   User command
└────────────────┬────────────────┘
                 │
    ┌────────────▼────────────────┐
    │  ArgusEngine._run_scanner() │
    │                             │
    │  1. scanner.is_available()? │
    │     YES → local subprocess  │
    │     NO  → container check   │
    │                             │
    │  2. docker available?       │
    │     YES → docker run        │
    │     NO  → error + install   │
    │          instructions       │
    └────────────┬────────────────┘
                 │
    ┌────────────▼────────────────┐
    │  docker run --rm            │
    │    -v ./src:/workspace:ro   │
    │    -v /tmp/out:/output      │
    │    aquasec/trivy ...        │
    └────────────┬────────────────┘
                 │
    ┌────────────▼────────────────┐
    │  scanner.parse_results()    │   Runs on host
    │  → List[Finding]            │   (SDK parses output)
    └─────────────────────────────┘
```

### Configuration

```yaml
# argus.yml
execution:
  backend: auto              # auto | local | docker
  registry: ""               # override for private/air-gapped registries
  pull_policy: if-not-present # always | if-not-present | never
```

- `auto` (default): try local tool first, fall back to Docker
- `local`: only use locally installed tools, fail if missing
- `docker`: always use containers, even if tool is local

### Published Images

**Per-scanner images** (for users who need one scanner):
- Most use official images directly — no Argus-built image needed
- Custom images only for bandit, opengrep, and supply-chain

**All-in-one image** (for CI or users who want everything):
```
ghcr.io/huntridge-labs/argus/cli:0.8.0
```
Contains argus CLI + all scanner tools. Appropriate for CI where image size doesn't matter.

### Dependency Maintenance

All container image references must be automatically maintained:

1. **Dependabot** (primary): Add `docker` ecosystem to `.github/dependabot.yml` for Dockerfiles
2. **Dependabot** tracks base image updates (e.g., `aquasec/trivy:0.58.0` → `0.59.0`)
3. **Pin images by digest** in production Dockerfiles for reproducibility
4. **Renovate** as fallback if Dependabot can't handle image references in Python source files
5. Container image versions in scanner modules tracked via a central `argus/containers.py` manifest for single-point updates

### Air-Gapped Environments

- Pre-pull images to internal registry
- Set `execution.registry` in argus.yml to point at internal mirror
- `pull_policy: never` with pre-loaded images
- All official images available on Docker Hub and GHCR
