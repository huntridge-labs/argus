# AGENTS.md

> The single entry point for every coding agent in this repo (Claude Code, GitHub Copilot, Cursor, Codex and the rest) and a good start for people too. `CLAUDE.md` imports this file and `.github/copilot-instructions.md` links to it. For structured, machine-readable data, see `.ai/context.yaml`.

**Quick reference:** every change starts with a GitHub issue, one PR per issue. Branch `<prefix>/<issue>-<description>` (for example `feat/483-issue-keyed-records`), open a draft PR as soon as work starts, and record a new ADR as `.ai/decisions/ADR-<issue>.yaml`. Details in [Issues, branches, and records](#issues-branches-and-records).

## Project Identity

**argus** is a unified security scanning framework by Huntridge Labs.

Python SDK and GitHub Actions toolkit for comprehensive security scanning. The **Argus SDK** (`argus/` package) is the primary interface for running scans locally or in CI. **Composite actions** (`.github/actions/`) remain available for GitHub Actions users, designed for GitHub Enterprise Server (GHES) with github.com access.

- **What it does**: Orchestrates 14 security scanners (SAST, secrets, containers, IaC, DAST) via the argus Python SDK or GitHub Actions composite actions
- **Primary interface**: `python -m argus scan --config argus.yml`
- **Current version**: 1.14.0
- **License**: AGPL-3.0

### One-Liner
Python SDK and composite GitHub Actions that orchestrate 14+ security scanners with unified CLI, SARIF upload, and PR comments.

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

## Issues, branches, and records

These rules apply to people and coding agents alike. An issue number is unique, so anything keyed to it (a branch, a PR, an ADR) can't clash with another PR's, and parallel work stops colliding. The reasoning is in [ADR-483](.ai/decisions/ADR-483.yaml).

### Before you start

1. **Start from an issue.** Every change has a GitHub issue, and each PR covers one issue. Split big work into sub-issues and give each its own PR. No issue yet? Open one first.
2. **Name the branch after the issue.** Use `<prefix>/<issue>-<short-description>`, with the issue number right after the prefix: `feat/483-issue-keyed-records`. For a sub-issue, use the sub-issue's number, never the parent's or the epic's. A ruleset rejects pushes whose branch doesn't start with an allowed prefix. Pick the one that matches the change: `feat`, `fix`, `chore`, `docs`, `style`, `refactor`, `test`, `ci`, `build`, `revert` or `hotfix`. Coding agents use these too. The ruleset also lets `copilot/`, `claude/`, `dependabot/`, `renovate/` and `aicac/` through for tools that pick their own branch names, but when you choose the name, use a type prefix.
3. **Check nobody has it, then open a draft PR.** Look for an open PR linked to the issue and for a branch already named for it. If either exists, stop and ask on the issue before doing anything else.
   ```bash
   gh issue view <issue> --json closedByPullRequestsReferences --jq '.closedByPullRequestsReferences[].url'
   gh pr list --state open --search "<issue>"
   git ls-remote --heads origin "*/<issue>-*"
   ```
   If both come back empty, push your first commit and open a draft PR right away (`gh pr create --draft`), so everyone can see the issue is taken.
4. **Link the issue.** Put `Closes #<issue>` in the PR body when the PR finishes the issue, or `Refs #<issue>` when it's partial work. The PR template has the line.
5. **Record decisions under the issue number.** A new ADR is one file, `.ai/decisions/ADR-<issue>.yaml`. See [Adding an ADR](#adding-an-adr).

Nobody edits an ADR index by hand. `python -m scripts.ci.adr_records list` builds it at read time from both stores. The **ADR Records** workflow (`.github/workflows/adr-records.yml`) checks every PR and every push to `main`.

### Adding an ADR

```bash
python -m scripts.ci.adr_records new --title "Short decision title"   # issue number comes from the branch
```

That writes `.ai/decisions/ADR-<issue>.yaml`. Fill it in:

| Field | Required | Notes |
|-------|----------|-------|
| `id` | yes | `ADR-<issue>`, same as the file name |
| `title` | yes | |
| `date` | | `'YYYY-MM-DD'` |
| `status` | yes | `proposed`, `accepted`, `rejected`, `deprecated` or `superseded` |
| `context` | yes | The problem that made the decision necessary |
| `decision` | yes | What was decided |
| `rationale`, `alternatives_considered`, `consequences`, `implementation` | | Same shapes as in `.ai/decisions.yaml` |
| `affects_components` | | Component IDs from `.ai/architecture.yaml` |
| `supersedes` | | List of ADR IDs this one replaces |

Rules:

- **Never add entries to `.ai/decisions.yaml`.** It holds ADR-001 to ADR-044 and is closed to new ones. You can still edit an existing entry there (status, wording).
- **Never renumber an ADR.** Legacy IDs are zero-padded three digits (`ADR-007`). Issue-keyed IDs are the bare issue number (`ADR-483`), never padded and never below 100, so the two can't collide.
- **One ADR per PR**, keyed to that PR's issue. A PR with two decisions either records both in its one ADR or gets split into two issues.
- **Superseding a legacy ADR:** set the old entry's `status: superseded` and list it under `supersedes` in the new file. Don't put the new ID in the old entry's `superseded_by`; the AICaC validator only resolves IDs inside `.ai/decisions.yaml`.
- See every ADR: `python -m scripts.ci.adr_records list` (add `--format yaml` or `--format json` for machine-readable output).
- Check before you push: `python -m scripts.ci.adr_records check --branch "$(git branch --show-current)" --base origin/main`

### If the check fails

| Message | Fix |
|---------|-----|
| `this branch is for issue #N, so its ADR must be .ai/decisions/ADR-N.yaml` | `git mv` the file to `ADR-N.yaml` and set `id: ADR-N`. If the ADR really belongs to another issue, it goes in that issue's PR. |
| `a PR that adds an ADR needs a branch named <prefix>/<issue>-<description>` | The branch has no issue number. See [Moving to a branch with an issue number](#moving-to-a-branch-with-an-issue-number). |
| `ADR-0NN is a new entry, but this file is closed to new ADRs` | Move the entry out of `.ai/decisions.yaml` into `.ai/decisions/ADR-<issue>.yaml`. |
| `ADR number N is used more than once` or `duplicate key` | Two entries share an ID, usually from a merge. Keep the one already on `main` and key yours to your issue. |
| `ADR files are named ADR-<issue>.yaml` or `issue-keyed ADR numbers start at 100` | Rename the file: no zero padding, `.yaml` extension, your issue number. |
| `'<field>' is required`, `unknown component`, `unknown ADR` | Fix the field in the ADR file. |
| Warning: `branch '...' has no issue number` | Only a warning. Fine for Dependabot, Renovate and other automated PRs. For anything else, move to a branch with an issue number. |

Pull requests from forks run the same check with a read-only token and no secrets. The ruleset can't enforce branch names in a fork, so a fork branch without an issue number gets the warning, and only fails if it adds an ADR.

### Moving to a branch with an issue number

**Never rename a PR's head branch on GitHub.** Renaming the head branch closes the PR. Push a new, correctly named branch and open a new PR instead:

```bash
git switch -c feat/<issue>-<short-description>     # starts from your current branch, keeps its commits
# If the PR adds an ADR: git mv it to .ai/decisions/ADR-<issue>.yaml, set its id, commit
git push -u origin feat/<issue>-<short-description>
gh pr create --draft --body "Closes #<issue>. Replaces #<old-pr>."
gh pr close <old-pr> --comment "Moved to #<new-pr>."
```

---

## Architecture Overview

### Architecture

The argus Python SDK (`python -m argus scan`) is the primary interface. Composite actions remain available for GitHub Actions users.

### Directory Structure

```
argus/                 # Python SDK (primary interface)
├── core/              # Models, config, engine
├── scanners/          # Scanner modules
├── reporters/         # Output reporters (terminal, markdown, sarif, json)
└── tests/             # SDK test suite

.github/
├── actions/           # Composite actions (GitHub Actions interface)
│   └── scanner-*/     # Each: action.yml, scripts/, tests/
├── workflows/         # CI/CD and test workflows

examples/workflows/    # User-facing workflow examples
tests/                 # Test infrastructure
docs/                  # Detailed documentation
```

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

### SDK Scan Flow

1. User runs `argus scan --config argus.yml` (or specifies scanners via CLI flags)
2. Config loaded by `argus.core.config` — resolves scanner list, paths, severity thresholds
3. Engine (`argus.core.engine`) iterates over requested scanners
4. Each scanner module implements the `Scanner` protocol: `scan()`, `is_available()`, `install_command()`
5. Engine checks `is_available()` — if the tool is missing, it can run via Docker container (`containers.py`)
6. Scanner runs the underlying tool, parses output into `Finding` / `ScanResult` objects
7. Results passed to reporters (terminal, markdown, SARIF, JSON) based on config
8. Exit code reflects severity threshold compliance

### Composite Action Flow

1. User configures action inputs (paths, severity thresholds, etc.)
2. Action runs scanner with appropriate configuration
3. Results parsed by action's `scripts/parse-results.py`
4. Summary generated by `scripts/generate-summary.py`
5. Artifacts uploaded (reports, SARIF, summaries)
6. Outputs set (counts, status) for downstream jobs
7. Optional: PR comment posted
8. Optional: SARIF uploaded to GitHub Security

### Supported Scanners

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

---

## Setup & Environment

### For Users

**SDK (recommended):**

```bash
pip install pyyaml
python -m argus scan --config argus.yml
```

**GitHub Actions (composite actions):**

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-gitleaks@1.14.0
  with:
    enable_code_security: true
    fail_on_severity: high
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### For Contributors (Developing)

```bash
# Clone and install (Python deps are pinned in uv.lock; needs uv)
git clone <repo>
uv sync --locked --all-extras      # package + every extra + dev group
uv sync --locked --all-extras --group hooks   # also pre-commit

# Dev container (recommended)
# Open in VS Code → "Reopen in Container"

# After changing any dependency range in pyproject.toml
uv lock
```

---

## Testing

### Testing Philosophy

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

### Build & Test Commands

```bash
# Run all tests
pytest

# With coverage
pytest --cov

# Fast validation (no coverage)
pytest --no-cov -q

# Linting
npm run lint
```

### Coverage Targets
- Overall: 80%+

### Testing Levels

**For simple actions** (scanners with 2 scripts):
1. **Unit tests**: Test parse/summary scripts with fixtures
2. **Integration**: Run action in test workflow

**For complex actions** (multi-script with logic):
1. **Level 1 - Unit Tests**: Test individual Python functions
   ```bash
   pytest .github/actions/my-action/tests/test_*.py -v
   ```

2. **Level 2 - Script Integration**: Test scripts end-to-end with mock data
   ```bash
   python scripts/classify.py --input mock-data.json --output results.json
   ```

3. **Level 3 - Action Integration**: Test full action with `act` locally
   ```bash
   act pull_request -j test-job --secret GITHUB_TOKEN=$TOKEN
   ```

4. **Level 4 - Full Workflow**: Test in real GitHub Actions environment
   - Create test branch with real changes
   - Open PR, verify action runs correctly

5. **Level 5 - AI Fallback**: Test external API integration (mock in CI)
   ```python
   @patch('requests.post')
   def test_ai_classification(mock_post):
       mock_post.return_value.json.return_value = {...}
   ```

6. **Level 6 - Performance**: Large inputs, stress testing

7. **Level 7 - Edge Cases**: Empty files, malformed configs, API failures

**Test Organization**:
```
tests/
├── fixtures/              # Mock data, sample configs
│   ├── api-responses/    # Mock AI/API responses
│   └── sample-data/      # Real-world examples
├── unit/                  # Fast unit tests
└── integration/           # Slower integration tests
```

### Test Locations

All tests are Python with pytest. Coverage enforced at 80% via pytest-cov.

```
argus/tests/                             # SDK unit tests (20 test files)
argus/tests/scanners/                    # Per-scanner tests (10 scanners)
argus/tests/reporters/                   # Reporter tests (4 reporters)
.github/actions/scanner-{name}/tests/    # Co-located with each action
tests/fixtures/                          # Shared mock data and test apps
```

**Coverage**: Python pytest-cov (80%+), reported via Codecov

---

## Code Conventions

### File Naming
- SDK modules: `argus/scanners/{name}.py`
- Actions: `.github/actions/scanner-{name}/`
- Tests: Co-located in `tests/` subdirectory of each action or SDK module

### Action Structure

**Scanner Pattern** (2-script, parse + summarize):
```
.github/actions/scanner-{name}/
├── action.yml              # Inputs, outputs, steps
├── scripts/
│   ├── parse-results.py    # Scanner output → JSON
│   └── generate-summary.py # JSON → Markdown summary
├── tests/
│   ├── test_parse_results.py
│   ├── test_generate_summary.py
│   └── conftest.py (optional)
└── README.md
```

**Multi-Script Pattern** (complex workflows with multiple stages):
```
.github/actions/{name}/
├── action.yml              # Orchestrates multiple scripts
├── scripts/
│   ├── analyze.py          # Data analysis/extraction
│   ├── classify.py         # Classification/decision logic
│   ├── generate-report.py  # Report generation
│   └── create-issue.py     # GitHub integration (optional)
├── tests/
│   ├── test_analyze.py
│   ├── test_classify.py
│   ├── test_generate_report.py
│   ├── test_create_issue.py
│   └── conftest.py
└── README.md

# Example: scn-detector (FedRAMP compliance)
# - analyze_iac_changes.py: Extract IaC changes from git diff
# - classify_changes.py: Classify using rules + AI fallback
# - generate_scn_report.py: Create compliance reports
# - create_scn_issue.py: GitHub Issues with timelines
```

### Commit Messages

Follow **Conventional Commits**:
```
feat(scanner-name): add support for X
fix(parser): handle empty results
fix(trivy): handle empty results
docs: update scanner reference
test(bandit): add edge case coverage
refactor: simplify parse logic
```

### Versioning & Release

- **Single Version Source**: `version.yaml` (prevents drift)
- **Release Command**: `npm run release` (manages all version updates and tags)
- **Version Tags**: Release workflow auto-tags and publishes

### Release Process

Users depend on you auto-releasing after dependency updates pass. The testing pipeline must be bulletproof for this trust.

Releases are cut by hand from the **Release** workflow (Actions → Release → Run workflow), so merging to `main` ships nothing on its own. A push to `main` only runs the dry-run preview.

### Trying a big change before it ships

There is no long-lived beta branch. Big batches of related PRs merge to `main` like any other PR, and a prerelease is how they get tried before the final release (ADR-500):

1. **One PR:** every same-repo PR that touches `argus/` or `pyproject.toml` publishes a `<version>.devN` build to TestPyPI.
2. **A batch:** once the batch is on `main`, run the Release workflow with `releaseType: prerelease` (or `minor` / `major`) and `preReleaseId: rc`. That cuts `X.Y.Z-rc.N`: the GitHub release is marked as a prerelease, the wheel goes to PyPI as `X.Y.ZrcN`, and the images get an `:X.Y.Z-rc.N` tag. `:latest` does not move.
3. **Try it:** `pip install --pre argus-security==X.Y.ZrcN`, or pull `ghcr.io/huntridge-labs/argus/<image>:X.Y.Z-rc.N`. pip and uv skip prereleases unless asked, so nobody gets one by accident.
4. **Ship it:** run the Release workflow again with the matching `releaseType` and no `preReleaseId` to cut `X.Y.Z`. That one moves `:latest`.

Prerelease tags are kept like any other version tag (the GHCR prune job only removes non-version tags), because the rc wheel on PyPI pins those image digests.

### Design Patterns

**Hybrid Classification (Rules + AI Fallback)**
When building actions that need intelligent decision-making:
1. **Rule-based first**: Fast, deterministic, cost-free
2. **AI fallback**: For ambiguous cases that rules can't handle
3. **Confidence thresholds**: If AI confidence < threshold, flag for manual review
4. **Mock AI in tests**: Use fixtures for reliable testing

```python
# Example from scn-detector
def classify_change(self, change: Dict) -> Dict:
    # Try rule-based first
    result = self.classify_with_rules(change)
    if result:
        return result

    # Fallback to AI if enabled
    if self.enable_ai:
        return self.classify_with_ai(change)

    # Flag for manual review
    return {"category": "MANUAL_REVIEW"}
```

**Generic vs. Cloud-Specific Patterns**
For broader applicability across clouds/platforms:
- ✅ **Generic attributes**: `encryption`, `region`, `capacity`, `authentication`
- ❌ **Cloud-specific**: `aws_bedrock`, `azure_openai`, `google_vertex_ai`

```yaml
# Good: Works across AWS, Azure, GCP, custom platforms
transformative:
  - pattern: "ai_service|ml_service|ml_model"
    description: "AI/ML capabilities"
  - attribute: "region|location|datacenter"
    description: "Geographic changes"

# Bad: Only works for AWS
transformative:
  - resource: "aws_bedrock.*"
    description: "AWS Bedrock only"
```

**Rule Ordering & Priority**
When processing rules for classification:
1. **Within category**: Check specific patterns before generic ones
2. **Across categories**: Order categories by desired precedence
3. **First match wins**: Stop processing after first successful match

```yaml
# Example: Check transformative (specific) before routine (generic)
transformative:
  - resource: "aws_bedrock.*"  # Specific resource type
    operation: "create"

routine:
  - attribute: "description"    # Generic attribute
    # This would match almost anything, so check last
```

**Business Day Calculations**
For compliance/audit timelines:
- Exclude weekends from calculations
- Use `datetime` + `timedelta` + weekend checks
- Document timezone assumptions (usually UTC)

```python
def calculate_business_days(start_date: datetime, num_days: int) -> datetime:
    current = start_date
    days_added = 0
    while days_added < num_days:
        current += timedelta(days=1)
        if current.weekday() < 5:  # Monday=0, Sunday=6
            days_added += 1
    return current
```

**AI API Integration with Fallback**
When integrating external AI APIs (Anthropic, OpenAI, etc.):

1. **Make it optional**: AI should be fallback, not requirement
   ```yaml
   inputs:
     enable_ai_fallback:
       default: 'true'
     anthropic_api_key:
       required: false
   ```

2. **Graceful degradation**: Handle API failures
   ```python
   def classify(self, data):
       # Try rule-based first
       result = self.classify_with_rules(data)
       if result:
           return result

       # AI fallback if enabled and API key present
       if self.enable_ai and self.api_key:
           try:
               return self.classify_with_ai(data)
           except Exception as e:
               logger.warning(f"AI fallback failed: {e}")
               return {"category": "MANUAL_REVIEW"}

       return {"category": "MANUAL_REVIEW"}
   ```

3. **Mock in tests**: Never make real API calls in CI
   ```python
   @patch('anthropic.Anthropic')
   def test_ai_classification(self, mock_anthropic):
       mock_client = Mock()
       mock_client.messages.create.return_value = Mock(
           content=[Mock(text='{"category": "TRANSFORMATIVE"}')]
       )
       mock_anthropic.return_value = mock_client

       result = classifier.classify_with_ai(change)
       assert result['category'] == 'TRANSFORMATIVE'
   ```

4. **Use fixtures for API responses**:
   ```
   tests/fixtures/api-responses/
   ├── classification-high-confidence.json
   ├── classification-low-confidence.json
   └── classification-error.json
   ```

5. **Document API costs**: Claude Haiku ~$0.25/million input tokens

---

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

---

## Common Tasks

### Add Security Scanning to a Repo

**SDK approach (recommended):**

```bash
# Create argus.yml
cat > argus.yml << 'EOF'
scanners:
  - gitleaks
  - bandit
  - osv

scan_path: "."
severity_threshold: high
EOF

# Run scan
pip install pyyaml
python -m argus scan --config argus.yml
```

**GitHub Actions approach (composite actions):**

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - uses: huntridge-labs/argus/.github/actions/scanner-gitleaks@1.14.0
        with:
          fail_on_severity: high
          enable_code_security: true
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - uses: huntridge-labs/argus/.github/actions/scanner-bandit@1.14.0
        with:
          fail_on_severity: high
          enable_code_security: true
```

### Scan Container Images

```bash
python -m argus scan container --severity-threshold high
```

### Add a New Scanner (Contributors)

See [Adding a New Scanner](#adding-a-new-scanner) and [Adding a New Linter](#adding-a-new-linter).

### GitHub Integration Patterns

**PR Comments** (Standard for most scanners):
```yaml
- name: Post PR Comment
  if: github.event_name == 'pull_request'
  uses: huntridge-labs/argus/.github/actions/comment-pr@1.14.0
  with:
    comment_file: summary.md
```

**GitHub Issues** (For audit trails, compliance, tracking):
```python
# Use PyGithub or direct API calls
from github import Github

g = Github(os.environ['GITHUB_TOKEN'])
repo = g.get_repo(os.environ['GITHUB_REPOSITORY'])

issue = repo.create_issue(
    title=f"🔐 Compliance: {category} - {resource}",
    body=issue_body,
    labels=['compliance', f'scn:{category.lower()}']
)
```

**When to use Issues vs PR Comments**:
- **PR Comments**: Immediate feedback, scanner results, validation
- **Issues**: Audit trail, compliance tracking, follow-up tasks, timelines

**Required Permissions**:
```yaml
permissions:
  pull-requests: write  # For PR comments
  issues: write         # For Issue creation
  security-events: write # For SARIF upload
```

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
  uses: huntridge-labs/argus/.github/actions/scanner-bandit@1.14.0
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
- uses: huntridge-labs/argus/.github/actions/parse-container-config@1.14.0
  id: parse
  with:
    config_file: 'container-config.yml'

- uses: huntridge-labs/argus/.github/actions/scanner-container@1.14.0
  strategy:
    matrix: ${{ fromJson(steps.parse.outputs.matrix) }}
  with:
    image_ref: ${{ matrix.image }}
    scanners: ${{ matrix.scanners }}
```

## Key Inputs (Standard Across Actions)

Most scanner actions support these common inputs:

| Input | Description | Default |
|-------|-------------|---------|
| `scan_path` / `iac_path` / `target_url` | What to scan | Varies by scanner |
| `fail_on_severity` | Fail threshold | `none` |
| `enable_code_security` | Upload SARIF to Security tab | `false` |
| `post_pr_comment` | Post results as PR comment | `true` |
| `job_id` | Job ID for artifact naming | `${{ github.job }}` |

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

---

## Error Resolution

### "Resource not accessible by integration"
**Cause**: Missing permissions
**Fix**: Add to workflow:
```yaml
permissions:
  security-events: write
  pull-requests: write
```

### "Scanner X not found in matrix"
**Cause**: Invalid scanner name
**Valid names**: `codeql`, `bandit`, `gitleaks`, `opengrep`, `trivy`, `grype`, `syft`, `checkov`, `trivy-iac`, `clamav`, `zap`, `osv`, `dependency-review`

### SARIF Upload Fails
**Cause**: GitHub Advanced Security not enabled
**Fix**: Settings → Security → Enable "GitHub Advanced Security"

### PR Comment Not Appearing
**Fix**: Ensure `enable_pr_comment: true` and `pull-requests: write` permission

---

## Security Considerations

- **Never** commit registry credentials in config files
- **Always** use GitHub Secrets for sensitive values
- **Pin** to version tags (`@main`), never `@main`
- **Enable** SARIF upload when GitHub Advanced Security available
- **Review** scanner findings before suppressing

---

## PR Guidelines

### CRITICAL: Feature Branch Workflow

**NEVER commit directly to main.** Always use feature branches and create draft PRs for team review. Start from an issue and follow [Issues, branches, and records](#issues-branches-and-records).

```bash
# Create a feature branch named for the issue
git checkout -b feat/<issue>-my-feature

# Make changes and commit
git add .
git commit -m "feat(component): description"

# Push to origin
git push -u origin feat/<issue>-my-feature

# Create a draft PR as soon as work starts (uses .github/PULL_REQUEST_TEMPLATE.md)
gh pr create --draft

# Or use GitHub UI: Check "Create as draft"
```

### Before Creating PR
- [ ] All tests pass (`pytest`)
- [ ] No linting errors (`npm run lint`)
- [ ] Conventional commit messages used
- [ ] Documentation updated if needed
- [ ] Action README updated if action changed
- [ ] Branch is `<prefix>/<issue>-<description>` (not main)
- [ ] PR body has `Closes #<issue>` or `Refs #<issue>`
- [ ] Draft PR for team review

### PR Description

Use the repo template, `.github/PULL_REQUEST_TEMPLATE.md` (`gh pr create` fills it in). Keep its `Closes #<issue>` line at the top.

---

## Key Decisions (Why Things Are This Way)

| Decision | Reason |
|----------|--------|
| SDK as primary interface | Platform-independent, works locally and in CI |
| Composite actions for GitHub Actions | GHES doesn't support cross-repo `workflow_call` |
| SARIF as output format | GitHub Security tab integration, industry standard |
| Python for all scripts | Single language, one test framework (pytest), unified coverage |
| Co-located tests | Tests live next to code they test |
| Single version.yaml | Prevents version drift across 20+ files |
| Feature branches + draft PRs | Team review required, never commit to main |
| Hybrid classification (rules + AI) | Fast/deterministic rules, AI handles ambiguity |
| Generic patterns over cloud-specific | Broader applicability (AWS, Azure, GCP, custom) |
| GitHub Issues for compliance | Audit trail with 90-day artifact retention |
| Rule-based before AI | Cost-free, deterministic, testable |
| Issue-keyed branches and ADRs | Issue numbers are unique, so parallel PRs never pick the same ADR ID or touch the same lines (ADR-483) |

---

## AI-Specific Notes

### Structured Data Available (AICaC)

This project uses **AI Context as Code (AICaC)** - structured, machine-readable context in `.ai/` for token-efficient documentation.
Tools that support structured context should read files in `.ai/` directory:

| File | Purpose |
|------|---------|
| `.ai/context.yaml` | Project metadata, identity, glossary, entry points |
| `.ai/architecture.yaml` | Components, relationships, dependencies, data flow |
| `.ai/workflows.yaml` | Common tasks with exact commands |
| `.ai/decisions.yaml` | Architectural Decision Records ADR-001 to ADR-044 (closed to new entries) |
| `.ai/decisions/ADR-<issue>.yaml` | Newer ADRs, one file each, keyed to their issue |
| `.ai/errors.yaml` | Error patterns → solutions |

**Reading order**: `.ai/context.yaml` → relevant module files → source code

**Additional reference files:**
- `CLAUDE.md` - imports this file (`@AGENTS.md`); nothing else lives there
- `.github/copilot-instructions.md` - symlink to this file

### Context Loading Priority
1. This file (AGENTS.md) - Quick orientation
2. `.ai/context.yaml` - Project overview
3. `.ai/architecture.yaml` - How it's built
4. `.ai/workflows.yaml` - How to do tasks
5. `.ai/errors.yaml` - Troubleshooting
6. `.ai/decisions.yaml` + `.ai/decisions/` - Why decisions were made (`python -m scripts.ci.adr_records list` shows both)
7. `docs/scanners.md` - Scanner configuration details
8. `examples/` - Working code examples

### Common Question Patterns
- "How do I scan X?" → See Common Tasks section
- "What scanners exist?" → See Supported Scanners table (under Architecture Overview)
- "Why doesn't X work?" → See Error Resolution section
- "Which implementation?" → Composite actions (default), reusable workflows for backwards compat

### CRITICAL: Maintain .ai/ Files

**After making changes to this project, you MUST update the relevant `.ai/` files.**

| When you change... | Update... |
|--------------------|-----------|
| Components/structure | `.ai/architecture.yaml` |
| Commands/tasks | `.ai/workflows.yaml` |
| Make design decisions | New file `.ai/decisions/ADR-<issue>.yaml` (see [Adding an ADR](#adding-an-adr)) |
| Fix common errors | `.ai/errors.yaml` |
| Project metadata | `.ai/context.yaml` |
| Scanners or actions | `.ai/architecture.yaml` (scanners list + components) |
| Version number | `.ai/context.yaml` (version field) |

**Before completing any task**, verify:
```
[ ] Relevant .ai/ files updated (or confirmed not needed)
```

### Tool-Specific Configuration

#### Global Standards (Claude Code)

Claude Code users: Global rules, skills, and agents from `~/.claude/` are automatically applied. These include:

- **Rules**: coding-style, git-workflow, testing, security, performance, refactor-clean
- **Skills**: security-skills, documentation-skills, data-analysis-skills
- **Agents**: planner, security-reviewer, technical-docs-writer

Source: [huntridge-labs/cheat-codes](https://github.com/huntridge-labs/cheat-codes)

#### Project Overrides

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

#### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CLAUDE_SKIP_GLOBAL_RULES` | Skip loading ~/.claude/rules/ | `false` |
| `CLAUDE_VERBOSE` | Show which rules are being applied | `false` |

#### GitHub Copilot Users

Copilot reads this file through the `.github/copilot-instructions.md` symlink. Global `~/.claude/` config does not apply. Key standards to follow:

- **Issues and branches**: one issue per PR, branch `<prefix>/<issue>-<description>` (see [Issues, branches, and records](#issues-branches-and-records))
- **Commits**: Conventional commits (`feat:`, `fix:`, `refactor:`, etc.)
- **Testing**: 80%+ coverage, TDD for new features
- **Security**: No hardcoded secrets, validate inputs, use parameterized queries
- **Code Style**: Functional patterns, immutability, early returns

---

## Contributing

See `CONTRIBUTING.md` for:
- Composite action development guide (step-by-step)
- Parser and summary script templates
- Testing requirements (unit + integration)
- Code review checklist
- Best practices and patterns

## Important Files

- `AGENTS.md` - Entry point for every coding agent (this file)
- `CLAUDE.md` - Imports this file
- `.github/copilot-instructions.md` - Symlink to this file
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
- `.ai/decisions/` - Issue-keyed ADRs (`ADR-<issue>.yaml`)
- `scripts/ci/adr_records.py` - ADR check, list and scaffold

---

## Quick Reference

| Need | Location |
|------|----------|
| SDK entry point | `python -m argus scan` |
| SDK source | `argus/` |
| SDK config | `argus.yml` |
| Composite actions | `.github/actions/scanner-*/` |
| All scanners | `docs/scanners.md` |
| Examples | `examples/workflows/` |
| Container config schema | `.github/actions/parse-container-config/schemas/container-config.schema.json` |
| Version | `version.yaml` |
| Changelog | `CHANGELOG.md` |
| ADRs (all) | `python -m scripts.ci.adr_records list` |
| New ADR | `python -m scripts.ci.adr_records new --title "..."` |

---

## Links

- [Quick Start Guide](QUICK-START.md)
- [Full Documentation](README.md)
- [Scanner Reference](docs/scanners.md)
- [Contributing Guide](CONTRIBUTING.md)
