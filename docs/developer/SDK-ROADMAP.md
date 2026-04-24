# Argus SDK Roadmap

Tracks what has been completed and what remains for the argus Python SDK migration.

---

## Completed

### Phase 1: Core SDK + CLI
- [x] `argus/core/models.py` — Severity enum (with comparison operators, multi-format parsing), Finding, ScanResult, ScanSummary dataclasses with `to_dict()`
- [x] `argus/core/scanner.py` — Scanner Protocol (scan, is_available, install_command, container_image, container_args)
- [x] `argus/core/config.py` — ArgusConfig, ScannerConfig, ReportingConfig, ExecutionConfig loaded from `argus.yml` via pyyaml
- [x] `argus/core/engine.py` — ArgusEngine orchestrating scanner registration, execution (local + Docker fallback), result aggregation
- [x] `argus/cli.py` — argparse CLI: `argus scan [scanner] --config --path --format --severity-threshold --output-dir --list --verbose`; `argus report`
- [x] `argus/__main__.py` — `python -m argus` entry point
- [x] Zero external dependencies beyond pyyaml

### Phase 2: Scanner Modules
- [x] 10 scanner modules, each implementing the Scanner protocol:
  - `bandit.py` — Python SAST (parses Bandit JSON)
  - `clamav.py` — malware detection (parses clamscan text output)
  - `trivy_iac.py` — IaC misconfigurations (parses Trivy JSON)
  - `gitleaks.py` — secrets detection (parses Gitleaks JSON array)
  - `osv.py` — dependency vulnerabilities (parses OSV-Scanner JSON)
  - `checkov.py` — IaC policy checks (parses Checkov JSON, handles list/dict output)
  - `opengrep.py` — pattern-based SAST (parses OpenGrep/Semgrep JSON)
  - `supply_chain.py` — GitHub Actions security (combines zizmor SARIF + actionlint JSON)
  - `zap.py` — DAST (parses ZAP JSON, strips HTML from descriptions)
  - `container.py` — container scanning (orchestrates trivy+grype+syft, CVE deduplication)
- [x] All `parse_results()` methods are public and independently testable with fixtures
- [x] All `container_args()` methods derive behavior from config dict (no hardcoded values)

### Reporters
- [x] `terminal.py` — ASCII tables with severity counts to stdout
- [x] `markdown.py` — collapsible sections, emoji severity indicators
- [x] `sarif.py` — SARIF 2.1.0 with per-scanner runs
- [x] `json_report.py` — full summary serialization via `to_dict()`

### Docker Execution Backend
- [x] Engine auto-falls back to Docker when tools not installed locally
- [x] `argus/containers.py` — central image manifest (9 official + 3 custom images)
- [x] ARM64 fallback: retries with `--platform linux/amd64` when native pull fails
- [x] Container stdout capture for scanners that write to stdout (ClamAV)
- [x] `container_entrypoint` support for images with non-tool entrypoints (ClamAV)
- [x] Registry override via `execution.registry` config for air-gapped environments
- [x] Pull policy: `always`, `if-not-present`, `never`
- [x] Custom Dockerfiles: `docker/Dockerfile.bandit`, `docker/Dockerfile.opengrep`, `docker/Dockerfile.supply-chain`, `docker/Dockerfile.cli`

### Testing (SDK)
- [x] 202 unit tests in `argus/tests/`, 83%+ coverage
- [x] Core tests: models (42), config (19), engine (18), CLI (20), containers (10)
- [x] Scanner tests: all 10 scanners tested with fixture data from `tests/fixtures/scanner-outputs/`
- [x] Reporter tests: terminal (8), markdown (8), SARIF (8), JSON (6)
- [x] Docker backend tests: image resolution, registry override, local-vs-container fallback

### CI/CD Dogfooding
- [x] `security-scan.yml` — runs `pip install pyyaml && python -m argus scan --config argus.yml` (no manual tool installs)
- [x] `argus.yml` — dogfood config: bandit, gitleaks, opengrep, clamav, osv, supply-chain enabled
- [x] `test-reusable-workflows.yml` — refactored to test argus CLI (listing, scanning, output validation)

### CI/CD Hardening
- [x] `test-actions.yml` — removed job-level `continue-on-error: true` from 23 jobs; added `test-results` gate job; fixed ZAP/ClamAV to run on PRs
- [x] `test-unit.yml` — Python version matrix (3.11, 3.12, 3.13); version ref coverage check
- [x] `test-examples-functional.yml` — minimum example count gate (prevents empty-matrix passes)
- [x] `.release-it.json` — added package.json to regex-bumper output
- [x] `scripts/ci/check_version_refs.py` — added `.claude`, `.agents` to SKIP_DIRS

### Workflow Deprecation → Restoration
Originally the plan was to delete all reusable workflows and push consumers to the SDK+composite-actions path. Commit `1a0cb24` did exactly that. Consumer feedback after release made clear the breakage wasn't acceptable, so commit `46bb2f9` restored all 22 workflows with identical input interfaces — internally they now wrap the argus CLI instead of calling composite actions directly. Users change nothing except the version tag.
- [x] Initial removal: 15 `scanner-*.yml` wrappers, 6 compound orchestrators (`reusable-security-hardening.yml`, `container-scan.yml`, `container-scan-from-config.yml`, `dependency-scan.yml`, `infrastructure-scan.yml`, `linting.yml`), `security-reusable-demo.yml`, 6 example workflows
- [x] Restoration: all 22 workflows re-added, 12 scanner workflows migrated to `argus scan` under the hood (bandit, checkov, clamav, gitleaks, grype, opengrep, osv, supply-chain, trivy-container, trivy-iac, zap, zap-from-config)
- [x] 3 scanner workflows kept as composite-action passthroughs (GitHub-native, not in the SDK registry): `scanner-codeql`, `scanner-dependency-review`, `scanner-syft`
- [x] `linting.yml` kept on composite actions — linters hadn't landed in the SDK registry at restoration time (they have now, follow-up to migrate its internals is tracked under Phase 3 wrapper follow-ups)
- [x] `reusable-security-hardening.yml` restored as a dispatcher that fans out to the scanner workflows; silent-failure gating added in PR #91 (see section below)
- [x] Updated `docsite.yml` excluded_workflows, `.github/zizmor.yml` ignore list

### Dependency Maintenance
- [x] Dependabot: GitHub Actions, npm, pip, Docker ecosystems
- [x] `renovate.yaml` — regex managers for container image tags (`argus/containers.py`), tool versions in action.yml, tool versions in Dockerfiles
- [x] CI gate: `check-version-refs.py` runs on every PR in test-unit.yml

### Documentation Updates
- [x] `docs/developer/portability-research.md` — architecture research + Phase 3 Docker backend design
- [x] `.ai/decisions.yaml` — ADR-013 (Python SDK architecture), ADR-014 (Docker execution backend)
- [x] `.ai/architecture.yaml` — SDK as primary, composite actions as secondary
- [x] `.ai/context.yaml`, `.ai/workflows.yaml`, `.ai/errors.yaml` — updated for SDK
- [x] `CLAUDE.md` — SDK-first architecture, dual scanner flow, SDK-first "adding a scanner" guide
- [x] `CONTRIBUTING.md` — SDK scanner module contribution guide with protocol template
- [x] `README.md`, `QUICK-START.md`, `AGENTS.md` — SDK-first usage
- [x] `docs/scanners.md`, `docs/failure-control.md`, `docs/developer/release-management.md` — SDK commands
- [x] `examples/README.md` — SDK as primary, composite actions as secondary
- [x] `.agents/skills/argus-scanner-selection/` — updated for SDK
- [x] `.github/ISSUE_TEMPLATE/bug_report.yml` — interface options: SDK, Composite Action, Other
- [x] `scripts/docsite/builder.py` — removed hardcoded nav entries for deleted workflows

### New Tests (non-SDK)
- [x] `tests/unit/test_check_version_refs.py` — 25 tests for brace expansion, ref detection, coverage checking
- [x] `tests/unit/actions/test_validate_action_schemas.py` — 259 parametrized tests across all actions
- [x] `tests/integration/test_security_summary.py` — 10 tests for security-summary aggregation

### CI Scripts Restructure
- [x] `scripts/ci/` package — moved CI gate scripts into importable package
- [x] `scripts/ci/check_version_refs.py` — renamed from `check-version-refs.py` (valid Python module name)
- [x] `scripts/ci/gen_cli_docs.py` — generates CLI reference from argparse parser
- [x] `scripts/ci/check_cli_docs.py` — CLI docs freshness gate (check + fix modes)
- [x] `tests/unit/test_check_cli_docs.py` — 12 tests for check/fix/stale detection
- [x] Pre-commit hook + CI step for CLI docs freshness (triggers on `argus/cli.py` changes)

### CLI Enhancements (for Phase 3)
- [x] `--no-timestamp` flag — flat output directory for CI (no timestamped subdirs)
- [x] `--no-spinner` flag — disable animated spinner output
- [x] `docs/cli-reference.md` — regenerated with all subcommands (init, collect, validate)
- [x] `docs/config-reference.md` — full `argus.yml` configuration specification

---

## Phase 3 — Composite Action Thin Wrappers ✅

All 16 scanner/linter actions refactored to call `argus scan` internally. Actions shrink from ~300 lines to ~170 lines. Same inputs, same outputs, same artifacts.

<details><summary>22 completed items</summary>

- [x] Add `--no-timestamp` CLI flag for CI-friendly flat output directories
- [x] Design thin wrapper pattern (generate argus config, run scan, parse JSON for outputs)
- [x] Refactor all 10 scanner actions (bandit, opengrep, clamav, trivy-iac, supply-chain, gitleaks, osv, checkov, container, zap)
- [x] Enhance `supply_chain.py`, `osv.py`, `checkov.py` with config passthrough
- [x] Removed published GitHub Action dependencies for portability
- [x] `--output-vars FILE` — machine-readable key=value counts for CI
- [x] SDK auto-discovers argus.yml — actions no longer generate temp configs
- [x] Add 6 linter SDK modules + refactor all 6 linter actions (-47%)
- [x] Update `test-actions.yml`, delete bundled `scripts/`, update docsite builder

</details>

**Remaining:**
- [ ] Verify backward compatibility: identical outputs, artifacts, SARIF

---

## Phase 4 — Distribution + Multi-Platform

### Completed

<details><summary>PyPI Publishing (7 items)</summary>

- [x] `pyproject.toml` — hardened with whitelist includes, optional extras (ai, completion, mcp), AGPL v3
- [x] CI workflows: `publish-pypi.yml` (PR validation) + `publish-release.yml` (tag publish)
- [x] TestPyPI: unique dev versions, trusted publishing (OIDC)
- [x] Safety check, dynamic versioning, tool version enforcement

</details>

<details><summary>Container Image Publishing (4 items)</summary>

- [x] GHCR publish on tag, cosign signing, multi-arch (amd64 + arm64)

</details>

<details><summary>SCN Detector SDK Port (13 items)</summary>

- [x] `argus/scn/` — 7 modules, `argus classify` CLI, 191 tests, thin action wrapper, AI deps, schema port
- [x] 6 classifier improvements (GitHub Actions IaC category, resource naming, false positives, etc.)

</details>

<details><summary>CLI Enhancements (6 items)</summary>

- [x] `argus init` with language/framework/linter detection, `--exclude`, parallel execution

</details>

<details><summary>CI Preflight and Config Health (4 items)</summary>

- [x] `argus validate --strict --check-tools --report-issue`
- [x] Living issue on GitHub/GitLab (auto-detect provider, auto-close when healthy)
- [x] Network dependency notes for OSV, ClamAV, Trivy
- [x] `argus/preflight/` package — 49 tests

</details>

<details><summary>Performance (3 items)</summary>

- [x] Scanner DB cache volume mounts (`$TMPDIR/argus-cache`), `argus cache info|clean`
- [x] Per-scanner duration logging in audit trail

</details>

<details><summary>CI Examples (5 items)</summary>

- [x] GitHub Actions, GitLab CI, Jenkins, Azure DevOps example workflows with PR comments

</details>

### Remaining

**Release blockers (Post-PyPI Cleanup):**
- [ ] README.md and QUICK-START.md: remove TestPyPI `--index-url` flags
- [x] ~~Update all 16 action wrappers: `pip install pyyaml` → `pip install argus-security`~~ — **approach changed:** install SDK from composite's own checkout (`pip install "${{ github.action_path }}/../../.."`) instead of PyPI, which implicitly pins SDK version to composite ref and sidesteps PyPI-release lag. Applied to `scanner-container` and `scanner-zap` in PR #91.
- [ ] Apply the install-from-source pattern to the remaining 14 wrappers (`scanner-bandit`, `scanner-gitleaks`, `scanner-opengrep`, `scanner-clamav`, `scanner-trivy-iac`, `scanner-checkov`, `scanner-osv`, `scanner-supply-chain`, `scanner-dependency-review`, and the 6 linter wrappers)
- [ ] Rename action step "Install dependencies" → "Install Argus SDK" (done in 2 wrappers)
- [ ] Remove `bin/argus` wrapper (pip creates the entry point)
- [ ] `argus init` summary: show `pip install argus-security` command

**Future (post-release):**
- [ ] Additional reporters: `github.py`, `gitlab.py`, `junit.py`, plugin registration system
- [ ] Additional scanners: `codeql.py`, `dependency_review.py` (GitHub-specific)
- [ ] Performance: profiling, pull_policy evaluation, pre-warming, lazy pulls, progress indicators

---

## Silent-Failure Gating (Wrapper Layer)

Born out of the medsecops-golden-path SDK-integration post-mortem. The pre-refactor `reusable-security-hardening` summary derived an "Overall Security Score" from SARIF finding counts and could not distinguish between "scanner ran cleanly with zero findings" and "scanner crashed and produced no artifact." Downstream consumers saw `✅ Excellent!` while scanner jobs were actually failing. This work propagates the same "make failures loud" discipline from the SDK-side fixes (0.7.2 — Docker fallback, pre-warm, scan-failure surfacing) into the wrapper layer.

### Completed (PR #91 — `refactor/wrappers-silent-failure-gating`)

- [x] `security-summary` composite: new `scan_statuses` JSON input renders a per-scanner pass/fail/skipped table at the top of the report (the source of truth, independent of artifact presence)
- [x] New `fail_on_scanner_failure` input (default `true`) + `overall_status` / `failed_count` outputs — composite exits non-zero when any listed scanner did not succeed
- [x] New `comment_marker` input for PR-comment continuity when migrating from legacy inline summaries
- [x] Summary logic extracted to stdlib-only `scripts/generate_summary.py` (unit-testable, follows the `scanner-clamav` reference pattern)
- [x] Outer `<details>` unwrap — summaries pre-wrapped for collapse now get their wrapper replaced by a heading (no more two-click disclosures)
- [x] `reusable-security-hardening.yml`: inline ~400-line summary job (17 per-pattern artifact downloads + shell-assembled report + inline GitHub-script comment JS) replaced with a single delegation to the `security-summary` composite. File shrinks 30% (1162 → 811 lines).
- [x] Legacy `security-hardening-comment-marker` preserved so consumer PRs keep updating the same comment thread post-upgrade
- [x] **Breaking:** `allow_failure` default flipped `true` → `false` (scanners now block by default; callers wanting informational-only mode must opt in explicitly)
- [x] `.release-it.json`: ref-rewrite extended to cover `reusable-security-hardening.yml`
- [x] ADR-016 in `.ai/decisions.yaml`, architecture + docs updated
- [x] 24 integration tests against the real `generate_summary.py` (status-table rendering, silent-failure guard, outer-`<details>` unwrap, `$GITHUB_OUTPUT` verdict, invalid-JSON handling)

### Remaining

- [ ] Verify medsecops-golden-path demo pipeline no longer reproduces the silent-failure scenarios once PR #91 is merged to `feat/argus-portability`
- [ ] Apply the same silent-failure audit to other aggregators (`linting-summary`) — they may have the same "no artifact = no findings" failure mode

---

## Interactive Findings Browser (`argus browse`)

Post-scan triage workflow. Engineers sitting with a fresh scan need a way to filter/sort/drill into findings interactively — reading `argus-results.json` in an editor or paging through linear markdown is the current (weak) alternative. The idea was sharpened in discussion: a Claude-code-style persistent-input-at-bottom TUI is wrong for argus's discrete one-shot commands, but a k9s/lazygit-style stateful dataset browser is the right shape for triaging findings.

**Scope:** offline-only, opinionated, scoped to post-scan triage. Reads `argus-results.json` from a results directory or file path. Keyboard-driven: `/` search, `1/2/3/4` severity filters, `s` cycle sort, `e` export CSV, `q` quit. No AI — Claude Code + argus MCP already covers that surface.

### Implementation — v1 (in progress on `feat/browse-tui`)

- [x] `argus browse [PATH]` subcommand wired into the CLI
- [x] `argus/browse/` package with loader (`loader.py`) and Textual app (`app.py`)
- [x] Two-pane layout: findings list (DataTable) + detail view (Static); status bar + footer for shortcuts
- [x] Filter: severity threshold (`1`=crit only / `2`=high+ / `3`=med+ / `4`=all) + free-text search across id/title/location/CVE/scanner
- [x] Sort: severity desc/asc, package, id (cycle via `s`)
- [x] CSV export of the currently filtered view (`e`)
- [x] Optional extra `pip install argus-security[browse]` — `textual>=0.80` is lazy-imported so CI/server installs stay lightweight
- [x] Friendly "install with [browse]" error when the extra isn't present
- [x] `ScanSummary.from_dict` on the model so consumers can rebuild a summary from persisted JSON without spinning up the engine
- [x] Tests: loader + view-state logic (Textual stubbed so tests run without the extra)

### Remaining

- [ ] Help modal (`?`) listing every binding + current scope
- [ ] Sort indicator in the column header (arrow glyph)
- [ ] Multi-select for batch actions (export a subset, copy CVE list to clipboard)
- [ ] `argus scan --interactive` convenience flag that auto-launches `browse` after a scan completes
- [ ] Screenshot + quickstart in `docs/browse.md`

---

## Remaining: Phase 5 — Agentic Substrate (CLI + MCP + Skill)

Products that serve developer workflows increasingly need three layers for AI assistant integration. Argus already ships a CLI. Phase 5 adds the MCP server and refines the skill to complete the stack.

### The three layers

| Layer | Role | Context cost | Update mechanism |
|-------|------|-------------|-----------------|
| **CLI** | Universal fallback — works everywhere, no AI integration needed | Zero (not loaded into context) | `pip install --upgrade` |
| **MCP server** | Structured execution — typed tools, JSON responses, deferred loading | Deferred (tool schemas load only when invoked) | Ships with the pip package |
| **Skill** | Routing — tells the agent *when* to reach for Argus and *how* to reason about security scanning | Minimal (lightweight strategy text, always loaded) | Published to skills.sh or bundled in repo |

**Why all three matter:**

An MCP server eagerly loads all its tool definitions into the agent's context window. If Argus exposes 5-6 tools, that's token budget consumed in every conversation even when the user isn't doing security scanning. The skill acts as the gatekeeper — a lightweight instruction that tells the agent "when the task involves security scanning, reach for the Argus MCP." Tool schemas only enter context when actually needed. The CLI remains the fallback for environments without MCP support, CI pipelines, and direct human use.

This is the pattern emerging across the industry: CLI for humans and CI, MCP for structured AI execution, skills for AI routing and strategy. Companies from security tools to workflow automation are shipping all three.

### Why we initially considered MCP-only (and why that was incomplete)

We explored replacing skills entirely with MCP (see ADR-015 discussion history). The concerns about skills were valid:
- Copying a full 300-line skill into a project creates a stale snapshot
- No universal skill format across AI tools
- Duplicated intelligence between skill and engine

The resolution: **the skill doesn't need to encode implementation details.** With MCP handling execution, the skill shrinks to a routing/strategy layer — when to scan, what Argus is good for, how to interpret results at a high level. That lightweight skill rarely changes because it describes Argus's *purpose*, not its *API surface*. The MCP server self-describes its tools, so the skill doesn't need to.

### MCP server

**Tools:**

| Tool | Parameters | Returns |
|------|-----------|---------|
| `argus_detect` | `path` | Detected project signals (languages, frameworks, IaC, containers) |
| `argus_scan` | `scanners`, `path`, `severity_threshold` | Structured findings with severity, file, line, rule, message |
| `argus_validate` | `config_path` | Validation errors and warnings for argus.yml |
| `argus_list_scanners` | — | Available scanners with install status and descriptions |
| `argus_init` | `path`, `platform` | Generated config content and file paths |

**Resources:**

| Resource URI | Description |
|-------------|-------------|
| `argus://config` | Current argus.yml parsed as structured data |
| `argus://results/latest` | Most recent scan results from the last run |

**User setup:**

```json
{
  "mcpServers": {
    "argus": {
      "command": "argus",
      "args": ["mcp"]
    }
  }
}
```

### Skill (routing layer)

The existing skill at `.agents/skills/argus-scanner-selection/` is a 300-line reference that encodes scanner selection logic, CLI syntax, and interpretation rules. With MCP handling execution, this gets refactored into a slim routing skill:

- **When** to invoke Argus (code changes, pre-push checks, CI setup, security review)
- **What** Argus covers (SAST, secrets, dependencies, IaC, containers, DAST, supply chain, malware)
- **How** to reach for it (prefer MCP tools if available, fall back to CLI)
- **How** to interpret results (severity thresholds, false positive patterns, remediation guidance)

The scanner selection logic, CLI argument construction, and output parsing move entirely to the MCP server. The skill becomes stable strategy that rarely needs updating.

**Distribution:** Publish to [skills.sh](https://skills.sh/) for discovery. The skill file in `.agents/skills/` remains as the canonical source in the repo.

### Dependencies and portability considerations

The MCP server is a new interface to the existing engine — it does not change the scanner dependency story. Scanners still require either local binaries or Docker. Key considerations:

- Pure Python scanners (bandit, checkov, osv) work without Docker
- Binary scanners (gitleaks, trivy, opengrep) need Docker or local install
- `argus_list_scanners` should clearly report what's available and what's missing
- Graceful degradation: scans return partial results with clear "unavailable" status per scanner rather than failing entirely
- Phase 3 (portability) should land first to maximize the set of scanners that work out of the box

### Implementation — completed

<details><summary>MCP server (13 items)</summary>

- [x] `argus/mcp.py` — 8 tools, 3 resources, 3 prompts, stdio transport
- [x] 69 tests across 11 test classes, documentation, init hint

</details>

<details><summary>Skill refactor (4 items)</summary>

- [x] Slimmed to 66-line routing/strategy layer with version frontmatter (0.7.2)
- [x] MCP-first instructions, scanner logic moved to MCP tool descriptions

</details>

### Remaining
- [ ] Publish skill to [skills.sh](https://skills.sh/)

---

## Known Issues

All engine, scanner, and testing issues from the migration have been resolved.

**Open:**
- [ ] No troubleshooting guide for Docker execution failures

---

## Dependency Maintenance — Full Coverage

| Dependency Type | Tool | Config Location | Status |
|---|---|---|---|
| GitHub Action SHAs | Dependabot | `.github/dependabot.yml` | Done |
| npm packages | Dependabot | `.github/dependabot.yml` | Done |
| Python packages (requirements.txt) | Dependabot | `.github/dependabot.yml` | Done |
| Dockerfile FROM base images | Dependabot | `.github/dependabot.yml` | Done |
| Container image tags in Python | Renovate | `renovate.yaml` | Done |
| Tool versions in action.yml scripts | Renovate | `renovate.yaml` | Done |
| Tool versions in Dockerfiles (ARG) | Renovate | `renovate.yaml` | Done |
| Version refs across all files | CI gate | `scripts/ci/check_version_refs.py` in test-unit.yml | Done |
| package.json version | release-it | `.release-it.json` regex-bumper | Done |
