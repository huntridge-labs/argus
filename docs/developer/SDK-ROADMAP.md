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

### Deprecated Workflow Removal
- [x] Removed 15 `scanner-*.yml` thin wrapper workflows
- [x] Removed 6 compound orchestrators: `reusable-security-hardening.yml`, `container-scan.yml`, `container-scan-from-config.yml`, `dependency-scan.yml`, `infrastructure-scan.yml`, `linting.yml`
- [x] Removed `security-reusable-demo.yml`
- [x] Removed 6 example workflows that only demonstrated deleted workflows
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

## Remaining: Phase 3 — Composite Action Thin Wrappers

Refactor `.github/actions/scanner-*` to call `argus scan` internally. Actions shrink from ~300 lines to ~170 lines. Same inputs, same outputs, same artifacts — backward compatible for external users.

- [x] Add `--no-timestamp` CLI flag for CI-friendly flat output directories
- [x] Design thin wrapper pattern (generate argus config, run scan, parse JSON for outputs)
- [x] Refactor `scanner-bandit/action.yml` as proof of concept (350 → 169 lines)
- [x] Refactor `scanner-opengrep/action.yml` (241 → 195 lines)
- [x] Refactor `scanner-clamav/action.yml` (348 → 214 lines)
- [x] Refactor `scanner-trivy-iac/action.yml` (362 → 234 lines)
- [x] Refactor `scanner-supply-chain/action.yml` (371 → 237 lines)
- [x] Enhance `supply_chain.py` scanner to accept persona, zizmor_config, run_actionlint, github_token from config
- [x] Refactor `scanner-gitleaks/action.yml` (207 → 161 lines, backend: auto/Docker)
- [x] Refactor `scanner-osv/action.yml` (357 → 222 lines, backend: auto/Docker)
- [x] Refactor `scanner-checkov/action.yml` (307 → 253 lines, backend: local/pip)
- [x] Removed published GitHub Action dependencies (gitleaks-action, osv-scanner-action, checkov-action) for portability
- [x] Enhanced `osv.py` with lockfile/recursive config passthrough
- [x] Enhanced `checkov.py` parse_results to return passed_count
- [x] Refactor `scanner-container/action.yml` (661 → 190 lines, SDK ContainerEngine)
- [x] Refactor `scanner-zap/action.yml` (544 → 229 lines, SDK DastEngine)
- [x] `--output-vars FILE` — machine-readable key=value counts for CI (eliminates jq dependency)
- [x] SDK auto-discovers argus.yml — actions no longer generate temp configs
- [x] All actions simplified to `pip install pyyaml` + `python -m argus scan`
- [x] Add 6 linter SDK modules: yamllint, jsonlint, flake8, jshint, hadolint, terraform
- [x] Refactor all 6 linter actions to thin wrappers (1424 → 757 lines, -47%)
- [ ] Verify backward compatibility: identical outputs, artifacts, SARIF
- [x] Update `test-actions.yml` to validate thin wrappers (already clean — no deleted inputs or scripts/ refs)
- [x] Delete bundled `scripts/` from refactored actions (already done in earlier commits)
- [x] Update docsite builder if action README structure changes (no changes needed — builder reads action.yml/README.md only)

---

## Remaining: Phase 4 — Distribution + Multi-Platform

### PyPI Publishing
- [x] `pyproject.toml` — hardened with whitelist includes, optional extras (ai, completion), AGPL v3
- [x] CI workflow: `publish-pypi.yml` validates on PR (build + safety check + test install)
- [x] CI workflow: `publish-release.yml` publishes to PyPI on tag (protected `prod` environment)
- [x] TestPyPI: unique dev versions per PR (`0.7.0.dev881`), trusted publishing (OIDC)
- [x] Safety check script: `scripts/ci/check_package.py` blocklist rejects secrets/tests/credentials
- [x] Package validated on TestPyPI — `pip install argus-security` works
- [x] Dynamic version from `argus.__version__`, tied to `version.yaml` via release-it
- [x] Tool version enforcement: `--allow-local-versions` bypass for airgapped environments

### Post-PyPI Cleanup (first release)
- [ ] Update all 16 action wrappers: `pip install pyyaml` → `pip install argus-security`
- [ ] Rename action step "Install dependencies" → "Install Argus"
- [ ] Remove `bin/argus` wrapper (pip creates the entry point)
- [ ] Update QUICK-START.md and README.md install instructions
- [ ] `argus init` summary: show `pip install argus-security` command

### Container Image Publishing
- [x] CI workflow: `publish-release.yml` builds and pushes to GHCR on tag
- [x] Tags with argus version (e.g., `scanner-bandit:0.8.0`) + `latest`
- [x] Image signing with cosign/sigstore
- [ ] Multi-arch builds (amd64 + arm64) — currently amd64 only

### Additional Reporters
- [ ] `github.py` — PR comments, SARIF upload, step summary (GitHub-specific)
- [ ] `gitlab.py` — MR comments, SAST report format
- [ ] `junit.py` — JUnit XML for Jenkins/Azure DevOps
- [ ] Reporter plugin registration system

### Additional Scanner Modules
- [ ] `codeql.py` — GitHub-specific, needs CodeQL CLI or Action
- [ ] `dependency_review.py` — GitHub PR-only, needs GitHub API
- [x] Linter modules: yaml, json, python, javascript, dockerfile, terraform (done in Phase 3)
### SCN Detector SDK Port (`argus classify`)
- [x] Create `argus/scn/` package — 7 modules ported from scn-detector scripts
- [x] `argus/scn/classifier.py` — rule-based change classification engine
- [x] `argus/scn/diff.py` — git diff parsing and IaC change analysis
- [x] `argus/scn/config.py` — SCN profile loading and validation
- [x] `argus/scn/ai.py` — AI fallback classification with provider abstraction
- [x] `argus/scn/report.py` — compliance report generation
- [x] `argus classify` CLI subcommand with --base/--head/--config/--format/--output-vars
- [x] Port tests to `argus/tests/scn/` (191 tests, 173 passing)
- [x] Thin wrapper for scn-detector action (505 → 285 lines)
- [ ] Optional AI deps: `pip install argus-security[ai]` adds anthropic/openai (post-PyPI)
- [ ] Port SCN config schema from `.github/actions/scn-detector/schemas/` to argus package

### SCN Classifier Improvements
- [x] Add GitHub Actions workflow as an IaC category (currently misdetected as kubernetes)
- [ ] Summary table should include Manual Review count (currently omitted)
- [ ] Resource naming: extract workflow `name:` field instead of defaulting to `unknown.*`
- [ ] False positive: `routine.pattern:description` rule matches workflow `name:` fields as "description changes"
- [ ] Report version should read from `version.yaml`, not hardcoded `v0.3.0`
- [ ] Report `<details>` wrapper should be optional (PR comments need it, standalone viewing doesn't)

### CLI Enhancements
- [x] `argus init` — detect languages/frameworks/linters/tool-configs, generate argus.yml
- [x] Dropped `--platform` flag — CI config is a one-liner (`argus scan`), not a generated file
- [x] Enhanced detection: Go, Java, JS/TS, GitLab CI, Jenkins, existing tool configs (.bandit, .gitleaks.toml, etc.)
- [x] Linter auto-enable: lint-python, lint-javascript, lint-dockerfile, lint-terraform based on signals
- [x] `--exclude` global CLI flag + auto-respect .gitignore/.dockerignore
- [x] Parallel scanner execution — ThreadPoolExecutor, max 8 workers, 40% speedup measured in CI (51.9s → 31.2s)

### Performance Research
- [ ] Profile individual scanner execution to identify bottlenecks (Docker pull latency, tool startup, output parsing)
- [ ] Investigate Docker image layer caching across runs (GitHub Actions cache, pre-pulled images)
- [ ] Evaluate `pull_policy: if-not-present` effectiveness in CI (image reuse between runs)
- [ ] Benchmark container vs local tool execution per scanner (overhead of Docker vs native)
- [ ] Consider pre-warming: pull all scanner images in parallel before scan phase
- [ ] Investigate lazy image pulls (start scanning available tools while others pull)
- [x] Measure and log per-scanner breakdown in audit trail for ongoing performance tracking
- [ ] Progress indicators during scanning and container pulls
- [ ] `argus report github` — post results as PR comment via GitHub API

### CI Preflight and Config Health

- [ ] CI workflow step: `argus validate --strict --check-tools` as a gate before scan jobs
- [ ] Living issue (Renovate-style): a single "Argus Config Health" GitHub issue that gets updated (not recreated) when config validation fails on the default branch. Scheduled workflow runs `argus validate --strict --check-tools`, updates the issue body with current status, and auto-closes when healthy. Avoids issue spam — one issue, always current.
- [ ] `argus validate --check-tools` notes for scanners with runtime network dependencies (e.g., OSV API, ClamAV freshclam, Trivy DB updates) — informational, not blocking

### CI Examples & PR Feedback
- [x] Example workflows with PR comment feedback for each platform
- [x] `examples/workflows/sdk-github-actions.yml` — SARIF upload + PR comment via github-script
- [x] `examples/workflows/sdk-gitlab-ci.yml` — SARIF to Security Dashboard + MR comment via API
- [x] `examples/workflows/sdk-jenkins.groovy` — Warnings NG SARIF + artifact archival
- [x] `examples/workflows/sdk-azure-devops.yml` — PR thread comment via REST API
- [x] Common pattern: `argus scan --format markdown` → platform posts `argus-summary.md` as comment

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

### Implementation tasks

**MCP server:**
- [ ] `argus/mcp.py` — MCP server module using the MCP Python SDK
- [ ] `argus mcp` CLI subcommand to start the server (stdio transport)
- [ ] `argus_detect` tool — wraps `detect_project()` from init module
- [ ] `argus_scan` tool — wraps engine scan, returns structured `ScanResult.to_dict()`
- [ ] `argus_validate` tool — wraps config validation
- [ ] `argus_list_scanners` tool — wraps scanner registry with availability status
- [ ] `argus_init` tool — wraps init workflow, returns generated content
- [ ] `argus://config` resource — reads and parses argus.yml
- [ ] `argus://results/latest` resource — reads most recent results from output dir
- [ ] Add `mcp` extra to pyproject.toml (`pip install argus-security[mcp]`)
- [ ] Tests for all MCP tools with mock engine
- [ ] Documentation: setup instructions per AI tool, example interactions
- [ ] `argus init` prints MCP setup hint in summary output

**Skill refactor:**
- [ ] Slim `.agents/skills/argus-scanner-selection/SKILL.md` to routing/strategy layer
- [ ] Move scanner selection logic, CLI syntax details, and output parsing guidance to MCP tool descriptions
- [ ] Add MCP-first instructions: "prefer `argus_scan` tool over CLI when MCP is available"
- [ ] Publish to [skills.sh](https://skills.sh/)
- [ ] Add version frontmatter to skill for tracking

---

## Known Issues

### Engine
- [ ] Container scanner (`container.py`) has empty `container_image` — can't Docker-fallback the orchestrator (sub-tools need individual execution)
- [x] `--list` now shows local/container/not-found availability per scanner
- [x] Container pull progress — spinner covers interactive use, audit log covers CI; streaming Docker pull output deferred (marginal benefit for high complexity)
- [x] `--fail-fast` flag — abort on first scanner failure instead of silent continue
- [x] `--timeout SECONDS` flag — per-scanner wall-clock timeout with thread-based enforcement

### Scanners
- [ ] ClamAV container requires virus DB update on first run (adds ~60s)
- [x] OSV-Scanner image pinned to `v2.3.5` (was `latest`)
- [x] OpenGrep image alias added — `get_image("opengrep")` now resolves via `_ALIASES` (OpenGrep doesn't publish its own images, semgrep image is correct)
- [x] Added `_ALIASES` dict in containers.py for scanner-name-to-image-key mapping (opengrep→semgrep, trivy-iac→trivy, osv→osv-scanner)
- [ ] Supply-chain `container_args` uses `sh -c` shell wrapper — fragile on non-Linux
- [ ] Bandit container ENTRYPOINT means args don't include `bandit` command — documented but could surprise contributors

### Testing Gaps
- [x] Docker execution integration tests (auto-skip when Docker unavailable, tests pull/run/mount/engine)
- [x] E2E scan test: `argus scan bandit` via Docker on test Python file
- [x] Container dedup edge cases: None CVE, empty CVE, severity ordering, large sets, order preservation
- [x] `argus report` integration tests (17 tests, from_dict roundtrip, all 4 formats)
- [x] `--version` flag: output format, version.yaml consistency, subprocess test

### Documentation Gaps
- [x] SDK docs covered by: cli-reference.md (auto-generated), config-reference.md, scanners.md, failure-control.md, and `argus scan <name> --help`
- [x] Migration guide: `docs/developer/migration-from-reusable-workflows.md`
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
