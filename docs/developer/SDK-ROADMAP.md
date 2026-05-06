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
- [x] ~~Apply the install-from-source pattern to the remaining 14 wrappers~~ — completed for `scanner-bandit`, `scanner-gitleaks`, `scanner-opengrep`, `scanner-clamav`, `scanner-trivy-iac`, `scanner-checkov`, `scanner-osv`, `scanner-supply-chain`, plus the 6 linter wrappers. (`scanner-dependency-review` was mistakenly listed — it wraps GitHub's `dependency-review-action` and doesn't use the SDK.)
- [x] ~~Rename action step "Install dependencies" → "Install Argus SDK"~~ — applied across all 16 SDK-using wrappers as part of the install-from-source migration
- [ ] Remove `bin/argus` wrapper (pip creates the entry point)
- [ ] `argus init` summary: show `pip install argus-security` command

**Future (post-release):**
- [ ] Additional reporters: `github.py`, `gitlab.py`, `junit.py`, plugin registration system
- [ ] Additional scanners: `codeql.py`, `dependency_review.py` (GitHub-specific)
- [x] ~~Progress indicators~~ — `argus/cli.py::Spinner` ships phase-aware progress with `--no-spinner` opt-out (PR #2c46fce: `feat(cli): phase-aware scan progress and clearer verbosity flags`)
- [x] ~~`pull_policy` evaluation~~ — `ArgusConfig.execution.pull_policy` accepts `always | if-not-present | never`; engine + container_runtime honor it
- [ ] Performance: profiling, pre-warming, lazy pulls (the remaining items from the original bundle)

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

## Interactive Findings Browser (`argus view terminal`)

Post-scan triage workflow. Engineers sitting with a fresh scan need a way to filter/sort/drill into findings interactively — reading `argus-results.json` in an editor or paging through linear markdown is the current (weak) alternative. The idea was sharpened in discussion: a Claude-code-style persistent-input-at-bottom TUI is wrong for argus's discrete one-shot commands, but a k9s/lazygit-style stateful dataset browser is the right shape for triaging findings.

**Scope:** offline-only, opinionated, scoped to post-scan triage. Reads `argus-results.json` from a results directory or file path. Keyboard-driven: `/` search, `1/2/3/4` severity filters, `s` cycle sort, `e` export CSV, `q` quit. No AI — Claude Code + argus MCP already covers that surface.

### Implementation — v1 (in progress on `feat/browse-tui`)

- [x] `argus view terminal [PATH]` subcommand wired into the CLI
- [x] `argus/browse/` package with loader (`loader.py`) and Textual app (`app.py`)
- [x] Two-pane layout: findings list (DataTable) + detail view (Static); status bar + footer for shortcuts
- [x] Filter: severity threshold (`1`=crit only / `2`=high+ / `3`=med+ / `4`=all) + free-text search across id/title/location/CVE/scanner
- [x] Sort: severity desc/asc, package, id (cycle via `s`)
- [x] CSV export of the currently filtered view (`e`)
- [x] Optional extra `pip install argus-security[terminal]` — `textual>=0.80` is lazy-imported so CI/server installs stay lightweight
- [x] Friendly "install with [browse]" error when the extra isn't present
- [x] `ScanSummary.from_dict` on the model so consumers can rebuild a summary from persisted JSON without spinning up the engine
- [x] Tests: loader + view-state logic (Textual stubbed so tests run without the extra)

### Remaining

#### UX polish (from first road-test, 2026-04-24)

- [x] `ESC` out of the search input returns focus to the findings list
- [x] Sort cycle surfaces the new sort mode via toast on each `s` press
- [x] Sort indicator in the column header (arrow glyph ↓/↑) for the active sort
- [x] Help modal (`?` keybinding) with grouped keyboard reference
- [ ] Column-resize / row-count improvements — visual polish from the Textual side

#### Export UX

- [x] **File path discoverability:** toast now shows the absolute path plus a `file://` URI most modern terminals auto-linkify
- [x] **`o` keybinding to open the last export** via platform-native opener
- [x] **`r` keybinding to reveal in file manager** (Finder/Explorer/parent dir on Linux)
- [x] **Additional export formats** — CSV, JSON, Markdown, SARIF shipped. XLSX deferred (adds dependency weight without clear demand).
- [x] **Timestamped + scope-embedded filenames** — repeated exports never clobber

#### Data model / scope

- [x] **Product × scanner scope** — `p` / `c` bindings open picker modals; status bar shows active filters
- [x] **Executive summary view** — `d` binding opens dashboard overlay (per-product severity counts, top-3 criticals per product, per-scanner contribution, quality warnings)
  - Works as a standalone command too: `argus summary <results-dir>` — *still open*, keep on roadmap for when `argus view browser` lands and wants the same computation.
- [ ] **Timeline / diff view** — compare a new results set against a previous one. Powers "what changed this scan-over-scan" workflow.

#### Integration with argus-portal

The `argus-portal` web app at `/Users/collinpesicka/Documents/HRL/github.com/argus-portal` is an adjacent surface for the same underlying data. Open questions (to be resolved before committing to a direction):

- [ ] **Does the portal consume `argus-results.json` natively?** If yes, the TUI's role is "local-dev triage before pushing to portal." If no, we'd want a shared schema/loader library to avoid format drift between CLI and web.
- [ ] **"Send to portal" keybinding** — `P` from the TUI uploads the current results (or currently filtered subset) to a configured portal instance. Needs portal API (or upload endpoint) defined first.
- [ ] **"Open in portal"** — deep-link to a scan view: `argus-portal://scan/<id>` or HTTP URL. Works if scans have portal-assigned IDs.
- [x] ~~**Shared findings renderer**~~ — `argus/core/findings_view.py` is the shared module: TUI imports it from `argus/viewers/terminal/app.py` and the browser interface imports it from `argus/viewers/browser/app.py` + `log_view.py`. Portal can consume the same module if/when it wants identical per-finding layout. (Note: bullets above this — portal protocol questions — remain open product decisions.)

Not all of these belong to the TUI itself — the portal integration items are primarily portal-side concerns. Tracked here so the CLI/TUI side doesn't drift from whatever the portal lands on.

#### Existing polish items (pre-roadtest)

- [ ] Multi-select for batch actions (export a subset, copy CVE list to clipboard)
- [x] `argus scan --interface=terminal` convenience flag — auto-launches the terminal viewer after the scan finishes
- [x] ~~Quickstart in `docs/view-terminal.md`~~ — install + launch + key bindings + workflows shipped
- [ ] Screenshot pass for `docs/view-terminal.md` — doc has no images yet

---

## SDK-Hosted Executive Web View (`argus view browser`)

A read-only web front-end bundled with the argus SDK, aimed at non-engineer stakeholders — product owners, managers, executives — who want easy insight into their products' security posture without digging through CI logs or PR comments. Launched locally or within a trusted team network; **not** a replacement for the separate `argus-portal` enterprise effort.

**Why it exists:**
- The real value argus provides is "CI pipeline findings + more, but easy to read." Today an exec has to read PR comments, dashboard screenshots, or raw JSON — none of which scale to quick-read questions like "are we shipping log4shell?"
- The TUI (`argus view terminal`) solves the same workflow for engineers, but not for users who don't live in a terminal.
- `argus-portal` exists as a proof-of-concept Next.js app, but has significant operational burden (Postgres, Kubernetes, planned OAuth/RBAC, FedRAMP session controls) that doesn't fit "I just want to glance at findings."

**Non-goals** (deliberately kept out of scope):
- Multi-tenant hosting, user management, authentication flows
- FedRAMP/SOC-2/enterprise compliance controls
- Persistent database — entirely in-memory from `argus-results.json`
- CRUD mutations (POAM management, change approvals, ticket creation) — the portal's territory
- Uploading scans from one machine to another

**Scope for v1:**

Minimal read-only web UI that displays the same data as `argus view terminal`, bound to localhost by default, launched via `argus view browser [RESULTS_DIR]`. Stakes in the ground:

| Decision | Direction |
|---|---|
| Backend | FastAPI or Starlette (Python, same runtime as argus SDK) — keeps the install story to "pip install 'argus-security[browser]'" |
| Frontend | Server-rendered HTML + HTMX for reactivity — no React/Next.js build toolchain, no separate bundler. Ship as Jinja2 templates inside the wheel. |
| Shared code with TUI | Factor the loader and per-finding renderer out of `argus/browse/` so both the TUI and the web app consume the same logic. Avoid drift between CLI and web. |
| Default binding | `127.0.0.1:<port>`. `--bind 0.0.0.0` prints an explicit warning and requires `--insecure-public-bind` ack. |
| Authentication | None in v1. If `--bind` is non-localhost, require `--basic-auth USER:PASS` (HTTP basic over HTTPS, not a full user system). |
| Data source | Single `argus-results.json` (or directory containing it). No cross-run aggregation, no history. |

### Implementation — v1 status

Shipped on `feat/serve-webui` across six commit-sized phases
(SA → SF). Summary below; git log for the full breakdown.

**Completed:**

- [x] **SA** — package scaffold, `[serve]` extra, CLI subcommand with
  friendly `ServeUnavailable` error, `/healthz` liveness.
- [x] **SB** — `/` executive dashboard route consuming
  `argus.core.findings_view.compute_summary()`; CSP + clickjacking
  headers via middleware; Jinja2Templates + StaticFiles mount.
- [x] **SC** — `/findings` filterable table route. Query-param-driven
  filters share `ViewState.matches()` with the TUI (one source of
  truth for filter semantics). URL-driven and refresh-safe. Unknown
  severity inputs degrade to "no filter" rather than 500.
- [x] **SD** — `/picker` one-level file browser with scan-ready hints
  (finding-count peek for directories containing
  `argus-results.json`). Dotfiles + build dirs hidden by default;
  `?show_hidden=1` toggle. No recursion (per scoping decision).
- [x] **SE** — Progressive-enhancement filter refresh via vanilla JS
  (80 lines, no HTMX dep). `/findings?partial=1` returns just the
  table fragment; `auto-filter.js` swaps it in on filter changes,
  keeps the URL in sync via `history.replaceState`. Form submit is
  the no-JS fallback.
- [x] **SF** — `docs/view-browser.md` user guide, README feature bullet,
  `.ai/architecture.yaml`, `.ai/workflows.yaml`, ADR in
  `.ai/decisions.yaml`.

**Scope deferrals (intentional):**

- `--bind` flag omitted — always `127.0.0.1`. Localhost-only is the
  product shape; multi-user network exposure belongs to
  `argus-portal`, not here.
- `--basic-auth` omitted for the same reason — no auth means no
  session-state complexity.
- Secret-redaction on finding text — not serve-specific; applies
  equally to CLI / TUI / JSON export. Tackle globally when it lands.

### Phase 2 additions (post-launch, shipped)

Iteration after dogfooding the initial build. Same scoping rules
apply: read-only, localhost-only, no new persistence.

- [x] **SG** — Drill-downs on dashboard cards and per-product /
  per-scanner rows; each deep-links into `/findings` with the
  matching filter pinned.
- [x] **SH** — Findings row detail (native `<details>` disclosure
  inside each title cell, rendering `finding_detail_rows` — same
  source of truth the TUI uses).
- [x] **SI** — Sortable column headers on the findings table
  (Severity / ID / Location / Scanner), aria-sort state reflected.
- [x] **SJ** — Path-scope constraint: `?scan=` and `/picker?path=`
  reject targets outside the launch root unless the user relaunches
  with a broader `--root`. Defense-in-depth even though cross-origin
  readback is already blocked by the browser SOP.
- [x] **SK** — Export routes (`/export?format=csv|json|markdown|sarif`)
  reusing `argus/browse/export.py`; each format exposed in the
  findings UI with both Download (browser save) and Copy (clipboard
  via `navigator.clipboard.writeText`) actions.
- [x] **SL** — Scan diff (`/diff?a=<path>&b=<path>`): new / fixed /
  severity-changed / still-open buckets keyed off the
  `(scanner, id, location)` identity tuple. Picker surfaces
  checkboxes on scan-ready rows + a "Compare selected" button.
- [x] **SM** — Recent-scans dropdown in the header, auto-populated
  from scan-ready siblings of the launch root; symlink-deduplicated
  so `latest/` doesn't double-count.
- [x] **SN** — Scan metadata panel on the dashboard exposing
  per-scanner tool versions, container image digests, durations,
  aggregate duration, and the scan file's mtime.
- [x] **SO** — Light/dark theme toggle with `prefers-color-scheme`
  default and a localStorage override. Brand palette unchanged in
  dark; light variant derived from the same tokens with deeper
  severity hues for legibility on a bright surface.

### Phase 3 — Scan log viewer in the browser interface

A read-only `/log` route that surfaces the per-run `argus.log` file in
the browser interface, with the same shape as `/findings`: a filter
bar (severity-equivalent for log levels, plus substring search) and a
scrollable monospace pane. Closes a real triage gap — answers like
"why did osv exclude 258 findings?" or "did clamav actually run?"
required dropping back to the terminal until now.

**Scope: read-only viewer, no live tailing.** Logs are written
synchronously to disk by `argus scan`; once the scan completes the
file is final. A live-tail mode would need a websocket and a process
watcher, which is out of proportion for a single-user localhost UI.

**MVP shape (shipped in this Phase 3):**
- Parses argus's standard logging format (`HH:MM:SS LEVEL  logger  msg`)
- Continuation lines (multi-line scanner stderr) join onto the previous entry
- Filter by minimum level (DEBUG/INFO/WARN/ERROR), URL-shareable
- Substring search across level + logger + message, URL-shareable
- "Showing N of M (filtered)" status with raw-log download link
- Level color accents (DEBUG muted, INFO accent-dim, WARN amber, ERROR red)
- Empty states for "no log file" and "no entries match filters"
- 27-test suite covering the parser, the filter, both routes, and nav threading

**Tasks:**

- [x] **SU** — `argus/viewers/browser/log_view.py`: `LogEntry` dataclass,
      `parse_log()`, `filter_entries()`, `load_log()`. UI-free; mirrors
      the pattern of `argus.core.findings_view`.
- [x] **SV** — `/log` route in `argus/viewers/browser/app.py` accepting
      `?scan=`, `?level=`, `?q=`. Whitelist + canonicalize `level` so
      crafted URLs fall back to "no filter" rather than 500.
- [x] **SW** — `/log/raw` route streaming the file as `text/plain` with
      a `Content-Disposition: attachment` header so browsers download
      it for grep/diff/issue-paste workflows.
- [x] **SX** — `templates/log.html.j2` + nav link in `base.html.j2` +
      `.log-pane` / `.log-level-*` rules in `static/argus.css`.
- [x] **SY** — `argus/tests/viewers/browser/test_log.py`: parser,
      filter combinations, route empty-states, CSP-friendly markup,
      raw-download download.

**Out of scope for this phase (potential follow-ups):**

- Per-scanner filter chips (parse `scanner=` field that already
  appears in many log lines). Keystroke chord on top of the search
  box would be cleaner than another `<select>`.
- Anchor jump-to-first-error / jump-to-last-error keyboard shortcuts.
- Match highlighting via `<mark>` tags. Today the user relies on the
  filter narrowing + the browser's native Cmd+F. Adding `<mark>`
  requires either a Jinja filter that escapes-then-marks or a
  client-side highlighter — neither is justified by the current
  pain.
- Per-scanner timing breakdown surfaced as a side panel (already
  tracked in `argus-audit.json`; would be a separate route or a
  metadata fold-out on the dashboard rather than inside this log
  viewer).
- Live tail (deliberately deferred — see Scope above).

### Future ideas (not on the roadmap)

Deliberately not pursuing for now — recording here so the decision
doesn't have to be re-litigated when someone files a "what about
X?" issue.

- **Keyboard shortcuts** (`/` focus search, `j/k` row nav, `Enter`
  expand detail). Considered during the post-launch walkthrough and
  deferred: browser URL bookmarking already handles the most common
  flows, and keyboard shortcuts are an expected affordance in TUIs
  like `argus view terminal` but a lower payoff in a web surface where
  mouse + click is the dominant interaction mode. Could revisit if
  users ask, but not planned.
- **Triage annotations** (mark false-positive, accepted risk, fix
  scheduled). Considered and declined. Adding these would mean:
  1. Writing state to a sidecar file, which breaks the strict
     read-only model serve is built around.
  2. Inventing a schema for persisting + recalling triage state
     across scan runs, with no standard way to surface it back into
     later scans or report it to a security review POC.
  3. Duplicating effort with `argus-portal`, which has first-class
     vuln management in its scope.
  Routes argus into vuln-management territory without a downstream
  consumer that uses the data — not worth the complexity.

### Relationship to `argus-portal`

The two are complementary, not competing:

| Aspect | `argus view browser` (this track) | `argus-portal` (separate track) |
|---|---|---|
| Audience | Single team / single product owner | Enterprise / multi-team compliance org |
| Deploy | `argus view browser` on a laptop or jumpbox | Kubernetes + Postgres + Traefik ingress |
| Auth | None or basic auth | GitHub OAuth + RBAC + FedRAMP MFA |
| State | Single file, ephemeral | Multi-scan history, CRUD (POAM, changes) |
| Goal | Answer "is product X shipping log4shell?" | FedRAMP continuous-authorization dashboard |
| Maintenance burden | ~2k LOC, no infra | Full Next.js app + Postgres + Kubernetes |

If `argus-portal` matures, it can consume the same `findings_view` shared module we extract for `argus view browser`, keeping the per-finding display consistent across CLI, local web, and enterprise web.

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

#### MCP registry submissions

The Argus MCP server is currently distributed only via PyPI (`pip install argus-security[mcp]`) and `uvx`. Listing it in community MCP server catalogs makes it discoverable for AI-tool users who don't already use the Argus CLI. Submission process for each is documented in [`docs/mcp.md`](../mcp.md#discovery-and-registry-listings).

- [ ] [`modelcontextprotocol/servers`](https://github.com/modelcontextprotocol/servers) — PR adding Argus to the **Community Servers** section of the README
- [ ] [`punkpeye/awesome-mcp-servers`](https://github.com/punkpeye/awesome-mcp-servers) — PR adding Argus to the **Security** section
- [ ] [mcp.so](https://mcp.so/) — submit at https://mcp.so/submit
- [ ] [Smithery](https://smithery.ai/) — manual submission for PyPI-distributed servers
- [ ] [Glama](https://glama.ai/mcp/servers) — auto-discovers from public repos with the `mcp-server` GitHub topic; ensure the topic is set on `huntridge-labs/argus`

Each is independent of the others; ship as bandwidth allows. Update the *"Where Argus is listed"* table in `docs/mcp.md` when each lands.

---

## Known Issues

All engine, scanner, and testing issues from the migration have been resolved.

**Open:**
- [ ] No troubleshooting guide for Docker execution failures

---

## FileDiscoveryScanner Template

Linters (`lint-yaml`, `lint-json`, `lint-python`, `lint-javascript`, `lint-dockerfile`, `lint-terraform`) and a few security scanners share a shape that doesn't fit the standard `build_args(ScanPaths) → list[str]` contract introduced in PR #117: they need to **discover files of a specific shape under a workspace, then run their tool against those file paths** (not against the workspace as a whole). Today each one rolls its own `_find_*` walk + per-file subprocess loop in its `scan()` method, which has three problems:

1. **Multi-subprocess inefficiency.** `HadolintLinter.scan()` (pre-PR #120) ran `subprocess.run(['hadolint', dockerfile])` once per Dockerfile in a Python loop — N startup costs for N files. Most of these tools accept a list of paths in a single invocation (`hadolint file1 file2 ...`), so the loop is unnecessary.
2. **No container-execution support.** The custom `scan()` flows hardcode `subprocess.run(['<binary>', ...])` and crash with `FileNotFoundError` when the binary isn't installed locally. The engine's container backend was added later and never extended to cover the discovery shape.
3. **Discovery patterns are duplicated.** Every linter implements its own `_find_dockerfiles` / `_find_yaml_files` / etc. with subtly different exclusion logic.

**Proposed shape**: a `FileDiscoveryScanner` mixin or template (analogous to `argus.core.scanner_template.run_subprocess_scan`) that:

```python
class HadolintLinter(FileDiscoveryScanner):
    name = "lint-dockerfile"
    file_glob = "Dockerfile*"            # workspace-relative pattern
    container_image = get_image("hadolint")

    def build_args(self, files: list[str], output: str) -> list[str]:
        # Tool that accepts multiple file paths in one invocation.
        return ["hadolint", "--format", "json", *files]

    def parse_results(self, output_path) -> list[Finding]:
        ...
```

The shared template handles:
- Workspace walk + glob matching with the standard exclusion set
- Single subprocess call (or `docker run`) with all matched files
- Container vs local routing via the existing `is_available()` / `container_image` mechanism
- Output file lifecycle + `parse_results` dispatch
- Empty-discovery case (return clean ScanResult with `no <files> found` info, not a failure row)

**Why deferred**: PR #120's engine fallback (`scanner.scan()` is honored when `build_args` is missing) gives every scanner a working escape hatch today, and PR #119's failure-row contract makes any remaining edge case visible. The template is a quality-of-life improvement for adding new linters that don't fit the standard shape — worth the design conversation but not load-bearing for any current functionality.

**Trigger to revisit**: when the second new linter contributor copy-pastes the file-discovery boilerplate from `HadolintLinter`. At that point the duplication has earned the abstraction.

**If/when we ship it**: likely `argus/core/file_discovery_scanner.py` exporting the template, plus migrations for the existing 6 linters + any security scanner with a similar shape (e.g. clamav's recursive directory scan). Each migration is a self-contained PR.

---

## Secret Redaction Hardening

The current redaction model (per-scanner, at the parser) is documented in [`docs/mcp.md` → Secrets handling](../mcp.md). Each scanner that emits potentially-sensitive content audits its own output and replaces secret-bearing fields with the `<redacted>` placeholder before the `Finding` is built. Downstream consumers (terminal reporter, JSON / Markdown / SARIF exports, MCP tool responses, the LLM context window) therefore never see raw values.

**Completed:**
- [x] `argus/core/redact.py` — primitive helpers (`redact_secret`, `redact_secret_in_message`, `is_redacted`)
- [x] `argus/scanners/gitleaks.py` — drops `Match` / `Secret` / `Email` / `Date` / `Message` from finding metadata; keeps `RuleID`, `Commit`, `Fingerprint`, `match_length`, line/col positions
- [x] `argus/scanners/bandit.py` — strips the literal value from `issue_text` and replaces `code` excerpt for B105 / B106 / B107 (hardcoded-credential tests). Other bandit rules pass through unchanged.

**Open — defense-in-depth safety net:**

- [ ] Pattern-based second-pass scanner that audits every `Finding`'s `description` and `metadata` values for high-entropy or known-prefix strings (`ghp_…`, `AKIA…`, `xoxb-…`, `glpat-…`, `xoxp-…`, etc.). Catches future scanners that get added without a per-parser redaction audit.
  - **Why deferred:** the per-scanner approach is the primary defense and is sufficient when contributors follow the audit checklist for new scanners. A pattern-based pass duplicates gitleaks's domain (and falls behind upstream rules immediately), risks false positives on legitimate non-secret strings (e.g., a CWE ID that happens to start with `AKIA`), and adds a per-finding regex pass that scales linearly with scan size.
  - **Trigger to revisit:** a real-world leak via a scanner whose parser was missed. At that point we have concrete data to tune false-positive thresholds against and a known cost of *not* having the safety net.
  - **If/when we ship it:** likely a `argus/core/redact_safety_net.py` module that runs at `Finding.__post_init__` time. Configurable allow/deny lists. Off by default for performance; gated by a per-scan flag and on by default for the MCP server's responses (where the cost-of-leak is highest).

**Audit checklist for new scanners** (the "follow this and the per-scanner approach holds" list):

1. Does the scanner's raw output ever contain matched literals from source code?
2. If yes: which JSON / output fields carry that content? List them in the parser's docstring.
3. Drop or `redact_secret(...)` those fields before building the `Finding`.
4. Add a test that loads a representative fixture and asserts the original literal does not appear anywhere in `Finding.to_dict()` JSON output.
5. Note the redaction policy in the scanner's module docstring so future maintainers don't accidentally re-add the leak.

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
