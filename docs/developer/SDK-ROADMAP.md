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
- [x] `scripts/check-version-refs.py` — added `.claude`, `.agents` to SKIP_DIRS

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

---

## Remaining: Phase 3 — Composite Action Thin Wrappers

Refactor `.github/actions/scanner-*` to call `argus scan` internally. Actions shrink from ~300 lines to ~15 lines. Same inputs, same outputs, same artifacts — backward compatible for external users.

- [ ] Design shared composite action step pattern (install argus + run scan + upload artifacts)
- [ ] Refactor `scanner-bandit/action.yml` as proof of concept
- [ ] Refactor remaining 9 scanner actions
- [ ] Refactor 6 linter actions (or add linter modules to SDK first)
- [ ] Verify backward compatibility: identical outputs, artifacts, SARIF
- [ ] Update `test-actions.yml` to validate thin wrappers
- [ ] Delete bundled `scripts/` from refactored actions (logic lives in SDK)
- [ ] Update docsite builder if action README structure changes

---

## Remaining: Phase 4 — Distribution + Multi-Platform

### PyPI Publishing
- [ ] `pyproject.toml` with package metadata, entry_points for `argus` CLI
- [ ] CI workflow to publish `argus-security` to PyPI on GitHub release
- [ ] Versioned: tied to `version.yaml` via release-it

### Container Image Publishing
- [ ] CI workflow to build and push custom images to GHCR on release
- [ ] Tag with argus version (e.g., `scanner-bandit:0.8.0`)
- [ ] Multi-arch builds (amd64 + arm64)
- [ ] Image signing with cosign/sigstore

### Additional Reporters
- [ ] `github.py` — PR comments, SARIF upload, step summary (GitHub-specific)
- [ ] `gitlab.py` — MR comments, SAST report format
- [ ] `junit.py` — JUnit XML for Jenkins/Azure DevOps
- [ ] Reporter plugin registration system

### Additional Scanner Modules
- [ ] `codeql.py` — GitHub-specific, needs CodeQL CLI or Action
- [ ] `dependency_review.py` — GitHub PR-only, needs GitHub API
- [ ] Linter modules: yaml, json, python, javascript, dockerfile, terraform
- [ ] `scn_detector.py` — FedRAMP SCN (port rule engine + AI providers from composite action)

### CLI Enhancements
- [ ] `argus init` — detect languages/frameworks, generate argus.yml
- [ ] `argus init --platform github|gitlab|jenkins` — generate CI config
- [ ] `argus install <scanner>` — install scanner tool locally
- [ ] `--exclude` global CLI flag for path exclusions
- [ ] Parallel scanner execution (multiprocessing/asyncio)
- [ ] Progress indicators during scanning and container pulls
- [ ] `argus report github` — post results as PR comment via GitHub API

### CI Templates
- [ ] GitLab CI template
- [ ] Jenkins pipeline template
- [ ] Azure DevOps template

---

## Known Issues

### Engine
- [ ] Container scanner (`container.py`) has empty `container_image` — can't Docker-fallback the orchestrator (sub-tools need individual execution)
- [ ] `--list` doesn't show local vs container-only availability
- [ ] No progress output during long-running container pulls
- [ ] Engine silently continues on scanner failure — needs optional `--fail-fast` mode
- [ ] No timeout handling for individual scanner execution

### Scanners
- [ ] ClamAV container requires virus DB update on first run (adds ~60s)
- [ ] OSV-Scanner image pinned to `latest` — should pin to specific version once available
- [ ] OpenGrep uses `returntocorp/semgrep` image — verify if opengrep publishes its own
- [ ] Supply-chain `container_args` uses `sh -c` shell wrapper — fragile on non-Linux
- [ ] Bandit container ENTRYPOINT means args don't include `bandit` command — documented but could surprise contributors

### Testing Gaps
- [ ] Docker execution path not covered in pytest (needs Docker daemon)
- [ ] No E2E test that builds containers and runs full scan
- [ ] Container scanner deduplication logic only tested with fixtures, not live
- [ ] `argus report` subcommand has no integration tests
- [ ] CLI `--version` flag behavior not fully tested

### Documentation Gaps
- [ ] Docsite has no SDK section — needs CLI reference, config reference, scanner module docs
- [ ] No migration guide for users of the deleted reusable workflows
- [ ] `argus.example.yml` missing documentation for all scanner-specific extra config keys
- [ ] No troubleshooting guide for Docker execution failures
- [ ] `--help` text for CLI subcommands could be more detailed

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
| Version refs across all files | CI gate | `scripts/check-version-refs.py` in test-unit.yml | Done |
| package.json version | release-it | `.release-it.json` regex-bumper | Done |
