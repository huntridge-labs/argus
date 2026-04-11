# Argus SDK Roadmap

Tracks remaining work after the initial SDK implementation (Phase 1-2) and CI migration.

## Completed (this PR)

### Phase 1: Core SDK + CLI
- [x] `argus/core/` — models, scanner protocol, config, engine
- [x] `argus/cli.py` — argparse CLI with scan and report subcommands
- [x] `argus/reporters/` — terminal, markdown, SARIF 2.1.0, JSON
- [x] `argus.yml` configuration loading via pyyaml
- [x] 202 unit tests, 83%+ coverage on argus/ package

### Phase 2: Scanner Migration + Docker Backend
- [x] 10 scanner modules: bandit, clamav, trivy-iac, gitleaks, osv, checkov, opengrep, supply-chain, zap, container
- [x] Docker execution backend — auto fallback to official containers
- [x] `argus/containers.py` central image manifest
- [x] ARM64 pull fallback (linux/amd64)
- [x] Container stdout capture for scanners that write to stdout
- [x] Custom Dockerfiles: bandit, opengrep, supply-chain, cli (all-in-one)
- [x] container_args driven by config, not hardcoded

### CI/CD Migration
- [x] `security-scan.yml` dogfood workflow — `pip install pyyaml && argus scan`
- [x] Removed 22 deprecated workflow wrappers
- [x] `test-reusable-workflows.yml` refactored to test argus CLI
- [x] Renovate + Dependabot for full dependency maintenance
- [x] CI hardening: continue-on-error removed, Python matrix, version ref gate

---

## Phase 3: Composite Action Thin Wrappers

Refactor `.github/actions/scanner-*` to call `argus scan` internally. Actions shrink from ~300 lines to ~15 lines while preserving the same inputs/outputs for external users.

### Tasks
- [ ] Create a shared composite action step pattern that installs argus and runs a scan
- [ ] Refactor `scanner-bandit/action.yml` as proof of concept
- [ ] Refactor remaining scanner actions one at a time
- [ ] Verify backward compatibility: same inputs, same outputs, same artifacts
- [ ] Update `test-actions.yml` to validate thin wrappers produce identical output
- [ ] Delete bundled `scripts/parse-results.py` and `scripts/generate-summary.py` from refactored actions (logic now lives in SDK)

### Design decision
Each action becomes:
```yaml
runs:
  using: 'composite'
  steps:
    - uses: actions/setup-python@v6
    - run: pip install pyyaml && PYTHONPATH=. python -m argus scan bandit --format sarif --format json
    - uses: actions/upload-artifact@v7
    - uses: github/codeql-action/upload-sarif@v4
```

---

## Phase 4: Multi-Platform + Distribution

### PyPI Publishing
- [ ] Create `pyproject.toml` with package metadata
- [ ] Add `argus-security` to PyPI
- [ ] CI workflow to publish on GitHub release
- [ ] Users install with: `pip install argus-security`

### Container Image Publishing
- [ ] CI workflow to build and push custom images to GHCR on release
- [ ] Tag images with argus version (e.g., `scanner-bandit:0.8.0`)
- [ ] Multi-arch builds (amd64 + arm64) for custom images
- [ ] Signed images with cosign/sigstore

### Additional Reporters
- [ ] `github.py` reporter — PR comments, SARIF upload, step summary (GitHub-specific)
- [ ] `gitlab.py` reporter — MR comments, SAST report format
- [ ] `junit.py` reporter — JUnit XML for Jenkins/Azure DevOps
- [ ] Reporter plugin system — users can register custom reporters

### Additional Scanner Modules
- [ ] `codeql.py` — CodeQL integration (GitHub-specific, needs special handling)
- [ ] `dependency_review.py` — GitHub dependency review (PR-only, GitHub-specific)
- [ ] Linter modules: yaml, json, python, javascript, dockerfile, terraform
- [ ] `scn_detector.py` — FedRAMP SCN detection (port from composite action)

### CLI Enhancements
- [ ] `argus init` — detect repo languages/frameworks, generate argus.yml
- [ ] `argus init --platform github` — generate GitHub Actions workflow
- [ ] `argus init --platform gitlab` — generate GitLab CI config
- [ ] `argus install <scanner>` — install scanner tool locally
- [ ] Parallel scanner execution (multiprocessing/asyncio)
- [ ] Progress indicators during scanning
- [ ] `--exclude` CLI flag for path exclusions (global, not per-scanner)

### CI Templates
- [ ] GitLab CI template (`templates/gitlab-ci.yml`)
- [ ] Jenkins pipeline template (`templates/Jenkinsfile`)
- [ ] Azure DevOps template (`templates/azure-pipelines.yml`)

---

## Known Issues

### Engine
- [ ] Container scanner (`container.py`) has no Docker-in-Docker fallback — requires local trivy/grype/syft or individual container execution
- [ ] `--list` flag doesn't show which scanners are available locally vs container-only
- [ ] No progress output during long-running container pulls
- [ ] Engine silently continues when a scanner fails — should optionally fail-fast

### Scanners
- [ ] ClamAV container requires virus DB update on first run (slow)
- [ ] OSV-Scanner container image tag needs pinning (currently `latest`)
- [ ] OpenGrep container uses `returntocorp/semgrep` image — verify opengrep-specific image availability
- [ ] Supply-chain container_args uses shell wrapper (`sh -c`) — fragile

### Testing
- [ ] No end-to-end test that builds containers and runs full scan in CI
- [ ] Docker execution path not tested in pytest (requires Docker daemon)
- [ ] `test-actions.yml` still tests composite actions with bundled scripts — should also test thin wrapper pattern once Phase 3 starts

### Documentation
- [ ] Docsite has no SDK section — needs CLI reference, config reference, scanner module docs
- [ ] No migration guide for users moving from reusable workflows to SDK
- [ ] `argus.example.yml` needs documentation for all scanner-specific config options
- [ ] Missing man page / --help improvements for each subcommand

---

## Dependency Maintenance Coverage

| What | Tool | Status |
|---|---|---|
| GitHub Action SHAs | Dependabot | Done |
| npm packages | Dependabot | Done |
| Python packages | Dependabot | Done |
| Dockerfile base images | Dependabot | Done |
| Container image tags in Python | Renovate | Done |
| Tool versions in action.yml | Renovate | Done |
| Tool versions in Dockerfiles | Renovate | Done |
| Version refs across repo | CI gate (check-version-refs.py) | Done |
| package.json version | release-it regex-bumper | Done |
