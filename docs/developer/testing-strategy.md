# Argus Testing Strategy

## Ref Lifecycle

Version references flow through three stages, each automatically managed:

### PR Branch (feature development)
- Composite actions: `./` (local path — tests the PR's code)
- Reusable workflows: `./` (local path via workflow_call)
- `test-actions.yml` E2E: uses local checkout, validates the PR branch
- `build-containers.yml`: builds images from the PR, scans with argus CLI from the PR
- No version tags involved — everything is local

### Main Branch (after merge)
- Composite actions: still `./` for internal CI
- Reusable workflows: callers outside the repo use `@main`
- `security-scan.yml`: runs argus scan against main (scheduled weekly + on push)
- All tests re-run on push to main as final validation

### Release Tag (cut by release-it)
- `release-it` bumps all version refs across the repo:
  - `version.yaml` (source of truth)
  - `package.json` `"version":`
  - `argus/__init__.py` `__version__ =`
  - `argus/containers.py` GHCR image tags
  - All `@X.Y.Z` refs in actions, workflows, examples, docs
- Container images published to GHCR with version tag + `latest`
- GitHub Release created with changelog

## In-Repo Testing (PR Pipeline)

All validation happens within the argus repo. No external repos required for PR gating.

### Test Matrix

| Workflow | What It Tests | Trigger |
|----------|--------------|---------|
| `test-unit.yml` | pytest suite (403+ tests), Python 3.11/3.12/3.13/3.14, version ref coverage | PR, push to main |
| `test-actions.yml` | Composite action E2E with real scanners against test fixtures | PR (path-filtered), push to main |
| `build-containers.yml` | Build images → scan with Trivy+Grype → test argus CLI → validate audit trail | PR (path-filtered) |
| `test-examples-functional.yml` | Example workflow YAML validation | PR (path-filtered) |
| `test-lint-workflows.yml` | actionlint on all workflow files | PR, push to main |
| `security-scan.yml` | Dogfood: argus scans argus | push to main, weekly schedule |

### Coverage Guarantees

- **Unit tests**: 80%+ coverage enforced via pytest-cov
- **Composite actions**: Every scanner action has E2E test in test-actions.yml
- **Argus CLI**: build-containers.yml tests --list, scan, output validation, SARIF structure, audit trail
- **Container images**: Built, scanned with Trivy+Grype, results posted as PR comment
- **Version refs**: check-version-refs.py runs in CI, fails if any ref would be stale after release

## External Validation: argus-test

The `huntridge-labs/argus-test` repo serves as an **external consumer validation** that runs on a schedule against the latest published release. It does NOT gate PRs.

### Purpose
- Validates that published releases work from a consumer's perspective
- Catches regressions that in-repo tests miss (real-world usage patterns)
- Generates a dashboard with historical pass/fail rates
- Alerts the team when the latest release breaks

### What argus-test Needs (TODO)

1. **Update to 1.0.0 interfaces**: The existing test workflows call `container-scan.yml`, `infrastructure-scan.yml`, etc. These were restored with the same interfaces but now use argus CLI internally. Tests should still pass.

2. **Add argus CLI tests**: New test category that validates:
   - `argus scan --list` returns all scanners
   - `argus scan bandit --path <test-fixtures>` produces expected findings
   - `argus scan container --image nginx:1.19.0` detects known CVEs
   - `argus collect` merges multi-scanner results
   - `argus-audit.json` is produced with valid structure

3. **Add SDK unit tests**: Run `pytest argus/tests/` against the published ref to ensure the SDK works when consumed via checkout (before PyPI is available).

4. **Alerting**: When the scheduled run fails:
   - Open an issue on `huntridge-labs/argus` with the failure details
   - Include: which tests failed, the argus ref tested, dashboard link
   - Label: `bug`, `automated`, `external-validation`

5. **Schedule**: Weekly (matches current cron). Optionally trigger on argus releases via `repository_dispatch` if cross-repo token is available.

### What argus-test Does NOT Do
- Does not gate argus PRs (cross-repo dispatch is fragile, static ref limitation)
- Does not duplicate in-repo tests (unit tests, E2E tests already comprehensive)
- Does not require maintenance for every argus change (tests use published interfaces)
