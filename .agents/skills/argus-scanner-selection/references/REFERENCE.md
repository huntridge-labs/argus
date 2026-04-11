# Argus Scanner Selection Reference

Use this file when you need the detailed mapping from repository signals or local change sets to Argus scanners, workflow structure, and operational caveats.

## Platform routing

| Environment | Preferred Argus integration path | Why |
| --- | --- | --- |
| local development | argus SDK (`python -m argus scan`) | fastest feedback, no Docker or Actions required |
| github.com CI | composite actions (`.github/actions/scanner-*`) | direct GitHub Actions integration |
| GHES with github.com access | composite actions | works from public github.com repos without mirroring |
| air-gapped GHES / internal mirror | composite actions from the internal mirror | same portability model, but refs must point at the mirrored source |
| any CI with Python | argus SDK | platform-independent, works in any CI environment |

For GHES, use `examples/github-enterprise/*` as the starting point for composite action workflows.

## Scanner matrix

| Repository signal | Evidence to look for | Recommended scanner(s) | Why | Caveats |
| --- | --- | --- | --- | --- |
| Any source repository | `src/`, `app/`, `lib/`, language source files | `gitleaks`, `opengrep` | Baseline coverage for secrets + multi-language SAST | `gitleaks` benefits from full git history on CI |
| Python present | `*.py`, `pyproject.toml`, `requirements*.txt`, `poetry.lock` | `bandit` | Python-specific security linting | Keep `opengrep` too for broader rules |
| CodeQL-supported languages + GHAS enabled | `*.py`, `*.js`, `*.ts`, `*.go`, `*.java`, `*.c`, `*.cpp`, `*.cs`, `*.rb`, `*.swift`, `*.kt` | `codeql` | Semantic analysis with language-aware results | Requires GitHub Code Security / GHAS to be enabled |
| Dependency manifests or lockfiles | `package-lock.json`, `pnpm-lock.yaml`, `poetry.lock`, `requirements.txt`, `go.sum`, `Cargo.lock`, etc. | `osv` | Works on any trigger and auto-discovers manifests | Prefer this over `dependency-review` for push/schedule runs |
| Pull request dependency policy | PR workflow + lockfiles/manifests | `dependency-review` | Dependency diff + optional license checks | PR-only; expected to skip on non-PR events |
| Dockerfiles or image publish/build pipeline | `Dockerfile*`, `docker-compose.yml`, container build jobs | `container` | Coordinated Trivy + Grype + Syft workflow | Prefer this over combining standalone container scanners |
| Need SBOM artifact or supply-chain inventory | release workflow, image publishing, compliance asks | `sbom` | Generates CycloneDX/SPDX/Syft inventories | `sbom` is not included in `all` |
| Terraform / Kubernetes / CloudFormation | `*.tf`, `*.tfvars`, `*.yaml` under k8s dirs, `cloudformation/` | `infrastructure` | Coordinated Trivy IaC + Checkov workflow | Prefer this over adding `trivy-iac` and `checkov` separately |
| Need only one IaC engine | same as above, but user wants split jobs | `trivy-iac` or `checkov` | Fine-grained control | Avoid pairing with `infrastructure` unless explicitly requested |
| Web app or API with stable target | app server, deploy preview URL, compose stack, OpenAPI spec | `zap` | DAST / API scanning | Needs target mode: `url`, `docker-run`, or `compose` |
| Untrusted binaries, archives, uploads | `*.zip`, `*.jar`, installers, media ingest, upload pipeline | `clamav` | Malware detection | Not a default scanner for source-only repos |
| FedRAMP change classification | `.github/scn-config.yml`, compliance docs, regulated infra diffs | `scn-detector` | Significant Change Notification detection | Separate composite action, not part of the standard scanner set |

## Local development decision table

Use this table when the goal is to catch issues before push.

| Local change pattern | Default local scanners | Usually keep in CI unless explicitly requested |
| --- | --- | --- |
| application code only | `gitleaks`, `opengrep`, plus `bandit` for Python | `zap`, `clamav`, `scn-detector` |
| manifest or lockfile change | `gitleaks`, `opengrep`, `osv` | `dependency-review` on non-PR events |
| Dockerfile, compose, or image build change | `gitleaks`, `opengrep`, `container` | separate standalone container scanners unless needed |
| Terraform / Kubernetes / CloudFormation change | `gitleaks`, `opengrep`, `infrastructure` | `scn-detector` unless FedRAMP workflows require it |
| upload pipeline or binary artifact change | `gitleaks`, `opengrep`, `clamav` when relevant | `zap` unless a local target exists |
| web app change with stable local or preview target | baseline local set plus `zap` if a target is available | `zap` if there is no reliable target mode |

## Local-first recommendations

- Start with the changed files, then widen to the full repository only when the changes touch shared security posture.
- Mirror CI where practical, but trim clearly slow or environment-dependent scans from the default pre-push loop.
- Prefer `osv` over `dependency-review` for local or non-PR checks.
- Treat `zap`, `clamav`, and `scn-detector` as explicitly justified local checks, not baseline defaults.
- Default local execution to the argus SDK: `python -m argus scan <scanners>`.
- Composite actions with `act` remain an alternative for users who prefer GitHub Actions locally.

## Grouped tokens vs standalone scanners

Use grouped tokens when the user wants broad onboarding with fewer workflow decisions:

| Token | Expands to | Best when |
| --- | --- | --- |
| `container` | coordinated container discovery/build + Trivy + Grype + Syft | repo builds images and you want one container job family |
| `infrastructure` | coordinated Trivy IaC + Checkov | repo has IaC and you want one infrastructure job family |
| `dependencies` | `osv` + `dependency-review` | pull request workflows need both manifest scanning and diff checks |
| `sast` | `codeql` + `opengrep` + `bandit` + `gitleaks` | repo is code-heavy and all grouped scanners are valid |

Use standalone scanners when:

- the trigger invalidates part of a group (`dependency-review` on push or schedule)
- you need separate permissions, thresholds, or job names
- the user wants only one scanner from the group

## Recipes

### SDK baseline (recommended)

Use this for most application repositories:

```bash
python -m argus scan gitleaks opengrep osv --severity-threshold high
```

Then add `bandit`, `codeql`, `container`, `trivy-iac`, `checkov`, or `clamav` when the repository signals justify them.

### Local pre-push baseline

Use this as the default mental model for a coding agent helping before push:

- start with `gitleaks` and `opengrep`
- add `bandit` for Python changes
- add `osv` for manifest or lockfile changes
- add `container` for Docker and image-related changes
- add `trivy-iac` and `checkov` for IaC changes
- add `zap`, `clamav`, or `scn-detector` only when the change set clearly requires them

When the repository already has Argus in CI, prefer keeping the local recommendation compatible with the CI scanner list while still optimizing for faster iteration.

### Concrete local execution

```bash
# Install
pip install pyyaml

# Baseline scan
python -m argus scan gitleaks opengrep

# Python project
python -m argus scan gitleaks opengrep bandit osv --severity-threshold high

# Infrastructure project
python -m argus scan gitleaks opengrep trivy-iac checkov --severity-threshold high
```

### Optional pre-push hook pattern

If the user wants automatic enforcement before push, wire the SDK into a git hook:

```bash
#!/bin/sh
python -m argus scan gitleaks opengrep --severity-threshold high || exit 1
```

Keep this opt-in. The skill should recommend hooks only when the user explicitly wants automatic blocking behavior.

### CI with composite actions

For GitHub Actions CI, use composite actions:

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - uses: huntridge-labs/argus/.github/actions/scanner-gitleaks@<argus-version>
        with:
          fail_on_severity: high
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - uses: huntridge-labs/argus/.github/actions/scanner-opengrep@<argus-version>
        with:
          fail_on_severity: high

      - uses: huntridge-labs/argus/.github/actions/scanner-osv@<argus-version>
        with:
          fail_on_severity: high
```

### Containerized service

```bash
python -m argus scan gitleaks opengrep osv container --severity-threshold high
```

### Python service

```bash
python -m argus scan gitleaks opengrep osv bandit --severity-threshold high
```

### Infrastructure repository

```bash
python -m argus scan gitleaks opengrep trivy-iac checkov --severity-threshold high
```

### Web app with DAST

Keep ZAP separate from baseline scans:

```bash
# Baseline
python -m argus scan gitleaks opengrep osv --severity-threshold high

# DAST (requires running target)
python -m argus scan zap --severity-threshold high
```

### FedRAMP companion flow

Use `scn-detector` as a separate job or workflow:

```yaml
- uses: huntridge-labs/argus/.github/actions/scn-detector@<argus-version>
  with:
    config_file: .github/scn-config.yml
    create_issues: true
    post_pr_comment: true
    enable_ai_fallback: true
```

## Inputs, secrets, and permissions

| Scanner | SDK CLI flags | Composite action inputs | Secrets | Notes |
| --- | --- | --- | --- | --- |
| `bandit` | `--path`, `--severity-threshold` | `path`, `fail_on_severity` | none | Python-only |
| `gitleaks` | `--severity-threshold` | `fail_on_severity`, `enable_code_security` | `GITLEAKS_LICENSE` optional | Benefits from full git history |
| `opengrep` | `--severity-threshold` | `fail_on_severity`, `enable_code_security` | none | Multi-language |
| `codeql` | `--severity-threshold` | `codeql_languages`, `enable_code_security` | `GITHUB_TOKEN` | Requires GitHub Code Security |
| `osv` | `--severity-threshold` | `osv_scan_path`, `fail_on_severity` | none | Any trigger |
| `container` | `--severity-threshold` | `image_ref`, `fail_on_severity` | `registry_password` optional | Add `packages: read` for private registries |
| `trivy-iac` | `--path`, `--severity-threshold` | `iac_path`, `fail_on_severity` | none | Terraform, K8s, CloudFormation |
| `checkov` | `--path`, `--severity-threshold` | `iac_path`, `fail_on_severity` | none | Policy as Code |
| `zap` | `--severity-threshold` | `zap_config_file`, `fail_on_severity` | `registry_password` optional | Target must be reachable |
| `clamav` | `--path`, `--severity-threshold` | `clamav_scan_path`, `fail_on_severity` | none | Malware detection |
| `scn-detector` | N/A (composite action only) | `config_file`, `create_issues`, `enable_ai_fallback` | `ANTHROPIC_API_KEY` optional | Also needs `issues: write` |

## Review checklist

Before finalizing a recommendation or implementation:

1. Confirm every selected scanner has a matching repository signal.
2. Confirm every omitted scanner has an explicit reason.
3. Check whether `enable_code_security` should be true or false.
4. Check whether `dependency-review` belongs only on PR events.
5. Check whether grouped tokens are hiding an invalid or redundant combination.
6. Validate any workflow YAML you edited.
