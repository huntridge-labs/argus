# Argus Scanner Selection Reference

Use this file when you need the detailed mapping from repository signals or local change sets to Argus scanners, workflow structure, and operational caveats.

## Scanner matrix

| Repository signal | Evidence to look for | Recommended scanner(s) | Why | Caveats |
| --- | --- | --- | --- | --- |
| Any source repository | `src/`, `app/`, `lib/`, language source files | `gitleaks`, `opengrep` | Baseline coverage for secrets + multi-language SAST | `gitleaks` benefits from full git history on CI |
| Python present | `*.py`, `pyproject.toml`, `requirements*.txt`, `poetry.lock` | `bandit` | Python-specific security linting | Keep `opengrep` too for broader rules |
| CodeQL-supported languages + GHAS enabled | `*.py`, `*.js`, `*.ts`, `*.go`, `*.java`, `*.c`, `*.cpp`, `*.cs`, `*.rb`, `*.swift`, `*.kt` | `codeql` | Semantic analysis with language-aware results | In Argus' reusable workflow, omit `codeql` unless `enable_code_security: true` |
| Dependency manifests or lockfiles | `package-lock.json`, `pnpm-lock.yaml`, `poetry.lock`, `requirements.txt`, `go.sum`, `Cargo.lock`, etc. | `osv` | Works on any trigger and auto-discovers manifests | Prefer this over `dependency-review` for push/schedule runs |
| Pull request dependency policy | PR workflow + lockfiles/manifests | `dependency-review` | Dependency diff + optional license checks | PR-only; expected to skip on non-PR events |
| Dockerfiles or image publish/build pipeline | `Dockerfile*`, `docker-compose.yml`, container build jobs | `container` | Coordinated Trivy + Grype + Syft workflow | Prefer this over combining standalone container scanners |
| Need SBOM artifact or supply-chain inventory | release workflow, image publishing, compliance asks | `sbom` | Generates CycloneDX/SPDX/Syft inventories | `sbom` is not included in `all` |
| Terraform / Kubernetes / CloudFormation | `*.tf`, `*.tfvars`, `*.yaml` under k8s dirs, `cloudformation/` | `infrastructure` | Coordinated Trivy IaC + Checkov workflow | Prefer this over adding `trivy-iac` and `checkov` separately |
| Need only one IaC engine | same as above, but user wants split jobs | `trivy-iac` or `checkov` | Fine-grained control | Avoid pairing with `infrastructure` unless explicitly requested |
| Web app or API with stable target | app server, deploy preview URL, compose stack, OpenAPI spec | `zap` | DAST / API scanning | Needs target mode: `url`, `docker-run`, or `compose` |
| Untrusted binaries, archives, uploads | `*.zip`, `*.jar`, installers, media ingest, upload pipeline | `clamav` | Malware detection | Not a default scanner for source-only repos |
| FedRAMP change classification | `.github/scn-config.yml`, compliance docs, regulated infra diffs | `scn-detector` | Significant Change Notification detection | Separate workflow/action, not part of `reusable-security-hardening.yml` |

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

## Trigger-aware recipes

### Pull request baseline

Use this for most application repositories:

```yaml
uses: huntridge-labs/argus/.github/workflows/reusable-security-hardening.yml@<argus-version>
with:
  scanners: gitleaks,opengrep,osv,dependency-review
  enable_code_security: false
  allow_failure: true
  severity_threshold: high
secrets: inherit
```

Then add `bandit`, `codeql`, `container`, `infrastructure`, `sbom`, or `clamav` when the repository signals justify them.

### Local pre-push baseline

Use this as the default mental model for a coding agent helping before push:

- start with `gitleaks` and `opengrep`
- add `bandit` for Python changes
- add `osv` for manifest or lockfile changes
- add `container` for Docker and image-related changes
- add `infrastructure` for IaC changes
- add `zap`, `clamav`, or `scn-detector` only when the change set clearly requires them

When the repository already has Argus in CI, prefer keeping the local recommendation compatible with the CI scanner list while still optimizing for faster iteration.

### Push or scheduled baseline

Prefer `osv` over `dependencies` unless you want a graceful PR-only skip from `dependency-review`:

```yaml
uses: huntridge-labs/argus/.github/workflows/reusable-security-hardening.yml@<argus-version>
with:
  scanners: gitleaks,opengrep,osv
  enable_code_security: false
  allow_failure: true
  severity_threshold: high
secrets: inherit
```

### Containerized service

```yaml
uses: huntridge-labs/argus/.github/workflows/reusable-security-hardening.yml@<argus-version>
with:
  scanners: gitleaks,opengrep,osv,container,sbom
  enable_code_security: false
  allow_failure: true
  severity_threshold: high
secrets: inherit
```

Drop `sbom` if the user does not need inventory artifacts.

### Python service with GHAS enabled

```yaml
uses: huntridge-labs/argus/.github/workflows/reusable-security-hardening.yml@<argus-version>
with:
  scanners: gitleaks,opengrep,osv,bandit,codeql
  enable_code_security: true
  allow_failure: true
  severity_threshold: high
secrets: inherit
```

### Infrastructure repository

```yaml
uses: huntridge-labs/argus/.github/workflows/reusable-security-hardening.yml@<argus-version>
with:
  scanners: gitleaks,opengrep,infrastructure
  iac_path: infrastructure
  enable_code_security: false
  allow_failure: true
  severity_threshold: high
secrets: inherit
```

### Web app with DAST

Keep ZAP separate unless the user explicitly wants it folded into the shared workflow:

```yaml
jobs:
  security:
    uses: huntridge-labs/argus/.github/workflows/reusable-security-hardening.yml@<argus-version>
    with:
      scanners: gitleaks,opengrep,osv
      enable_code_security: false
      allow_failure: true
      severity_threshold: high
    secrets: inherit

  dast:
    uses: huntridge-labs/argus/.github/workflows/scanner-zap.yml@<argus-version>
    with:
      scan_mode: url
      scan_type: baseline
      target_url: https://example.test
      fail_on_severity: high
    secrets: inherit
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

| Scanner / workflow | Key inputs | Secrets | Permissions / notes |
| --- | --- | --- | --- |
| `reusable-security-hardening.yml` | `scanners`, `enable_code_security`, `allow_failure`, `severity_threshold` | `GITHUB_TOKEN` implied, `GITLEAKS_LICENSE` optional | `contents: read`, `actions: read`, `pull-requests: write`, `security-events: write`; add `id-token: write` when using the full reusable workflow defaults |
| `codeql` | `codeql_languages`, `config_file`, `enable_code_security` | none beyond `GITHUB_TOKEN` | Requires GitHub Code Security to stay enabled in the reusable workflow |
| `bandit` | `bandit_config_file` | none | Python-only |
| `osv` | `osv_scan_path`, `osv_lockfile`, `osv_recursive` | none | Any trigger |
| `dependency-review` | `vulnerability_check`, `license_check`, `allow_licenses`, `deny_licenses` | none | Pull request event only |
| `container` | `scan_mode`, `image_ref`, `container_name`, `scanners` | `registry_password` optional | add `packages: read` for private registries and image pulls |
| `infrastructure` | `iac_path` | optional `AWS_ACCOUNT_ID` in some setups | same baseline permissions as the shared workflow |
| `sbom` | `scan_path`, `scan_image`, `output_format` | `registry_password` optional | Dependency Graph upload requires the relevant GitHub permissions |
| `zap` | `scan_mode`, `scan_type`, `target_url` or `api_spec`, `compose_file`, `app_image_ref` | `registry_password` optional | target must exist and be reachable from the runner |
| `scn-detector` | `config_file`, `create_issues`, `post_pr_comment`, `enable_ai_fallback` | `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` optional, `GITHUB_TOKEN` required | also needs `issues: write` when creating issues |

## Review checklist

Before finalizing a recommendation or implementation:

1. Confirm every selected scanner has a matching repository signal.
2. Confirm every omitted scanner has an explicit reason.
3. Check whether `enable_code_security` should be true or false.
4. Check whether `dependency-review` belongs only on PR events.
5. Check whether grouped tokens are hiding an invalid or redundant combination.
6. Validate any workflow YAML you edited.
