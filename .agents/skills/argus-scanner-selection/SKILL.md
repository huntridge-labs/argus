---
name: argus-scanner-selection
description: Analyze a repository or local change set and choose the right Argus scanners and inputs. Use when a coding agent needs pre-push security checks during development or wants to align local scans with Argus CI coverage. The argus SDK (python -m argus scan) is the primary interface.
license: AGPL-3.0
compatibility: Designed for skills-compatible coding agents with file search, file read, shell, git, and GitHub workflow editing access. The argus SDK is the primary execution path; composite actions provide GitHub Actions integration.
metadata:
  author: huntridge-labs
  repository: huntridge-labs/argus
---

# Argus Scanner Selection

Use this skill when you need to bring Argus into a local development loop, map a repository or change set to the smallest effective set of Argus scanners, explain the choice, and optionally wire the same coverage into CI.

Read [the reference guide](references/REFERENCE.md) when you need the full scanner matrix, trigger caveats, or workflow templates.

## Goals

1. Detect the repository's languages, dependency ecosystems, containers, infrastructure, web surfaces, compliance signals, and changed files.
2. Recommend the right Argus scanners for the current development task.
3. Run or prepare the smallest effective scan plan using the argus SDK.
4. Optionally generate or update GitHub Actions workflows with composite actions for CI alignment.
5. Avoid over-scanning, unsupported scanners, and noisy combinations.

## Inputs to gather

Collect or infer these before making recommendations:

- repository path or URL
- scan scope: staged diff, branch diff, working tree, or full repository
- hosting environment: github.com, GHES with github.com access, or air-gapped/internal mirror
- local execution path: argus SDK availability (Python 3.11+), or `act` for composite action testing
- workflow trigger(s): `pull_request`, `push`, `schedule`, `workflow_dispatch` (for CI integration)
- whether GitHub Code Security / GitHub Advanced Security is enabled
- whether the repo builds or publishes container images
- whether the repo has a stable running web target or OpenAPI spec for DAST
- whether FedRAMP SCN tracking is required
- whether the user wants report-only or gating behavior

Infer from the repository first. Ask the user only when a missing detail changes scanner choice.

## Working procedure

1. Inspect the current repository state first. If there is a staged diff, branch diff, or working-tree change set, treat that as the primary signal for a local development scan.
2. Inspect the repository for source languages, lockfiles, manifests, Dockerfiles, compose files, container build or publish workflows, Terraform, Kubernetes, CloudFormation, Helm, installer or binary assets, and web entrypoints.
3. Build a short evidence list from the files you found. Quote concrete paths and changed files when available.
4. Choose scanners using the selection rules below.
5. For local development, prefer the smallest effective scanner set that matches the current changes so feedback arrives before push.
6. Route by platform:
   - for local development and pre-push checks, prefer the argus SDK (`python -m argus scan`)
   - for GitHub Actions CI, prefer composite actions from `.github/actions/scanner-*`
   - for GHES or air-gapped environments, prefer composite actions or the SDK
7. Prefer an explicit scanner list when generating commands or workflows.
8. Produce:
   - the recommended scanners
   - why each scanner is included
   - what should be run locally now versus what should remain CI-only
   - which execution path applies locally, on github.com CI, and on GHES if relevant
   - which scanners were intentionally excluded
   - any required inputs, secrets, and permissions
   - the exact workflow or action snippet to use
   - the exact local execution command when local runs are requested
9. If the user asked you to implement, edit the workflow files and preserve the repository's existing conventions.
10. After editing files, validate the YAML and run the repository's relevant validators.

## Local development guidance

- Start diff-first. If the change set only touches application code, run the source-focused scanners that match the changed languages and dependency manifests.
- Escalate to full-repository recommendations when the changes touch shared configuration, dependency manifests, Dockerfiles, IaC, release workflows, or security-sensitive areas.
- Keep DAST and compliance scans opt-in unless the local environment clearly provides the required target or policy context.
- Default local execution to the argus SDK: `python -m argus scan <scanners> --severity-threshold <level>`.
- If the repository is not yet using Argus in CI, still return a local SDK scan plan and then propose the minimal CI workflow (composite actions) that mirrors it.
- Composite actions with `act` remain an alternative for users who prefer GitHub Actions locally.

## Platform routing

- Use the argus SDK (`python -m argus scan`) as the primary recommendation for local development and any CI environment with Python.
- Use composite actions for GitHub Actions CI workflows (github.com and GHES).
- For GHES or air-gapped setups, composite actions provide direct GitHub Actions integration without cross-repo dependencies.
- When the platform is unclear, default to the SDK for local use and composite actions for CI.

## Selection rules

### Baseline for most source repositories

Start with:

- `gitleaks` for secret detection
- `opengrep` for multi-language pattern-based SAST
- `osv` for dependency vulnerability scanning when manifests or lockfiles are present

### Add language-specific or platform-specific scanners

- Add `bandit` when Python is present.
- Add `codeql` when the repository contains CodeQL-supported languages and GitHub Code Security is enabled.
- Add `dependency-review` for pull request workflows that need dependency diff or license checks.
- Add `container` when the repository builds container images or contains Dockerfiles and you want the coordinated Trivy + Grype + Syft flow.
- Add `infrastructure` when Terraform, Kubernetes, or CloudFormation is present and you want the coordinated Trivy IaC + Checkov flow.
- Add `sbom` when the user explicitly wants SBOM artifacts or the repository publishes build artifacts or container images and supply-chain inventory matters.
- Add `zap` only when there is a stable URL, a runnable container image, or a compose stack to target.
- Add `clamav` only when the repository handles uploaded files, archives, installers, binaries, or other third-party artifacts worth malware scanning.
- Add `scn-detector` only for FedRAMP significant-change workflows on infrastructure diffs.

### Local pre-push prioritization

- For code-only changes, start with `gitleaks`, `opengrep`, and any language-specific scanner such as `bandit`.
- Add `osv` when the change set touches manifests or lockfiles, or when the repository has dependency risk that should be checked before push.
- Add `container` only when Dockerfiles, compose files, image build scripts, or container publishing paths are touched, or when the user wants full local image coverage.
- Add `infrastructure` only when Terraform, Kubernetes, or CloudFormation files are touched, or when the repository is primarily an IaC repo.
- Keep `zap`, `clamav`, and `scn-detector` out of the default local loop unless the changes or repository signals clearly justify them.

### Prefer grouped workflow tokens for onboarding

Use grouped tokens when they match the user's goal:

- `container` = discover, build, and scan containers with Trivy, Grype, and Syft
- `infrastructure` = run Trivy IaC and Checkov together
- `dependencies` = run `osv` and `dependency-review`
- `sast` = run `codeql`, `opengrep`, `bandit`, and `gitleaks`

Use individual scanners instead of grouped tokens when:

- the user wants only one scanner from the group
- the workflow trigger makes part of the group invalid (`dependency-review` is PR-only)
- the repository needs separate jobs, severities, or permissions per scanner

### Avoid these mistakes

- Do not assume `all` includes `zap`, `dependency-review`, or `sbom`.
- Do not add `codeql` if GitHub Code Security is unavailable; call out the gap and use `opengrep` plus language-specific scanners instead.
- Do not pair `container` with `trivy-container` or `grype` unless the user explicitly wants separate standalone jobs.
- Do not pair `infrastructure` with `trivy-iac` or `checkov` unless the user explicitly wants separate standalone jobs.
- Do not recommend `dependency-review` on non-PR triggers unless the user accepts that it will skip gracefully.
- Do not add `zap` without a target acquisition plan (`url`, `docker-run`, or `compose`).

## Output format

Return a concise plan with these sections:

1. `Repository and change signals`
2. `Recommended Argus scanners`
3. `Local development loop`
4. `Inputs, secrets, and permissions`
5. `Excluded scanners and why`
6. `Workflow shape`
7. `Next implementation step`

## Implementation guidance

### For SDK usage (recommended)

Prefer the argus SDK as the primary recommendation:

```bash
pip install pyyaml
python -m argus scan gitleaks opengrep osv --severity-threshold high
```

Or with a config file:

```yaml
# argus.yml
scanners:
  - gitleaks
  - opengrep
  - osv

severity_threshold: high
```

```bash
python -m argus scan --config argus.yml
```

Then add or remove scanners based on the repository signals you found.

### For local development

- Prioritize the scanners that match the changed files and repository risk profile.
- Return a pre-push recommendation that distinguishes:
  - scanners to run now in the local loop via the SDK
  - scanners to keep primarily in CI because they are slower, need hosted permissions, or need runtime targets
- When the repository already has Argus wired into CI, keep the local recommendation aligned with the CI scanner list unless you have a clear reason to trim it for speed.
- Default to the SDK for local runs.

### For GitHub Actions CI (composite actions)

- Use composite actions from `.github/actions/scanner-*` for CI workflows.
- For GHES, use composite actions directly -- they work from public github.com repos.
- If the environment is air-gapped, call out that action references may need to point to an internal mirror.

### For concrete local execution

When the user wants to actually run Argus before push:

```bash
# Install
pip install pyyaml

# Run baseline scanners
python -m argus scan gitleaks opengrep --severity-threshold high

# Add language-specific scanners
python -m argus scan gitleaks opengrep bandit osv --severity-threshold high
```

For users who prefer GitHub Actions locally with `act`, composite actions still work:

```bash
act workflow_dispatch --workflows .github/workflows/local-argus-pre-push.yml --secret GITHUB_TOKEN=local-test-token
```

### For DAST

If `zap` is selected, keep it in a dedicated job unless the user explicitly wants it in the shared workflow. Choose one mode:

- `url` for an already-running target
- `docker-run` for a single container image
- `compose` for a local compose stack
- `api` scan type when an OpenAPI or Swagger spec exists

### For SCN detection

If `scn-detector` is selected, wire it as a separate job with a dedicated `.github/scn-config.yml`. Treat it as a compliance workflow, not a default scanner.

## Verification

Before you finish:

1. Confirm the selected scanners match the repository signals you found.
2. Validate that any referenced workflow inputs actually exist in Argus.
3. Validate edited YAML files.
4. Run the target repository's relevant validation commands.
5. Summarize assumptions that still need human confirmation.

## Escalation points

Stop and ask for confirmation only when:

- CodeQL depends on GitHub Code Security status and you cannot infer it
- ZAP needs a target and none is discoverable
- SCN detection is relevant but no compliance policy or config exists
- the repository has no clear manifests, code, infra, containers, or web surface to justify Argus
