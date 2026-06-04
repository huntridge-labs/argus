# Migration from Reusable Workflows

The 15 `scanner-*.yml` reusable workflows under `.github/workflows/` are deprecated. They still work (they delegate to composite actions internally) but new integrations should use either the **SDK** or **composite actions** directly.

## Why migrate?

Reusable workflows are GitHub-specific and carry restrictions:
- Cannot be called from GitHub Enterprise Server (GHES) unless the callee repo is on the same instance
- Cross-repository `workflow_call` requires the called workflow to be public
- No portability to GitLab CI, Jenkins, Azure DevOps, or local use

The SDK runs anywhere Python runs. Composite actions work on any GitHub instance with github.com access.

## What was deprecated

| Reusable workflow | Replacement (composite action) | Replacement (SDK) |
|---|---|---|
| `scanner-bandit.yml` | `scanner-bandit` | `argus scan bandit` |
| `scanner-checkov.yml` | `scanner-checkov` | `argus scan checkov` |
| `scanner-clamav.yml` | `scanner-clamav` | `argus scan clamav` |
| `scanner-codeql.yml` | `scanner-codeql` | N/A (GitHub-only) |
| `scanner-dependency-review.yml` | `scanner-dependency-review` | N/A (GitHub-only) |
| `scanner-gitleaks.yml` | `scanner-gitleaks` | `argus scan gitleaks` |
| `scanner-grype.yml` | `scanner-container` | `argus scan container` |
| `scanner-opengrep.yml` | `scanner-opengrep` | `argus scan opengrep` |
| `scanner-osv.yml` | `scanner-osv` | `argus scan osv` |
| `scanner-supply-chain.yml` | `scanner-supply-chain` | `argus scan supply-chain` |
| `scanner-syft.yml` | `scanner-syft` | N/A (SBOM-only) |
| `scanner-trivy-container.yml` | `scanner-container` | `argus scan container` |
| `scanner-trivy-iac.yml` | `scanner-trivy-iac` | `argus scan trivy-iac` |
| `scanner-zap.yml` | `scanner-zap` | `argus scan zap` |
| `scanner-zap-from-config.yml` | `scanner-zap` + `parse-zap-config` | `argus scan zap` |

## How to migrate

### Option A: Composite action (GitHub Actions users)

Replace `workflow_call` references with direct action usage.

**Before:**
```yaml
jobs:
  bandit:
    uses: huntridge-labs/argus/.github/workflows/scanner-bandit.yml@1.3.1
    with:
      fail_on_severity: 'high'
      enable_code_security: true
    secrets: inherit
```

**After:**
```yaml
jobs:
  bandit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: huntridge-labs/argus/.github/actions/scanner-bandit@1.3.1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          fail_on_severity: 'high'
          enable_code_security: 'true'
```

Key differences:
- You provide `runs-on` and `permissions` (the reusable workflow handled these)
- Inputs that were `boolean` in the workflow become `string` in the action (`true` not `true`)
- `GITHUB_TOKEN` is passed via `env`, not `secrets: inherit`

### Option B: SDK (any CI platform)

Replace the entire workflow job with a direct SDK invocation.

**Before (reusable workflow):**
```yaml
jobs:
  bandit:
    uses: huntridge-labs/argus/.github/workflows/scanner-bandit.yml@1.3.1
    with:
      fail_on_severity: 'high'
    secrets: inherit
```

**After (SDK):**
```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install pyyaml
      - run: |
          python -m argus scan bandit \
            --severity-threshold high \
            --format terminal --format sarif \
            --output-dir ./argus-results
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-reports
          path: ./argus-results/
```

The SDK approach works identically on GitLab CI, Jenkins, Azure DevOps, or locally. See `examples/workflows/` for platform-specific examples.

### Multiple scanners at once

The SDK can run multiple scanners in a single invocation:

```yaml
- run: |
    python -m argus scan bandit gitleaks osv \
      --severity-threshold high \
      --format terminal --format sarif --format markdown \
      --output-dir ./argus-results
```

Or configure everything in `argus.yml`:

```yaml
scanners:
  - bandit
  - gitleaks
  - osv
  - opengrep
fail_on_severity: high
reporters:
  - terminal
  - sarif
  - markdown
```

Then run: `python -m argus scan --config argus.yml`

## Input mapping reference

Common reusable workflow inputs and their equivalents:

| Workflow input | Composite action input | SDK flag |
|---|---|---|
| `fail_on_severity` | `fail_on_severity` | `--severity-threshold` |
| `enable_code_security` | `enable_code_security` | N/A (upload SARIF separately) |
| `post_pr_comment` | `post_pr_comment` | N/A (use `comment-pr` action) |
| `scan_path` | `scan_path` | `--path` |
| `python_version` | N/A (action handles setup) | N/A (user installs Python) |
