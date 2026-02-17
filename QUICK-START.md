# Quick start

Kick off the reusable workflow with these minimal snippets.

## Fast SAST (dev branches)

```yaml
name: security-dev
on: [push]

jobs:
  sast:
    uses: huntridge-labs/argus/.github/workflows/reusable-security-hardening.yml@0.2.0
    with:
      scanners: codeql
    permissions:
      contents: read
      security-events: write
```

## Full coverage on PRs

```yaml
name: security-pr
on: [pull_request]

jobs:
  hardening:
    uses: huntridge-labs/argus/.github/workflows/reusable-security-hardening.yml@0.2.0
    with:
      scanners: all
      post_pr_comment: true
    permissions:
      contents: read
      security-events: write
      pull-requests: write
```

## Enforcing security gates

Fail the workflow when vulnerabilities exceed a severity threshold:

```yaml
name: security-enforced
on: [pull_request]

jobs:
  hardening:
    uses: huntridge-labs/argus/.github/workflows/reusable-security-hardening.yml@0.2.0
    with:
      scanners: all
      allow_failure: false        # Enable failure mode
      severity_threshold: high    # Fail on high or critical findings
      post_pr_comment: true
    permissions:
      contents: read
      security-events: write
      pull-requests: write
```

**Severity levels:** `low` → `medium` → `high` → `critical`

## Targeted mix

```yaml
name: security-mix
on: [push]

jobs:
  security:
    uses: huntridge-labs/argus/.github/workflows/reusable-security-hardening.yml@0.2.0
    with:
      scanners: container,infrastructure,gitleaks
      aws_region: us-west-2
    secrets:
      AWS_ACCOUNT_ID: ${{ secrets.AWS_ACCOUNT_ID }}
      GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}  # Required for org repos
      # Required for private GitHub Enterprise Server installations:
      # HARDENING_WORKFLOWS_CHECKOUT_TOKEN: ${{ secrets.HARDENING_WORKFLOWS_CHECKOUT_TOKEN }}
```

## Nightly deep scan

```yaml
name: security-nightly
on:
  schedule:
    - cron: '0 4 * * *'

jobs:
  nightly:
    uses: huntridge-labs/argus/.github/workflows/reusable-security-hardening.yml@0.2.0
    with:
      scanners: all
      post_pr_comment: false
```

## Individual scanner workflows

Use standalone scanners for more granular control:

### Infrastructure scanning

```yaml
name: iac-security
on: [pull_request]

jobs:
  trivy-iac:
    uses: huntridge-labs/argus/.github/workflows/scanner-trivy-iac.yml@0.2.0
    with:
      iac_path: 'infrastructure'
      enable_code_security: true
      fail_on_severity: high  # Fail on high or critical

  checkov:
    uses: huntridge-labs/argus/.github/workflows/scanner-checkov.yml@0.2.0
    with:
      iac_path: 'infrastructure'
      fail_on_severity: medium  # Stricter threshold
```

### Container scanning

```yaml
name: container-security
on:
  push:
    branches: [main]

jobs:
  scan-image:
    uses: huntridge-labs/argus/.github/workflows/scanner-trivy-container.yml@0.2.0
    with:
      image_ref: 'myapp:${{ github.sha }}'
      enable_code_security: true
      fail_on_severity: critical  # Only fail on critical vulnerabilities
```

More examples in the `examples/` directory. See `README.md` for the complete scanner reference.
