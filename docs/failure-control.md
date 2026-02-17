<div align=center>

# Failure Control

Configure how workflows handle security findings with severity-based failure thresholds.

</div>

## Overview

By default, security scanners will report findings but not fail the workflow. Use `fail_on_severity` to enforce quality gates based on severity levels.

## Configuration

Set the `fail_on_severity` input to specify the minimum severity that should fail the workflow:

```yaml
with:
  scanners: all
  fail_on_severity: high  # Fail on HIGH or CRITICAL findings
```

## Severity Levels

Most scanners use this severity hierarchy:

- `critical` - Highest severity only
- `high` - HIGH and CRITICAL findings
- `medium` - MEDIUM, HIGH, and CRITICAL findings
- `low` - LOW, MEDIUM, HIGH, and CRITICAL findings
- `none` - Never fail (default)

## Scanner-Specific Behavior

### CodeQL

```yaml
with:
  scanners: codeql
  fail_on_severity: high
```

**Severity mapping:**
- `critical` - Error level
- `high` - Warning level
- `medium` - Note level

### Gitleaks

```yaml
with:
  scanners: gitleaks
  fail_on_severity: critical
```

**Note:** Any detected secret is considered critical. Setting to `critical` will fail if secrets are found.

### Bandit

```yaml
with:
  scanners: bandit
  fail_on_severity: medium
```

**Severity levels:** LOW, MEDIUM, HIGH

### Trivy (Container & IaC)

```yaml
with:
  scanners: trivy-container
  fail_on_severity: high
```

**Severity levels:** LOW, MEDIUM, HIGH, CRITICAL

### Grype

```yaml
with:
  scanners: grype
  fail_on_severity: critical
```

**Severity levels:** Negligible, Low, Medium, High, Critical

### Checkov

```yaml
with:
  scanners: checkov
  fail_on_severity: high
```

**Note:** Checkov uses pass/fail checks. Any failed check at or above the threshold will fail the workflow.

### ClamAV

```yaml
with:
  scanners: clamav
  fail_on_severity: critical
```

**Note:** Any malware detection is considered critical.

## Usage Patterns

### Development Branch (Permissive)

Allow developers to iterate without blocking:

```yaml
on:
  pull_request:
    branches: [develop]

jobs:
  security:
    uses: huntridge-labs/argus/.github/workflows/security-scan.yml@0.2.1
    with:
      scanners: all
      fail_on_severity: none  # Report only
      post_pr_comment: true
```

### Staging Branch (Moderate)

Block HIGH and CRITICAL issues before production:

```yaml
on:
  pull_request:
    branches: [staging]

jobs:
  security:
    uses: huntridge-labs/argus/.github/workflows/security-scan.yml@0.2.1
    with:
      scanners: all
      fail_on_severity: high
      post_pr_comment: true
```

### Production Branch (Strict)

Zero tolerance for vulnerabilities:

```yaml
on:
  pull_request:
    branches: [main]

jobs:
  security:
    uses: huntridge-labs/argus/.github/workflows/security-scan.yml@0.2.1
    with:
      scanners: all
      fail_on_severity: medium
      enable_code_security: true
```

### Scheduled Scans (Monitoring)

Regular scans for visibility without blocking:

```yaml
on:
  schedule:
    - cron: '0 2 * * 1'  # Weekly Monday at 2 AM

jobs:
  security:
    uses: huntridge-labs/argus/.github/workflows/security-scan.yml@0.2.1
    with:
      scanners: all
      fail_on_severity: none
      enable_code_security: true
      post_pr_comment: false
```

### Container Scanning (Critical Only)

Fail only on critical container vulnerabilities:

```yaml
with:
  scanners: trivy-container,grype
  image_ref: 'myapp:latest'
  fail_on_severity: critical
```

## Per-Scanner Thresholds

Configure different thresholds for different scanners by running them in separate jobs:

```yaml
jobs:
  code-scan:
    uses: huntridge-labs/argus/.github/workflows/security-scan.yml@0.2.1
    with:
      scanners: codeql,bandit
      fail_on_severity: high

  secret-scan:
    uses: huntridge-labs/argus/.github/workflows/security-scan.yml@0.2.1
    with:
      scanners: gitleaks
      fail_on_severity: critical

  container-scan:
    uses: huntridge-labs/argus/.github/workflows/security-scan.yml@0.2.1
    with:
      scanners: trivy-container
      image_ref: 'myapp:latest'
      fail_on_severity: medium
```

## Exit Codes

When a workflow fails due to severity threshold:

- Exit code: `1`
- Workflow status: Failed ❌
- GitHub check: Failure
- Blocks merging if required

When findings exist but below threshold:

- Exit code: `0`
- Workflow status: Success ✅
- GitHub check: Pass
- Findings visible in Security tab

## Best Practices

1. **Start permissive**, then gradually increase strictness
2. **Use different thresholds** for different branches
3. **Enable Security tab** for visibility regardless of failures
4. **Review findings regularly** even when workflows pass
5. **Document exceptions** when lowering thresholds temporarily
6. **Set critical threshold** for secrets and malware detection
7. **Test threshold changes** on feature branches first

## Overriding Failures

If you need to proceed despite findings:

### Bypass for specific PR

Add `[skip security]` to commit message (if configured in workflow).

### Temporarily disable

```yaml
with:
  scanners: all
  fail_on_severity: none  # Temporarily permissive
```

### Manual approval

Use GitHub branch protection to require manual review:

```yaml
# .github/workflows/security.yml
jobs:
  security:
    uses: huntridge-labs/argus/.github/workflows/security-scan.yml@0.2.1
    with:
      fail_on_severity: high
    continue-on-error: true  # Don't block merge

  approval:
    needs: security
    if: failure()
    runs-on: ubuntu-latest
    steps:
      - name: Request manual review
        run: echo "Security scan failed. Manual review required."
```

## Troubleshooting

### Too many failures

**Problem:** Workflow fails constantly on existing code

**Solution:**
- Start with `fail_on_severity: critical`
- Fix critical issues first
- Gradually increase to `high`, then `medium`

### Inconsistent failures

**Problem:** Same code fails sometimes but not others

**Solution:**
- Check if scanner databases updated
- Review scanner-specific configuration
- Verify consistent scanner versions

### False positives causing failures

**Problem:** Known false positives block workflow

**Solution:**
- Use scanner-specific suppression files
- Configure exceptions in scanner config
- Consider per-scanner jobs with different thresholds
