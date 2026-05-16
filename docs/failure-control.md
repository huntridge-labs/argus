<div align=center>

# Failure Control

Configure how workflows handle security findings with severity-based failure thresholds.

</div>

## Overview

By default, security scanners report findings but do not fail. Use `severity_threshold` (SDK) or `fail_on_severity` (composite actions) to enforce quality gates based on severity levels.

## Configuration

### SDK (argus.yml)

Set `severity_threshold` in your config file or via CLI flag:

```yaml
# argus.yml
scanners:
  - gitleaks
  - bandit

severity_threshold: high  # Fail on HIGH or CRITICAL findings
```

```bash
python -m argus scan --config argus.yml --severity-threshold high
```

### Composite Actions (GitHub Actions)

Set the `fail_on_severity` input on each action:

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-bandit@1.0.1
  with:
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

```bash
python -m argus scan codeql --severity-threshold high
```

**Severity mapping:**
- `critical` - Error level
- `high` - Warning level
- `medium` - Note level

### Gitleaks

```bash
python -m argus scan gitleaks --severity-threshold critical
```

**Note:** Any detected secret is considered critical. Setting to `critical` will fail if secrets are found.

### Bandit

```bash
python -m argus scan bandit --severity-threshold medium
```

**Severity levels:** LOW, MEDIUM, HIGH

### Trivy (Container & IaC)

```bash
python -m argus scan trivy-iac --severity-threshold high
```

**Severity levels:** LOW, MEDIUM, HIGH, CRITICAL

### Grype

```bash
python -m argus scan container --severity-threshold critical
```

**Severity levels:** Negligible, Low, Medium, High, Critical

### Checkov

```bash
python -m argus scan checkov --severity-threshold high
```

**Note:** Checkov uses pass/fail checks. Any failed check at or above the threshold will fail.

### ClamAV

```bash
python -m argus scan clamav --severity-threshold critical
```

**Note:** Any malware detection is considered critical.

## Usage Patterns

### Development (Permissive)

Allow developers to iterate without blocking:

```bash
python -m argus scan --config argus.yml --severity-threshold none
```

### Staging (Moderate)

Block HIGH and CRITICAL issues before production:

```bash
python -m argus scan --config argus.yml --severity-threshold high
```

### Production (Strict)

Zero tolerance for vulnerabilities:

```bash
python -m argus scan --config argus.yml --severity-threshold medium
```

### Container Scanning (Critical Only)

Fail only on critical container vulnerabilities:

```bash
python -m argus scan container --severity-threshold critical
```

## Per-Scanner Thresholds

Run scanners individually with different thresholds:

```bash
# Code scanning - high threshold
python -m argus scan codeql bandit --severity-threshold high

# Secret scanning - critical threshold
python -m argus scan gitleaks --severity-threshold critical

# Container scanning - medium threshold
python -m argus scan container --severity-threshold medium
```

For GitHub Actions, configure different thresholds on each composite action step:

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - uses: huntridge-labs/argus/.github/actions/scanner-bandit@1.0.1
        with:
          fail_on_severity: high

      - uses: huntridge-labs/argus/.github/actions/scanner-gitleaks@1.0.1
        with:
          fail_on_severity: critical
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
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

```bash
python -m argus scan --config argus.yml --severity-threshold none
```

### Manual approval

Use GitHub branch protection to require manual review for composite action workflows:

```yaml
# .github/workflows/security.yml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: huntridge-labs/argus/.github/actions/scanner-bandit@1.0.1
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
