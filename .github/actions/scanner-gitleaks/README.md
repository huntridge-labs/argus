# Gitleaks Secrets Scanner Composite Action

Detect hardcoded secrets, passwords, and API keys in your repository using [Gitleaks](https://gitleaks.io/).

## Overview

This composite action runs Gitleaks to scan for secrets across:
- Git history (all commits)
- Current files
- Uncommitted changes

It detects 200+ types of secrets including:
- AWS credentials
- API keys and tokens
- Database passwords
- Private keys
- OAuth tokens
- And many more...

## Usage

### Basic Example

```yaml
- name: Checkout code
  uses: actions/checkout@v6
  with:
    fetch-depth: 0  # Required for full history scan

- name: Run Gitleaks Scanner
  uses: huntridge-labs/argus/.github/actions/scanner-gitleaks@0.2.1
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}  # Optional
  with:
    fail_on_severity: 'none'
```

### Advanced Example

```yaml
- name: Scan for secrets with strict settings
  uses: huntridge-labs/argus/.github/actions/scanner-gitleaks@0.2.1
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}
  with:
    enable_code_security: true
    post_pr_comment: true
    gitleaks_enable_comments: true
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `post_pr_comment` | Post results as PR comment | No | `true` |
| `enable_code_security` | Upload SARIF to GitHub Security tab | No | `false` |
| `fail_on_severity` | Fail if secrets are found (Gitleaks doesn't support severity filtering; any value other than `none` fails if secrets detected) | No | `none` |
| `gitleaks_enable_comments` | Enable Gitleaks PR comments | No | `true` |

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GITHUB_TOKEN` | GitHub token for API access | Yes |
| `GITLEAKS_LICENSE` | License key for Gitleaks organization features | No |

> **Note**: `GITLEAKS_LICENSE` is only needed for organization-level features. The scanner works without it but may have reduced functionality. Obtain a license from [gitleaks.io](https://gitleaks.io).

## Outputs

| Output | Description |
|--------|-------------|
| `secrets_count` | Number of secrets detected |
| `has_secrets` | Whether secrets were found (`true`/`false`) |

## Features

- ✅ Scans entire Git history
- ✅ 200+ secret patterns detected
- ✅ SARIF output for GitHub Security
- ✅ JSON and CSV reports
- ✅ PR comments with findings
- ✅ Baseline support (ignore known secrets)

## Reports Generated

The action generates multiple report formats:
- `gitleaks-report.sarif` - GitHub Security integration
- `gitleaks-report.json` - Detailed JSON with findings
- `gitleaks-report.csv` - CSV format for analysis

All reports are uploaded as artifacts: `gitleaks-reports`

## Examples

### Full History Scan (Recommended)

```yaml
- name: Checkout with full history
  uses: actions/checkout@v6
  with:
    fetch-depth: 0  # Scan all commits

- uses: huntridge-labs/argus/.github/actions/scanner-gitleaks@0.2.1
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Shallow Scan (Faster, Less Thorough)

```yaml
- name: Checkout latest only
  uses: actions/checkout@v6
  # Default fetch-depth: 1

- uses: huntridge-labs/argus/.github/actions/scanner-gitleaks@0.2.1
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Fail on Any Secret

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-gitleaks@0.2.1
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    fail_on_severity: 'high'  # Any non-'none' value fails on secrets
```

## Important Notes

### Fetch Depth Matters

For comprehensive scanning:
```yaml
uses: actions/checkout@v6
with:
  fetch-depth: 0  # Full history
```

Without full history, Gitleaks only scans recent commits.

### Severity Filtering

Gitleaks treats all secrets as critical. The `fail_on_severity` input is simplified:
- `none` - Report but don't fail
- Any other value - Fail if secrets found

### License Key

The `GITLEAKS_LICENSE` is optional but recommended for organizations:
- Enables organization-level features
- Provides enhanced scanning capabilities
- Obtain from [gitleaks.io](https://gitleaks.io)

## Handling False Positives

### Using .gitleaksignore

Create a `.gitleaksignore` file in your repository root:
```
# Ignore specific findings
abc123def456...  # Finding hash from report

# Ignore patterns (not recommended)
test-data.json
```

### Using Baseline

Generate a baseline to ignore existing secrets:
```bash
gitleaks detect --baseline-path .gitleaksbaseline --report-path gitleaks-report.json
```

## Requirements

- Repository must be checked out before running this action
- `GITHUB_TOKEN` environment variable (automatically available)
- Git history available (use `fetch-depth: 0` for full scan)

## Related Documentation

- [Gitleaks Documentation](https://github.com/gitleaks/gitleaks)
- [Secret Scanning Best Practices](https://docs.github.com/en/code-security/secret-scanning)
- [Complete Example Workflow](../../examples/composite-actions-example.yml)

## Troubleshooting

### No Secrets Found (Expected Secrets)

If Gitleaks doesn't find expected secrets:
- Check Git history depth (`fetch-depth: 0`)
- Verify secret patterns match Gitleaks rules
- Review `.gitleaksignore` for exclusions

### Too Many False Positives

If you get false positives:
- Use `.gitleaksignore` to suppress specific findings
- Create a baseline with existing secrets
- Consider custom configuration

### License Key Issues

If license key fails:
- Verify `GITLEAKS_LICENSE` secret is set correctly
- Check license is valid and not expired
- Scanner still works without license (reduced features)

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [Gitleaks Community](https://github.com/gitleaks/gitleaks/discussions)
- [View Changelog](../../CHANGELOG.md)
