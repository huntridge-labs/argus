# Trivy IaC Scanner Composite Action

Scan infrastructure-as-code (IaC) for security misconfigurations using [Trivy](https://trivy.dev/).

## Overview

This composite action runs Trivy's IaC scanner to detect security issues in:
- **Terraform** configurations
- **CloudFormation** templates
- **Kubernetes** manifests
- **Docker Compose** files
- **Ansible** playbooks
- Other IaC formats

## Usage

### Basic Example

```yaml
- name: Checkout code
  uses: actions/checkout@v6

- name: Run Trivy IaC Scanner
  uses: huntridge-labs/argus/.github/actions/scanner-trivy-iac@feat/migrate-to-composite-actions
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    iac_path: 'infrastructure'
    fail_on_severity: 'high'
```

### Advanced Example

```yaml
- name: Scan Terraform with strict settings
  uses: huntridge-labs/argus/.github/actions/scanner-trivy-iac@feat/migrate-to-composite-actions
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    iac_path: 'terraform'
    enable_code_security: true
    post_pr_comment: true
    fail_on_severity: 'critical'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `iac_path` | Relative path to IaC directory to scan | No | `infrastructure` |
| `enable_code_security` | Upload SARIF to GitHub Security tab | No | `false` |
| `post_pr_comment` | Post results as PR comment | No | `true` |
| `fail_on_severity` | Fail on severity: `none`, `low`, `medium`, `high`, `critical` | No | `none` |

## Outputs

| Output | Description |
|--------|-------------|
| `critical_count` | Number of critical severity misconfigurations |
| `high_count` | Number of high severity misconfigurations |
| `medium_count` | Number of medium severity misconfigurations |
| `low_count` | Number of low severity misconfigurations |
| `total_count` | Total number of misconfigurations |
| `has_iac` | Whether IaC directory was found (`true`/`false`) |

## Features

- ✅ Multi-format support (Terraform, K8s, CloudFormation, etc.)
- ✅ SARIF output for GitHub Security
- ✅ JSON and text reports
- ✅ Configurable severity thresholds
- ✅ PR comments with findings
- ✅ Artifacts uploaded automatically

## Reports Generated

The action generates multiple report formats:
- `trivy-results.sarif` - GitHub Security integration
- `trivy-results.json` - Detailed JSON for parsing
- `trivy-results.txt` - Human-readable table

All reports are uploaded as artifacts: `trivy-iac-scan-results`

## Examples

### Scan Multiple IaC Directories

Use a matrix strategy:

```yaml
jobs:
  trivy-iac:
    strategy:
      matrix:
        iac_path: ['terraform', 'kubernetes', 'cloudformation']
    steps:
      - uses: actions/checkout@v6
      - uses: huntridge-labs/argus/.github/actions/scanner-trivy-iac@feat/migrate-to-composite-actions
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          iac_path: ${{ matrix.iac_path }}
```

### Fail on High Severity Only

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-trivy-iac@feat/migrate-to-composite-actions
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    fail_on_severity: 'high'  # Fails on HIGH and CRITICAL
```

## Requirements

- Repository must be checked out before running this action
- `GITHUB_TOKEN` environment variable (automatically available in workflows)
- Target directory must exist (action skips if not found)

## Related Documentation

- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Container Scanning Docs](../../docs/container-scanning.md)
- [Complete Example Workflow](../../examples/composite-actions-example.yml)

## Troubleshooting

### Directory Not Found

If you see "Directory not found. Skipping Trivy IaC scan", check:
- The `iac_path` input matches your repository structure
- The directory contains IaC files

### No Results Generated

If scans complete but no results appear:
- Verify the directory contains valid IaC files
- Check the action logs for Trivy output
- Ensure Trivy supports your IaC format

### SARIF Upload Fails

If Security tab upload fails:
- Ensure `enable_code_security: true` is set
- Verify GitHub Advanced Security is enabled for your repository
- Check that `security-events: write` permission is granted

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [View Changelog](../../CHANGELOG.md)
- [Contributing Guide](../../CONTRIBUTING.md)
