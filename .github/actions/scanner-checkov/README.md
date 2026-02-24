# Checkov Scanner Composite Action

Run Checkov infrastructure-as-code security scanning and generate reports.

## Overview

This composite action analyzes IaC for security misconfigurations using Checkov. It supports multiple frameworks including Terraform, CloudFormation, Kubernetes, and more. Results integrate with the security summary aggregator.

## Usage

### Basic Example

```yaml
- name: Checkout code
  uses: actions/checkout@v6

- name: Run Checkov
  uses: huntridge-labs/argus/.github/actions/scanner-checkov@0.3.0
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    iac_path: 'infrastructure'
    framework: 'terraform'
    fail_on_severity: 'high'
```

### With Prisma Cloud API Key (Enhanced Features)

```yaml
- name: Checkout code
  uses: actions/checkout@v6

- name: Run Checkov with API Key
  uses: huntridge-labs/argus/.github/actions/scanner-checkov@0.3.0
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    iac_path: 'infrastructure'
    framework: 'terraform'
    api_key: ${{ secrets.BC_API_KEY }}  # Enables severity scoring
    fail_on_severity: 'high'
```

### Multiple Frameworks

```yaml
strategy:
  matrix:
    config:
      - path: 'terraform'
        framework: 'terraform'
      - path: 'kubernetes'
        framework: 'kubernetes'
steps:
  - uses: actions/checkout@v6
  - uses: huntridge-labs/argus/.github/actions/scanner-checkov@0.3.0
    env:
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    with:
      iac_path: ${{ matrix.config.path }}
      framework: ${{ matrix.config.framework }}
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `iac_path` | Relative path to the IaC directory to scan | No | `infrastructure` |
| `framework` | IaC framework (terraform, cloudformation, kubernetes, etc.) | No | `terraform` |
| `enable_code_security` | Upload SARIF to GitHub Security tab | No | `false` |
| `post_pr_comment` | Post results as PR comment | No | `true` |
| `fail_on_severity` | Fail at or above severity: none, low, medium, high, critical. Note: Checkov doesn't natively support severity filtering; any value other than "none" will fail on any failed check. | No | `none` |
| `api_key` | Prisma Cloud API key for severity scoring and enhanced features | No | `''` |

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GITHUB_TOKEN` | GitHub token for API access | Yes |
| `BC_API_KEY` | Alternative way to provide Prisma Cloud API key | No |

> **Note**: The API key can be provided via the `api_key` input or `BC_API_KEY` environment variable. Without an API key, severity information will not be available, but all other functionality works normally.

## Outputs

| Output | Description |
|--------|-------------|
| `critical_count` | Number of critical severity findings |
| `high_count` | Number of high severity findings |
| `medium_count` | Number of medium severity findings |
| `low_count` | Number of low severity findings |
| `total_count` | Total number of failed checks |
| `passed_count` | Number of passed checks |
| `has_iac` | Whether IaC directory was found and scanned |

## Artifacts

- `checkov-reports`: SARIF, JSON, and text reports
- `scanner-summary-checkov`: summary artifact used by security-summary

## Supported Frameworks

Checkov supports:
- Terraform
- CloudFormation
- Kubernetes
- Helm
- Serverless
- ARM Templates
- Dockerfile
- Docker Compose
- And many more...

## Requirements

- Repository must be checked out before running this action
- `GITHUB_TOKEN` environment variable
- IaC directory must exist (action will skip if not found)

## Example with Security Summary

```yaml
jobs:
  checkov-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: huntridge-labs/argus/.github/actions/scanner-checkov@0.3.0
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          iac_path: 'terraform'
          fail_on_severity: 'high'

  security-summary:
    runs-on: ubuntu-latest
    needs: [checkov-scan]
    if: always()
    steps:
      - uses: huntridge-labs/argus/.github/actions/security-summary@0.3.0
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Notes

- Checkov does not natively support severity-based filtering like other scanners
- Setting `fail_on_severity` to anything other than "none" will cause the job to fail if any check fails
- The action parses severity information from Checkov's JSON output when available
- **Severity information requires a Prisma Cloud API key** - without it, all findings are grouped as "high" severity
- Results are organized by severity in the summary for easier review
- Works perfectly without an API key - just with less detailed severity classification

## Prisma Cloud Integration

The `api_key` input enables integration with Prisma Cloud (formerly Bridgecrew) for:
- ✅ Detailed severity scoring (Critical, High, Medium, Low)
- ✅ Advanced risk prioritization
- ✅ Centralized dashboard and reporting
- ✅ Policy enforcement rules
- ✅ Custom compliance frameworks

Without an API key:
- ✅ Full IaC scanning still works
- ✅ All policy checks run normally
- ✅ SARIF and JSON reports generated
- ❌ No severity classification (all findings shown as one group)
- ❌ No centralized platform features

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [Contributing Guide](../../../CONTRIBUTING.md)
