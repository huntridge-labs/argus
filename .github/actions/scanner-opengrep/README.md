# OpenGrep Scanner Composite Action

Run OpenGrep SAST analysis and generate reports.

## Overview

This composite action runs OpenGrep, a pattern-based static analysis tool, to detect security issues across multiple languages. Results integrate with the security summary aggregator.

## Usage

### Basic Example

```yaml
- name: Checkout code
  uses: actions/checkout@v6

- name: Run OpenGrep
  uses: huntridge-labs/argus/.github/actions/scanner-opengrep@feat/migrate-to-composite-actions
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    config: 'auto'
    fail_on_severity: 'high'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `config` | OpenGrep config (auto, p/default, p/security-audit, or path to custom rules) | No | `auto` |
| `paths` | Paths to scan (space-separated) | No | `.` |
| `enable_code_security` | Upload SARIF to GitHub Security tab | No | `false` |
| `fail_on_severity` | Fail at or above severity: none, low, medium, high | No | `none` |

## Outputs

| Output | Description |
|--------|-------------|
| `error_count` | Number of error severity findings |
| `warning_count` | Number of warning severity findings |
| `info_count` | Number of info severity findings |
| `total_count` | Total number of findings |

## Artifacts

- `opengrep-reports`: SARIF and JSON reports
- `scanner-summary-opengrep`: summary artifact used by security-summary

## Requirements

- Repository must be checked out before running this action
- `GITHUB_TOKEN` environment variable

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [Contributing Guide](../../CONTRIBUTING.md)
