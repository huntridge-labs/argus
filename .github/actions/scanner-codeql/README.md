# CodeQL Scanner Composite Action

Run GitHub CodeQL SAST analysis for a single language and generate reports.

## Overview

This composite action analyzes code for security vulnerabilities using CodeQL. Run it once per language (use a matrix for multiple languages). Results integrate with the security summary aggregator.

## Usage

### Basic Example

```yaml
- name: Checkout code
  uses: actions/checkout@v6

- name: Run CodeQL (Python)
  uses: huntridge-labs/argus/.github/actions/scanner-codeql@0.2.2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    language: 'python'
    fail_on_severity: 'high'
```

### Matrix Example

```yaml
strategy:
  matrix:
    language: [python, javascript]
steps:
  - uses: actions/checkout@v6
  - uses: huntridge-labs/argus/.github/actions/scanner-codeql@0.2.2
    env:
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    with:
      language: ${{ matrix.language }}
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `language` | Language to analyze (python, javascript, go, java, csharp, cpp, ruby, swift, etc.) | Yes | - |
| `config_file` | Path to CodeQL configuration file | No | `''` |
| `enable_code_security` | Upload SARIF to GitHub Security tab | No | `false` |
| `fail_on_severity` | Fail at or above severity: none, low, medium, high, critical | No | `none` |
| `setup_python_version` | Python version to use for Python analysis | No | `3.12` |
| `setup_node_version` | Node.js version to use for JavaScript analysis | No | `22` |

## Outputs

| Output | Description |
|--------|-------------|
| `critical_count` | Number of critical severity findings |
| `high_count` | Number of high severity findings |
| `medium_count` | Number of medium severity findings |
| `low_count` | Number of low severity findings |
| `total_count` | Total number of findings |

## Artifacts

- `codeql-reports-<language>`: SARIF and supporting reports
- `scanner-summary-codeql-<language>`: summary artifact used by security-summary

## Requirements

- Repository must be checked out before running this action
- `GITHUB_TOKEN` environment variable
- CodeQL supports a single language per run; use a matrix for multiple languages

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [Contributing Guide](../../CONTRIBUTING.md)
