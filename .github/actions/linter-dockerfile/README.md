# Dockerfile Linter Composite Action

Validate Dockerfiles using Hadolint.

## Overview

This action checks Dockerfiles for best practices and common issues. It uploads results as artifacts that can be aggregated by the linting summary action.

## Usage

```yaml
- name: Checkout code
  uses: actions/checkout@v6

- name: Run Dockerfile linting
  uses: huntridge-labs/argus/.github/actions/linter-dockerfile@0.2.2
  with:
    fail_on_issues: false
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `fail_on_issues` | Fail the job if issues are found | No | `false` |
| `paths` | Paths to search for Dockerfiles (space-separated) | No | `.` |
| `config_file` | Path to Hadolint configuration file | No | `''` |
| `ignore_rules` | Hadolint rules to ignore (comma-separated) | No | `''` |

## Outputs

| Output | Description |
|--------|-------------|
| `issues_count` | Number of linting issues found |

## Artifacts

- `linter-summary-dockerfile`: summary for linting-summary
- `dockerfile-lint-results`: raw lint output

## Requirements

- Repository must be checked out before running this action

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [Contributing Guide](../../CONTRIBUTING.md)
