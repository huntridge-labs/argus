# YAML Linter Composite Action

Validate YAML files using yamllint.

## Overview

This action checks YAML syntax and style. It uploads results as artifacts that can be aggregated by the linting summary action.

## Usage

```yaml
- name: Checkout code
  uses: actions/checkout@v6

- name: Run YAML linting
  uses: huntridge-labs/argus/.github/actions/linter-yaml@feat/migrate-to-composite-actions
  with:
    fail_on_issues: false
    config_file: '.yamllint.yml'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `fail_on_issues` | Fail the job if issues are found | No | `false` |
| `config_file` | Path to yamllint configuration file | No | `''` |
| `paths` | Paths to lint (space-separated) | No | `.` |
| `python_version` | Python version to use for yamllint | No | `3.12` |

## Outputs

| Output | Description |
|--------|-------------|
| `issues_count` | Number of linting issues found |

## Artifacts

- `linter-summary-yaml`: summary for linting-summary
- `yaml-lint-results`: raw lint output

## Requirements

- Repository must be checked out before running this action

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [Contributing Guide](../../CONTRIBUTING.md)
