# YAML Linter Composite Action

Validate YAML files using yamllint.

## Overview

This action checks YAML syntax and style. It uploads results as artifacts that can be aggregated by the linting summary action.

## Usage

```yaml
- name: Checkout code
  uses: actions/checkout@v6

- name: Run YAML linting
  uses: huntridge-labs/argus/.github/actions/linter-yaml@1.11.0
  with:
    fail_on_issues: false
    config_file: '.yamllint.yml'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `fail_on_issues` | Fail the job if issues are found | No | `false` |
| `fail_on_tool_error` | Fail the job when the linter tool itself errors (a crash — argus exit code 2), independent of `fail_on_issues`. Tool errors are always surfaced in the job log, status table, and PR comment; this only makes them block. | No | `false` |
| `config_file` | Path to yamllint configuration file | No | `''` |
| `paths` | Paths to lint (space-separated) | No | `.` |
| `python_version` | Python version to use for yamllint | No | `3.12` |

## Outputs

| Output | Description |
|--------|-------------|
| `issues_count` | Number of linting issues found |
| `tool_status` | Whether the linter tool ran cleanly: `ok`, or `error` when the tool itself crashed (argus exit code 2). |

## Artifacts

- `linter-summary-yaml`: summary for linting-summary
- `yaml-lint-results`: raw lint output

## Requirements

- Repository must be checked out before running this action

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [Contributing Guide](../../CONTRIBUTING.md)
