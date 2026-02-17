# Python Linter Composite Action

Run Python code quality checks using flake8 and bandit.

## Overview

This action checks Python code for style violations (flake8) and security issues (bandit). It uploads results as artifacts that can be aggregated by the linting summary action.

## Usage

```yaml
- name: Checkout code
  uses: actions/checkout@v6

- name: Run Python linting
  uses: huntridge-labs/argus/.github/actions/linter-python@0.2.0
  with:
    fail_on_issues: false
    max_line_length: '120'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `fail_on_issues` | Fail the job if issues are found | No | `false` |
| `paths` | Paths to lint (space-separated) | No | `.` |
| `python_version` | Python version to use | No | `3.12` |
| `max_line_length` | Maximum line length for flake8 | No | `120` |
| `flake8_ignore` | Flake8 error codes to ignore (comma-separated) | No | `E203,W503` |

## Outputs

| Output | Description |
|--------|-------------|
| `issues_count` | Total number of issues found |
| `flake8_issues` | Number of flake8 style issues |
| `bandit_issues` | Number of bandit security issues |

## Artifacts

- `linter-summary-python`: summary for linting-summary
- `python-lint-results`: raw lint output

## Requirements

- Repository must be checked out before running this action

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [Contributing Guide](../../CONTRIBUTING.md)
