# Dockerfile Linter Composite Action

Validate Dockerfiles using Hadolint.

## Overview

This action checks Dockerfiles for best practices and common issues. It uploads results as artifacts that can be aggregated by the linting summary action.

## Usage

```yaml
- name: Checkout code
  uses: actions/checkout@v6

- name: Run Dockerfile linting
  uses: huntridge-labs/argus/.github/actions/linter-dockerfile@1.9.2
  with:
    fail_on_issues: false
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `fail_on_issues` | Fail the job if issues are found | No | `false` |
| `fail_on_tool_error` | Fail the job when the linter tool itself errors (a crash — argus exit code 2), independent of `fail_on_issues`. Tool errors are always surfaced in the job log, status table, and PR comment; this only makes them block. | No | `false` |
| `paths` | Paths to search for Dockerfiles (space-separated) | No | `.` |
| `config_file` | Path to Hadolint configuration file | No | `''` |
| `ignore_rules` | Hadolint rules to ignore (comma-separated) | No | `''` |

## Outputs

| Output | Description |
|--------|-------------|
| `issues_count` | Number of linting issues found |
| `tool_status` | Whether the linter tool ran cleanly: `ok`, or `error` when the tool itself crashed (argus exit code 2). |

## Artifacts

- `linter-summary-dockerfile`: summary for linting-summary
- `dockerfile-lint-results`: raw lint output

## Requirements

- Repository must be checked out before running this action

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [Contributing Guide](../../CONTRIBUTING.md)
