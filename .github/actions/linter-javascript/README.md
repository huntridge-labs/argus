# JavaScript Linter Composite Action

Run JavaScript code quality checks using syntax validation and JSHint.

## Overview

This action validates JavaScript files for syntax errors and code quality issues. It uploads results as artifacts that can be aggregated by the linting summary action.

## Usage

```yaml
- name: Checkout code
  uses: actions/checkout@v6

- name: Run JavaScript linting
  uses: huntridge-labs/argus/.github/actions/linter-javascript@1.12.1
  with:
    fail_on_issues: false
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `fail_on_issues` | Fail the job if issues are found | No | `false` |
| `fail_on_tool_error` | Fail the job when the linter tool itself errors (a crash — argus exit code 2), independent of `fail_on_issues`. Tool errors are always surfaced in the job log, status table, and PR comment; this only makes them block. | No | `false` |
| `paths` | Paths to search for JavaScript files (space-separated) | No | `.` |
| `node_version` | Node.js version to use | No | `20` |

## Outputs

| Output | Description |
|--------|-------------|
| `issues_count` | Total number of issues found |
| `tool_status` | Whether the linter tool ran cleanly: `ok`, or `error` when the tool itself crashed (argus exit code 2). |
| `syntax_issues` | Number of syntax errors |
| `jshint_issues` | Number of JSHint code quality issues |

## Artifacts

- `linter-summary-javascript`: summary for linting-summary
- `javascript-lint-results`: raw lint output

## Requirements

- Repository must be checked out before running this action

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [Contributing Guide](../../CONTRIBUTING.md)
