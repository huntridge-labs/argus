# JSON Linter Composite Action

Validate JSON files using jsonlint.

## Overview

This action checks JSON syntax across your repository. It uploads results as artifacts that can be aggregated by the linting summary action.

## Usage

```yaml
- name: Checkout code
  uses: actions/checkout@v6

- name: Run JSON validation
  uses: huntridge-labs/argus/.github/actions/linter-json@1.9.1
  with:
    fail_on_issues: false
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `fail_on_issues` | Fail the job if issues are found | No | `false` |
| `fail_on_tool_error` | Fail the job when the linter tool itself errors (a crash — argus exit code 2), independent of `fail_on_issues`. Tool errors are always surfaced in the job log, status table, and PR comment; this only makes them block. | No | `false` |
| `paths` | Paths to search for JSON files (space-separated) | No | `.` |
| `node_version` | Node.js version to use | No | `20` |

## Outputs

| Output | Description |
|--------|-------------|
| `issues_count` | Number of validation issues found |
| `tool_status` | Whether the linter tool ran cleanly: `ok`, or `error` when the tool itself crashed (argus exit code 2). |

## Artifacts

- `linter-summary-json`: summary for linting-summary
- `json-lint-results`: raw lint output

## Requirements

- Repository must be checked out before running this action

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [Contributing Guide](../../CONTRIBUTING.md)
