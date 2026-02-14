# Linting Summary Composite Action

Aggregate linter results into a unified report.

## Overview

This action is designed to run as the final job in your linting workflow. It downloads linter summary artifacts and combines them into a single GitHub Step Summary and optional PR comment.

## Usage

```yaml
linting-summary:
  runs-on: ubuntu-latest
  needs: [yaml-lint, json-lint, python-lint, javascript-lint, dockerfile-lint, terraform-lint]
  if: always()
  steps:
    - uses: huntridge-labs/argus/.github/actions/linting-summary@feat/migrate-to-composite-actions
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `summary_pattern` | Artifact pattern to match linter summaries | No | `linter-summary-*` |
| `title` | Title for the summary report | No | `Code Quality & Linting Summary` |
| `show_metadata` | Show workflow metadata in the summary | No | `true` |
| `show_stats` | Show statistics about linter results | No | `true` |
| `post_pr_comment` | Post combined summary as PR comment | No | `true` |

## Outputs

This action does not expose outputs.

## Requirements

- Linter jobs must upload summary artifacts named `linter-summary-*`
- Add this job after all linter jobs and use `if: always()`

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [Contributing Guide](../../CONTRIBUTING.md)
