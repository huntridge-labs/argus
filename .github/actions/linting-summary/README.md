# Linting Summary Composite Action

Aggregate linter results into a unified report.

## Overview

This action is designed to run as the final job in your linting workflow. It downloads linter summary artifacts, stitches them together, and — when `scan_statuses` is provided — renders a per-linter pass/fail/skipped table at the top so downstream consumers can distinguish "no findings" from "linter crashed and produced nothing."

## Usage

### Basic (discovery-only)

```yaml
linting-summary:
  runs-on: ubuntu-latest
  needs: [yaml-lint, json-lint, python-lint, javascript-lint, dockerfile-lint, terraform-lint]
  if: always()
  steps:
    - uses: huntridge-labs/argus/.github/actions/linting-summary@1.5.0
```

### With status gating (recommended)

Pass `scan_statuses` — a JSON object mapping linter name to the corresponding job's `result` — to render a pass/fail/skipped table and exit non-zero when any linter did not succeed.

```yaml
linting-summary:
  runs-on: ubuntu-latest
  needs: [yaml-lint, json-lint, python-lint, javascript-lint, dockerfile-lint, terraform-lint]
  if: always()
  steps:
    - uses: huntridge-labs/argus/.github/actions/linting-summary@1.5.0
      with:
        scan_statuses: |
          {
            "yaml": "${{ needs.yaml-lint.result }}",
            "json": "${{ needs.json-lint.result }}",
            "python": "${{ needs.python-lint.result }}",
            "javascript": "${{ needs.javascript-lint.result }}",
            "dockerfile": "${{ needs.dockerfile-lint.result }}",
            "terraform": "${{ needs.terraform-lint.result }}"
          }
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `summary_pattern` | Artifact pattern to match linter summaries | No | `linter-summary-*` |
| `title` | Title for the summary report | No | `Code Quality & Linting Summary` |
| `show_metadata` | Show workflow metadata in the summary | No | `true` |
| `show_stats` | Show statistics about linter results | No | `true` |
| `post_pr_comment` | Post combined summary as PR comment | No | `true` |
| `scan_statuses` | JSON object mapping linter name to job result. When provided, renders a per-linter status table and drives the overall verdict. | No | `''` |
| `fail_on_scanner_failure` | When `"true"` and `scan_statuses` is provided, exit non-zero if any linter is not `success`/`skipped`. | No | `'true'` |
| `comment_marker` | HTML-comment marker used to identify the bot's PR comment so subsequent runs update the same comment. | No | `linting-summary-comment-marker` |

## Outputs

| Output | Description |
|--------|-------------|
| `overall_status` | Derived verdict: `success`, `failure`, or `unknown` (when `scan_statuses` is empty). |
| `failed_count` | Number of linters in `scan_statuses` that did not succeed. |

## Requirements

- Linter jobs must upload summary artifacts named `linter-summary-*`
- Add this job after all linter jobs and use `if: always()`
- For status gating, list every linter job in `needs:` and pass `needs.<job>.result` in `scan_statuses`

## Support

- [Report Issues](https://github.com/huntridge-labs/argus/issues)
- [Contributing Guide](../../CONTRIBUTING.md)
