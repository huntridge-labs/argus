# Dependency Review Scanner

Scans pull request dependency changes for vulnerabilities and license compliance using [GitHub's dependency-review-action](https://github.com/actions/dependency-review-action).

> **Composite-only by design.** Dependency-review has no `argus.scanners.dependency_review` SDK module and won't get one. The whole feature is a thin client over GitHub's `/repos/{owner}/{repo}/dependency-graph/compare/{basehead}` API — the intelligence is server-side, the data only exists for repos with GitHub's Dependency Graph enabled, and the comparison only makes sense in a `pull_request` event context. There's no off-platform shape worth porting. See [`.ai/decisions.yaml` ADR-021](../../../.ai/decisions.yaml) for the SDK-vs-composite-action boundary rule.

## Overview

- Compares dependency changes between PR base and head via the GitHub Dependency Graph API
- Detects newly introduced vulnerable dependencies
- Checks license compliance against allow/deny policies
- **PR-only**: Gracefully skips on non-PR events with a warning annotation

## Usage

```yaml
- uses: actions/checkout@v6
- uses: huntridge-labs/argus/.github/actions/scanner-dependency-review@1.3.0
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    vulnerability_check: 'true'
    license_check: 'true'
    deny_licenses: 'GPL-3.0'
    fail_on_severity: 'high'
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `vulnerability_check` | Enable vulnerability checking | `'true'` |
| `license_check` | Enable license compliance checking | `'false'` |
| `allow_licenses` | Comma-separated SPDX identifiers to allow | `''` |
| `deny_licenses` | Comma-separated SPDX identifiers to deny | `''` |
| `enable_code_security` | Upload results to GitHub Security tab | `'false'` |
| `post_pr_comment` | Post results as PR comment | `'false'` |
| `fail_on_severity` | Fail threshold: `none`, `low`, `medium`, `high`, `critical` | `'none'` |
| `job_id` | Job ID for artifact naming | `github.job` |

## Outputs

| Output | Description |
|--------|-------------|
| `critical_count` | Number of critical severity findings |
| `high_count` | Number of high severity findings |
| `medium_count` | Number of medium severity findings |
| `low_count` | Number of low severity findings |
| `license_violations` | Number of license policy violations |
| `total_count` | Total vulnerability count |
| `scan_status` | `clean`, `vulnerable`, or `skipped` |

## Non-PR Behavior

When triggered on non-PR events (push, schedule, etc.), this action:
1. Emits a warning annotation explaining the skip
2. Uploads a zero-count summary artifact (for security-summary compatibility)
3. Exits cleanly with status code 0

For dependency scanning outside of PRs, use [scanner-osv](../scanner-osv/).

## Artifacts

- `dependency-review-reports-{job_id}` — Parsed vulnerability and license results
- `scanner-summary-dependency-review-{job_id}` — Markdown summary for security-summary aggregation

## Companion Scanner

Use alongside [scanner-osv](../scanner-osv/) for comprehensive dependency scanning that works on any event trigger and is GHES-compatible.
