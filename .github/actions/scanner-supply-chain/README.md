# Supply Chain Security Scanner

Scans GitHub Actions workflows for security vulnerabilities using [zizmor](https://docs.zizmor.sh/) and optionally [actionlint](https://github.com/rhysd/actionlint).

## Overview

- Detects template injection, unpinned actions, excessive permissions, impostor commits, credential leakage, cache poisoning, and more
- Uses the [official zizmor-action](https://github.com/zizmorcore/zizmor-action) for SARIF integration
- Optionally runs actionlint for workflow syntax validation
- Supports SARIF upload to GitHub Security tab
- Works on any event trigger (push, PR, schedule, workflow_dispatch)

## Usage

```yaml
- uses: actions/checkout@v6
- uses: huntridge-labs/argus/.github/actions/scanner-supply-chain@1.5.0
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    scan_path: '.'
    fail_on_severity: 'high'
    enable_code_security: true
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `github_token` | GitHub token for API access (needed for online audits) | *required* |
| `scan_path` | Path to scan for workflow YAML files | `.` |
| `fail_on_severity` | Fail threshold: `none`, `low`, `medium`, `high` | `'none'` |
| `enable_code_security` | Upload SARIF to GitHub Security tab | `'false'` |
| `post_pr_comment` | Post results as PR comment | `'false'` |
| `persona` | Zizmor audit strictness: `regular`, `pedantic`, `auditor` | `'regular'` |
| `zizmor_config` | Path to zizmor configuration file | `''` |
| `run_actionlint` | Also run actionlint for syntax checking | `'true'` |
| `job_id` | Job ID for artifact naming | `github.job` |

## Outputs

| Output | Description |
|--------|-------------|
| `high_count` | Number of high severity findings |
| `medium_count` | Number of medium severity findings |
| `low_count` | Number of low severity findings |
| `info_count` | Number of informational findings |
| `total_count` | Total finding count |
| `scan_status` | `clean` or `findings` |

## What It Detects

**Zizmor** (33 audit rules) covers:
- Template injection via user-controlled inputs
- Unpinned action references (supply chain risk)
- Excessive workflow permissions
- Impostor commits in fork networks
- Cache poisoning vectors
- Credential persistence and leakage
- Dangerous workflow triggers (`pull_request_target`, `workflow_run`)
- Secrets inheritance risks

**Actionlint** covers:
- Workflow YAML syntax errors
- Invalid runner labels
- Deprecated workflow commands
- ShellCheck integration for run steps
- Type checking for expressions

## Severity Mapping

| Zizmor Severity | Mapped Level | Examples |
|-----------------|-------------|----------|
| high | HIGH | template-injection, dangerous-triggers |
| medium | MEDIUM | unpinned-uses, excessive-permissions |
| low | LOW | ref-confusion |
| informational | INFO | github-env (pedantic mode) |

Actionlint findings are mapped to MEDIUM severity.

## Artifacts

- `supply-chain-reports-{job_id}` — Raw JSON results from zizmor and actionlint
- `scanner-summary-supply-chain-{job_id}` — Markdown summary for security-summary aggregation

## Persona Modes

| Persona | Description |
|---------|-------------|
| `regular` | High-signal, low-noise actionable findings (default) |
| `pedantic` | Includes code smells and non-critical improvements |
| `auditor` | Flags everything including likely false positives |
