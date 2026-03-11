# OSV Dependency Scanner

Scans project dependencies for known vulnerabilities using [Google OSV-Scanner](https://github.com/google/osv-scanner).

## Overview

- Scans lockfiles and SBOMs against the [OSV database](https://osv.dev)
- Works on **any event trigger** (push, PR, schedule, workflow_dispatch)
- GHES-compatible via direct binary installation (no marketplace dependency)
- Deduplicates vulnerabilities across lockfiles
- Supports SARIF upload to GitHub Security tab

## Usage

```yaml
- uses: actions/checkout@v6
- uses: huntridge-labs/argus/.github/actions/scanner-osv@0.4.2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    scan_path: '.'
    fail_on_severity: 'high'
    enable_code_security: true
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `scan_path` | Path to scan for lockfiles | `.` |
| `lockfile` | Specific lockfile path (auto-discovers if empty) | `''` |
| `recursive` | Scan subdirectories recursively | `'true'` |
| `osv_version` | OSV-Scanner version to install | `'1.9.1'` |
| `enable_code_security` | Upload SARIF to GitHub Security tab | `'false'` |
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
| `total_count` | Total vulnerability count |
| `scan_status` | `clean` or `vulnerable` |

## Supported Lockfiles

OSV-Scanner auto-detects: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock`, `requirements.txt`, `poetry.lock`, `Gemfile.lock`, `Cargo.lock`, `go.sum`, `composer.lock`, `pom.xml`, `gradle.lockfile`, and more.

## Artifacts

- `osv-reports-{job_id}` — Raw JSON results and vulnerability details
- `scanner-summary-osv-{job_id}` — Markdown summary for security-summary aggregation

## Companion Scanner

Use alongside [scanner-dependency-review](../scanner-dependency-review/) for PR-specific dependency diff analysis and license compliance checking.
