# CodeQL Scanner Composite Action

Run GitHub CodeQL SAST analysis for a single language and generate reports.

> **Composite-only by design.** CodeQL has no `argus.scanners.codeql` SDK module and won't get one. The CodeQL CLI's licence terms restrict use to open-source repos and GHAS-entitled private repos, the bundle is ~500MB to redistribute, and SARIF upload to the GitHub Security tab is the primary value of running it — none of which an off-platform SDK consumer can take advantage of. See [`.ai/decisions.yaml` ADR-021](../../../.ai/decisions.yaml) for the SDK-vs-composite-action boundary rule.

## Overview

This composite action analyzes code for security vulnerabilities using CodeQL. Run it once per language (use a matrix for multiple languages). Results integrate with the security summary aggregator.

## Usage

### Basic Example

```yaml
- name: Checkout code
  uses: actions/checkout@v6

- name: Run CodeQL (Python)
  uses: huntridge-labs/argus/.github/actions/scanner-codeql@1.12.2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    language: 'python'
    fail_on_severity: 'high'
```

### Matrix Example

```yaml
strategy:
  matrix:
    language: [python, javascript]
steps:
  - uses: actions/checkout@v6
  - uses: huntridge-labs/argus/.github/actions/scanner-codeql@1.12.2
    env:
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    with:
      language: ${{ matrix.language }}
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `language` | Language to analyze (python, javascript, go, java, csharp, cpp, ruby, swift, etc.) | Yes | - |
| `config_file` | Path to CodeQL configuration file | No | `''` |
| `enable_code_security` | Upload SARIF to GitHub Security tab | No | `false` |
| `fail_on_severity` | Fail at or above severity: none, low, medium, high, critical | No | `none` |
| `setup_python_version` | Python version to use for Python analysis | No | `3.12` |
| `setup_node_version` | Node.js version to use for JavaScript analysis | No | `22` |

## Outputs

| Output | Description |
|--------|-------------|
| `critical_count` | Number of critical severity findings |
| `high_count` | Number of high severity findings |
| `medium_count` | Number of medium severity findings |
| `low_count` | Number of low severity findings |
| `total_count` | Total number of findings |
| `scan_status` | `success` when the analysis completed and produced SARIF output, `failed` otherwise. Zero findings are only meaningful when this is `success`. |

## Scan Status and the Severity Gate

A CodeQL run that never happened also reports zero findings. This action treats
those two situations differently, so a broken scan can never be mistaken for a
clean one.

`Parse results` runs with `if: always()` and always publishes a `scan_status`
output:

| `scan_status` | Meaning |
|---------------|---------|
| `success` | `Perform CodeQL Analysis` and `Organize CodeQL results` both completed **and** at least one SARIF file landed in `codeql-reports/sarif/`. The severity counts are trustworthy. |
| `failed` | The analysis was skipped or failed (a failing `Initialize CodeQL` or `Autobuild` skips it), or it reported success but emitted no SARIF. The severity counts are **not** a clean bill of health. |

`Check severity threshold` also runs with `always()` and **fails closed**: when
`fail_on_severity` is set to anything other than `none`, a `scan_status` that is
not `success` fails the step before any count is examined:

```
::error::CodeQL analysis did not complete (scan_status='failed'). Failing the
severity gate: zero findings from a scan that did not run is not a pass.
```

The generated summary carries the same distinction — a non-`success` scan
renders a "CodeQL analysis did not complete" banner rather than a findings
table.

Consumers that need to react to this themselves can read the `scan_status`
output directly:

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-codeql@main
  id: codeql
  with:
    language: python
    fail_on_severity: high

- name: Handle an incomplete scan
  if: always() && steps.codeql.outputs.scan_status != 'success'
  run: echo "CodeQL did not complete; treat its results as unknown"
```

> **Note on `fail_on_severity: none`** (the default): the severity gate does not
> run at all, so an incomplete scan does not fail the job. The `scan_status`
> output and the summary banner still report it. Set `fail_on_severity` if you
> want an incomplete scan to break the build.

## Artifacts

- `codeql-reports-<language>`: SARIF and supporting reports
- `scanner-summary-codeql-<language>`: summary artifact used by security-summary

## Requirements

- Repository must be checked out before running this action
- `GITHUB_TOKEN` environment variable
- CodeQL supports a single language per run; use a matrix for multiple languages

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [Contributing Guide](../../CONTRIBUTING.md)
