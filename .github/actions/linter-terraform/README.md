# Terraform Linter Composite Action

Run Terraform formatting and validation checks.

## Overview

This action validates Terraform files using `terraform fmt`, `terraform validate`, and optional TFLint. It uploads results as artifacts that can be aggregated by the linting summary action.

## Usage

```yaml
- name: Checkout code
  uses: actions/checkout@v6

- name: Run Terraform linting
  uses: huntridge-labs/argus/.github/actions/linter-terraform@feat/migrate-to-composite-actions
  with:
    fail_on_issues: false
    terraform_version: 'latest'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `fail_on_issues` | Fail the job if issues are found | No | `false` |
| `paths` | Paths to search for Terraform files (space-separated) | No | `.` |
| `terraform_version` | Terraform version to use | No | `latest` |
| `run_tflint` | Run TFLint in addition to fmt/validate | No | `true` |

## Outputs

| Output | Description |
|--------|-------------|
| `issues_count` | Total number of linting issues found |
| `fmt_issues` | Number of formatting issues |
| `validate_issues` | Number of validation issues |
| `tflint_issues` | Number of TFLint issues |

## Artifacts

- `linter-summary-terraform`: summary for linting-summary
- `terraform-lint-results`: raw lint output

## Requirements

- Repository must be checked out before running this action

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [Contributing Guide](../../CONTRIBUTING.md)
