# Get Job ID Composite Action

Resolve the current GitHub Actions job ID for consistent artifact naming.

## Overview

This action looks up the current job in the workflow run and returns a stable job identifier. It supports both literal string matching and regex pattern matching against job names. If the job cannot be resolved, it falls back to a run-based identifier with a provided suffix.

## Usage

### String matching (literal)

```yaml
- name: Resolve job ID
  id: job
  uses: huntridge-labs/argus/.github/actions/get-job-id@0.2.0
  with:
    job-name-string: 'YAML Linting'
    fallback-suffix: 'yaml'
```

### Regex matching

```yaml
- name: Resolve job ID
  id: job
  uses: huntridge-labs/argus/.github/actions/get-job-id@0.2.0
  with:
    job-name-pattern: 'Scan my-app[ (/].*trivy'
    fallback-suffix: 'my-app-trivy'
```

Regex mode is useful when job names vary due to reusable workflow nesting or matrix disambiguation.

### Using the output

```yaml
- name: Use job ID
  run: echo "Job ID: ${{ steps.job.outputs.job-id }}"
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `job-name-string` | Literal string to match (exact, suffix, or substring). Mutually exclusive with `job-name-pattern`. | No | `''` |
| `job-name-pattern` | Regex pattern to match against job names. Mutually exclusive with `job-name-string`. | No | `''` |
| `fallback-suffix` | Suffix for fallback naming | Yes | - |

> **Note:** Exactly one of `job-name-string` or `job-name-pattern` must be provided.

## Outputs

| Output | Description |
|--------|-------------|
| `job-id` | The job ID or fallback identifier |

## Matching behavior

**String mode** (`job-name-string`): Matches if the job name equals the string, ends with `/ <string>`, or contains the string as a substring.

**Regex mode** (`job-name-pattern`): Matches if the job name matches the regular expression (using JavaScript `RegExp.test()`).

In both modes, in-progress or queued jobs are preferred. If no candidates are found, the action falls back to `<run-id>-<fallback-suffix>`.

## Requirements

- `GITHUB_TOKEN` is provided automatically to `actions/github-script`

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [Contributing Guide](../../CONTRIBUTING.md)
