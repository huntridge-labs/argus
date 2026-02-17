# Security Summary Action

Automatically aggregates and displays all security scan results in a unified, formatted report.

## Features

- **Zero Configuration** - Automatically discovers all scanner summaries
- **Works with Any Scanners** - Compatible with all argus scanner actions
- **Flexible** - Works with 1 scanner or 10+ scanners
- **GitHub Step Summary** - Formatted summary in workflow Summary tab
- **Pull Request Comments** - Consolidated, updateable PR comments
- **Metadata Rich** - Shows workflow run, branch, and commit information
- **Graceful Degradation** - Helpful messages when no summaries are found

## Usage

### Basic Usage

Add this to the end of your security scanning workflow:

```yaml
security-summary:
  name: Security Scan Summary
  runs-on: ubuntu-latest
  needs: [bandit-scan, gitleaks-scan, trivy-iac-scan, clamav-scan]
  if: always()

  steps:
    - uses: huntridge-labs/argus/.github/actions/security-summary@0.2.1
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

That's it! The action will automatically find and combine all scanner summaries, display them in the workflow summary, and post a consolidated comment to PRs.

### With Custom Settings

```yaml
- uses: huntridge-labs/argus/.github/actions/security-summary@0.2.1
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    title: '🛡️ Custom Security Report'
    show_metadata: true
    show_stats: true
    post_pr_comment: true
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `summary_pattern` | Artifact pattern to match scanner summaries | No | `scanner-summary-*` |
| `title` | Title for the summary report | No | `🔒 Security Scan Summary` |
| `show_metadata` | Show workflow metadata (run, branch, commit) | No | `true` |
| `show_stats` | Show scanner execution statistics | No | `true` |
| `post_pr_comment` | Post combined summary as PR comment | No | `true` |

## Features

### GitHub Step Summary

The action generates a formatted summary visible in the workflow run's Summary tab, showing:
- Workflow metadata (run number, branch, commit)
- Scanner execution statistics
- Individual scanner results in collapsible sections
- Links to artifacts

### Pull Request Comments

When running on pull requests, the action automatically posts a consolidated comment with all security scan results:

- **Updates existing comment** - Prevents PR spam by updating the same comment on each push
- **Rich formatting** - Collapsible sections for each scanner
- **Metadata footer** - Shows last update time, commit SHA, and workflow run link
- **Graceful error handling** - Falls back to workflow summary if PR comments fail (e.g., on forks)

**Required:** The workflow must have `pull-requests: write` permission and `GITHUB_TOKEN` must be provided:

```yaml
permissions:
  contents: read
  pull-requests: write  # Required for PR comments

jobs:
  security-summary:
    steps:
      - uses: huntridge-labs/argus/.github/actions/security-summary@0.2.1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}  # Required for PR comments
```

To disable PR comments, set `post_pr_comment: false`.
- scanner-zap (DAST)
- scanner-container (Container security)

## Example Output

### GitHub Step Summary

The action generates a formatted summary in the workflow run's Summary tab showing:
1. **Header** - Title and metadata (run, branch, commit)
2. **Statistics** - Number of scanners executed
3. **Scanner Results** - Individual collapsible sections for each scanner
4. **Footer** - Link to argus

### Pull Request Comment

On pull requests, a consolidated comment is posted/updated with:
1. **Metadata** - Branch, commit, workflow run link
2. **Scanner count** - Number of scanners executed
3. **All scanner results** - Same format as step summary
4. **Update footer** - Last update timestamp and workflow run link

## Complete Workflow Example

```yaml
name: Security Scanning

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write
  pull-requests: write  # Required for PR comments

jobs:
  bandit-scan:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - uses: actions/checkout@v6
      - uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.2.1

  gitleaks-scan:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - uses: actions/checkout@v6
      - uses: huntridge-labs/argus/.github/actions/scanner-gitleaks@0.2.1

  security-summary:
    runs-on: ubuntu-latest
    needs: [bandit-scan, gitleaks-scan]
    if: always()
    steps:
      - uses: huntridge-labs/argus/.github/actions/security-summary@0.2.1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Tips

- **Use `continue-on-error: true`** on scanner jobs so they don't block the summary
- **Use `if: always()`** on the summary job so it runs even if scanners fail
- **Add all scanner jobs to `needs`** so the summary waits for them
- **Provide `GITHUB_TOKEN`** for PR comment functionality
- **Add `pull-requests: write` permission** to enable PR comments
- **Keep the default pattern** unless you have custom artifact names

## Troubleshooting

### No summaries found

If you see "No scanner summaries found":
1. Check that scanner jobs are uploading summary artifacts
2. Verify scanner jobs have `scanner-summary-*` artifact names
3. Ensure summary job has `needs` listing all scanner jobs
4. Check scanner job logs for errors

### PR comments not working

If PR comments aren't being posted:
1. Verify workflow has `pull-requests: write` permission
2. Check that `GITHUB_TOKEN` is provided to the action
3. Confirm the workflow is running on a pull request event
4. Check action logs for permission errors (403) - forks can't post comments
5. Ensure repository settings allow PR comments from workflows
2. Verify scanner jobs have `scanner-summary-*` artifact names
3. Ensure summary job has `needs` listing all scanner jobs
4. Check scanner job logs for errors

### Missing scanners in summary

If some scanners don't appear:
1. Verify the scanner job completed (check `needs` list)
2. Check if the scanner uploaded its summary artifact
3. Ensure artifact names match the `summary_pattern` input
