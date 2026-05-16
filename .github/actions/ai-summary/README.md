# ai-summary

Generates an AI-powered executive security summary from aggregated Argus scanner results. Consumes `scanner-summary-*` artifacts produced by other Argus scanner actions and delivers a structured summary as a GitHub Issue and/or PR comment.

## Supported AI Providers

| Provider | Input Required |
|----------|---------------|
| GitHub Copilot | `COPILOT_GITHUB_TOKEN` |
| Anthropic Claude | `ANTHROPIC_API_KEY` |
| Google Gemini | `GEMINI_API_KEY` |

## Usage

```yaml
- uses: huntridge-labs/argus/.github/actions/ai-summary@1.0.0
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    GITHUB_TOKEN:      ${{ secrets.GITHUB_TOKEN }}
  with:
    provider: 'claude'
    post_issue: 'true'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `provider` | AI provider to use: `copilot`, `claude`, or `gemini` | No | `copilot` |
| `max_findings` | Maximum findings to include per scanner in the prompt | No | `20` |
| `post_issue` | Post the summary as a GitHub Issue | No | `true` |
| `post_pr_comment` | Post the summary as a PR comment | No | `false` |
| `issue_label` | Label to apply to the generated GitHub Issue | No | `security-summary` |
| `fail_on_ai_error` | Fail the workflow if AI summary generation fails | No | `false` |
| `skip_download` | Skip internal artifact download when summaries are pre-populated by the caller | No | `false` |

## Outputs

None. Results are delivered as a GitHub Issue and/or PR comment.

## Required Permissions

```yaml
permissions:
  contents: read
  issues: write
  pull-requests: write  # only needed if post_pr_comment: true
```

## Secrets

| Secret | Required For |
|--------|-------------|
| `COPILOT_GITHUB_TOKEN` | GitHub Copilot provider |
| `ANTHROPIC_API_KEY` | Anthropic Claude provider |
| `GEMINI_API_KEY` | Google Gemini provider |
| `GITHUB_TOKEN` | Posting Issues and PR comments |

## Example: Full Pipeline Integration

Add `ai-summary` as the final step after your scanners have run:

```yaml
jobs:
  # ... your scanner jobs ...

  scanner-bandit:
    uses: huntridge-labs/argus/.github/actions/scanner-bandit@1.0.0
    ...

  scanner-gitleaks:
    uses: huntridge-labs/argus/.github/actions/scanner-gitleaks@1.0.0
    ...

  ai-summary:
    needs: [scanner-bandit, scanner-gitleaks]
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - uses: actions/checkout@v6
      - uses: huntridge-labs/argus/.github/actions/ai-summary@1.0.0
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GITHUB_TOKEN:      ${{ secrets.GITHUB_TOKEN }}
        with:
          provider: 'claude'
          post_issue: 'true'
```
## Manual Execution

The **AI Scan Summary** workflow in the Actions tab allows you to generate a summary on demand for any PR that has a completed security scan run. Select the AI provider and enter the PR number — the workflow resolves the scan artifacts automatically.

## Summary Structure

The generated summary includes:

- **Key Findings Summary** — table of finding counts by severity
- **Executive Overview** — 1-2 sentence posture summary
- **Critical Risk Areas** — detailed breakdown of critical/high findings
- **Risk Assessment** — overall risk level with rationale
- **Recommended Actions** — prioritized remediation steps with timelines
- **Compliance Considerations** — relevant frameworks (NIST, FedRAMP, etc.)
- **Appendices** — scanning tools used, affected containers
