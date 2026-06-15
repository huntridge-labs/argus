<div align=center>

# Enhanced PR comments

The reusable security workflow can post a single, trimmed summary comment on pull requests. This file captures how to toggle and extend that feature.

</div>

## Enabling comments

Comments are on by default. Disable them when you schedule scans or run the workflow outside PRs.

```yaml
with:
  scanners: all
  post_pr_comment: false
```

## Comment contents

- Title: **🛡️ Security Hardening Pipeline Results**
- Body: Same Markdown report uploaded as `security-hardening-report-<job-id>.md`, clipped to 65k characters
- Footer: Timestamp, commit SHA, and a link back to the workflow run

## Updating existing comments

The workflow rewrites the latest comment tagged with `<!-- security-hardening-comment-marker -->`. This keeps PRs tidy even when you rerun scans.

Under the hood, `reusable-security-hardening.yml` delegates to the
[`security-summary` composite action](../../.github/actions/security-summary/),
which accepts a `comment_marker` input. The reusable workflow passes
`security-hardening-comment-marker` to keep the historical marker stable
across the pre- and post-refactor implementations.

## Custom formatting (optional)

Pass a custom title and marker to the composite to carve out your own
comment thread (for example, a compliance-only view):

```yaml
- uses: huntridge-labs/argus/.github/actions/security-summary@1.5.0
  with:
    title: '🛡️ Compliance Scan Summary'
    comment_marker: 'compliance-scan-comment-marker'
    scan_statuses: |
      {"bandit": "${{ needs.bandit.result }}"}
```

Set `post_pr_comment: false` when you manage comments yourself, or pull
the aggregated markdown out of the `combined-summaries/security.md` file
the composite writes.

## Customization

The workflow supports custom comment formatting through the enhancement script. Modify `.github/scripts/enhance-pr-comments.js` to adjust:

- Risk level thresholds
- Badge colors and styles  
- Comment templates and branding

## Troubleshooting

**Comments not appearing:**
- Check PR permissions: `pull-requests: write`
- Verify enhancement script path is correct
- Check for JavaScript syntax errors

**Missing features:**
- Ensure `enhance-pr-comments.js` is in `.github/scripts/`
- Verify Node.js compatibility (requires Node 14+)

**Broken links:**
- Verify repository owner/name variables
- Ensure artifacts are properly uploaded