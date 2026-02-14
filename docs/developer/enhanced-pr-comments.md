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

## Custom formatting (optional)

Drop a Node.js script into your repository to post a fully custom comment:

```yaml
- name: Custom PR comment
  if: github.event_name == 'pull_request'
  uses: actions/github-script@v8
  with:
    script: |
      const fs = require('fs');
      const report = fs.readFileSync('security-hardening-report.md', 'utf8');
      await github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: `## � Security Report\n\n${report.slice(0, 3000)}...`
      });
```

Set `post_pr_comment: false` when you manage comments yourself.

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