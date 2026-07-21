# Container Scanner Summary Composite Action

> [!WARNING]
> **Deprecated.** This action is now a thin compatibility shim that forwards to
> [`security-summary`](../security-summary/), scoped to the per-container scan
> summaries that `scanner-container` emits (`scanner-summary-container-*`). It
> remains only so existing `@<version>` pins keep working and will be removed in
> a future major release.
>
> Why: the parse/summary scripts this action depended on were removed during the
> Phase 3 thin-wrapper migration (the SDK-backed `scanner-container` now produces
> the per-container summary directly), which broke the combined summary at
> 1.4.0 / 1.4.1 (issue #251). `security-summary` is the canonical aggregator.

## Migration

Replace the summary job with [`security-summary`](../security-summary/), pointed
at the per-container summary artifacts:

```yaml
summary:
  needs: scan
  if: always()
  runs-on: ubuntu-latest
  steps:
    - uses: huntridge-labs/argus/.github/actions/security-summary@1.10.0
      with:
        summary_pattern: 'scanner-summary-container-*'
        title: '🐳 Container Security Scan Results'
        # optional: keep the same PR-comment thread this action used
        comment_marker: 'container-scan-parallel-comment'
```

Your scan jobs must publish a `scanner-summary-container-<name>` artifact for
each container (the [`scanner-container`](../scanner-container/) action does this
automatically; workflows that invoke `argus scan container` inline should write
`--output-dir <dir> --no-timestamp` and upload `<dir>/container-scan.md` under
that artifact name before the summary job runs).

## Compatibility shim

While this action remains, it accepts:

| Input | Description | Default |
|-------|-------------|---------|
| `artifact_pattern` | Glob of the per-container summary artifacts to aggregate (forwarded to `security-summary`'s `summary_pattern`) | `scanner-summary-container-*` |
| `post_pr_comment` | Post the combined results as a PR comment | `true` |

It emits a deprecation warning and forwards to `security-summary`. It no longer
exposes the old `total_vulnerabilities` / `critical_count` / `high_count` /
`containers_scanned` outputs (those never functioned once the underlying scripts
were removed, and `security-summary` does not expose per-severity counts). See
[ADR-030](../../../.ai/decisions.yaml) for the full rationale.
