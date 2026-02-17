# Container Scanner Summary Composite Action

Aggregate and deduplicate results from parallel container scans into a unified summary.

## Overview

This action is designed to work with matrix-based container scanning workflows. When you scan multiple containers or use multiple scanners in parallel, this action:
- ✅ Downloads all scan artifacts
- ✅ Deduplicates vulnerabilities across scanners
- ✅ Generates a unified summary with rich formatting
- ✅ Posts results as PR comments
- ✅ Creates combined artifacts for reporting

## Usage

### Basic Example with Matrix Scanning

```yaml
jobs:
  # Step 1: Scan containers in parallel
  container-scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        image:
          - { ref: 'nginx:latest', name: 'web' }
          - { ref: 'postgres:15', name: 'db' }
    steps:
      - uses: actions/checkout@v6

      - name: Scan container
        uses: huntridge-labs/argus/.github/actions/scanner-container@0.2.2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          image_ref: ${{ matrix.image.ref }}
          scan_name: ${{ matrix.image.name }}
          skip_summary: true  # Important: skip individual summaries

  # Step 2: Generate combined summary
  summary:
    needs: container-scan
    if: always()  # Run even if some scans fail
    runs-on: ubuntu-latest
    steps:
      - name: Generate combined summary
        uses: huntridge-labs/argus/.github/actions/scanner-container-summary@0.2.2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          post_pr_comment: true
```

### Advanced Example with Config-Driven Scanning

```yaml
jobs:
  # Parse container configuration
  setup:
    runs-on: ubuntu-latest
    outputs:
      scan_matrix: ${{ steps.parse.outputs.scan_matrix }}
    steps:
      - uses: actions/checkout@v6
      - uses: huntridge-labs/argus/.github/actions/parse-container-config@0.2.2
        id: parse
        with:
          config_file: 'container-config.yml'

  # Scan in parallel
  scan:
    needs: setup
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix: ${{ fromJson(needs.setup.outputs.scan_matrix) }}
    steps:
      - uses: huntridge-labs/argus/.github/actions/scanner-container@0.2.2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          image_ref: ${{ matrix.image }}
          scan_name: ${{ matrix.name }}
          scanners: ${{ matrix.scanner }}
          skip_summary: true

  # Aggregate results
  summary:
    needs: scan
    if: always()
    runs-on: ubuntu-latest
    steps:
      - uses: huntridge-labs/argus/.github/actions/scanner-container-summary@0.2.2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `artifact_pattern` | Pattern to match scan artifacts | No | `container-scan-results-*` |
| `post_pr_comment` | Post combined results as PR comment | No | `true` |

## Outputs

| Output | Description |
|--------|-------------|
| `total_vulnerabilities` | Total unique vulnerabilities across all containers |
| `critical_count` | Number of critical vulnerabilities |
| `high_count` | Number of high severity vulnerabilities |
| `containers_scanned` | Number of containers scanned |

## Features

### Vulnerability Deduplication

When multiple scanners detect the same vulnerability:
- Deduplicates based on CVE ID
- Keeps the highest severity reported
- Shows which scanners detected each issue

### Rich Summary Output

Generates comprehensive summaries with:
- 📊 Overall vulnerability statistics
- 🐳 Per-container breakdowns
- 🔍 Detailed finding tables
- 📈 Severity distribution
- 🔗 Clickable links to artifacts

### PR Comments

Automatically posts (or updates) PR comments with:
- Combined vulnerability counts
- Container-by-container breakdown
- Links to full reports
- Timestamp of last update

## How It Works

1. **Artifact Collection**: Downloads all artifacts matching the pattern
2. **Parsing**: Extracts vulnerability data from JSON reports
3. **Deduplication**: Merges findings from multiple scanners
4. **Summary Generation**: Creates formatted markdown summaries
5. **Upload**: Saves combined summary as artifact
6. **PR Comment**: Posts results to pull request

## Reports Generated

The action generates:
- `container.md` - Combined markdown summary
- `container-summary.json` - Structured data (if available)

These are uploaded as artifact: `container-scan-summary`

## Examples

### Custom Artifact Pattern

If your scan artifacts use a different naming pattern:

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-container-summary@0.2.2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    artifact_pattern: 'my-scan-results-*'
```

### Disable PR Comments

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-container-summary@0.2.2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    post_pr_comment: false
```

### Use Outputs for Gating

```yaml
- name: Generate summary
  id: summary
  uses: huntridge-labs/argus/.github/actions/scanner-container-summary@0.2.2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

- name: Check vulnerability threshold
  run: |
    if [ "${{ steps.summary.outputs.critical_count }}" -gt 0 ]; then
      echo "❌ Found ${{ steps.summary.outputs.critical_count }} critical vulnerabilities"
      exit 1
    fi
    echo "✅ No critical vulnerabilities found"
```

## Important Notes

### Skip Individual Summaries

When using matrix scanning, set `skip_summary: true` in the scanner-container action to avoid duplicate summaries:

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-container@0.2.2
  with:
    skip_summary: true  # Important!
```

### Always Run Summary

Use `if: always()` to ensure the summary runs even if some scans fail:

```yaml
summary:
  needs: scan
  if: always()  # Run regardless of scan results
```

### Artifact Retention

Scan artifacts are downloaded from the current workflow run. Ensure:
- Artifacts are uploaded before summary runs
- Artifact names match the pattern
- Artifacts haven't expired (retention period)

## Workflow Requirements

The summary action requires:
- **Needs dependency**: Must run after scan jobs
- **Always condition**: Should run even if scans fail
- **GITHUB_TOKEN**: For PR comment posting
- **Artifacts**: Scan results must be uploaded first

## Deduplication Logic

When the same CVE is found by multiple scanners:

```yaml
# Trivy finds: CVE-2024-1234 (HIGH)
# Grype finds: CVE-2024-1234 (CRITICAL)

# Result: CVE-2024-1234 (CRITICAL) - highest severity kept
# Note: Shows detection by both scanners
```

## Performance

Summary generation is fast:
- Typical time: 10-30 seconds
- Depends on: Number of containers and findings
- Network: Artifact download time

## Troubleshooting

### No Artifacts Found

If "No artifacts found" appears:
- Verify artifact names match pattern
- Check scan jobs completed successfully
- Ensure artifacts were uploaded
- Review `artifact_pattern` input

### Missing Vulnerabilities

If summary shows fewer vulnerabilities than expected:
- Deduplication is working (same CVE from multiple scanners)
- Check individual scan reports for details
- Review deduplication logic in action logs

### PR Comment Not Posted

If PR comments don't appear:
- Verify `post_pr_comment: true`
- Check workflow has `pull-requests: write` permission
- Ensure running on pull request event
- Review action logs for errors

### Summary Too Large

If PR comment is truncated:
- Summary auto-truncates at 262KB
- Use artifacts for full reports
- Consider scanning fewer containers per job

## Best Practices

1. **Matrix Strategy**: Scan containers in parallel for speed
2. **Always Run**: Use `if: always()` for summary job
3. **Skip Individual**: Set `skip_summary: true` on scanner
4. **Fail Fast False**: Allow all scans to complete
5. **Deduplicate**: Leverage built-in deduplication
6. **Review Results**: Check both summary and individual reports

## Related Documentation

- [scanner-container](../scanner-container/README.md) - Container scanning action
- [parse-container-config](../parse-container-config/) - Configuration parser
- [Container Scanning Guide](../../docs/container-scanning.md)
- [Complete Example](../../examples/actions-container-scan-matrix.yml)

## Matrix Scanning Benefits

Using this summary action with matrix scanning:
- ⚡ **Faster**: Parallel execution
- 📊 **Cleaner**: Single unified report
- 🔍 **Better**: Deduplication across scanners
- 💾 **Efficient**: Combined artifacts

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [View Changelog](../../CHANGELOG.md)
- [Contributing Guide](../../CONTRIBUTING.md)
