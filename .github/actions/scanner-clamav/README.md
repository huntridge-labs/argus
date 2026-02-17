# ClamAV Malware Scanner Composite Action

Scan files, directories, and archives for malware using [ClamAV](https://www.clamav.net/).

## Overview

This composite action runs ClamAV to detect:
- Viruses and malware
- Trojans and backdoors
- Suspicious executables
- Potentially unwanted programs
- Malicious archives

ClamAV is an open-source antivirus engine commonly used for scanning in CI/CD pipelines.

## Usage

### Basic Example

```yaml
- name: Checkout code
  uses: actions/checkout@v6

- name: Run ClamAV Scanner
  uses: huntridge-labs/argus/.github/actions/scanner-clamav@0.2.0
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    scan_path: '.'
    fail_on_severity: 'none'
```

### Advanced Example

```yaml
- name: Scan specific directory
  uses: huntridge-labs/argus/.github/actions/scanner-clamav@0.2.0
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    scan_path: 'uploads'
    enable_code_security: true
    post_pr_comment: true
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `scan_path` | Path to scan (file, directory, or archive) | No | `.` (root) |
| `post_pr_comment` | Post results as PR comment | No | `true` |
| `enable_code_security` | Upload SARIF to GitHub Security tab | No | `false` |
| `fail_on_severity` | Fail if malware found (any value other than `none` fails on malware) | No | `none` |

## Outputs

| Output | Description |
|--------|-------------|
| `infected_count` | Number of infected files found |
| `has_malware` | Whether malware was detected (`true`/`false`) |

## Features

- ✅ Comprehensive virus database (updated daily)
- ✅ Archive scanning (zip, tar, rar, etc.)
- ✅ SARIF output for GitHub Security
- ✅ JSON and text reports
- ✅ PR comments with findings
- ✅ Scans 1M+ signatures

## Reports Generated

The action generates multiple report formats:
- `clamav-report.sarif` - GitHub Security integration
- `clamav-report.json` - Detailed JSON with findings
- `clamav-report.txt` - Human-readable scan log

All reports are uploaded as artifacts: `clamav-reports`

## Examples

### Scan Repository Root

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-clamav@0.2.0
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    scan_path: '.'
```

### Scan Specific Directory

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-clamav@0.2.0
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    scan_path: 'downloads'
```

### Scan Multiple Paths

Use a matrix strategy:

```yaml
jobs:
  clamav-scan:
    strategy:
      matrix:
        path: ['uploads', 'static', 'downloads']
    steps:
      - uses: actions/checkout@v6
      - uses: huntridge-labs/argus/.github/actions/scanner-clamav@0.2.0
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          scan_path: ${{ matrix.path }}
```

### Fail on Any Malware

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-clamav@0.2.0
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    fail_on_severity: 'high'  # Any non-'none' value fails on malware
```

## Scan Coverage

ClamAV scans:
- **Files**: All file types
- **Archives**: ZIP, TAR, RAR, 7Z, and more
- **Executables**: Windows PE, ELF, Mach-O
- **Scripts**: Shell, Python, JavaScript, etc.
- **Documents**: Office documents, PDFs
- **Media**: Images, videos (for exploits)

## Understanding Results

### Clean Scan
```
Infected files: 0
```
No malware detected.

### Malware Found
```
Infected files: 1
path/to/file: Win.Trojan.Generic FOUND
```
Malware detected with signature name.

### Severity

ClamAV doesn't use severity levels - all detections are treated as malware. The `fail_on_severity` input is simplified:
- `none` - Report but don't fail
- Any other value - Fail if malware found

## Performance Considerations

### Scan Time

Scan duration depends on:
- Repository size
- Number of files
- Archive depth

Typical scans: 2-10 minutes for small/medium repos.

### Database Updates

ClamAV automatically updates its virus database before scanning:
- ~200MB download (cached between runs)
- Updated daily by ClamAV
- 1M+ signatures

## Requirements

- Repository must be checked out before running this action
- `GITHUB_TOKEN` environment variable (automatically available)
- Sufficient runner disk space (for database)

## Related Documentation

- [ClamAV Documentation](https://docs.clamav.net/)
- [Virus Database Info](https://www.clamav.net/documents/virus-database-faq)
- [Complete Example Workflow](../../examples/composite-actions-example.yml)

## Troubleshooting

### Database Update Fails

If virus database update fails:
- Check runner internet connectivity
- Verify ClamAV mirrors are accessible
- Review action logs for specific errors

### Scan Timeout

If scans timeout:
- Reduce `scan_path` scope
- Increase workflow `timeout-minutes`
- Consider excluding large archives

### False Positives

If ClamAV reports false positives:
- Verify the file is actually clean
- Check [ClamAV false positive reporting](https://www.clamav.net/reports/fp)
- Consider excluding specific files (modify action)

### Out of Memory

For very large repositories:
- Scan specific directories instead of root
- Increase runner memory
- Use matrix strategy to scan in chunks

## Common Use Cases

### 1. User Upload Validation
Scan user-uploaded content before deployment.

### 2. Dependency Checking
Scan third-party dependencies for malware.

### 3. Build Artifact Validation
Verify build outputs before release.

### 4. Regular Scans
Run on schedule to detect repository compromise.

## Best Practices

1. **Scan Regularly**: Run on push and schedule
2. **Scope Appropriately**: Scan relevant directories only
3. **Handle Failures**: Use `continue-on-error` for non-blocking scans
4. **Review Findings**: Investigate all detections
5. **Keep Updated**: Database updates automatically

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [ClamAV Forums](https://discord.com/invite/clamav)
- [View Changelog](../../CHANGELOG.md)
