# Bandit Python Security Scanner Composite Action

Scan Python code for security issues using [Bandit](https://bandit.readthedocs.io/).

## Overview

This composite action runs Bandit to detect common security issues in Python code, including:
- Hardcoded credentials
- SQL injection vulnerabilities
- Use of insecure functions
- Weak cryptography
- Shell injection risks
- And more...

## Usage

### Basic Example

```yaml
- name: Checkout code
  uses: actions/checkout@v6

- name: Run Bandit Scanner
  uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.2.1
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    fail_on_severity: 'high'
```

### Advanced Example

```yaml
- name: Scan Python with custom Python version
  uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.2.1
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    python_version: '3.11'
    enable_code_security: true
    post_pr_comment: true
    fail_on_severity: 'medium'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `post_pr_comment` | Post results as PR comment | No | `true` |
| `enable_code_security` | Upload SARIF to GitHub Security tab | No | `false` |
| `fail_on_severity` | Fail on any issue (Bandit doesn't support severity filtering; any value other than `none` fails on any issue) | No | `none` |
| `python_version` | Python version to use | No | `3.12` |

## Outputs

| Output | Description |
|--------|-------------|
| `high_count` | Number of high severity issues |
| `medium_count` | Number of medium severity issues |
| `low_count` | Number of low severity issues |
| `issue_count` | Total number of issues found |

## Features

- ✅ SARIF output for GitHub Security
- ✅ JSON and text reports
- ✅ CWE mapping for vulnerabilities
- ✅ PR comments with detailed findings
- ✅ Configurable Python version
- ✅ Severity-based reporting (HIGH, MEDIUM, LOW)

## Reports Generated

The action generates multiple report formats:
- `bandit-report.sarif` - GitHub Security integration
- `bandit-report.json` - Detailed JSON with CWE mappings
- `bandit-report.txt` - Human-readable text report

All reports are uploaded as artifacts: `bandit-reports`

## Examples

### Scan with Specific Python Version

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.2.1
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    python_version: '3.10'
```

### Fail on Medium or Higher

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.2.1
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    fail_on_severity: 'medium'
```

### Report Only (Never Fail)

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.2.1
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    fail_on_severity: 'none'
```

## Understanding Severity Levels

Bandit reports three severity levels:
- **HIGH**: Critical security issues requiring immediate attention
- **MEDIUM**: Important issues that should be reviewed
- **LOW**: Minor issues or best practice violations

Note: Due to Bandit's design, the `fail_on_severity` input is simplified - any value other than `none` will fail if any issues are found.

## Requirements

- Repository must be checked out before running this action
- `GITHUB_TOKEN` environment variable (automatically available in workflows)
- Python code in the repository
- Action automatically installs Bandit and dependencies

## Exclusions

The scanner automatically excludes:
- `.husky` directory
- `.github` directory

To customize exclusions, you'll need to modify the action or use Bandit configuration files.

## Related Documentation

- [Bandit Documentation](https://bandit.readthedocs.io/)
- [CWE Database](https://cwe.mitre.org/)
- [Complete Example Workflow](../../examples/composite-actions-example.yml)

## Troubleshooting

### No Python Files Found

If no issues are reported and you have Python files:
- Verify Python files have `.py` extension
- Check that files aren't in excluded directories
- Review action logs for Bandit output

### False Positives

If Bandit reports false positives:
- Use `# nosec` comments to suppress specific warnings
- Create a `.bandit` configuration file to customize rules
- See [Bandit configuration docs](https://bandit.readthedocs.io/en/latest/config.html)

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [View Changelog](../../CHANGELOG.md)
- [Contributing Guide](../../CONTRIBUTING.md)
