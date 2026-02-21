# FedRAMP Significant Change Notification (SCN) Detector

Automatically analyzes Infrastructure as Code (IaC) changes and classifies them according to [FedRAMP 20X Significant Change Notification guidelines](https://www.fedramp.gov/docs/20x/significant-change-notifications/).

## Overview

This action inspects IaC changes in pull requests and classifies them into four FedRAMP categories:

| Category | Description | Notification Required |
|----------|-------------|----------------------|
| 🟢 **Routine** | Regular maintenance, patching, minor config changes | No |
| 🟡 **Adaptive** | Frequent improvements with minimal security plan changes | Within 10 business days after |
| 🟠 **Transformative** | Rare, significant changes altering risk profile | 30 days initial + 10 days final + after |
| 🔴 **Impact** | Security boundary or FIPS level changes | New assessment required |

### Features

- **Hybrid Classification**: Rule-based engine with AI fallback for ambiguous cases
- **Multi-Format Support**: Terraform (HCL), Kubernetes (YAML), CloudFormation (JSON/YAML)
- **GitHub Integration**: Creates issues with compliance timelines and posts PR comments
- **Configurable Rules**: Customize classification via YAML config file
- **Audit Trail**: Comprehensive JSON artifacts with 90-day retention
- **CI/CD Gates**: Optional workflow failure on specific change categories

## Quick Start

### Basic Usage

```yaml
name: SCN Detection

on:
  pull_request:
    paths:
      - 'terraform/**'
      - 'kubernetes/**'
      - 'cloudformation/**'

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  scn-detection:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0  # Required for git diff

      - uses: huntridge-labs/argus/.github/actions/scn-detector@v0.3.0
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}  # Optional for AI fallback
        with:
          config_file: '.github/scn-config.yml'
          create_issues: true
          post_pr_comment: true
```

### With Configuration File

Create `.github/scn-config.yml`:

```yaml
version: "1.0"

rules:
  routine:
    - pattern: "tags.*"
      description: "Tag-only changes"
    - pattern: "description"
      description: "Description changes"

  adaptive:
    - resource: "aws_ami.*"
      operation: "modify"
      description: "AMI updates"
    - resource: "aws_instance.*.instance_type"
      operation: "modify"
      description: "Instance type changes"

  transformative:
    - resource: "aws_rds_cluster.*"
      attribute: "engine"
      operation: "modify"
      description: "Database engine changes"
    - pattern: "provider.*.region"
      operation: "modify"
      description: "Region/datacenter migrations"

  impact:
    - resource: ".*"
      attribute: ".*encryption.*"
      operation: "delete|modify"
      description: "Encryption changes"

ai_fallback:
  enabled: true
  model: "claude-3-haiku-20240307"
  confidence_threshold: 0.8
```

See [`.github/scn-config.example.yml`](../../../scn-config.example.yml) for a complete example.

## Inputs

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `base_ref` | Base branch/ref for comparison | `github.base_ref` or `main` | No |
| `head_ref` | Head commit/ref for comparison | `github.sha` | No |
| `config_file` | Path to SCN configuration file | `.github/scn-config.yml` | No |
| `create_issues` | Create GitHub Issues for tracking | `true` | No |
| `post_pr_comment` | Post PR comment with summary | `true` | No |
| `enable_ai_fallback` | Use AI for ambiguous classifications | `true` | No |
| `fail_on_category` | Fail on specific category | `none` | No |
| `job_id` | Job ID for artifact naming | `github.job` | No |

### fail_on_category Options

- `none` - Never fail (default)
- `adaptive` - Fail on Adaptive, Transformative, or Impact changes
- `transformative` - Fail on Transformative or Impact changes
- `impact` - Fail only on Impact changes

## Outputs

| Output | Description |
|--------|-------------|
| `change_category` | Highest severity category detected |
| `routine_count` | Number of routine changes |
| `adaptive_count` | Number of adaptive changes |
| `transformative_count` | Number of transformative changes |
| `impact_count` | Number of impact categorization changes |
| `has_changes` | Whether any IaC changes were detected |
| `issue_numbers` | Comma-separated list of created issue numbers |

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GITHUB_TOKEN` | GitHub token for PR comments and issue creation | Yes |
| `ANTHROPIC_API_KEY` | Anthropic API key for AI fallback | No (if `enable_ai_fallback=true`) |

## Configuration

### Rule Format

Rules are evaluated in order: `routine` → `adaptive` → `transformative` → `impact`. First match wins.

```yaml
rules:
  {category}:
    - pattern: "regex_pattern"           # Match attribute/resource name
      resource: "resource_type.name"     # Match specific resource
      attribute: "attribute_name"        # Match specific attribute
      operation: "create|modify|delete"  # Match operation type
      description: "Human-readable"      # Explanation for audit trail
```

### Pattern Matching

- **Wildcard**: `aws_instance.*` matches all instances
- **Regex**: `.*encryption.*` matches any encryption-related attribute
- **Multiple operations**: `create|modify` matches either operation

### AI Fallback

When enabled, unmatched changes are classified using Claude Haiku with FedRAMP context:

```yaml
ai_fallback:
  enabled: true
  model: "claude-3-haiku-20240307"  # Fast, cost-effective
  confidence_threshold: 0.8         # Minimum confidence for classification
  max_tokens: 1024
```

**Cost Estimate**: ~$0.001-0.005 per change classification (Haiku pricing: $0.25/1M input, $1.25/1M output)

## Supported IaC Formats

| Format | Detection | Example Files |
|--------|-----------|---------------|
| **Terraform** | `*.tf`, `*.tfvars` | `main.tf`, `variables.tf` |
| **Kubernetes** | YAML with `kind:`/`apiVersion:` | `deployment.yaml`, `service.yaml` |
| **CloudFormation** | JSON/YAML with `AWSTemplateFormatVersion:` | `template.yaml`, `stack.json` |
| **Generic** | Any IaC file in specified paths | All above formats |

## GitHub Issues

For Adaptive, Transformative, and Impact changes, the action automatically creates tracking issues with:

- **Labels**: `scn`, `scn:adaptive`, `scn:transformative`, `scn:impact`
- **Compliance Timelines**: Due dates calculated from FedRAMP requirements
- **Checklists**: Required documentation and steps
- **Links**: PR, artifacts, change details

### Example Issue

```markdown
## 🔐 FedRAMP Significant Change Notification

**Category**: 🟠 Transformative
**PR**: #123
**Detection Date**: 2026-02-21

### FedRAMP Compliance Timeline

- [ ] **Initial Notice** - Due: 2026-03-23 (30 business days before)
- [ ] **Impact Analysis** - Due: 2026-04-15
- [ ] **Final Notice** - Due: 2026-04-22 (10 business days before)
- [ ] **Change Execution** - Target: 2026-05-06
- [ ] **Post-Completion Notification** - Due: 2026-05-16
```

## Artifacts

All runs upload artifacts with extended retention:

| Artifact | Description | Retention |
|----------|-------------|-----------|
| `scn-reports-{job_id}` | JSON files: `iac-changes.json`, `scn-classifications.json`, `scn-audit-trail.json` | 90 days |
| `scn-summary-{job_id}` | Markdown report for PR comments | 7 days |

## Advanced Usage

### Fail CI on High-Impact Changes

```yaml
- uses: huntridge-labs/argus/.github/actions/scn-detector@v0.3.0
  with:
    fail_on_category: 'transformative'  # Fail on Transformative or Impact
```

### Disable AI Fallback (Rule-Based Only)

```yaml
- uses: huntridge-labs/argus/.github/actions/scn-detector@v0.3.0
  with:
    enable_ai_fallback: false
```

### Multiple Repositories with Shared Config

```yaml
- uses: actions/checkout@v6
  with:
    repository: 'org/shared-configs'
    path: 'shared-configs'

- uses: huntridge-labs/argus/.github/actions/scn-detector@v0.3.0
  with:
    config_file: 'shared-configs/scn-config.yml'
```

### Custom Branch Comparison

```yaml
- uses: huntridge-labs/argus/.github/actions/scn-detector@v0.3.0
  with:
    base_ref: 'production'
    head_ref: 'staging'
```

## Troubleshooting

### No Changes Detected

**Problem**: Action reports "No IaC changes detected" but you know files changed.

**Solutions**:
- Ensure `fetch-depth: 0` in `actions/checkout` step
- Verify IaC files match supported patterns (`*.tf`, `*.yaml` with `kind:`, etc.)
- Check that changed files are in tracked paths

### Classification Seems Wrong

**Problem**: Changes classified incorrectly.

**Solutions**:
- Review rule ordering in config (first match wins)
- Add more specific rules for your use case
- Check AI fallback confidence scores in audit trail
- Add manual review rule:
  ```yaml
  adaptive:
    - resource: "aws_instance.*"
      pattern: ".*my_special_case.*"
      description: "Override for specific resource"
  ```

### AI Fallback Not Working

**Problem**: All changes classified as "manual review required".

**Solutions**:
- Verify `ANTHROPIC_API_KEY` is set correctly
- Check API key has quota remaining
- Review confidence threshold (lower if too strict)
- Check logs for API errors

### Issues Not Created

**Problem**: No GitHub Issues created for Transformative changes.

**Solutions**:
- Verify `issues: write` permission in workflow
- Check `GITHUB_TOKEN` has correct scopes
- Ensure `create_issues: true` input
- Review logs for API rate limiting

## How It Works

1. **Git Diff Analysis**: Compares base and head refs, identifies IaC files
2. **Change Extraction**: Parses diffs to extract resource types, operations, attributes
3. **Rule Matching**: Applies user-configured rules in order (routine → adaptive → transformative → impact)
4. **AI Fallback**: For unmatched changes, queries Claude Haiku with FedRAMP context
5. **Report Generation**: Creates markdown summary and JSON audit trail
6. **Integration**: Posts PR comments, creates GitHub Issues, uploads artifacts

## Examples

See [`examples/workflows/scn-detection-example.yml`](../../../../examples/workflows/scn-detection-example.yml) for complete workflow examples.

## Related Documentation

- [FedRAMP SCN Guidelines](https://www.fedramp.gov/docs/20x/significant-change-notifications/)
- [Argus Documentation](../../../../README.md)
- [Configuration Example](../../../scn-config.example.yml)

## Support

- **Issues**: [GitHub Issues](https://github.com/huntridge-labs/argus/issues)
- **Discussions**: [GitHub Discussions](https://github.com/huntridge-labs/argus/discussions)

## License

AGPL v3 - See [LICENSE.md](../../../../LICENSE.md)
