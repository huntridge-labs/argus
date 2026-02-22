# FedRAMP Significant Change Notification (SCN) Detector

Automatically analyze Infrastructure as Code (IaC) changes and classify them according to FedRAMP 20X Significant Change Notification guidelines.

## Features

- **Hybrid Classification**: Rule-based pattern matching with optional AI fallback for ambiguous changes
- **Multi-Format IaC Support**: Terraform (HCL), Kubernetes (YAML), CloudFormation (YAML/JSON), generic git diff
- **Built-in FedRAMP Low Profile**: Pre-configured rules aligned with FedRAMP requirements
- **Custom Profiles**: Define organization-specific classification rules and risk thresholds
- **Separate AI Configuration**: Share AI provider settings across multiple profiles
- **IAM Detection**: Comprehensive rules for IAM roles, policies, users, and cross-account access
- **Automated Notifications**: Creates GitHub Issues for ADAPTIVE, TRANSFORMATIVE, and IMPACT changes
- **PR Comments**: Posts detailed analysis as PR comments with compliance timelines
- **SARIF Upload**: Optional upload to GitHub Security tab for centralized visibility
- **Audit Trail**: 90-day artifact retention for compliance evidence

## Quick Start

### Minimal Setup (Default FedRAMP Low Profile)

```yaml
name: SCN Detection

on:
  pull_request:
    paths:
      - 'terraform/**'
      - 'infrastructure/**'

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

      - uses: huntridge-labs/argus/.github/actions/scn-detector@main
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          create_issues: true
          post_pr_comment: true
```

## FedRAMP Change Categories

| Category | Notification Required | Timeline | Examples |
|----------|----------------------|----------|----------|
| **ROUTINE** | None | None | Tag changes, description updates, minor capacity adjustments |
| **ADAPTIVE** | Yes | Within 10 business days after completion | AMI updates, instance type changes, policy attachments |
| **TRANSFORMATIVE** | Yes | 30 days initial + 10 days final + post-completion | Region changes, new roles/policies, AI/ML services |
| **IMPACT** | New assessment required | Work with AO/3PAO | Encryption changes, admin roles, security boundary changes |

## Configuration Options

### 1. Default Configuration (Simplest)

Uses built-in FedRAMP Low profile with rule-based classification only.

```yaml
- uses: huntridge-labs/argus/.github/actions/scn-detector@main
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### 2. With AI Fallback

Enables AI classification for changes that don't match any rules.

```yaml
- uses: huntridge-labs/argus/.github/actions/scn-detector@main
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}  # or OPENAI_API_KEY
  with:
    enable_ai_fallback: true
```

### 3. Custom Profile

Use organization-specific classification rules.

Create `.github/scn-profiles/my-profile.yml`:

```yaml
version: "1.0"
name: "My Organization Profile"
compliance_framework: "FedRAMP 20X"
impact_level: "Moderate"

rules:
  routine:
    - pattern: 'tags.*'
      description: 'Tag changes'
  adaptive:
    - resource: 'aws_instance.*.instance_type'
      operation: 'modify'
      description: 'Instance type changes'
  # ... more rules
```

Use in workflow:

```yaml
- uses: huntridge-labs/argus/.github/actions/scn-detector@main
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    config_file: '.github/scn-profiles/my-profile.yml'
```

### 4. Separate AI Configuration (Recommended)

Share AI provider settings across multiple profiles.

Create `.github/ai-config.yml`:

```yaml
provider: 'anthropic'  # or 'openai'
model: 'claude-3-haiku-20240307'
confidence_threshold: 0.85
max_tokens: 1024
```

Use in workflow:

```yaml
- uses: huntridge-labs/argus/.github/actions/scn-detector@main
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  with:
    config_file: '.github/scn-profiles/my-profile.yml'
    ai_config_file: '.github/ai-config.yml'
    enable_ai_fallback: true
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `base_ref` | Base branch/ref for comparison | `github.base_ref` or `main` |
| `head_ref` | Head commit/ref for comparison | `github.sha` |
| `config_file` | Path to SCN profile configuration | `''` (uses built-in fedramp-low) |
| `ai_config_file` | Path to AI configuration file | `''` (uses profile settings) |
| `create_issues` | Create GitHub Issues for tracking | `true` |
| `post_pr_comment` | Post PR comment with analysis summary | `true` |
| `enable_ai_fallback` | Use AI for ambiguous changes | `false` |
| `fail_on_category` | Fail workflow on category (`none`, `adaptive`, `transformative`, `impact`) | `none` |
| `job_id` | Job ID for artifact naming | `github.job` |

## Outputs

| Output | Description |
|--------|-------------|
| `change_category` | Highest severity category detected (`ROUTINE`, `ADAPTIVE`, `TRANSFORMATIVE`, `IMPACT`, `NONE`) |
| `routine_count` | Number of routine changes |
| `adaptive_count` | Number of adaptive changes |
| `transformative_count` | Number of transformative changes |
| `impact_count` | Number of impact changes |
| `has_changes` | Whether any IaC changes were detected (`true`/`false`) |
| `issue_numbers` | Comma-separated list of GitHub issue numbers created |

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GITHUB_TOKEN` | GitHub token for API access | Yes |
| `ANTHROPIC_API_KEY` | Anthropic API key for Claude models | No (if AI enabled) |
| `OPENAI_API_KEY` | OpenAI API key for GPT models | No (if AI enabled) |

## AI Providers

### Anthropic (Claude)

**Recommended Models:**
- `claude-3-haiku-20240307` - Fast, affordable, good for routine classification (default)
- `claude-3-sonnet-20240229` - Balanced speed/quality
- `claude-3-opus-20240229` - Highest quality

**Configuration:**

```yaml
# .github/ai-config.yml
provider: 'anthropic'
model: 'claude-3-haiku-20240307'
confidence_threshold: 0.8
max_tokens: 1024
```

**Environment:** Set `ANTHROPIC_API_KEY` secret in GitHub

### OpenAI (GPT)

**Recommended Models:**
- `gpt-4o-mini` - Fast, affordable (recommended)
- `gpt-4o` - Latest GPT-4 optimized
- `gpt-4-turbo` - High quality

**Configuration:**

```yaml
# .github/ai-config.yml
provider: 'openai'
model: 'gpt-4o-mini'
confidence_threshold: 0.8
max_tokens: 1024
```

**Environment:** Set `OPENAI_API_KEY` secret in GitHub

### Azure OpenAI / OpenAI-Compatible APIs

```yaml
# .github/ai-config.yml
provider: 'openai'
model: 'gpt-4'
api_base_url: 'https://YOUR_RESOURCE.openai.azure.com/openai/deployments/YOUR_DEPLOYMENT'
```

## Configuration Files

### SCN Profile Structure

```yaml
version: "1.0"
name: "Profile Name"
description: "Profile description"
compliance_framework: "FedRAMP 20X"
impact_level: "Low|Moderate|High"

rules:
  routine: [...]
  adaptive: [...]
  transformative: [...]
  impact: [...]

ai_fallback:
  enabled: true
  provider: 'anthropic'
  model: 'claude-3-haiku-20240307'
  # ...

notifications:
  adaptive: { post_completion_days: 10 }
  transformative: { initial_notice_days: 30, final_notice_days: 10 }
  impact: { requires_new_assessment: true }
```

See `examples/configs/scn-profile-custom.example.yml` for complete example.

### AI Configuration Structure

```yaml
enabled: true
provider: 'anthropic'  # or 'openai'
model: 'claude-3-haiku-20240307'
confidence_threshold: 0.8
max_tokens: 1024
max_diff_chars: 1000
# Optional: api_base_url, system_prompt, user_prompt_template
```

See `examples/configs/ai-config-anthropic.example.yml` and `ai-config-openai.example.yml` for complete examples.

## Rule Matching

Rules are evaluated in category order: **routine** → **adaptive** → **transformative** → **impact**

**First match wins** — this means a routine rule will match before a more severe rule. Place your rules carefully: if a change should be classified as IMPACT, ensure no broader routine/adaptive rule matches it first.

When a rule has **multiple criteria** (e.g., both `pattern` and `resource`), **all criteria must match** (AND logic). A change must satisfy every criterion in the rule to be classified.

If **no rule matches** and AI fallback is disabled, the change is classified as **MANUAL_REVIEW** (requiring human assessment).

### Rule Criteria

| Criteria | Description | Match Target | Example |
|----------|-------------|--------------|---------|
| `pattern` | Regex matching | `type.name attributes diff` (concatenated) | `'tags.*'` |
| `resource` | Regex matching | `type.name` or `type.name.attribute` | `'aws_instance.*.instance_type'` |
| `attribute` | Regex matching | Changed attributes list **and** diff text | `'.*encryption.*'` |
| `operation` | Exact or pipe-delimited match | Operation field | `'create\|delete\|modify'` |

### Rule Examples

```yaml
# ROUTINE: Tag changes only
- pattern: 'tags.*'
  description: 'Tag changes'

# ADAPTIVE: Instance type changes
- resource: 'aws_instance.*.instance_type'
  operation: 'modify'
  description: 'Instance type changes'

# TRANSFORMATIVE: Database engine changes
- resource: 'aws_rds_.*\.engine'
  operation: 'modify'
  description: 'Database engine changes'

# IMPACT: Admin roles (pattern matching in resource name)
- resource: 'aws_iam_role.*'
  pattern: '.*[Aa]dmin.*|.*[Rr]oot.*'
  operation: 'create|modify|delete'
  description: 'Administrative IAM role changes'

# IMPACT: Wildcard permissions (pattern matching in diff)
- resource: 'aws_iam_policy.*.policy'
  pattern: '.*Action.*:\s*\*'
  operation: 'create|modify'
  description: 'Wildcard action permissions'
```

## Examples

See `examples/` directory for complete examples:

- **`workflows/scn-detection-example.yml`** - Basic examples (default, custom profile, AI config)
- **`workflows/scn-detection-complete.example.yml`** - Advanced examples (multi-profile, notifications, auto-approval)
- **`configs/scn-profile-custom.example.yml`** - Complete custom profile with all options
- **`configs/ai-config-anthropic.example.yml`** - Anthropic AI configuration
- **`configs/ai-config-openai.example.yml`** - OpenAI AI configuration

## Built-in Profiles

### FedRAMP Low (Default)

Located at `.github/actions/scn-detector/profiles/fedramp-low.yml`

**Includes:**
- 35 rules across all categories
- IAM detection (13 rules for roles, policies, users)
- AI/ML service detection
- Encryption and security boundary changes
- Cross-account access detection
- Wildcard permission detection

## Use Cases

### 1. Basic Compliance

```yaml
- uses: huntridge-labs/argus/.github/actions/scn-detector@main
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### 2. Fail on High-Severity Changes

```yaml
- uses: huntridge-labs/argus/.github/actions/scn-detector@main
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    fail_on_category: 'transformative'  # Fail on TRANSFORMATIVE or IMPACT
```

### 3. Team Notifications

```yaml
- uses: huntridge-labs/argus/.github/actions/scn-detector@main
  id: scn
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

- name: Notify Security Team
  if: steps.scn.outputs.impact_count > 0
  run: |
    echo "Impact changes: ${{ steps.scn.outputs.impact_count }}"
    # Send Slack/Teams notification
```

### 4. Multi-Profile Strategy

```yaml
# Strict for infrastructure
- uses: huntridge-labs/argus/.github/actions/scn-detector@main
  if: contains(github.event.pull_request.files, 'terraform/')
  with:
    config_file: '.github/scn-profiles/infrastructure-strict.yml'
    fail_on_category: 'transformative'

# Lenient for frontend
- uses: huntridge-labs/argus/.github/actions/scn-detector@main
  if: contains(github.event.pull_request.files, 'frontend/')
  with:
    config_file: '.github/scn-profiles/frontend-lenient.yml'
```

## Artifacts

The action uploads the following artifacts (90-day retention for compliance):

- **`scn-reports-{job_id}`** - Full analysis (iac-changes.json, scn-classifications.json, scn-audit-trail.json)
- **`scn-summary-{job_id}`** - Markdown summary (scn-report.md)

## Troubleshooting

### No Changes Detected

Ensure `fetch-depth: 0` is set in `actions/checkout` to get full git history for diff analysis.

### AI Classification Not Working

1. Check that `enable_ai_fallback: true` is set
2. Verify API key environment variable is set (`ANTHROPIC_API_KEY` or `OPENAI_API_KEY`)
3. Check action logs for API errors
4. Verify AI config has correct `provider` and `model` values

### Rules Not Matching

1. Review rule syntax in profile YAML
2. Check pattern regex (use online regex testers)
3. Enable AI fallback to see what unmatched changes look like
4. Check action logs for rule evaluation details

### Low AI Confidence

Increase `max_diff_chars` to provide more context in AI prompts, or lower `confidence_threshold` to accept more AI classifications.

## Contributing

See [CONTRIBUTING.md](../../../../CONTRIBUTING.md) for development guidelines.

## License

MIT License - see [LICENSE](../../../../LICENSE)

## Support

- **Issues**: https://github.com/huntridge-labs/argus/issues
- **Documentation**: https://github.com/huntridge-labs/argus
- **FedRAMP Guidance**: https://www.fedramp.gov/documents/
