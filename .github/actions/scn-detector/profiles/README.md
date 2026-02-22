# SCN Detector Configuration Profiles

This directory contains configuration profiles for the FedRAMP Significant Change Notification (SCN) detector.

## What is a Profile?

A profile defines:
- **Classification rules** for each FedRAMP category (ROUTINE, ADAPTIVE, TRANSFORMATIVE, IMPACT)
- **AI prompts** for fallback classification when rules don't match
- **Notification timelines** based on FedRAMP requirements
- **Issue templates** for tracking compliance workflows

## Built-in Profiles

### `fedramp-low.yml` (Default)
Classification rules for **FedRAMP Low impact systems**.

**Use when:**
- System handles only low-impact data
- Confidentiality, integrity, and availability impacts are LOW
- Examples: Public websites, non-sensitive data processing

**Key characteristics:**
- Focused on security boundary and encryption changes
- AI/ML services are typically TRANSFORMATIVE
- Infrastructure scaling is ADAPTIVE or ROUTINE

### Future Profiles (Planned)

- `fedramp-moderate.yml` - For moderate impact systems
- `fedramp-high.yml` - For high impact systems
- `custom-template.yml` - Template for creating custom profiles

## Profile Structure

```yaml
version: "1.0"
name: "Profile Display Name"
description: "Profile description"
compliance_framework: "FedRAMP 20X"
impact_level: "Low|Moderate|High"

rules:
  routine:
    - pattern: 'regex_pattern'
      description: 'What this matches'
    - resource: 'resource_type_pattern'
      operation: 'create|modify|delete'
      description: 'What this matches'

  adaptive:
    - resource: 'aws_instance.*.instance_type'
      operation: 'modify'
      description: 'Instance type changes'

  transformative:
    - resource: 'aws_rds_.*\.engine'
      operation: 'modify'
      description: 'Database engine changes'

  impact:
    - attribute: '.*encryption.*'
      operation: 'delete|modify'
      description: 'Encryption changes'

ai_fallback:
  enabled: true
  model: 'claude-3-haiku-20240307'
  confidence_threshold: 0.8
  system_prompt: |
    Your expert prompt here
  user_prompt_template: |
    Change Details: {resource_type}, {operation}, etc.

notifications:
  adaptive:
    post_completion_days: 10
  transformative:
    initial_notice_days: 30
    final_notice_days: 10

issue_templates:
  labels:
    prefix: "scn"
  checklist:
    adaptive:
      - "Required step 1"
      - "Required step 2"
```

## Using Profiles

### Use Built-in Profile (Default)

```yaml
- uses: huntridge-labs/argus/.github/actions/scn-detector@main
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  # No profile specified = uses fedramp-low.yml
```

### Use Custom Profile

Create your custom profile file:

```yaml
# .github/scn-profiles/my-custom-profile.yml
version: "1.0"
name: "My Custom Profile"
# ... rest of profile config
```

Reference it in your workflow:

```yaml
- uses: huntridge-labs/argus/.github/actions/scn-detector@main
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    config_file: '.github/scn-profiles/my-custom-profile.yml'
```

### Use Separate AI Configuration (Recommended)

For maximum flexibility, separate your AI settings from your SCN profile:

**Benefits:**
- Share one AI config across multiple SCN profiles
- Swap AI providers without modifying classification rules
- Keep credentials/settings separate from compliance rules
- Easier to manage and version control

Create AI config file:

```yaml
# .github/ai-config.yml
provider: 'openai'  # or 'anthropic'
model: 'gpt-4o-mini'
confidence_threshold: 0.85
max_tokens: 2048
```

Use in workflow:

```yaml
- uses: huntridge-labs/argus/.github/actions/scn-detector@main
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
  with:
    config_file: '.github/scn-profiles/my-profile.yml'  # Classification rules
    ai_config_file: '.github/ai-config.yml'              # AI provider settings
    enable_ai_fallback: true
```

See `examples/configs/ai-config.example.yml` for full AI configuration options.

## Rule Matching Logic

Rules are evaluated in priority order:

1. **Pattern** - Matches resource name, type, or attributes (regex)
2. **Resource** - Matches `resource_type.resource_name` or `resource_type.name.attribute`
3. **Attribute** - Matches specific changed attributes
4. **Operation** - Filters by create/modify/delete

### Rule Evaluation Order

Categories are checked from **least to most severe**:
1. ROUTINE
2. ADAPTIVE
3. TRANSFORMATIVE
4. IMPACT

**First match wins** - more specific rules should be placed earlier in each category.

## AI Fallback

When no rule matches, the AI fallback (if enabled) uses:
- `system_prompt` - Context about compliance framework and impact level
- `user_prompt_template` - Template with placeholders: `{resource_type}`, `{resource_name}`, `{operation}`, `{attributes}`, `{diff_snippet}`

The AI response must be valid JSON:
```json
{
  "category": "ROUTINE|ADAPTIVE|TRANSFORMATIVE|IMPACT",
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation"
}
```

## Creating Custom Profiles

### 1. Start with Template

Copy `fedramp-low.yml` as a starting point:

```bash
cp .github/actions/scn-detector/profiles/fedramp-low.yml \
   .github/scn-profiles/my-profile.yml
```

### 2. Customize Rules

Modify rules to match your compliance requirements:
- Add organization-specific resources
- Adjust severity thresholds
- Include custom patterns

### 3. Test Profile

```bash
python3 .github/actions/scn-detector/scripts/classify_changes.py \
  --input test-changes.json \
  --output classifications.json \
  --config .github/scn-profiles/my-profile.yml
```

### 4. Validate YAML

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/scn-profiles/my-profile.yml'))"
```

## Profile Best Practices

1. **Start Conservative** - Classify changes as higher severity when uncertain
2. **Document Rules** - Clear descriptions help auditors understand decisions
3. **Test Thoroughly** - Use real infrastructure changes to validate rules
4. **Version Control** - Track profile changes alongside infrastructure code
5. **Regular Review** - Update profiles as compliance requirements evolve

## Notification Timelines (FedRAMP)

| Category | Initial Notice | Final Notice | Post-Completion |
|----------|---------------|--------------|-----------------|
| ROUTINE | None | None | None |
| ADAPTIVE | None | None | 10 business days |
| TRANSFORMATIVE | 30 business days | 10 business days | Required |
| IMPACT | Requires new authorization (contact AO/3PAO) | | |

## Support

- **Issues**: https://github.com/huntridge-labs/argus/issues
- **Documentation**: https://github.com/huntridge-labs/argus
- **FedRAMP Guidance**: https://www.fedramp.gov/documents/
