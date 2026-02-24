# AGENTS.md

> AI coding assistants: Read this file first. For structured/machine-readable data, see `.ai/context.yaml`.

## Project Identity

**argus** is a GitHub Actions security scanning framework by Huntridge Labs.

- **What it does**: Orchestrates 14 security scanners (SAST, secrets, containers, IaC, DAST) from a single workflow call
- **Current version**: 2.12.0
- **License**: AGPL-3.0

### One-Liner
Reusable GitHub Actions workflows + composite actions with unified interface, SARIF upload, and PR comments.

---

## Architecture Overview

### Critical: Dual Implementation

This project has TWO parallel implementations. Always clarify which the user needs:

| v2.x (Production) | v3.0 (In Development) |
|-------------------|----------------------|
| Reusable workflows | Composite actions |
| `.github/workflows/` | `.github/actions/` |
| Tag: `@v2.12.0` | Tag: `@v3` (future) |
| Requires github.com | Works on GHES |

**Default assumption**: If user doesn't specify, assume v2.x.

### Directory Structure

```
.github/
├── actions/           # v3.0 composite actions
│   └── scanner-*/     # Each: action.yml, scripts/, tests/
├── workflows/         # v2.x reusable workflows
│   └── reusable-security-hardening.yml  # MAIN ENTRY POINT
└── schemas/           # JSON schemas for config validation

examples/              # User-facing workflow examples
tests/                 # Test infrastructure
docs/                  # Detailed documentation
```

### Supported Actions

| Category | Actions | Purpose |
|----------|---------|---------|
| SAST | codeql, bandit, opengrep | Code security analysis |
| Secrets | gitleaks | Credential detection |
| Container | trivy, grype, syft | Container scanning |
| IaC | trivy-iac, checkov | Infrastructure as Code |
| Malware | clamav | File malware detection |
| DAST | zap | Dynamic web app security |
| Compliance | scn-detector | FedRAMP change notifications |

---

## Setup & Environment

### For Users (Consuming the Workflows)

No setup required. Reference workflows directly:

```yaml
uses: huntridge-labs/argus/.github/workflows/reusable-security-hardening.yml@main
with:
  scanners: all
  enable_code_security: true
  github_token: ${{ secrets.GITHUB_TOKEN }}
```

### For Contributors (Developing)

```bash
# Clone and install
git clone <repo>
pip install -r requirements.txt

# Dev container (recommended)
# Open in VS Code → "Reopen in Container"

# Or manual setup
pip install -r .devcontainer/requirements.txt
```

---

## Build & Test Commands

```bash
# Run all tests
pytest

# With coverage
pytest --cov

# Fast validation (no coverage)
pytest --no-cov -q

# Linting
npm run lint
```

### Coverage Targets
- Overall: 80%+

### Testing Levels

**For simple actions** (scanners with 2 scripts):
1. **Unit tests**: Test parse/summary scripts with fixtures
2. **Integration**: Run action in test workflow

**For complex actions** (multi-script with logic):
1. **Level 1 - Unit Tests**: Test individual Python functions
   ```bash
   pytest .github/actions/my-action/tests/test_*.py -v
   ```

2. **Level 2 - Script Integration**: Test scripts end-to-end with mock data
   ```bash
   python scripts/classify.py --input mock-data.json --output results.json
   ```

3. **Level 3 - Action Integration**: Test full action with `act` locally
   ```bash
   act pull_request -j test-job --secret GITHUB_TOKEN=$TOKEN
   ```

4. **Level 4 - Full Workflow**: Test in real GitHub Actions environment
   - Create test branch with real changes
   - Open PR, verify action runs correctly

5. **Level 5 - AI Fallback**: Test external API integration (mock in CI)
   ```python
   @patch('requests.post')
   def test_ai_classification(mock_post):
       mock_post.return_value.json.return_value = {...}
   ```

6. **Level 6 - Performance**: Large inputs, stress testing

7. **Level 7 - Edge Cases**: Empty files, malformed configs, API failures

**Test Organization**:
```
tests/
├── fixtures/              # Mock data, sample configs
│   ├── api-responses/    # Mock AI/API responses
│   └── sample-data/      # Real-world examples
├── unit/                  # Fast unit tests
└── integration/           # Slower integration tests
```

---

## Code Conventions

### File Naming
- Workflows: `scanner-{name}.yml`, `reusable-{purpose}.yml`
- Actions: `.github/actions/scanner-{name}/`
- Tests: Co-located in `tests/` subdirectory of each action

### Action Structure

**Scanner Pattern** (2-script, parse + summarize):
```
.github/actions/scanner-{name}/
├── action.yml              # Inputs, outputs, steps
├── scripts/
│   ├── parse-results.py    # Scanner output → JSON
│   └── generate-summary.py # JSON → Markdown summary
├── tests/
│   ├── test_parse_results.py
│   ├── test_generate_summary.py
│   └── conftest.py (optional)
└── README.md
```

**Multi-Script Pattern** (complex workflows with multiple stages):
```
.github/actions/{name}/
├── action.yml              # Orchestrates multiple scripts
├── scripts/
│   ├── analyze.py          # Data analysis/extraction
│   ├── classify.py         # Classification/decision logic
│   ├── generate-report.py  # Report generation
│   └── create-issue.py     # GitHub integration (optional)
├── tests/
│   ├── test_analyze.py
│   ├── test_classify.py
│   ├── test_generate_report.py
│   ├── test_create_issue.py
│   └── conftest.py
└── README.md

# Example: scn-detector (FedRAMP compliance)
# - analyze_iac_changes.py: Extract IaC changes from git diff
# - classify_changes.py: Classify using rules + AI fallback
# - generate_scn_report.py: Create compliance reports
# - create_scn_issue.py: GitHub Issues with timelines
```

### Commit Messages
Follow Conventional Commits:
```
feat(scanner): add support for X
fix(trivy): handle empty results
docs: update scanner reference
test(bandit): add edge case pytest coverage
```

### Design Patterns

**Hybrid Classification (Rules + AI Fallback)**
When building actions that need intelligent decision-making:
1. **Rule-based first**: Fast, deterministic, cost-free
2. **AI fallback**: For ambiguous cases that rules can't handle
3. **Confidence thresholds**: If AI confidence < threshold, flag for manual review
4. **Mock AI in tests**: Use fixtures for reliable testing

```python
# Example from scn-detector
def classify_change(self, change: Dict) -> Dict:
    # Try rule-based first
    result = self.classify_with_rules(change)
    if result:
        return result

    # Fallback to AI if enabled
    if self.enable_ai:
        return self.classify_with_ai(change)

    # Flag for manual review
    return {"category": "MANUAL_REVIEW"}
```

**Generic vs. Cloud-Specific Patterns**
For broader applicability across clouds/platforms:
- ✅ **Generic attributes**: `encryption`, `region`, `capacity`, `authentication`
- ❌ **Cloud-specific**: `aws_bedrock`, `azure_openai`, `google_vertex_ai`

```yaml
# Good: Works across AWS, Azure, GCP, custom platforms
transformative:
  - pattern: "ai_service|ml_service|ml_model"
    description: "AI/ML capabilities"
  - attribute: "region|location|datacenter"
    description: "Geographic changes"

# Bad: Only works for AWS
transformative:
  - resource: "aws_bedrock.*"
    description: "AWS Bedrock only"
```

**Rule Ordering & Priority**
When processing rules for classification:
1. **Within category**: Check specific patterns before generic ones
2. **Across categories**: Order categories by desired precedence
3. **First match wins**: Stop processing after first successful match

```yaml
# Example: Check transformative (specific) before routine (generic)
transformative:
  - resource: "aws_bedrock.*"  # Specific resource type
    operation: "create"

routine:
  - attribute: "description"    # Generic attribute
    # This would match almost anything, so check last
```

**Business Day Calculations**
For compliance/audit timelines:
- Exclude weekends from calculations
- Use `datetime` + `timedelta` + weekend checks
- Document timezone assumptions (usually UTC)

```python
def calculate_business_days(start_date: datetime, num_days: int) -> datetime:
    current = start_date
    days_added = 0
    while days_added < num_days:
        current += timedelta(days=1)
        if current.weekday() < 5:  # Monday=0, Sunday=6
            days_added += 1
    return current
```

**AI API Integration with Fallback**
When integrating external AI APIs (Anthropic, OpenAI, etc.):

1. **Make it optional**: AI should be fallback, not requirement
   ```yaml
   inputs:
     enable_ai_fallback:
       default: 'true'
     anthropic_api_key:
       required: false
   ```

2. **Graceful degradation**: Handle API failures
   ```python
   def classify(self, data):
       # Try rule-based first
       result = self.classify_with_rules(data)
       if result:
           return result

       # AI fallback if enabled and API key present
       if self.enable_ai and self.api_key:
           try:
               return self.classify_with_ai(data)
           except Exception as e:
               logger.warning(f"AI fallback failed: {e}")
               return {"category": "MANUAL_REVIEW"}

       return {"category": "MANUAL_REVIEW"}
   ```

3. **Mock in tests**: Never make real API calls in CI
   ```python
   @patch('anthropic.Anthropic')
   def test_ai_classification(self, mock_anthropic):
       mock_client = Mock()
       mock_client.messages.create.return_value = Mock(
           content=[Mock(text='{"category": "TRANSFORMATIVE"}')]
       )
       mock_anthropic.return_value = mock_client

       result = classifier.classify_with_ai(change)
       assert result['category'] == 'TRANSFORMATIVE'
   ```

4. **Use fixtures for API responses**:
   ```
   tests/fixtures/api-responses/
   ├── classification-high-confidence.json
   ├── classification-low-confidence.json
   └── classification-error.json
   ```

5. **Document API costs**: Claude Haiku ~$0.25/million input tokens

---

## Common Tasks

### Add Security Scanning to a Repo

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    uses: huntridge-labs/argus/.github/workflows/reusable-security-hardening.yml@main
    with:
      scanners: codeql,bandit,gitleaks
      fail_on_severity: high
      enable_code_security: true
    secrets:
      github_token: ${{ secrets.GITHUB_TOKEN }}
```

### Scan Container Images

```yaml
uses: huntridge-labs/argus/.github/workflows/container-scan-from-config.yml@main
with:
  config_file: .github/container-config.yml
```

Config file format:
```yaml
version: "1.0"
containers:
  - name: app
    registry: ghcr.io
    image: org/app
    tag: latest
    scanners: [trivy, grype]
```

### Add a New Scanner (Contributors)

1. Create `.github/actions/scanner-{name}/action.yml`
2. Add `scripts/parse-results.py` (convert output → JSON)
3. Add `scripts/generate-summary.py` (JSON → Markdown)
4. Add pytest tests in `tests/` directory
5. Update `docs/scanners.md`
6. Add to matrix in main orchestrator

### GitHub Integration Patterns

**PR Comments** (Standard for most scanners):
```yaml
- name: Post PR Comment
  if: github.event_name == 'pull_request'
  uses: huntridge-labs/argus/.github/actions/comment-pr@main
  with:
    comment_file: summary.md
```

**GitHub Issues** (For audit trails, compliance, tracking):
```python
# Use PyGithub or direct API calls
from github import Github

g = Github(os.environ['GITHUB_TOKEN'])
repo = g.get_repo(os.environ['GITHUB_REPOSITORY'])

issue = repo.create_issue(
    title=f"🔐 Compliance: {category} - {resource}",
    body=issue_body,
    labels=['compliance', f'scn:{category.lower()}']
)
```

**When to use Issues vs PR Comments**:
- **PR Comments**: Immediate feedback, scanner results, validation
- **Issues**: Audit trail, compliance tracking, follow-up tasks, timelines

**Required Permissions**:
```yaml
permissions:
  pull-requests: write  # For PR comments
  issues: write         # For Issue creation
  security-events: write # For SARIF upload
```

---

## Error Resolution

### "Resource not accessible by integration"
**Cause**: Missing permissions
**Fix**: Add to workflow:
```yaml
permissions:
  security-events: write
  pull-requests: write
```

### "Scanner X not found in matrix"
**Cause**: Invalid scanner name
**Valid names**: `codeql`, `bandit`, `gitleaks`, `opengrep`, `trivy`, `grype`, `syft`, `checkov`, `trivy-iac`, `clamav`, `zap`

### SARIF Upload Fails
**Cause**: GitHub Advanced Security not enabled
**Fix**: Settings → Security → Enable "GitHub Advanced Security"

### PR Comment Not Appearing
**Fix**: Ensure `enable_pr_comment: true` and `pull-requests: write` permission

---

## Security Considerations

- **Never** commit registry credentials in config files
- **Always** use GitHub Secrets for sensitive values
- **Pin** to version tags (`@main`), never `@main`
- **Enable** SARIF upload when GitHub Advanced Security available
- **Review** scanner findings before suppressing

---

## PR Guidelines

### CRITICAL: Feature Branch Workflow

**NEVER commit directly to main.** Always use feature branches and create draft PRs for team review.

```bash
# Create feature branch
git checkout -b feat/my-feature

# Make changes and commit
git add .
git commit -m "feat(component): description"

# Push to origin
git push origin feat/my-feature

# Create draft PR for team review
gh pr create --draft --title "..." --body "..."

# Or use GitHub UI: Check "Create as draft"
```

### Before Creating PR
- [ ] All tests pass (`pytest`)
- [ ] No linting errors (`npm run lint`)
- [ ] Conventional commit messages used
- [ ] Documentation updated if needed
- [ ] Action README updated if action changed
- [ ] Feature branch (not main)
- [ ] Draft PR for team review

### PR Description Template
```markdown
## Summary
Brief description of changes

## Type
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Test improvement

## Testing
How was this tested?

## Checklist
- [ ] Tests added/updated
- [ ] Docs updated
- [ ] CHANGELOG entry (if user-facing)
```

---

## Key Decisions (Why Things Are This Way)

| Decision | Reason |
|----------|--------|
| Dual implementation (workflows + actions) | GHES doesn't support cross-repo `workflow_call` |
| SARIF as output format | GitHub Security tab integration, industry standard |
| Python for all scripts | Single language, one test framework (pytest), unified coverage |
| Co-located tests | Tests live next to code they test |
| Single version.yaml | Prevents version drift across 20+ files |
| Feature branches + draft PRs | Team review required, never commit to main |
| Hybrid classification (rules + AI) | Fast/deterministic rules, AI handles ambiguity |
| Generic patterns over cloud-specific | Broader applicability (AWS, Azure, GCP, custom) |
| GitHub Issues for compliance | Audit trail with 90-day artifact retention |
| Rule-based before AI | Cost-free, deterministic, testable |

---

## AI-Specific Notes

### Structured Data Available (AICaC)

This project uses **AI Context as Code (AICaC)** for token-efficient documentation.
Tools that support structured context should read files in `.ai/` directory:

| File | Purpose |
|------|---------|
| `.ai/context.yaml` | Project metadata, identity, glossary |
| `.ai/architecture.yaml` | Components, dependencies, data flow |
| `.ai/workflows.yaml` | Common tasks with exact commands |
| `.ai/decisions.yaml` | Architectural Decision Records (ADRs) |
| `.ai/errors.yaml` | Error patterns → solutions |
| `.ai/prompting.md` | Guide for humans asking questions |

**Additional reference files:**
- `CLAUDE.md` - Claude-specific extended context

### Context Loading Priority
1. This file (AGENTS.md) - Quick orientation
2. `.ai/context.yaml` - Project overview
3. `.ai/architecture.yaml` - How it's built
4. `.ai/workflows.yaml` - How to do tasks
5. `.ai/errors.yaml` - Troubleshooting
6. `.ai/decisions.yaml` - Why decisions were made
7. `docs/scanners.md` - Scanner configuration details
8. `examples/` - Working code examples

### Common Question Patterns
- "How do I scan X?" → See Common Tasks section
- "What scanners exist?" → See Supported Scanners table
- "Why doesn't X work?" → See Error Resolution section
- "Which implementation?" → v2.x unless user has GHES without github.com access

### CRITICAL: Maintain .ai/ Files

**After making changes to this project, you MUST update the relevant `.ai/` files.**

| When you change... | Update... |
|--------------------|-----------|
| Components/structure | `.ai/architecture.yaml` |
| Commands/tasks | `.ai/workflows.yaml` |
| Make design decisions | `.ai/decisions.yaml` |
| Fix common errors | `.ai/errors.yaml` |
| Project metadata | `.ai/context.yaml` |

See `.ai/MAINTENANCE.md` for detailed update instructions.

**Before completing any task**, verify:
```
[ ] Relevant .ai/ files updated (or confirmed not needed)
```

---

## Quick Reference

| Need | Location |
|------|----------|
| Main workflow | `.github/workflows/reusable-security-hardening.yml` |
| All scanners | `docs/scanners.md` |
| Examples | `examples/workflows/` |
| Container config schema | `.github/schemas/container-config.schema.json` |
| Version | `version.yaml` |
| Changelog | `CHANGELOG.md` |

---

## Links

- [Quick Start Guide](QUICK-START.md)
- [Full Documentation](README.md)
- [Scanner Reference](docs/scanners.md)
- [Contributing Guide](CONTRIBUTING.md)
