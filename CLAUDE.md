# Argus

Composite actions for comprehensive security scanning, designed for GitHub Enterprise Server (GHES) with github.com access.

---

## Project Vision & Goals

**Primary Vision**: Make it as easy as possible for users to employ a hardening pipeline on their projects to gain insights into their security footprint and current vulnerabilities.

### Core Principles

1. **Documentation serves both humans and AI**: Concise, clear, on point. Structured context in `.ai/` for machine-readability.
2. **Code must be simple and maintainable**: Minimize complexity, maximize clarity. Easy for anyone to understand and extend.
3. **Dependabot is foundational**: Automated dependency updates are critical to the pipeline's value.
4. **Trust is everything**: The pipeline must earn trust in PRs through extremely robust testing. Only then can it auto-merge and auto-release.
5. **Automation end-state**:
   - Dependabot dependency updates arrive in PRs
   - Pipeline runs automatically
   - Green test results = trusted
   - Auto-merge enabled
   - Auto-release to users

---

## Testing Philosophy

**Just completed migration: ALL action scripts and tests are now Python.**

### Standards

- **Single Language**: Python for all action scripts and tests (not Bash, not Node.js for actions)
- **Single Test Framework**: pytest (not jest, mocha, or other)
- **Single Coverage Tool**: pytest-cov (with `--cov-fail-under=80` in pytest.ini)
- **Minimum Coverage**: 80% enforced at all times

### Test Structure

```
.github/actions/scanner-{name}/
├── scripts/
│   ├── parse-results.py       # Scanner output → JSON
│   └── generate-summary.py    # JSON → Markdown
└── tests/
    ├── test_parse_results.py
    ├── test_generate_summary.py
    └── conftest.py (optional)

tests/
├── fixtures/
│   └── scanner-outputs/       # Pre-captured real scanner results
└── (integration tests)
```

### Test Execution

```bash
# Full run with coverage (enforced: ≥80%)
pytest

# Fast validation (no coverage)
pytest --no-cov -q

# Specific action
pytest .github/actions/scanner-clamav/tests/
```

### Reference Implementation

**`scanner-clamav`** is the reference pattern for:
- Python action script structure
- Test organization and fixtures
- Coverage targets (80%+)
- How to test scanner parsing and summary generation

All new scanner actions should follow this exact pattern.

---

## Project Conventions

### Versioning & Release

- **Single Version Source**: `version.yaml` (prevents drift)
- **Release Command**: `npm run release` (manages all version updates and tags)
- **Version Tags**: Release workflow auto-tags and publishes

### Commit Messages

Follow **Conventional Commits**:
```
feat(scanner-name): add support for X
fix(parser): handle empty results
docs: update scanner reference
test(bandit): add edge case coverage
refactor: simplify parse logic
```

### Release Process

Users depend on you auto-releasing after dependency updates pass. The testing pipeline must be bulletproof for this trust.

---

## AI Context Ecosystem

This project uses **AI Context as Code (AICaC)** - structured, machine-readable context in `.ai/`:

| File | Purpose |
|------|---------|
| `.ai/context.yaml` | Project metadata and entry points |
| `.ai/architecture.yaml` | Component relationships and dependencies |
| `.ai/workflows.yaml` | Common tasks with exact commands |
| `.ai/decisions.yaml` | Architectural Decision Records (ADRs) |
| `.ai/errors.yaml` | Error patterns and solutions |
**Reading order**: `.ai/context.yaml` → relevant module files → source code

### CRITICAL: Maintain .ai/ Files

**After making changes to this project, you MUST update the relevant `.ai/` files.**

| When you change... | Update... |
|--------------------|-----------|
| Components/structure | `.ai/architecture.yaml` |
| Commands/tasks | `.ai/workflows.yaml` |
| Make design decisions | `.ai/decisions.yaml` |
| Fix common errors | `.ai/errors.yaml` |
| Project metadata | `.ai/context.yaml` |
| Scanners or actions | `.ai/architecture.yaml` (scanners list + components) |
| Version number | `.ai/context.yaml` (version field) |

**Before completing any task**, verify:
```
[ ] Relevant .ai/ files updated (or confirmed not needed)
```

---

## AI Assistant Configuration

### Global Standards (Claude Code)

Claude Code users: Global rules, skills, and agents from `~/.claude/` are automatically applied. These include:

- **Rules**: coding-style, git-workflow, testing, security, performance, refactor-clean
- **Skills**: security-skills, documentation-skills, data-analysis-skills
- **Agents**: planner, security-reviewer, technical-docs-writer

Source: [huntridge-labs/cheat-codes](https://github.com/huntridge-labs/cheat-codes)

### Project Overrides

To override global settings for this project, create `.claude/settings.json`:

```json
{
  "rules": {
    "disabled": ["performance"],
    "project_specific": true
  }
}
```

Or add project-specific rules in `.claude/rules/`.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CLAUDE_SKIP_GLOBAL_RULES` | Skip loading ~/.claude/rules/ | `false` |
| `CLAUDE_VERBOSE` | Show which rules are being applied | `false` |

### GitHub Copilot Users

Copilot reads only this file (via `.github/copilot-instructions.md` symlink). Global `~/.claude/` config does not apply. Key standards to follow:

- **Commits**: Conventional commits (`feat:`, `fix:`, `refactor:`, etc.)
- **Testing**: 80%+ coverage, TDD for new features
- **Security**: No hardcoded secrets, validate inputs, use parameterized queries
- **Code Style**: Functional patterns, immutability, early returns

---

## Architecture

Composite actions are the primary architecture. Reusable workflows are maintained as thin backwards-compatible wrappers.

```
.github/actions/
├── scanner-*/                         # Individual scanner actions
│   ├── action.yml                    # Action definition
│   ├── .docsite.yml                  # Docsite category declaration
│   ├── scripts/                      # Supporting Python scripts
│   │   ├── parse-results.py         # Result parsing
│   │   └── generate-summary.py      # Summary generation
│   ├── tests/                        # Co-located pytest tests
│   └── README.md                     # Action documentation
├── parse-container-config/           # Config-driven container scanning
├── comment-pr/                       # PR comment utility
├── security-summary/                 # Aggregate security results
└── linting-summary/                  # Aggregate linting results

examples/workflows/                   # User-facing workflow examples
```

**Why Composite Actions?**
- Works on any GHES with github.com access (no reusable workflow restrictions)
- Self-contained with scripts and dependencies
- Easier to compose and customize
- Faster execution (no cross-repo workflow calls)

## Scanner Action Flow

1. User configures action inputs (paths, severity thresholds, etc.)
2. Action runs scanner with appropriate configuration
3. Results parsed by action's `scripts/parse-results.py`
4. Summary generated by `scripts/generate-summary.py`
5. Artifacts uploaded (reports, SARIF, summaries)
6. Outputs set (counts, status) for downstream jobs
7. Optional: PR comment posted
8. Optional: SARIF uploaded to GitHub Security

## Adding a New Scanner Action

See `CONTRIBUTING.md` for the complete composite actions development guide. Key steps:

1. **Create action structure**:
   ```bash
   mkdir -p .github/actions/scanner-{name}/scripts
   ```

2. **Create action.yml** with standard inputs/outputs:
   ```yaml
   inputs:
     scan_path:              # What to scan
     fail_on_severity:       # Severity threshold
     enable_code_security:   # Upload SARIF
     post_pr_comment:        # Post PR comments
   outputs:
     critical_count:         # Number of critical findings
     high_count:            # Number of high findings
     # ... other severity counts
   ```

3. **Create scripts**:
   - `scripts/parse-results.py` - Parse scanner output, extract counts
   - `scripts/generate-summary.py` - Generate markdown summary

4. **Add tests**:
   - Co-located pytest tests in `tests/` directory
   - Use shared fixtures from `tests/fixtures/`

5. **Update documentation**:
   - Action README.md with usage examples
   - `.github/actions/README.md` catalog
   - `examples/workflows/composite-actions-example.yml`

## Supported Scanners

| Category | Actions | Documentation |
|----------|---------|---------------|
| **SAST** | scanner-codeql<br>scanner-bandit<br>scanner-opengrep | Multi-language<br>Python<br>Pattern-based |
| **Secrets** | scanner-gitleaks | Git history & files |
| **Dependencies** | scanner-osv<br>scanner-dependency-review | OSV database<br>PR diff analysis & license compliance |
| **Infrastructure** | scanner-trivy-iac<br>scanner-checkov | Terraform, K8s, etc.<br>Multi-framework |
| **Container** | scanner-container | Trivy + Grype + Syft |
| **Malware** | scanner-clamav | File scanning |
| **Supply Chain** | scanner-supply-chain | GitHub Actions workflow security (zizmor + actionlint) |
| **DAST** | scanner-zap | Web applications |
| **Compliance** | scn-detector | FedRAMP SCN detection |
| **Linting** | linter-yaml<br>linter-json<br>linter-python<br>linter-javascript<br>linter-dockerfile<br>linter-terraform | Syntax & style |

## Testing

All tests are Python with pytest. Coverage enforced at 80% via pytest-cov.

```
.github/actions/scanner-{name}/tests/   # Co-located with each action
tests/fixtures/                          # Shared mock data and test apps
```

**Coverage**: Python pytest-cov (80%+), reported via Codecov

## Key Inputs (Standard Across Actions)

Most scanner actions support these common inputs:

| Input | Description | Default |
|-------|-------------|---------|
| `scan_path` / `iac_path` / `target_url` | What to scan | Varies by scanner |
| `fail_on_severity` | Fail threshold | `none` |
| `enable_code_security` | Upload SARIF to Security tab | `false` |
| `post_pr_comment` | Post results as PR comment | `true` |
| `job_id` | Job ID for artifact naming | `${{ github.job }}` |

## Usage Examples

### Individual Scanner
```yaml
- name: Run Bandit Python Scanner
  uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.7.1
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    scan_path: 'src'
    fail_on_severity: 'high'
    enable_code_security: true
```

### Complete Security Workflow
See `examples/composite-actions-example.yml` for a full example with:
- Multiple scanners running in parallel
- security-summary aggregating results
- PR comments with findings
- SARIF uploads to GitHub Security

### Config-Driven Container Scanning
```yaml
- uses: huntridge-labs/argus/.github/actions/parse-container-config@0.7.1
  id: parse
  with:
    config_file: 'container-config.yml'

- uses: huntridge-labs/argus/.github/actions/scanner-container@0.7.1
  strategy:
    matrix: ${{ fromJson(steps.parse.outputs.matrix) }}
  with:
    image_ref: ${{ matrix.image }}
    scanners: ${{ matrix.scanners }}
```

## Contributing

See `CONTRIBUTING.md` for:
- Composite action development guide (step-by-step)
- Parser and summary script templates
- Testing requirements (unit + integration)
- Code review checklist
- Best practices and patterns

## Example Workflow Validation

When creating or modifying example workflows in `examples/`, ensure they are valid and functional:

### Validation Requirements

All example workflows must:
1. ✅ Use valid YAML syntax
2. ✅ Reference existing action paths (paths must exist in `.github/actions/`)
3. ✅ Include all required action inputs
4. ✅ Have clear documentation and comments
5. ✅ Follow current conventions and best practices

**Note:** Version references (e.g., `@main`, `@0.6.5`) are managed by `release-it` during releases. Examples should use appropriate references that will be updated automatically.

### Testing Examples Locally

Before committing example changes, validate them:

```bash
# Validate YAML syntax for all examples
for example in examples/*.yml; do
  python -c "import yaml; yaml.safe_load(open('$example'))" || echo "❌ Invalid: $example"
done

# Validate config examples parse correctly
python -c "import yaml; yaml.safe_load(open('examples/container-config.example.yml'))"
python -c "import json; json.load(open('examples/container-config.example.json'))"

# Run full validation suite
npm test
```

### Example Quality Checklist

When adding/updating examples:
- [ ] YAML syntax is valid (run `python -c "import yaml; yaml.safe_load(open('example.yml'))"`)
- [ ] All action references point to existing actions in `.github/actions/`
- [ ] Required inputs are documented with clear comments
- [ ] Optional inputs show sensible defaults
- [ ] Has descriptive workflow name and job names
- [ ] Includes `on:` trigger section (even if just `workflow_dispatch`)
- [ ] Permissions are explicitly set (principle of least privilege)
- [ ] Comments explain the purpose and key configuration options
- [ ] Uses version references compatible with release-it (e.g., `@main`, `@0.6.5`)

### Automated Validation

Examples are automatically validated by `.github/workflows/test-examples-functional.yml`:
- Runs on PRs that modify `examples/` or `.github/actions/`
- Validates each example using a dynamic matrix strategy
- Checks syntax, action paths, and structure
- No duplication - validates the actual example files themselves

**Note**: Example validation focuses on documentation quality. Functional testing of actions themselves is handled by `test-actions.yml`. Version references are managed by release-it during the release process.

## Important Files

- `CLAUDE.md` - AI assistant reference guide (this file)
- `AGENTS.md` - Cross-tool AI entry point
- `CONTRIBUTING.md` - Composite actions contributor guide
- `tests/CONTRIBUTING.md` - How to add tests for actions
- `examples/README.md` - Example usage patterns and testing info
- `.ai/` - Structured AI context (AICaC) — keep in sync with code changes
- `examples/workflows/` - Usage examples for all actions
