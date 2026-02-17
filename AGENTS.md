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

### Supported Scanners

| Category | Scanners |
|----------|----------|
| SAST | codeql, bandit, opengrep |
| Secrets | gitleaks |
| Container | trivy, grype, syft |
| IaC | trivy-iac, checkov |
| Malware | clamav |
| DAST | zap |

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

---

## Code Conventions

### File Naming
- Workflows: `scanner-{name}.yml`, `reusable-{purpose}.yml`
- Actions: `.github/actions/scanner-{name}/`
- Tests: Co-located in `tests/` subdirectory of each action

### Action Structure
Every composite action follows this pattern:
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

### Commit Messages
Follow Conventional Commits:
```
feat(scanner): add support for X
fix(trivy): handle empty results
docs: update scanner reference
test(bandit): add edge case pytest coverage
```

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

### Before Creating PR
- [ ] All tests pass (`pytest`)
- [ ] No linting errors (`npm run lint`)
- [ ] Conventional commit messages used
- [ ] Documentation updated if needed
- [ ] Action README updated if action changed

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
