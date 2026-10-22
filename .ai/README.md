# AI Context as Code (AICaC)

This directory contains structured, machine-optimized documentation for AI coding assistants.

## Specification

**Version:** 1.0
**Schema:** https://aicac.dev/schema/v1 *(forthcoming)*

## Files

| File | Purpose |
|------|---------|
| `context.yaml` | Project metadata, identity, constraints |
| `architecture.yaml` | Components, dependencies, data flow |
| `workflows.yaml` | Common tasks with exact commands |
| `decisions.yaml` | Architectural Decision Records ADR-001 to ADR-044 (closed to new entries) |
| `decisions/ADR-<issue>.yaml` | Newer ADRs, one file each, keyed to the issue that asked for them |
| `errors.yaml` | Error patterns → solutions |

## For AI Assistants

**IMPORTANT**: After making changes to this project, update the relevant `.ai/` files.
See the mapping in `AGENTS.md` for what to update and when. New ADRs follow "Issues, branches, and records" in `AGENTS.md`.

**Reading order:**
1. `context.yaml` - Understand what this project is
2. `architecture.yaml` - Understand how it's built
3. `workflows.yaml` - Find how to do common tasks
4. `errors.yaml` - Troubleshoot issues
5. `decisions.yaml` + `decisions/` - Understand why decisions were made (`python -m scripts.ci.adr_records list` merges both)

**If information conflicts with source code**, these files may be stale. Note the discrepancy in your response.

## For Humans

This directory complements (not replaces):
- `README.md` - Human-friendly introduction
- `AGENTS.md` - Entry point for every coding agent
- `CLAUDE.md` - Imports `AGENTS.md`

## Validation

```bash
# Future tooling
aicac validate .ai/
aicac lint --check-required-fields
```

## About AICaC

AI Context as Code (AICaC) is a structured, machine-optimized approach to project documentation. It uses YAML files to provide token-efficient context that AI assistants can parse more effectively than prose-based documentation.
