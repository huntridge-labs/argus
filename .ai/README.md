# AI Context as Code (AICaC)

This directory contains structured, machine-optimized documentation for AI coding assistants.

## Specification

**Version:** 2.0 (the `version` key in each file)

## Files

| File | Purpose |
|------|---------|
| `index.yaml` | Generated list of every key in the files below, plus routing. Don't edit it by hand |
| `context.yaml` | Project metadata, identity, constraints |
| `architecture.yaml` | Components, dependencies, data flow |
| `workflows.yaml` | Common tasks with exact commands |
| `decisions.yaml` | Architectural Decision Records ADR-001 to ADR-044 (closed to new entries) |
| `decisions/ADR-<issue>.yaml` | Newer ADRs, one file each, keyed to the issue that asked for them |
| `errors.yaml` | Error patterns → solutions |

## For AI Assistants

These files are large (`decisions.yaml` alone is ~50k tokens). Don't read them in order or load them whole:

1. Start from the routing table in [`AGENTS.md`, "Where to look"](../AGENTS.md#where-to-look). It says which file, and which key, a task needs.
2. Use `index.yaml` to find the exact key, then search for it in the file it lives in.
3. For decisions, run `python -m scripts.ci.adr_records list`. It merges `decisions.yaml` and `decisions/` into one list.

After a change, update the relevant `.ai/` file in the same PR (the mapping is in [`AGENTS.md`, "Keeping `.ai/` in sync"](../AGENTS.md#keeping-ai-in-sync)), then regenerate the index.

**If information conflicts with source code**, these files may be stale. Note the discrepancy in your response.

## For Humans

This directory complements (not replaces):
- `README.md` - Human-friendly introduction
- `AGENTS.md` - Entry point for every coding agent
- `CLAUDE.md` - Imports `AGENTS.md`

## Validation

CI runs these on every PR:

```bash
python -m scripts.ci.check_ai_index           # index.yaml matches the files (--fix regenerates it)
python -m scripts.ci.check_architecture_sync  # registries and CLI are all in architecture.yaml / context.yaml
python -m scripts.ci.check_version_drift      # context.yaml and every other release-it version ref match version.yaml
python -m scripts.ci.adr_records check        # both ADR stores are valid
```

The AICaC action (`.github/workflows/aicac.yml`) also validates the schema. Its own index regeneration stays off; see ADR-555.

## About AICaC

AI Context as Code (AICaC) is a structured, machine-optimized approach to project documentation. It uses YAML files to provide token-efficient context that AI assistants can parse more effectively than prose-based documentation.
