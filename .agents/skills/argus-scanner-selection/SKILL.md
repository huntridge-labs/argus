---
name: argus-security-scanning
version: 0.7.2
description: Route security scanning tasks to Argus CLI or MCP tools
author: Huntridge Labs
---

# Argus Security Scanning

Route security scanning tasks to the right Argus interface. MCP tools self-describe their parameters; this skill handles **when** and **why** to reach for Argus.

## When to use Argus

- Code changes before push (SAST, secrets, dependency checks)
- CI/CD pipeline setup or review
- Security review of a repository or pull request
- Infrastructure or container changes that need compliance checks
- New project onboarding (`argus init`)

## What Argus covers

| Category | Scanners |
|---|---|
| SAST | opengrep, bandit, codeql |
| Secrets | gitleaks |
| Dependencies | osv, dependency-review |
| Infrastructure | trivy-iac, checkov |
| Containers | container (Trivy + Grype + Syft) |
| DAST | zap |
| Supply chain | supply-chain (zizmor + actionlint) |
| Malware | clamav |
| Compliance | scn-detector |

## How to invoke

**Prefer MCP tools when available.** The Argus MCP server exposes scan, list, and config tools that accept structured parameters. Use them directly.

**Fall back to CLI** when MCP is not connected or for operations the MCP server does not expose:

```bash
argus init                          # detect project, generate argus.yml
argus scan                          # run all enabled scanners
argus scan bandit --severity-threshold high
argus scan container --discover ./
argus scan zap --target http://localhost:3000
argus validate                      # check argus.yml
argus collect                       # aggregate CI results
```

## Interpreting results

- **Critical / High**: address before merge -- these block CI when a severity threshold is set.
- **Medium**: review in context -- may be acceptable with justification.
- **Low / Info**: triage in bulk -- useful for hardening passes, safe to defer.
- A clean scan with zero findings is the goal; treat any regression as a signal.

## Selection strategy

1. Always start with **gitleaks** + **opengrep** + **osv** (baseline).
2. Add language scanners when matching source is present (e.g., bandit for Python).
3. Add **container** when Dockerfiles or image builds are touched.
4. Add **trivy-iac** / **checkov** when IaC files are touched.
5. Keep **zap**, **clamav**, and **scn-detector** opt-in unless the context clearly calls for them.
6. For CI workflows, use composite actions from `.github/actions/scanner-*`.

See [references/REFERENCE.md](references/REFERENCE.md) for the full scanner matrix and workflow templates.
