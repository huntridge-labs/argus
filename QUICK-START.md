# Quick Start

Get running with Argus in minutes. The argus SDK is the primary interface; composite actions remain available for GitHub Actions users.

## Argus SDK (Recommended)

### Install

```bash
pip install argus-security
```

### Enable shell tab-completion (recommended)

Generate and persist a completion script for your shell. Pressing
`<Tab>` will then auto-complete subcommands (`scan`, `list`, `view`,
`cache`, …), scanner and linter names (`bandit`, `gitleaks`,
`lint-yaml`, …), and common flags (`--config`, `--scanners`,
`--severity`, …).

```bash
# zsh
argus completion zsh  >> ~/.zshrc  && source ~/.zshrc

# bash
argus completion bash >> ~/.bashrc && source ~/.bashrc
```

For one-off use in the current session only:

```bash
eval "$(argus completion zsh)"   # or bash
```

Completions are generated from the live scanner registry, so newly
added scanners appear after re-running the command.

### Fast SAST scan

```bash
argus scan gitleaks opengrep bandit
```

### Full scan with config file

Create `argus.yml`:

```yaml
scanners:
  - gitleaks
  - opengrep
  - bandit
  - osv
  - trivy-iac
  - checkov

scan_path: "."
severity_threshold: high
```

```bash
argus scan --config argus.yml
```

### Enforcing security gates

Fail when vulnerabilities exceed a severity threshold:

```bash
argus scan --config argus.yml --severity-threshold high
```

**Severity levels:** `low` -> `medium` -> `high` -> `critical`

### Targeted scan

```bash
argus scan gitleaks container trivy-iac checkov --severity-threshold high
```

### Output formats

```bash
# Terminal output (default)
argus scan --config argus.yml

# Markdown report
argus scan --config argus.yml --format markdown

# SARIF output
argus scan --config argus.yml --format sarif

# JSON output
argus scan --config argus.yml --format json
```

## GitHub Actions (Composite Actions)

For GitHub Actions users, use composite actions directly:

### SAST scanning

```yaml
name: security
on: [pull_request, push]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - uses: huntridge-labs/argus/.github/actions/scanner-gitleaks@1.5.0
        with:
          enable_code_security: true
          fail_on_severity: high
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - uses: huntridge-labs/argus/.github/actions/scanner-bandit@1.5.0
        with:
          enable_code_security: true
          fail_on_severity: high
```

### Infrastructure scanning

```yaml
jobs:
  iac:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - uses: huntridge-labs/argus/.github/actions/scanner-trivy-iac@1.5.0
        with:
          iac_path: 'infrastructure'
          enable_code_security: true
          fail_on_severity: high

      - uses: huntridge-labs/argus/.github/actions/scanner-checkov@1.5.0
        with:
          iac_path: 'infrastructure'
          fail_on_severity: medium
```

More examples in the `examples/` directory. See `README.md` for the complete scanner reference.
