# Quick Start

Get running with Argus in minutes. The argus SDK is the primary interface; composite actions remain available for GitHub Actions users.

## Argus SDK (Recommended)

### Install

```bash
pip install pyyaml
```

### Fast SAST scan

```bash
python -m argus scan gitleaks opengrep bandit
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
python -m argus scan --config argus.yml
```

### Enforcing security gates

Fail when vulnerabilities exceed a severity threshold:

```bash
python -m argus scan --config argus.yml --severity-threshold high
```

**Severity levels:** `low` -> `medium` -> `high` -> `critical`

### Targeted scan

```bash
python -m argus scan gitleaks container trivy-iac checkov --severity-threshold high
```

### Output formats

```bash
# Terminal output (default)
python -m argus scan --config argus.yml

# Markdown report
python -m argus scan --config argus.yml --format markdown

# SARIF output
python -m argus scan --config argus.yml --format sarif

# JSON output
python -m argus scan --config argus.yml --format json
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

      - uses: huntridge-labs/argus/.github/actions/scanner-gitleaks@0.7.0
        with:
          enable_code_security: true
          fail_on_severity: high
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.7.0
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

      - uses: huntridge-labs/argus/.github/actions/scanner-trivy-iac@0.7.0
        with:
          iac_path: 'infrastructure'
          enable_code_security: true
          fail_on_severity: high

      - uses: huntridge-labs/argus/.github/actions/scanner-checkov@0.7.0
        with:
          iac_path: 'infrastructure'
          fail_on_severity: medium
```

More examples in the `examples/` directory. See `README.md` for the complete scanner reference.
