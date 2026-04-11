# Argus - Examples

This directory contains example workflows and configurations demonstrating different approaches to using argus security scanners.

## Directory Structure

```
examples/
├── workflows/         # Complete workflow examples
│   ├── composite-actions-example.yml
│   ├── actions-linting-example.yml
│   ├── actions-container-scan-matrix.yml
│   ├── actions-scanner-zap-from-config.yml
│   ├── actions-scanner-zap-full-example.yml
│   ├── scn-detection-example.yml
│   └── scn-detection-complete.example.yml
├── configs/          # Configuration file examples
│   ├── container-config.example.yml
│   ├── zap-config.example.yml
│   └── ...
└── README.md
```

## Quick Start Guide

Choose the approach that best fits your needs:

### 1. Argus CLI / Python SDK (Recommended)

The argus Python SDK (`python -m argus scan`) is the primary way to run security scans. It works locally and in CI, driven by a single `argus.yml` configuration file.

**Best for:**
- Local development security scanning
- CI/CD pipelines on any platform (GitHub Actions, GitLab, Jenkins, etc.)
- Portable, configuration-driven scanning
- Teams that want a single tool to manage all scanners

**Usage in GitHub Actions:**
```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v6
        with:
          python-version: '3.13'

      - name: Install Argus SDK
        run: |
          pip install pyyaml
          echo "PYTHONPATH=$GITHUB_WORKSPACE" >> "$GITHUB_ENV"

      - name: Install scanner tools
        run: |
          pip install 'bandit[toml,sarif]>=1.7.5'
          # Install other scanner binaries as needed...

      - name: Run Argus scan
        run: |
          python -m argus scan \
            --config argus.yml \
            --format terminal \
            --format sarif \
            --verbose
```

**Example `argus.yml`:**
```yaml
version: "1.0"

scanners:
  bandit:
    enabled: true
    path: "."
  gitleaks:
    enabled: true
  opengrep:
    enabled: true
    path: "."

reporting:
  formats: [terminal, sarif, json]
  severity_threshold: high
  output_dir: "./argus-results"

execution:
  backend: auto
```

**Local usage:**
```bash
# List available scanners
python -m argus scan --list

# Run a single scanner
python -m argus scan bandit --path . --format terminal

# Run all configured scanners
python -m argus scan --config argus.yml --format terminal --format sarif
```

See [`.github/workflows/security-scan.yml`](../.github/workflows/security-scan.yml) for the real dogfood workflow that argus uses to scan itself.

---

### 2. Composite Actions (GitHub Actions Users)

**File:** [`workflows/composite-actions-example.yml`](workflows/composite-actions-example.yml)

**Best for:**
- Projects that want full control over GitHub Actions workflow execution
- Teams that need to customize scanner configurations per-job
- Repositories that want to run scanners in parallel as separate jobs
- GHES environments where composite actions are preferred

**Usage:**
```yaml
- name: Run Bandit Scanner
  uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.7.0
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    fail_on_severity: 'high'
```

---

### 3. Configuration-Driven Container Scanning

**File:** [`configs/container-config.example.yml`](configs/container-config.example.yml)

**Best for:**
- Container-focused projects
- Teams that want to scan multiple images in parallel
- Projects with complex scanning requirements

---

## Available Examples

| Example File | Description | Approach |
|--------------|-------------|----------|
| [`composite-actions-example.yml`](workflows/composite-actions-example.yml) | Full security scanning with composite actions | Composite Actions |
| [`actions-linting-example.yml`](workflows/actions-linting-example.yml) | Linting with composite actions | Composite Actions |
| [`actions-container-scan-matrix.yml`](workflows/actions-container-scan-matrix.yml) | Matrix-based container scanning | Composite Actions |
| [`actions-scanner-zap-from-config.yml`](workflows/actions-scanner-zap-from-config.yml) | ZAP DAST from config file | Composite Actions |
| [`actions-scanner-zap-full-example.yml`](workflows/actions-scanner-zap-full-example.yml) | ZAP DAST full input exercise | Composite Actions |
| [`scn-detection-example.yml`](workflows/scn-detection-example.yml) | FedRAMP SCN detection | Composite Actions |
| [`scn-detection-complete.example.yml`](workflows/scn-detection-complete.example.yml) | Complete SCN detection workflow | Composite Actions |
| [`container-config.example.yml`](configs/container-config.example.yml) | Container scanning configuration | Config File |

---

## Available Composite Actions

The following composite actions are available for direct use in GitHub Actions workflows:

### Code Security (SAST)
- **scanner-bandit** - Python security scanner
- **scanner-codeql** - GitHub CodeQL multi-language analysis
- **scanner-opengrep** - Pattern-based security scanner

### Secrets Detection
- **scanner-gitleaks** - Git secrets scanner

### Dependency Security
- **scanner-osv** - OSV dependency vulnerability scanning (any trigger)
- **scanner-dependency-review** - PR dependency review and license compliance (PR-only)

### Infrastructure Security
- **scanner-trivy-iac** - Terraform, CloudFormation, Kubernetes scanning
- **scanner-checkov** - Multi-framework IaC scanner

### Container Security
- **scanner-container** - Multi-scanner container security (Trivy + Grype + Syft)

### Supply Chain Security
- **scanner-supply-chain** - GitHub Actions workflow security (zizmor + actionlint)
- **scn-detector** - FedRAMP SCN detection

### Web Application Security
- **scanner-zap** - ZAP DAST scanner

### Malware Detection
- **scanner-clamav** - ClamAV malware scanner

---

## Common Patterns

### Pattern 1: Core Security Scanners Only
Run essential scanners for most projects:
- Gitleaks (secrets)
- Bandit (Python SAST)
- Trivy IaC (infrastructure)

### Pattern 2: Container-Focused
For containerized applications:
- Container scanning
- Trivy IaC
- Gitleaks

### Pattern 3: Web Application
For web applications:
- ZAP DAST
- Bandit/CodeQL (backend)
- Gitleaks

### Pattern 4: Full Security Suite
Run everything:
- All code scanners
- IaC scanners
- Container scanners
- DAST scanners
- Malware scanning

---

## Best Practices

1. **Start with `argus.yml`**: Define your scanner configuration once, run everywhere
2. **Fail Appropriately**: Use `severity_threshold` wisely - consider starting with `high` and adjusting
3. **Enable GitHub Security**: Upload SARIF results to populate the Security tab
4. **Run on Schedule**: Add scheduled runs for drift detection
5. **Customize Paths**: Adjust scanner paths to match your repository structure

---

## Testing Examples

All examples in this directory are functionally tested to ensure they work correctly:

### Automated Testing

- **Syntax Validation**: All `.yml` files are validated for YAML syntax
- **Action Path Verification**: All action references are checked to ensure they exist
- **Functional Tests**: Example patterns are tested against real test fixtures

### CI/CD Integration

- **Workflow**: `.github/workflows/test-examples-functional.yml`
- **Trigger**: Runs on PRs that modify examples or actions

### Local Testing

To test examples locally before publishing:

```bash
# Validate YAML syntax
for example in examples/workflows/*.yml; do
  python -c "import yaml; yaml.safe_load(open('$example'))" && echo "OK: $example"
done

# Validate config examples
python -c "import yaml; yaml.safe_load(open('examples/configs/container-config.example.yml'))"
```

---

## Need Help?

- **Documentation**: See [main README](../README.md)
- **Scanner Docs**: Check individual scanner documentation in [`docs/`](../docs/)
- **Testing Guide**: See [tests/CONTRIBUTING.md](../tests/CONTRIBUTING.md)
- **Issues**: [Report issues](https://github.com/huntridge-labs/argus/issues)
- **Contributing**: See [CONTRIBUTING.md](../CONTRIBUTING.md)

---

_Last Updated: April 2026_
