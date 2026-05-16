# Argus - Examples

This directory contains example workflows and configurations demonstrating different approaches to using argus security scanners.

## Directory Structure

```
examples/
├── workflows/             # GitHub Actions workflow examples
│   ├── sdk-github-actions.yml
│   ├── composite-actions-example.yml
│   ├── actions-linting-example.yml
│   ├── actions-container-scan-matrix.yml
│   ├── actions-scanner-zap-from-config.yml
│   ├── actions-scanner-zap-full-example.yml
│   ├── scn-detection-example.yml
│   └── scn-detection-complete.example.yml
├── ci-platforms/          # Non-GitHub CI platform examples
│   ├── gitlab-ci.yml
│   ├── Jenkinsfile
│   └── azure-devops.yml
├── configs/               # Configuration file examples
│   ├── container-config.example.yml
│   ├── zap-config.example.yml
│   └── ...
├── github-enterprise/     # GHES-specific examples
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
  uses: huntridge-labs/argus/.github/actions/scanner-bandit@1.0.0
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

## CI Integration Pattern

Every CI platform follows the same four-step pattern. Argus produces platform-agnostic output files; your CI pipeline posts them using native APIs.

### How It Works

```
argus scan
  │
  ├── argus-summary.md      ─→  Post as PR/MR comment (platform API)
  ├── argus-results.sarif    ─→  Upload to security dashboard (Code Security, GitLab SAST, etc.)
  ├── argus-results.json     ─→  Archive as build artifact
  └── counts.env             ─→  key=value pairs → CI output variables
```

1. **`--format markdown`** produces `argus-summary.md` -- a human-readable summary of all findings.
2. **Your CI posts that file as a PR/MR comment** using the platform's native API (GitHub Script, GitLab Notes API, Azure DevOps Threads API, etc.).
3. **`--format sarif`** produces `argus-results.sarif` -- upload it to the platform's security dashboard (GitHub Code Security, GitLab SAST, Jenkins Warnings NG).
4. **`--output-vars`** produces a `counts.env` file with `key=value` lines (`critical_count=0`, `high_count=2`, etc.) that you source into CI output variables for downstream decisions.

### Quick Start by Platform

The core scan command is identical everywhere:

```bash
pip install pyyaml  # Will become: pip install argus-security
python -m argus scan \
  --format sarif --format markdown \
  --output-dir ./argus-results \
  --output-vars ./argus-results/counts.env \
  --no-timestamp
```

What changes per platform is how you **post the comment** and **upload SARIF**.

#### GitHub Actions

```yaml
# Post argus-summary.md as PR comment → actions/github-script
# Upload SARIF → github/codeql-action/upload-sarif
# Full example: examples/workflows/sdk-github-actions.yml
```

See [`workflows/sdk-github-actions.yml`](workflows/sdk-github-actions.yml) for the complete workflow including PR comment upsert logic and artifact archiving.

#### GitLab CI

```yaml
# Post argus-summary.md as MR note → curl to GitLab Notes API
# Upload SARIF → artifacts.reports.sast (GitLab ingests natively)
# Full example: examples/ci-platforms/gitlab-ci.yml
```

See [`ci-platforms/gitlab-ci.yml`](ci-platforms/gitlab-ci.yml). GitLab's `artifacts.reports.sast` key automatically ingests SARIF into the Security Dashboard -- no extra upload step needed.

#### Jenkins

```groovy
// Post argus-summary.md as PR comment → pullRequest.comment() or HTTP plugin
// Upload SARIF → recordIssues(tools: [sarif(...)]) via Warnings NG plugin
// Full example: examples/ci-platforms/Jenkinsfile
```

See [`ci-platforms/Jenkinsfile`](ci-platforms/Jenkinsfile). Uses the Pipeline Utility Steps plugin for `readFile` and Warnings NG for SARIF ingestion with quality gates.

#### Azure DevOps

```yaml
# Post argus-summary.md as PR thread → curl to Azure DevOps REST API
# Counts exported via ##vso[task.setvariable] for downstream steps
# Full example: examples/ci-platforms/azure-devops.yml
```

See [`ci-platforms/azure-devops.yml`](ci-platforms/azure-devops.yml). Exports scan counts as pipeline variables using the `##vso` logging commands.

### Output Files Reference

| File | Flag | Purpose |
|------|------|---------|
| `argus-summary.md` | `--format markdown` | Human-readable summary for PR comments |
| `argus-results.sarif` | `--format sarif` | SARIF for security dashboards |
| `argus-results.json` | `--format json` | Machine-readable full results |
| `counts.env` | `--output-vars <path>` | `key=value` counts for CI variables |

All files land in the directory specified by `--output-dir`. The `--no-timestamp` flag ensures predictable file names (no run-specific subdirectories).

---

## Available Examples

| Example File | Description | Approach |
|--------------|-------------|----------|
| [`sdk-github-actions.yml`](workflows/sdk-github-actions.yml) | SDK scan with PR comment and SARIF upload | SDK + GitHub Actions |
| [`gitlab-ci.yml`](ci-platforms/gitlab-ci.yml) | SDK scan with MR comment and GitLab SAST | SDK + GitLab CI |
| [`Jenkinsfile`](ci-platforms/Jenkinsfile) | SDK scan with Warnings NG and artifacts | SDK + Jenkins |
| [`azure-devops.yml`](ci-platforms/azure-devops.yml) | SDK scan with PR thread and pipeline vars | SDK + Azure DevOps |
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
