# Argus - Examples

This directory contains example workflows and configurations demonstrating different approaches to using argus security scanners.

## Directory Structure

```
examples/
├── workflows/         # Complete workflow examples
│   ├── composite-actions-example.yml
│   ├── actions-linting-example.yml
│   ├── scanner-zap-podinfo.yml
│   └── ...
├── configs/          # Configuration file examples
│   ├── container-config.example.yml
│   ├── zap-config.example.yml
│   └── ...
└── README.md
```

## Quick Start Guide

Choose the approach that best fits your needs:

### 1. Composite Actions (Recommended for Most Projects) ⭐

**File:** [`workflows/composite-actions-example.yml`](workflows/composite-actions-example.yml)

**Best for:**
- Projects that want full control over workflow execution
- Teams that need to customize scanner configurations
- Repositories that want to run scanners in parallel
- Cases where you need fine-grained control over when scanners run

**Pros:**
- ✅ Maximum flexibility and customization
- ✅ Easy to add/remove specific scanners
- ✅ Transparent execution (all steps visible in workflow)
- ✅ Better for debugging and understanding
- ✅ Can use matrix strategies for complex scenarios

**Cons:**
- ⚠️ More verbose workflow configuration
- ⚠️ Each scanner must be explicitly configured

**Usage:**
```yaml
- name: Run Bandit Scanner
  uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.3.0
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    fail_on_severity: 'high'
```

---

### 2. Reusable Workflows (Easiest to Get Started)

**File:** [`use-reusable-workflow.yml`](workflows/use-reusable-workflow.yml)

**Best for:**
- Quick setup with sensible defaults
- Small to medium projects
- Teams that want a "one-click" security solution
- Consistent security policies across multiple repositories

**Pros:**
- ✅ Minimal configuration required
- ✅ Centrally managed and updated
- ✅ Consistent across all repositories
- ✅ Single workflow call runs multiple scanners

**Cons:**
- ⚠️ Less flexibility for customization
- ⚠️ All scanners run together (can't easily disable one)
- ⚠️ Harder to debug individual scanner issues

**Usage:**
```yaml
jobs:
  security-scan:
    uses: huntridge-labs/argus/.github/workflows/reusable-security-hardening.yml@0.3.0
    with:
      enable_code_security: true
```

---

### 3. Configuration-Driven Scanning

**File:** [`container-config.example.yml`](configs/container-config.example.yml)

**Best for:**
- Container-focused projects
- Teams that want to scan multiple images
- Projects with complex scanning requirements
- Advanced users who need scanner-specific configurations

**Pros:**
- ✅ Highly configurable via YAML
- ✅ Supports multiple targets and scanners
- ✅ Good for container-heavy workloads

**Cons:**
- ⚠️ More complex setup
- ⚠️ Requires understanding of scanner configurations

---

## Available Examples

| Example File | Description | Use Case |
|--------------|-------------|----------|
| [`composite-actions-example.yml`](workflows/composite-actions-example.yml) | Full example using composite actions | Most flexible approach |
| [`use-reusable-workflow.yml`](workflows/use-reusable-workflow.yml) | Simple reusable workflow call | Quick setup |
| [`individual-scanner-workflows.yml`](individual-scanner-workflows.yml) | Individual scanner workflow calls | Granular control |
| [`container-config.example.yml`](configs/container-config.example.yml) | Container scanning configuration | Container security |
| [`scanner-zap-podinfo.yml`](scanner-zap-podinfo.yml) | ZAP DAST scanning example | Web app security |
| [`actions-container-scan-matrix.yml`](actions-container-scan-matrix.yml) | Matrix-based container scanning | Multiple images |

---

## Available Composite Actions

The following composite actions are available for direct use:

### Code Security
- **scanner-bandit** - Python security scanner (SAST)
- **scanner-codeql** - GitHub's code analysis (coming soon)
- **scanner-opengrep** - Pattern-based security scanner (coming soon)

### Secrets Detection
- **scanner-gitleaks** - Git secrets scanner

### Infrastructure Security
- **scanner-trivy-iac** - Terraform, CloudFormation, Kubernetes scanning
- **scanner-checkov** - Multi-framework IaC scanner (coming soon)

### Container Security
- **scanner-container** - Multi-scanner container security
- **scanner-trivy-container** - Trivy container scanning (coming soon)

### Web Application Security
- **scanner-zap** - ZAP DAST scanner

### Malware Detection
- **scanner-clamav** - ClamAV malware scanner

---

## Migration Path

### From Reusable Workflows → Composite Actions

If you're currently using reusable workflows and want more control:

1. Copy [`composite-actions-example.yml`](workflows/composite-actions-example.yml) to `.github/workflows/security.yml`
2. Remove scanners you don't need
3. Customize inputs for remaining scanners
4. Test the workflow
5. Remove the old reusable workflow call

### From Individual Workflows → Composite Actions

If you have individual scanner workflows:

1. Review the composite action for each scanner
2. Replace workflow calls with composite action steps
3. Consolidate into fewer workflow files
4. Test thoroughly

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

1. **Start Simple**: Begin with the reusable workflow, then migrate to composite actions if needed
2. **Fail Appropriately**: Use `fail_on_severity` wisely - consider starting with 'none' and gradually increasing
3. **Enable GitHub Security**: Set `enable_code_security: true` to populate Security tab
4. **Use PR Comments**: Enable `post_pr_comment: true` for developer feedback
5. **Run on Schedule**: Add scheduled runs for drift detection
6. **Customize Paths**: Adjust `iac_path`, `scan_path`, etc. to your repository structure

---

## Testing Examples

All examples in this directory are functionally tested to ensure they work correctly:

### Automated Testing

- **Syntax Validation**: All `.yml` files are validated for YAML syntax
- **Action Path Verification**: All action references are checked to ensure they exist
- **Branch Reference Checks**: Examples use `@main` or versioned tags (e.g., `@v2.11.2`)
- **Functional Tests**: Example patterns are tested against real test fixtures

### CI/CD Integration

- **Workflow**: `.github/workflows/test-examples-functional.yml`
- **Trigger**: Runs on PRs that modify examples or actions
- **Coverage**: Tests composite actions, configurations, ZAP/DAST, linting, and container scanning patterns

### Local Testing

To test examples locally before publishing:

```bash
# Validate YAML syntax
for example in examples/*.yml; do
  python -c "import yaml; yaml.safe_load(open('$example'))"
done

# Test configuration parsers
node .github/scripts/parse-container-config.js examples/container-config.example.yml
node .github/scripts/parse-container-config.js examples/container-config.example.json

# Run npm validation
npm test
```

### Example Quality Standards

All examples must:
- ✅ Use current branch references (`@main` or versioned tags, not feature branches)
- ✅ Include all required inputs for actions
- ✅ Have clear documentation and comments
- ✅ Pass YAML syntax validation
- ✅ Reference actual, existing actions
- ✅ Work with provided test fixtures

---

## Need Help?

- **Documentation**: See [main README](../README.md)
- **Scanner Docs**: Check individual scanner documentation in [`docs/`](../docs/)
- **Testing Guide**: See [tests/CONTRIBUTING.md](../tests/CONTRIBUTING.md)
- **Issues**: [Report issues](https://github.com/huntridge-labs/argusissues)
- **Contributing**: See [CONTRIBUTING.md](../CONTRIBUTING.md)

---

_Last Updated: January 2026_
