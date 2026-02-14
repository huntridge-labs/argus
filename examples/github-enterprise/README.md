# GitHub Enterprise Server (GHES) Examples

These examples demonstrate how to use Argus composite actions directly on GitHub Enterprise Server.

**Why use actions instead of reusable workflows on GHES?**

GHES cannot call `workflow_call` reusable workflows from github.com. However, GHES **can** use composite actions from public github.com repositories directly. These examples use our composite actions with full path references.

## How to Use These Examples

1. Copy the desired example to your repository's `.github/workflows/` directory
2. Update the version refs (e.g., `@v2.12.0`) to match your desired version
3. Customize inputs as needed

That's it! The actions will be pulled directly from our public github.com repository.

## Available Examples

| File | Description | Scanners |
|------|-------------|----------|
| `containerized-web-app.yml` | **Recommended** - Full pipeline for containerized web apps | Gitleaks, Bandit, CodeQL, OpenGrep, ClamAV, Container (Trivy/Grype/Syft), ZAP DAST |
| `all-scanners.yml` | Complete security scanning | Bandit, OpenGrep, Gitleaks, Trivy IaC, Checkov, ClamAV |
| `sast-only.yml` | Static analysis only | Bandit, OpenGrep, Gitleaks |
| `container-scanning.yml` | Container vulnerability scanning | Trivy, Grype, Syft (SBOM) |
| `infrastructure-scanning.yml` | Infrastructure as Code scanning | Trivy IaC, Checkov |
| `dast-scanning.yml` | Dynamic application security testing | ZAP |

### Containerized Web App Pattern

The `containerized-web-app.yml` demonstrates best practices:

- **Consolidated PR comments** - Individual scanners set `post_pr_comment: false`, security-summary posts one combined comment
- **Build and scan your own image** - Demonstrates real app workflow with `scan_mode: 'discover'`
- **DAST with health checking** - Robust container startup with health endpoint polling
- **Complete coverage** - Secrets, SAST, malware, container vulnerabilities, and web app security

## Required Permissions

All examples require these base permissions:

```yaml
permissions:
  contents: read           # Read repository content
  security-events: write   # Upload SARIF to Security tab
  pull-requests: write     # Post PR comments
  actions: read            # Read workflow artifacts
```

For container scanning or DAST with service containers, also add:

```yaml
  packages: read           # Pull images from GHCR
```

## Version Pinning

All examples use pinned versions (e.g., `@v2.12.0`). Check the [latest release](https://github.com/huntridge-labs/argusreleases) and update version refs accordingly.

Consider using Dependabot or Renovate to keep action versions current.

## Customization Guide

### Severity Thresholds

Control when workflows fail based on findings:

```yaml
fail_on_severity: 'high'    # Fail on high or critical
fail_on_severity: 'critical' # Fail only on critical
fail_on_severity: 'none'     # Never fail (report only)
```

### GitHub Security Tab Integration

Enable SARIF upload to the Security tab:

```yaml
enable_code_security: 'true'
```

Note: Requires `security-events: write` permission and GitHub Advanced Security license on GHES.

### PR Comments

Enable/disable PR comments:

```yaml
post_pr_comment: 'true'   # Post findings as PR comments
post_pr_comment: 'false'  # Silent mode
```

### Scan Paths

Customize what gets scanned:

```yaml
# IaC scanning
iac_path: 'terraform/'       # Default: 'infrastructure'

# Code scanning
scan_path: 'src/'           # Specific directory

# Container scanning
image_ref: 'myregistry.io/myapp:latest'
```

## Secrets Handling

For scanners that need secrets (e.g., Gitleaks license, registry auth):

```yaml
env:
  GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}
  REGISTRY_PASSWORD: ${{ secrets.REGISTRY_PASSWORD }}
```

Actions use environment variables for secrets, not the `secrets` context directly.

## Support

- [Main Documentation](../../README.md)
- [Scanner Reference](../../docs/scanners.md)
- [GitHub Issues](https://github.com/huntridge-labs/argusissues)
