# Container Security Scanner Composite Action

Comprehensive container image scanning using multiple security scanners.

## Overview

This composite action provides a unified interface for scanning container images with multiple security scanners:
- **Trivy** - Vulnerability and misconfiguration detection
- **Grype** - Vulnerability scanner by Anchore
- **Syft** - Software Bill of Materials (SBOM) generation

The action can scan images from:
- Local Docker daemon
- Remote registries (Docker Hub, GHCR, ECR, etc.)
- Archives and tarballs

## Usage

### Basic Example

```yaml
- name: Checkout code
  uses: actions/checkout@v6

- name: Build container image
  run: docker build -t myapp:latest .

- name: Run Container Scanner
  uses: huntridge-labs/argus/.github/actions/scanner-container@0.2.0
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    image_ref: 'myapp:latest'
    scan_name: 'myapp'
    fail_on_severity: 'high'
```

### Advanced Example with Remote Registry

```yaml
- name: Scan image from ECR
  uses: huntridge-labs/argus/.github/actions/scanner-container@0.2.0
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    image_ref: '123456.dkr.ecr.us-east-1.amazonaws.com/myapp:v1.0.0'
    scan_name: 'production-myapp'
    registry_username: 'AWS'
    registry_password: ${{ secrets.ECR_PASSWORD }}
    enable_code_security: true
    fail_on_severity: 'critical'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `image_ref` | Container image reference to scan | **Yes** | - |
| `scan_name` | Name for scan artifacts | No | `container` |
| `registry_username` | Registry authentication username | No | - |
| `registry_password` | Registry authentication password/token | No | - |
| `enable_code_security` | Upload SARIF to GitHub Security tab | No | `false` |
| `fail_on_severity` | Fail on severity: `none`, `low`, `medium`, `high`, `critical` | No | `none` |

## Secrets

For private registries, pass credentials securely:
```yaml
registry_username: ${{ secrets.REGISTRY_USERNAME }}
registry_password: ${{ secrets.REGISTRY_PASSWORD }}
```

Common registry patterns:
- **Docker Hub**: username/password or token
- **GHCR**: username + GitHub PAT with `read:packages`
- **ECR**: `AWS` + ECR token
- **GCR**: `_json_key` + service account JSON

## Outputs

| Output | Description |
|--------|-------------|
| `critical_count` | Number of critical vulnerabilities |
| `high_count` | Number of high severity vulnerabilities |
| `medium_count` | Number of medium severity vulnerabilities |
| `low_count` | Number of low severity vulnerabilities |
| `total_count` | Total number of vulnerabilities |
| `image_digest` | SHA256 digest of scanned image |

## Features

- ✅ Multi-scanner approach (Trivy, Grype, Syft)
- ✅ SBOM generation (CycloneDX, SPDX)
- ✅ SARIF output for GitHub Security
- ✅ Remote registry support
- ✅ Vulnerability deduplication
- ✅ Comprehensive reporting

## Reports Generated

The action generates multiple report formats:

### Trivy Reports
- `trivy-results.sarif` - GitHub Security integration
- `trivy-results.json` - Detailed vulnerability data
- `trivy-sbom.json` - Software Bill of Materials

### Grype Reports
- `grype-results.sarif` - Alternative SARIF format
- `grype-results.json` - Grype vulnerability data

### Syft Reports
- `syft-sbom.json` - Detailed SBOM

All reports are uploaded as artifacts: `container-scan-{scan_name}`

## Examples

### Scan Local Image

```yaml
- name: Build and scan
  run: docker build -t myapp:test .

- uses: huntridge-labs/argus/.github/actions/scanner-container@0.2.0
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    image_ref: 'myapp:test'
```

### Scan Multiple Images

Use a matrix strategy:

```yaml
jobs:
  container-scan:
    strategy:
      matrix:
        image:
          - { ref: 'frontend:latest', name: 'frontend' }
          - { ref: 'backend:latest', name: 'backend' }
          - { ref: 'worker:latest', name: 'worker' }
    steps:
      - uses: actions/checkout@v6
      - run: docker build -t ${{ matrix.image.ref }} .
      - uses: huntridge-labs/argus/.github/actions/scanner-container@0.2.0
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          image_ref: ${{ matrix.image.ref }}
          scan_name: ${{ matrix.image.name }}
```

### Scan from GitHub Container Registry

```yaml
- name: Login to GHCR
  uses: docker/login-action@v3
  with:
    registry: ghcr.io
    username: ${{ github.actor }}
    password: ${{ secrets.GITHUB_TOKEN }}

- uses: huntridge-labs/argus/.github/actions/scanner-container@0.2.0
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    image_ref: 'ghcr.io/myorg/myapp:latest'
    scan_name: 'ghcr-scan'
    registry_username: ${{ github.actor }}
    registry_password: ${{ secrets.GITHUB_TOKEN }}
```

### Scan from AWS ECR

```yaml
- name: Configure AWS credentials
  uses: aws-actions/configure-aws-credentials@v4
  with:
    aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
    aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    aws-region: us-east-1

- name: Login to ECR
  run: |
    aws ecr get-login-password --region us-east-1 | \
    docker login --username AWS --password-stdin 123456.dkr.ecr.us-east-1.amazonaws.com

- uses: huntridge-labs/argus/.github/actions/scanner-container@0.2.0
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    image_ref: '123456.dkr.ecr.us-east-1.amazonaws.com/myapp:latest'
    scan_name: 'ecr-scan'
```

### Fail on Critical Only

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-container@0.2.0
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    image_ref: 'myapp:latest'
    fail_on_severity: 'critical'
```

## Understanding Vulnerability Severities

Vulnerabilities are categorized by CVSS scores:
- **CRITICAL**: CVSS 9.0-10.0 - Immediate action required
- **HIGH**: CVSS 7.0-8.9 - Should be addressed soon
- **MEDIUM**: CVSS 4.0-6.9 - Plan to address
- **LOW**: CVSS 0.1-3.9 - Minor issues

## Image References

The `image_ref` input supports various formats:

```yaml
# Docker Hub (official)
image_ref: 'nginx:latest'

# Docker Hub (user/org)
image_ref: 'myorg/myapp:v1.0'

# GitHub Container Registry
image_ref: 'ghcr.io/myorg/myapp:latest'

# AWS ECR
image_ref: '123456.dkr.ecr.us-east-1.amazonaws.com/myapp:latest'

# Google Container Registry
image_ref: 'gcr.io/project-id/myapp:latest'

# Azure Container Registry
image_ref: 'myregistry.azurecr.io/myapp:latest'

# Local images
image_ref: 'myapp:test'
```

## Requirements

- Repository must be checked out before running this action
- `GITHUB_TOKEN` environment variable (automatically available)
- Docker image must exist (built or pulled)
- For private registries: valid credentials

## Related Documentation

- [Container Scanning Guide](../../docs/container-scanning.md)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Grype Documentation](https://github.com/anchore/grype)
- [Complete Example Workflow](../../examples/composite-actions-example.yml)

## Troubleshooting

### Image Not Found

If scanner can't find the image:
- Verify image exists: `docker images`
- Check image name and tag spelling
- For remote images, verify authentication
- Ensure image was built before scanning

### Authentication Fails

For private registries:
- Verify credentials are correct
- Check secret names match workflow
- Ensure user has pull permissions
- For ECR: verify AWS credentials

### Scan Too Slow

Container scans can take 5-15 minutes. To optimize:
- Use smaller base images
- Scan during off-peak hours
- Cache scanner databases
- Consider parallel scanning for multiple images

### Too Many Vulnerabilities

If finding too many issues:
- Review base image choice (use minimal/alpine variants)
- Update base images regularly
- Prioritize by severity
- Consider vulnerability suppression for false positives

## Best Practices

1. **Scan Early**: Scan during build, not just pre-deployment
2. **Update Regularly**: Keep base images and dependencies current
3. **Choose Wisely**: Use minimal base images (alpine, distroless)
4. **Track SBOMs**: Store and compare SBOMs over time
5. **Set Thresholds**: Use `fail_on_severity` to enforce standards
6. **Review Findings**: Not all vulnerabilities are exploitable

## Multi-Scanner Benefits

Using multiple scanners provides:
- **Coverage**: Different scanners find different issues
- **Confidence**: Cross-validation of findings
- **SBOM**: Comprehensive inventory with Syft
- **Flexibility**: Choose scanner that fits your needs

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [Container Scanning Docs](../../docs/container-scanning.md)
- [View Changelog](../../CHANGELOG.md)
