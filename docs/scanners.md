<div align=center>

# Scanner Configuration Reference

Complete configuration reference for all available security scanners.

</div>

## Architecture

This project uses an **actions-first architecture**:

- **Composite Actions** (`.github/actions/scanner-*/`) - Single source of truth for all scanner logic
- **Reusable Workflows** (`.github/workflows/scanner-*.yml`) - Thin wrappers for backwards compatibility
- **Example Workflows** (`examples/github-enterprise/`) - Templates for GHES users

**For github.com users**: Use the reusable workflows via `workflow_call` (recommended for simplicity).

**For GHES users**: Use composite actions directly - they work from public github.com repos without mirroring.

<details>
<summary><strong>GHES Usage Example</strong></summary>

```yaml
# Direct composite action usage (GHES compatible)
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - uses: huntridge-labs/argus/.github/actions/scanner-gitleaks@v2.12.0
        with:
          enable_code_security: true
          fail_on_severity: high
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

See [examples/github-enterprise/](../examples/github-enterprise/) for complete templates.

</details>

---

## Table of Contents

- [SAST Scanners](#sast-scanners)
  - [CodeQL](#codeql)
  - [Gitleaks](#gitleaks)
  - [Bandit](#bandit)
  - [OpenGrep (Semgrep)](#opengrep-semgrep)
- [Container Scanners](#container-scanners)
  - [Trivy Container](#trivy-container)
  - [Grype](#grype)
  - [Syft (SBOM)](#syft-sbom)
- [Infrastructure Scanners](#infrastructure-scanners)
  - [Trivy IaC](#trivy-iac)
  - [Checkov](#checkov)
- [Malware Scanner](#malware-scanner)
  - [ClamAV](#clamav)
- [DAST Scanners](#dast-scanners)
  - [ZAP](#zap)
- [Common Configuration Patterns](#common-configuration-patterns)
## SAST Scanners

### CodeQL

GitHub's semantic code analysis engine for finding security vulnerabilities and coding errors.

**Supported languages:** `python`, `javascript`, `typescript`, `java`, `csharp`, `cpp`, `go`, `ruby`

<details>
<summary><strong>Configuration & Examples</strong></summary>

**Configuration:**

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `codeql_languages` | Comma-separated list of languages | `python,javascript` | No |
| `enable_code_security` | Upload to GitHub Security tab | `false` | No |
| `post_pr_comment` | Post findings as PR comments | `true` | No |

**Example:**

```yaml
with:
  scanners: codeql
  codeql_languages: 'python,javascript,go'
  enable_code_security: true
```

</details>

### Gitleaks

Scans git history and code for hardcoded secrets, API keys, passwords, and tokens.

**Scan behavior:** Scans PR changes, new commits, or full history depending on event type.

<details>
<summary><strong>Configuration & Examples</strong></summary>

**Configuration:**

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `gitleaks_enable_comments` | Enable inline PR comments | `true` | No |
| `gitleaks_notify_user_list` | Users to notify (e.g., `@user1,@user2`) | `''` | No |
| `gitleaks_enable_summary` | Enable job summary | `true` | No |
| `gitleaks_enable_upload_artifact` | Upload SARIF artifact | `true` | No |
| `gitleaks_config` | Path to custom config file | `''` | No |
| `enable_code_security` | Upload to GitHub Security tab | `false` | No |
| `fail_on_severity` | Fail on any secret detection | `none` | No |

**Required secrets:**

| Secret | Description | Required |
|--------|-------------|----------|
| `GITLEAKS_LICENSE` | License key from [gitleaks.io](https://gitleaks.io) | Yes (for organizations) |

**Scan behavior by event type:**
- `pull_request`: Scans all changes in the PR
- `push`: Scans only new commits
- `workflow_dispatch`/`schedule`: Full repository history scan

**Example:**

```yaml
with:
  scanners: gitleaks
  gitleaks_enable_comments: true
  gitleaks_notify_user_list: '@security-team'
  fail_on_severity: critical
secrets:
  GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}
```

</details>

### Bandit

Python security linter for finding common security issues using static analysis.

**Severity levels:** LOW, MEDIUM, HIGH

<details>
<summary><strong>Configuration & Examples</strong></summary>

**Configuration:**

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `enable_code_security` | Upload to GitHub Security tab | `false` | No |
| `post_pr_comment` | Post findings as PR comments | `true` | No |
| `fail_on_severity` | Fail on any finding | `none` | No |

**Example:**

```yaml
with:
  scanners: bandit
  enable_code_security: true
  fail_on_severity: high
```

</details>

### OpenGrep (Semgrep)

Fast, customizable static analysis with extensive rule sets for multiple languages.

<details>
<summary><strong>Configuration & Examples</strong></summary>

**Configuration:**

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `enable_code_security` | Upload to GitHub Security tab | `false` | No |
| `post_pr_comment` | Post findings as PR comments | `true` | No |
| `fail_on_severity` | Severity threshold | `none` | No |

**Example:**

```yaml
with:
  scanners: opengrep
  enable_code_security: true
  fail_on_severity: medium
```

</details>

## Container Scanners

### Trivy Container

Comprehensive vulnerability scanner for container images and filesystems.

<details>
<summary><strong>Configuration & Examples</strong></summary>

**Configuration:**

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `image_ref` | Container image to scan | - | Yes |
| `registry_username` | Username for private registry authentication | `''` | No |
| `enable_code_security` | Upload to GitHub Security tab | `false` | No |
| `post_pr_comment` | Post findings as PR comments | `false` | No |
| `fail_on_severity` | Severity threshold | `none` | No |

**Required secrets (for private registries):**

| Secret | Description | Required |
|--------|-------------|----------|
| `registry_password` | Password/token for registry authentication | No |

**Example:**

```yaml
# Public image
with:
  scanners: trivy-container
  image_ref: 'nginx:latest'
  enable_code_security: true
  fail_on_severity: critical

# Private registry
with:
  scanners: trivy-container
  image_ref: 'ghcr.io/myorg/myapp:latest'
  registry_username: ${{ github.actor }}
  enable_code_security: true
  fail_on_severity: critical
secrets:
  registry_password: ${{ secrets.GITHUB_TOKEN }}
```

</details>

### Grype

Fast, accurate vulnerability scanner with excellent detection rates.

<details>
<summary><strong>Configuration & Examples</strong></summary>

**Configuration:**

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `image_ref` | Container image to scan | - | Yes |
| `registry_username` | Username for private registry authentication | `''` | No |
| `enable_code_security` | Upload to GitHub Security tab | `false` | No |
| `post_pr_comment` | Post findings as PR comments | `false` | No |
| `fail_on_severity` | Severity threshold | `none` | No |

**Required secrets (for private registries):**

| Secret | Description | Required |
|--------|-------------|----------|
| `registry_password` | Password/token for registry authentication | No |

**Example:**

```yaml
# Public image
with:
  scanners: grype
  image_ref: 'nginx:latest'
  fail_on_severity: high

# Private registry
with:
  scanners: grype
  image_ref: 'ghcr.io/myorg/myapp:latest'
  registry_username: ${{ github.actor }}
  fail_on_severity: high
secrets:
  registry_password: ${{ secrets.GITHUB_TOKEN }}
```

</details>

### Syft (SBOM)

Generates detailed Software Bill of Materials (SBOM) for images and filesystems.

<details>
<summary><strong>Configuration & Examples</strong></summary>

**Configuration:**

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `scan-path` | Directory or file path to scan | `.` | No |
| `scan-image` | Container image to scan | - | No |
| `registry_username` | Username for private registry authentication | `''` | No |
| `enable_code_security` | Upload to GitHub Security tab | `false` | No |

**Required secrets (for private registries):**

| Secret | Description | Required |
|--------|-------------|----------|
| `registry_password` | Password/token for registry authentication | No |

**Example:**

```yaml
# Scan filesystem
with:
  scanners: sbom
  scan-path: 'dist/'

# Scan public container image
with:
  scanners: sbom
  scan-image: 'nginx:latest'

# Scan private container image
with:
  scanners: sbom
  scan-image: 'ghcr.io/myorg/myapp:latest'
  registry_username: ${{ github.actor }}
secrets:
  registry_password: ${{ secrets.GITHUB_TOKEN }}
```

</details>

## Infrastructure Scanners

### Trivy IaC

Scans Infrastructure as Code files for misconfigurations and security issues.

**Supported frameworks:** Terraform, CloudFormation, Kubernetes, Dockerfile

<details>
<summary><strong>Configuration & Examples</strong></summary>

**Configuration:**

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `iac_path` | Path to IaC directory | `infrastructure` | No |
| `enable_code_security` | Upload to GitHub Security tab | `false` | No |
| `post_pr_comment` | Post findings as PR comments | `false` | No |
| `fail_on_severity` | Severity threshold | `none` | No |

**Example:**

```yaml
with:
  scanners: trivy-iac
  iac_path: 'terraform/'
  enable_code_security: true
  fail_on_severity: high
```

</details>

### Checkov

Policy as Code scanner for cloud infrastructure configurations.

<details>
<summary><strong>Configuration & Examples</strong></summary>

**Configuration:**

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `iac_path` | Path to IaC directory | `infrastructure` | No |
| `framework` | IaC framework | `terraform` | No |
| `enable_code_security` | Upload to GitHub Security tab | `false` | No |
| `post_pr_comment` | Post findings as PR comments | `false` | No |
| `fail_on_severity` | Fail on any check failure | `none` | No |

**Example:**

```yaml
with:
  scanners: checkov
  iac_path: 'infrastructure/'
  framework: terraform
  enable_code_security: true
```

</details>

## Malware Scanner

### ClamAV

Open-source antivirus engine for detecting trojans, viruses, and malware.

<details>
<summary><strong>Configuration & Examples</strong></summary>

**Configuration:**

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `clamav_scan_path` | Path to scan | `.` | No |
| `enable_code_security` | Upload to GitHub Security tab | `false` | No |
| `post_pr_comment` | Post findings as PR comments | `true` | No |
| `fail_on_severity` | Fail if malware detected | `none` | No |

**Example:**

```yaml
# Scan entire repository
with:
  scanners: clamav

# Scan specific directory
with:
  scanners: clamav
  clamav_scan_path: 'uploads/'
  fail_on_severity: critical
```

</details>


## DAST Scanners

### ZAP

ZAP (Zed Attack Proxy) provides Dynamic Application Security Testing (DAST) for running web applications and APIs.

**Key Features:**
- **Config-file driven**: Define multiple scans with different targets, types, and settings in a single YAML/JSON file
- **Parallel scan groups**: Run URL-based and container-based scans in parallel pipelines
- **Flexible defaults**: Set defaults once, override per-scan as needed
- **Multiple target modes**: URL (already running), docker-run (single container), or compose (multi-container)
- **Multiple scan types**: baseline, full, or API scans with OpenAPI/Swagger specs

---

#### Quick Start (Recommended: Config File)

**1. Create a ZAP config file** (e.g., `.github/zap-config.yml`):

```yaml
# Simple flat config - single target mode
defaults:
  max_duration_minutes: 10
  fail_on_severity: medium
  allow_failure: false

target:
  mode: url

scans:
  - name: baseline-scan
    type: baseline
    target_url: https://example.com

  - name: api-scan
    type: api
    target_url: https://api.example.com
    api_spec: https://api.example.com/openapi.json
```

**2. Call the workflow**:

```yaml
jobs:
  security:
    uses: huntridge-labs/argus/.github/workflows/reusable-security-hardening.yml@main
    with:
      scanners: zap
      zap_config_file: .github/zap-config.yml
```

---

<details>
<summary><strong>Configuration Options</strong></summary>

#### Configuration Options

**Via workflow inputs (legacy/simple mode):**

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `scanners` | Include `zap` (opt-in; not included in `all`) | - | Yes |
| `zap_config_file` | Path to ZAP config file (YAML/JSON). **Recommended approach** - drives all scan configuration. | `''` | No |
| `zap_scan_mode` | `url`, `docker-run`, or `compose` (ignored if `zap_config_file` set) | `url` | No |
| `zap_target_urls` | Comma-separated URLs to scan (ignored if `zap_config_file` set) | `''` | Conditional |
| `zap_scan_type` | `baseline`, `full`, or `api` (ignored if `zap_config_file` set) | `baseline` | No |
| `zap_api_spec` | OpenAPI/Swagger spec URL or path (ignored if `zap_config_file` set) | `''` | Conditional |
| `allow_failure` | Allow workflow to continue on failures | `true` | No |
| `severity_threshold` | Minimum severity to fail (`none`, `low`, `medium`, `high`, `critical`) | `high` | No |

> **Note**: When `zap_config_file` is provided, it takes precedence and other `zap_*` inputs are ignored.

</details>

---

<details>
<summary><strong>Config File Reference</strong></summary>

#### Config File Reference

**Schema URL**: [`zap-config.schema.json`](../.github/actions/parse-zap-config/schemas/zap-config.schema.json)

**Two config styles supported:**

1. **Flat** - single target, multiple scans
2. **Grouped** - multiple scan groups with different targets (enables parallel pipelines)

##### Flat Config Example

All scans share the same target configuration:

```yaml
target:
  mode: url  # or docker-run, compose

defaults:
  max_duration_minutes: 10
  fail_on_severity: medium
  allow_failure: false
  post_pr_comment: true

scans:
  - name: baseline-scan
    type: baseline
    target_url: https://app.example.com

  - name: api-scan
    type: api
    target_url: https://api.example.com
    api_spec: https://api.example.com/openapi.json
    fail_on_severity: high  # Override default
```

##### Grouped Config Example (Parallel Pipelines)

Create separate scan groups with their own targets - ideal for running URL scans and container scans in parallel:

```yaml
defaults:
  max_duration_minutes: 10
  fail_on_severity: medium
  allow_failure: true

scan_groups:
  # Group 1: URL-based scans (external targets)
  - name: url-scans
    description: "External URL Scans"
    target:
      mode: url
    scans:
      - name: baseline-prod
        type: baseline
        target_url: https://example.com

      - name: api-prod
        type: api
        target_url: https://api.example.com
        api_spec: https://api.example.com/openapi.json

  # Group 2: Container scans (start app, then scan)
  - name: docker-scans
    description: "Container-based Scans"
    target:
      mode: docker-run
      image: ghcr.io/myorg/myapp:latest
      ports: "8080:8080"
    defaults:
      target_url: http://localhost:8080
    scans:
      - name: baseline-container
        type: baseline

      - name: full-container
        type: full
        max_duration_minutes: 20
```

##### Target Configuration

**`target.mode`** options:

- **`url`** (default): Scan already-running endpoints
- **`docker-run`**: Start a single container, then scan
- **`compose`**: Start a docker-compose stack, then scan

**Docker-run mode example:**

```yaml
target:
  mode: docker-run
  image: myapp:latest
  ports: "3000:3000,8080:8080"
  healthcheck_url: http://localhost:3000/health
  
  # Optional: build from local Dockerfile
  build:
    context: .
    dockerfile: ./Dockerfile
    tag: myapp:test
  
  # Optional: private registry auth
  registry:
    host: ghcr.io
    username: ${{ github.actor }}
    auth_secret: GITHUB_TOKEN  # Secret name
```

**Compose mode example:**

```yaml
target:
  mode: compose
  compose_file: docker-compose.test.yml
  compose_build: true
  healthcheck_url: http://localhost:8080/health
```

##### Scan Configuration

**Required fields:**
- `name`: Unique scan identifier (alphanumeric, hyphens, underscores)
- `type`: `baseline`, `full`, or `api`

**Common fields:**
- `target_url`: Target URL to scan (required for baseline/full scans)
- `api_spec`: OpenAPI/Swagger spec URL or file path (required for api scans)
- `max_duration_minutes`: Maximum scan duration (1-120, default: 10)
- `fail_on_severity`: Fail threshold - `none`, `low`, `medium`, `high`, `critical` (default: `none`)
- `allow_failure`: Continue workflow on failure (default: `false`)
- `post_pr_comment`: Post scan results as PR comment (default: `false`)

**Advanced fields:**
- `healthcheck_url`: Override target healthcheck (waits for 200 response before scanning)
- `rules_file`: Path to ZAP rules file (.tsv) to ignore specific alerts
- `context_file`: Path to ZAP context file for session/auth
- `cmd_options`: Additional ZAP CLI options (e.g., `-z "-config api.addrs.addr.name=.*"`)

**Authentication (header-based):**

```yaml
scans:
  - name: authenticated-scan
    type: baseline
    target_url: https://app.example.com
    auth:
      header_name: Authorization
      header_secret: API_TOKEN  # GitHub secret name
      # OR for non-secret values:
      # header_value: "Bearer ${MY_TOKEN}"
```

##### Defaults

Set defaults at root or per-group that apply to all scans (scans can override):

```yaml
defaults:
  max_duration_minutes: 15
  fail_on_severity: medium
  allow_failure: false
  post_pr_comment: true
  target_url: http://localhost:8080  # Default target
  rules_file: .zap/rules.tsv
  auth:
    header_name: X-API-Key
    header_secret: API_KEY
```

</details>

---

<details>
<summary><strong>Complete Examples</strong></summary>

#### Complete Examples

##### Example 1: Simple URL Scan

```yaml
# .github/zap-config.yml
target:
  mode: url

scans:
  - name: baseline
    type: baseline
    target_url: https://example.com
    max_duration_minutes: 5
    fail_on_severity: high
```

```yaml
# .github/workflows/security.yml
jobs:
  zap-scan:
    uses: huntridge-labs/argus/.github/workflows/reusable-security-hardening.yml@main
    with:
      scanners: zap
      zap_config_file: .github/zap-config.yml
```

##### Example 2: Container Scan with Build

```yaml
# .github/zap-config.yml
target:
  mode: docker-run
  build:
    context: .
    dockerfile: Dockerfile
    tag: app:test
  ports: "8080:8080"
  healthcheck_url: http://localhost:8080/health

defaults:
  max_duration_minutes: 10
  fail_on_severity: medium
  target_url: http://localhost:8080

scans:
  - name: baseline
    type: baseline

  - name: api
    type: api
    api_spec: http://localhost:8080/openapi.json
```

##### Example 3: Parallel Pipelines (Grouped)

```yaml
# .github/zap-config.yml
defaults:
  max_duration_minutes: 10
  fail_on_severity: medium

scan_groups:
  - name: url-scans
    description: "Production URL Scans"
    target:
      mode: url
    scans:
      - name: prod-baseline
        type: baseline
        target_url: https://example.com

      - name: prod-api
        type: api
        target_url: https://api.example.com
        api_spec: https://api.example.com/openapi.json

  - name: container-scans
    description: "Local Container Scans"
    target:
      mode: docker-run
      image: myapp:latest
      ports: "3000:3000"
    defaults:
      target_url: http://localhost:3000
    scans:
      - name: container-baseline
        type: baseline

      - name: container-full
        type: full
        max_duration_minutes: 20
```

This creates two parallel scan pipelines in your GitHub Actions workflow - one for URL scans and one for container scans.

</details>

---

<details>
<summary><strong>Legacy Input-Based Configuration</strong></summary>

#### Legacy Input-Based Configuration

For simple single-scan scenarios, you can still use workflow inputs directly (no config file):

**URL-only scan:**

```yaml
jobs:
  security:
    uses: huntridge-labs/argus/.github/workflows/reusable-security-hardening.yml@main
    with:
      scanners: zap
      zap_scan_mode: url
      zap_target_urls: https://example.com
      allow_failure: false
      severity_threshold: medium
```

**Container scan:**

```yaml
jobs:
  security:
    uses: huntridge-labs/argus/.github/workflows/reusable-security-hardening.yml@main
    with:
      scanners: zap
      zap_scan_mode: docker-run
      zap_app_image_ref: ghcr.io/myorg/app:latest
      zap_app_ports: "8080:8080"
      allow_failure: false
```

> **Note**: Input-based configuration is limited to single scans. Use config files for multiple scans, matrix execution, or advanced features.

</details>


## Common Configuration Patterns

### Enable GitHub Security Tab

Upload SARIF results for all scanners:

```yaml
with:
  scanners: all
  enable_code_security: true
```

### Disable PR Comments

Useful for scheduled scans:

```yaml
with:
  scanners: all
  post_pr_comment: false
```

### Scanner Selection Patterns

- Full coverage: `scanners: all`
- SAST only: `scanners: codeql,opengrep,bandit,gitleaks`
- DAST only: `scanners: zap`
- Infrastructure only: `scanners: trivy-iac,checkov`
- Container only: `scanners: trivy-container,grype,sbom`
- Focused mix: `scanners: container,infrastructure,gitleaks`
