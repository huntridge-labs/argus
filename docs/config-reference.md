<div align=center>

# Configuration Reference

Complete specification for `argus.yml` — the Argus security scanner configuration file.

</div>

## Overview

Argus is configured via a YAML file that defines which scanners to run, how results are reported, and how tools are executed. The configuration is validated against a [JSON Schema](../argus-config.schema.json) and a built-in Python validator before any scan begins.

**Schema version:** `1.0`

## File Discovery

Argus searches the current directory for config files in this order:

1. `argus.yml`
2. `argus.yaml`
3. `.argus.yml`
4. `.argus.yaml`

You can also specify a path explicitly:

```bash
python -m argus scan --config path/to/argus.yml
```

If no config file is found, Argus uses default settings.

## IDE Support

Add the JSON Schema directive at the top of your config file for autocompletion and inline validation:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/huntridge-labs/argus/0.7.0/argus-config.schema.json
version: "1.0"
```

## Top-Level Structure

```yaml
version: "1.0"        # Schema version (required value: "1.0")
scanners: {}           # Scanner configurations
reporting: {}          # Output format and threshold settings
execution: {}          # Tool execution backend settings
containers: {}         # Container image scanning
dast: {}               # Dynamic application security testing
```

Only these six top-level keys are permitted. Unknown keys produce a validation warning.

---

## `version`

| Property | Type | Required | Values | Default |
|----------|------|----------|--------|---------|
| `version` | string | No | `"1.0"` | `"1.0"` |

The configuration schema version. Currently only `"1.0"` is supported.

```yaml
version: "1.0"
```

---

## `scanners`

A mapping of scanner names to their configuration. Each key must be a registered scanner name.

### Available Scanners

| Name | Category | Description |
|------|----------|-------------|
| `bandit` | SAST | Python security linting |
| `opengrep` | SAST | Pattern-based static analysis |
| `gitleaks` | Secrets | Git history and file secret detection |
| `osv` | Dependencies | OSV database vulnerability scanning |
| `trivy-iac` | Infrastructure | Terraform, Kubernetes, Dockerfile scanning |
| `checkov` | Infrastructure | Multi-framework IaC scanning |
| `clamav` | Malware | File-based malware detection |
| `supply-chain` | Supply Chain | GitHub Actions workflow security |
| `container` | Container | Container image scanning (Trivy + Grype + Syft) |
| `zap` | DAST | Web application dynamic scanning |

### Scanner Properties

Every scanner accepts these common properties:

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `enabled` | boolean | `true` | Whether this scanner is active. Disabled scanners are skipped. |
| `path` | string | `"."` | Path to scan, relative to the repository root. |
| `severity_threshold` | [severity](#severity-levels) | *(inherit)* | Per-scanner severity threshold. Overrides the global `reporting.severity_threshold`. |
| `config_file` | string | | Path to a scanner-specific config file (e.g. `pyproject.toml` for Bandit). |
| `exclude` | string | | Comma-separated paths or patterns to exclude from analysis. |

### Scanner-Specific Properties

Some scanners accept additional properties, passed through as extra configuration:

| Property | Type | Applicable Scanners | Description |
|----------|------|---------------------|-------------|
| `image_ref` | string | `container` | Container image to scan (e.g. `myapp:latest`). |
| `target_url` | string | `zap` | URL of the target web application. |
| `scanners` | string | `container` | Comma-separated sub-scanners: `trivy`, `grype`, `syft`. |
| `scan_type` | string | `zap` | Scan type: `baseline` or `full`. |
| `framework` | string | `checkov` | Framework filter (e.g. `terraform`, `kubernetes`). |
| `check` | string | `checkov`, `bandit` | Specific check IDs to run. |
| `skip_check` | string | `checkov`, `bandit` | Specific check IDs to skip. |
| `config` | string | *(any)* | Inline scanner configuration string. |
| `registry_username` | string | `container` | Username for private container registry auth. |
| `registry_password` | string | `container` | Password/token for private registry auth. Prefer environment variables. |

Unknown scanner keys produce a validation warning but are passed through as extra config.

### Examples

**Minimal — enable a scanner with defaults:**

```yaml
scanners:
  gitleaks:
    enabled: true
```

**Scanner with null value — uses all defaults:**

```yaml
scanners:
  gitleaks:
```

**Fully configured scanner:**

```yaml
scanners:
  bandit:
    enabled: true
    path: "src"
    severity_threshold: high
    config_file: "pyproject.toml"
    exclude: "tests,docs"
```

**Container scanning:**

```yaml
scanners:
  container:
    enabled: true
    image_ref: "myapp:latest"
    scanners: "trivy,grype,syft"
    registry_username: "${REGISTRY_USER}"
    registry_password: "${REGISTRY_TOKEN}"
```

**DAST scanning:**

```yaml
scanners:
  zap:
    enabled: true
    target_url: "http://localhost:3000"
    scan_type: baseline
```

---

## `reporting`

Controls how scan results are formatted and where they are written.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `formats` | array of strings | `["terminal"]` | Output formats to generate. |
| `severity_threshold` | [severity](#severity-levels) | `none` | Global severity threshold. Findings at or above this level cause a non-zero exit code. |
| `output_dir` | string | `"./argus-results"` | Directory for report files (SARIF, JSON, Markdown). |

### Report Formats

| Format | Description |
|--------|-------------|
| `terminal` | Rich terminal output to stdout |
| `markdown` | Markdown summary file |
| `sarif` | SARIF format (for GitHub Code Security integration) |
| `json` | JSON structured report |

### Example

```yaml
reporting:
  formats:
    - terminal
    - sarif
    - json
  severity_threshold: high
  output_dir: "./argus-results"
```

No additional keys are permitted in the `reporting` block.

---

## `execution`

Controls how scanner tools are executed — locally, in containers, or auto-detected.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `backend` | string | `"auto"` | Execution backend: `auto`, `local`, or `docker`. |
| `registry` | string | | Override the default container registry (e.g. `registry.internal.corp/argus`). |
| `pull_policy` | string | `"if-not-present"` | Container image pull policy: `always`, `if-not-present`, or `never`. |
| `prewarm_images` | boolean | `true` | Pull container images in the background during scan startup so scanners with cached images don't wait on the registry. Disable on metered connections. |
| `prewarm_workers` | integer | `4` | Concurrency cap for the pre-warm thread pool. Lower for stricter registry rate-limits; higher only with first-class network. |

### Backend Modes

| Mode | Behavior |
|------|----------|
| `auto` | Prefers containers for reproducibility. Falls back to local tools if no container image exists for the scanner. |
| `local` | Uses locally installed tools only. Faster, but the user accepts version risk. |
| `docker` | Containers only. Fails if Docker is unavailable or no image exists for a scanner. |

### Pull Policies

| Policy | Behavior |
|--------|----------|
| `always` | Pull the latest image on every run. |
| `if-not-present` | Use cached images if available; pull only when missing. |
| `never` | Never pull images. Requires pre-pulled images. Use for air-gapped environments. |

### Example

```yaml
execution:
  backend: auto
  registry: "registry.internal.corp/argus"
  pull_policy: if-not-present
```

No additional keys are permitted in the `execution` block.

---

## `containers`

Configuration for container image scanning via `argus scan container`. This section defines which images to scan and how to discover them.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `discover` | boolean | `false` | Automatically discover Dockerfiles and build images for scanning. |
| `search_paths` | array of strings | | Directories to search for Dockerfiles when `discover` is enabled. |
| `images` | array of [image objects](#image-object) | | Explicit list of container images to scan. |
| `scanners` | array of strings | `["trivy", "grype"]` | Sub-scanners to use. Values: `trivy`, `grype`, `syft`. |
| `output_dir` | string | `"./argus-results"` | Output directory for container scan results. |

### Image Object

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `image` | string | **Yes** | Image reference (e.g. `nginx:latest`, `myapp:v1`). |
| `name` | string | No | Human-readable name for reports. |
| `dockerfile` | string | No | Path to the Dockerfile used to build this image. |

### Example

```yaml
containers:
  discover: false
  images:
    - image: "nginx:1.25"
      name: "Web Server"
    - image: "myapp:latest"
      name: "Application"
      dockerfile: "docker/Dockerfile"
  scanners:
    - trivy
    - grype
    - syft
  output_dir: "./argus-results"
```

No additional keys are permitted in the `containers` block.

---

## `dast`

Configuration for dynamic application security testing (DAST) via ZAP.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `targets` | array of [target objects](#target-object) | | List of web application targets. |
| `scan_type` | string | `"baseline"` | ZAP scan type: `baseline` (faster, CI-friendly) or `full` (deeper analysis). |
| `startup_timeout` | integer | `60` | Seconds to wait for a target container to become healthy before scanning. |

### Target Object

| Property | Type | Description |
|----------|------|-------------|
| `url` | string | URL of an already-running web application. |
| `image` | string | Container image to start and scan (Argus handles the lifecycle). |
| `name` | string | Human-readable name for reports. |
| `port` | integer | Override the exposed port for image-based targets. |
| `env` | object | Key-value environment variables to pass to the target container. |

Provide either `url` (for a running app) or `image` (for Argus to manage) per target.

### Example

```yaml
dast:
  scan_type: baseline
  startup_timeout: 90
  targets:
    - url: "https://staging.example.com"
      name: "Staging"
    - image: "myapp:latest"
      name: "Local App"
      port: 8080
      env:
        NODE_ENV: "test"
        DATABASE_URL: "sqlite:///test.db"
```

No additional keys are permitted in the `dast` block.

---

## Severity Levels

Severity levels are used in `severity_threshold` (both global and per-scanner). Findings at or above the threshold cause a non-zero exit code.

| Level | Triggers failure on |
|-------|---------------------|
| `critical` | Critical findings only |
| `high` | High + Critical |
| `medium` | Medium + High + Critical |
| `low` | Low + Medium + High + Critical |
| `none` | Never fail (default) |

Per-scanner thresholds override the global `reporting.severity_threshold`. See the [Failure Control guide](failure-control.md) for details.

---

## Validation

Argus validates your config before running any scan. Validation catches:

- **Unknown top-level keys** (warning)
- **Unknown scanner keys** (warning — passed through as extra config)
- **Invalid severity values** (error)
- **Invalid backend or pull policy** (error)
- **Invalid report format** (error)
- **Type mismatches** (error — e.g. `enabled: "yes"` instead of `enabled: true`)

Errors are fatal and abort the scan. Warnings are logged but the scan proceeds.

---

## Complete Example

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/huntridge-labs/argus/0.7.0/argus-config.schema.json
version: "1.0"

scanners:
  bandit:
    enabled: true
    path: "src"
    config_file: "pyproject.toml"

  gitleaks:
    enabled: true

  osv:
    enabled: true

  trivy-iac:
    enabled: true
    path: "infrastructure"
    severity_threshold: medium

  checkov:
    enabled: true
    path: "infrastructure"
    framework: "terraform"

  opengrep:
    enabled: true
    path: "src"

  clamav:
    enabled: true

  supply-chain:
    enabled: true

reporting:
  formats:
    - terminal
    - sarif
  severity_threshold: high
  output_dir: "./argus-results"

execution:
  backend: auto
  pull_policy: if-not-present
```

## Related Guides

- [CLI Reference](cli-reference.md) — Command-line flags and usage
- [Scanner Reference](scanners.md) — Detailed per-scanner documentation
- [Failure Control](failure-control.md) — Severity threshold behavior
- [Container Scanning](container-scanning.md) — Config-driven container matrix scanning
