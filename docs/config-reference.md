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
# yaml-language-server: $schema=https://raw.githubusercontent.com/huntridge-labs/argus/1.7.0/argus-config.schema.json
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
| `container` | Container | Container image scanning (Trivy + Grype + Syft + declared-port exposure surface) |
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
| `target_url` | string | `zap` | URL of the running app to scan (the system under test). |
| `scanners` | string | `container` | Comma-separated sub-scanners: `trivy`, `grype`, `syft`, `exposure`, `services`. Default `"trivy,grype,syft,exposure,services"`. |
| `expose_warn_ports` | list[string] | `container` | Override the built-in WARN-list for the `exposure` sub-scanner. Replaces the defaults (SSH 22/tcp, MySQL 3306/tcp, Redis 6379/tcp, etc.). Pass `[]` to demote every declared port to INFO. Entries are `"PORT/PROTO"` strings; bare `"PORT"` defaults to tcp. |
| `expose_ignore_ports` | list[string] | `container` | Suppress findings entirely for these ports (use for ports the team has explicitly accepted, e.g. the app's known 8080/tcp). |
| `services_warn` | list[string] | `container` | Override the built-in WARN-list for the `services` sub-scanner. Replaces the defaults (sshd, postgresql, redis-server, etc.). Pass `[]` to demote every declared service to INFO. Matching is case-insensitive. |
| `services_ignore` | list[string] | `container` | Suppress findings entirely for these services (use for services the team has explicitly accepted, e.g. `cron`, `rsyslog`). Matching is case-insensitive. |
| `scan_type` | string | `zap` | Scan type: `baseline`, `full`, or `api`. Auto-set to `api` when `api_spec` is provided. |
| `api_spec` | string | `zap` | OpenAPI/Swagger spec URL or path; switches the scan to `zap-api-scan.py`. |
| `rules_file` | string | `zap` | Path to a ZAP `.tsv` ignore-rules file. Mounted into the container at `/zap/wrk/rules.tsv`. |
| `cmd_options` | list[string] | `zap` | Extra ZAP CLI flags appended verbatim after the built-in arguments. |
| `max_duration_minutes` | integer | `zap` | Hard cap on scan duration (translates to `-T <minutes>`). |
| `app_image_ref` | string | `zap` | Pre-built container image to bring up as the sidecar SUT (no `target_url` needed). |
| `app_ports` | string | `zap` | Port-forward spec for `app_image_ref` (e.g. `8080:8080`). |
| `auth` | mapping | `zap` | Web-app authentication block — see [Web-app authentication](#web-app-authentication-zap) below. |
| `framework` | string | `checkov` | Framework filter (e.g. `terraform`, `kubernetes`). |
| `check` | string | `checkov`, `bandit` | Specific check IDs to run. |
| `skip_check` | string | `checkov`, `bandit` | Specific check IDs to skip. |
| `config` | string | *(any)* | Inline scanner configuration string. |
| `registry_username` | string | `container`, `zap` | Username for private registry auth. Prefer `registry_username_env` (see [Credential fields](#credential-fields)). |
| `registry_password` | string | `container`, `zap` | Password/token for private registry auth. Prefer `registry_password_env`. |
| `registry_username_env` | string | `container`, `zap` | **Name** of an environment variable holding the registry username. Resolved at scan time. |
| `registry_password_env` | string | `container`, `zap` | **Name** of an environment variable holding the registry password/token. Resolved at scan time. |

Unknown scanner keys produce a validation warning but are passed through as extra config.

### Credential fields

Credential fields accept two forms:

```yaml
# Preferred — only the env-var *name* lives in argus.yml.
# Argus reads os.environ at scan time. No secret in VCS.
registry_password_env: REGISTRY_TOKEN

# Back-compat — accepts a literal string. ``argus validate`` warns
# at config-load time if the value matches a known vendor secret
# prefix (gh*, AKIA, AIza, glpat-, etc.), so the leak is caught
# before the scan runs.
registry_password: "literal-value"
```

The same shape applies to **any** credential field across scanners — both forms are interchangeable, and the `*_env` form always wins when both are set.

**Third form — CLI stdin** (highest precedence; overrides both YAML forms):

```bash
echo "$REGISTRY_TOKEN" | argus scan --registry-password-stdin --config argus.yml
echo "$APP_PASSWORD"   | argus scan zap --zap-auth-password-stdin --target https://app
```

Mirrors `docker login --password-stdin`: the value is read once from stdin, stored in a process-local slot, and consumed by scanners at scan time. The value never reaches the per-scanner config dict, so it can't leak into `argus-audit.json` or `argus.log`. At most **one** `--*-password-stdin` flag per invocation (stdin is a single stream); use `<field>_env` for the other credentials. Argus errors out with a usage hint if stdin is a TTY or if more than one stdin flag is set.

Available CLI stdin flags:

| Flag | Slot it fills |
|---|---|
| `--registry-password-stdin` | Registry password for any scanner that needs registry auth (`container`, `zap` with `app_image_ref`). |
| `--zap-auth-password-stdin` | ZAP web-app authentication password (`scanners.zap.auth.password`). |

**Validation rules:**

- `<field>_env` must be a valid POSIX shell identifier (`[A-Za-z_][A-Za-z0-9_]*`); invalid names are a config error.
- `<field>` literal that matches a vendor-secret prefix produces a warning suggesting `<field>_env`.
- Setting both `<field>` and `<field>_env` is a warning; `*_env` takes precedence at resolution.
- Unset env-var-name references resolve to `None` and skip the credential entirely (logged at WARNING) — the scan still runs.

### Web-app authentication (`zap`)

ZAP's web-app authentication uses a ZAP context file as the source of truth for login URL, form selectors, logged-in regex, and session management. Argus mounts the file into the container and exports credentials via `ZAP_AUTH_USERNAME` / `ZAP_AUTH_PASSWORD`, which the context file references via ZAP's native `{%username%}` / `{%password%}` placeholders.

```yaml
scanners:
  zap:
    target_url: "https://app.example.com"
    auth:
      context_file: ".zap/context.xml"  # mounted at /zap/wrk/context.xml
      username_env: ZAP_APP_USER         # env-var name
      password_env: ZAP_APP_PASSWORD     # env-var name
      # username / password literal forms are also accepted (warned).
```

The DOM specification (form selectors via XPath/CSS, logged-in detection regex) lives in the user-authored context file — the ZAP GUI can record and emit one. Argus stays out of the DOM-mapping business intentionally.

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

**Container scanning with private registry:**

```yaml
scanners:
  container:
    enabled: true
    image_ref: "myapp:latest"
    # Default sub-scanner set; drop any you don't want
    scanners: "trivy,grype,syft,exposure"
    # Env-var name references — the actual values live in
    # the runner's environment (e.g. exported from
    # `${{ secrets.REGISTRY_USER }}` on GitHub Actions).
    registry_username_env: REGISTRY_USER
    registry_password_env: REGISTRY_TOKEN
```

**Attack-surface tuning (exposed ports):**

```yaml
scanners:
  container:
    enabled: true
    image_ref: "myapp:latest"
    # The default WARN list flags SSH/MySQL/Redis/etc. Add or replace
    # entries here when your image legitimately exposes one of them
    # and you want a different severity (or omit the override and
    # use ``expose_ignore_ports`` to suppress entirely).
    expose_warn_ports:
      - 22/tcp
      - 3306/tcp
      - 8080/tcp        # promote this app port to WARN
    # Ports the team has explicitly accepted — suppressed entirely.
    expose_ignore_ports:
      - 443/tcp
      - 9090/tcp
```

**Attack-surface tuning (declared services):**

```yaml
scanners:
  container:
    enabled: true
    image_ref: "myapp:latest"
    # The default WARN list flags sshd/postgresql/redis-server/etc.
    # Replace or extend when your image legitimately declares one of
    # them and you want a different severity (or omit the override
    # and use ``services_ignore`` to suppress entirely). Matching is
    # case-insensitive.
    services_warn:
      - sshd
      - postgresql
      - nginx           # promote this app service to WARN
    # Services the team has explicitly accepted — suppressed entirely.
    services_ignore:
      - cron
      - rsyslog
```

**DAST baseline scan:**

```yaml
scanners:
  zap:
    enabled: true
    target_url: "http://localhost:3000"
    scan_type: baseline
```

**DAST API scan with custom rules and time cap:**

```yaml
scanners:
  zap:
    enabled: true
    target_url: "https://api.example.com"
    api_spec: "https://api.example.com/openapi.json"
    rules_file: ".zap/api-rules.tsv"
    max_duration_minutes: 30
    cmd_options:
      - "-z"
      - "-config view.locale=en_GB"
```

**DAST authenticated scan (ZAP context-file passthrough):**

```yaml
scanners:
  zap:
    enabled: true
    target_url: "https://app.example.com"
    auth:
      context_file: ".zap/context.xml"   # mounted at /zap/wrk/context.xml
      username_env: ZAP_APP_USER          # env-var name
      password_env: ZAP_APP_PASSWORD      # env-var name
```

---

## `reporting`

Controls how scan results are formatted and where they are written.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `formats` | array of strings | `["terminal"]` | Output formats to generate. |
| `severity_threshold` | [severity](#severity-levels) | `none` | Global severity threshold. Findings at or above this level cause a non-zero exit code. |
| `output_dir` | string | `"./argus-results"` | Directory for report files (SARIF, JSON, Markdown). |
| `keep_raw` | boolean | `false` | Persist each scanner's raw output (results.json / *.sarif / stdout.txt) under `<output_dir>/raw/<scanner>/`. Default OFF because scanners like `gitleaks` write literal matched secret bytes into raw output — the canonical `argus-results.json` is always written and is pattern-redacted. Forensic / triage workflows that need unredacted per-scanner artifacts opt in. CLI `--keep-raw` / `--no-keep-raw` overrides this setting. |
| `attest` | boolean | `false` | Sign the scan attestation with [cosign](https://docs.sigstore.dev/cosign/): an in-toto Statement wrapping the OpenVEX predicate (`subject` = scanned image digests + repo commit), written as `argus-attestation.intoto.json` + a `sign-blob` `.bundle`, plus a registry-attached attestation for any pushed image. **Keyless** — needs cosign on PATH and ambient OIDC (e.g. CI with `id-token: write`); a no-op that still writes the unsigned statement otherwise. Default OFF (network + registry side effects). See [Security → Signing the attestation](security.md#signing-the-attestation-cosign-opt-in). |

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

### Output directory layout

The canonical aggregate artifacts are written at the root of `output_dir` and are
unchanged across versions, so existing consumers (the viewers, CI SARIF upload, the
GitHub/GitLab reporters) keep working:

```
argus-results/
├── argus-results.json          # full aggregate (all scanners) — canonical
├── argus-summary.md            # executive markdown
├── argus-results.sarif         # SARIF (when requested)
├── argus-results.openvex.json  # OpenVEX (when requested)
├── argus-audit.json · argus.log
```

Alongside them, Argus writes **scope-organized views** so each audience finds its
slice co-located — additive, the root artifacts above are untouched:

```
├── security/        argus-results.json, argus-summary.md, argus-results.sarif
├── lint/            argus-results.json, argus-summary.md
└── supply-chain/    argus-results.json, argus-summary.md, argus-results.openvex.json
```

A finding's scope follows its scanner: linters → `lint`; SCA / container / supply-chain
scanners → `supply-chain`; everything else (SAST, secrets, IaC, DAST, malware) →
`security`. Only scopes with findings get a subdirectory. Per-scope SARIF/OpenVEX are
written only when those formats are requested. `--keep-raw` still writes per-scanner raw
output under `raw/<scanner>/`.

---

## `execution`

Controls how scanner tools are executed — locally, in containers, or auto-detected.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `backend` | string | `"auto"` | Execution backend: `auto`, `local`, or `docker`. |
| `registry` | string | | Override the default container registry (e.g. `registry.internal.corp/argus`). Flat host-swap — every image gets rewritten to `<registry>/<original-path>`. For per-upstream mirrors (Harbor / Artifactory / ECR proxy caches), use `registry_map` instead. |
| `registry_map` | map[string→string] | `{}` | Per-upstream registry mirrors, keyed by upstream host (`docker.io`, `ghcr.io`, `quay.io`, etc.). Wins over `registry` for any matching upstream; unmapped upstreams fall through to `registry` (if set) or the original reference. Recommended for proxy-cache setups where each project mirrors a single upstream. See [Container scanning → Per-upstream mirrors](troubleshooting/docker.md#image-pull-failures-registry-auth-rate-limits-air-gapped-ghes). |
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
| `registry_username` | string | | Literal username applied to every image when no `registry_auth` entry matches. Prefer `registry_username_env`. |
| `registry_username_env` | string | | **Name** of an environment variable holding the default registry username. |
| `registry_password` | string | | Literal password/token applied to every image. Prefer `registry_password_env`. |
| `registry_password_env` | string | | **Name** of an environment variable holding the default registry password/token. |
| `registry_auth` | mapping | | Per-registry credential map keyed by registry host (or `host/path-prefix` for finer granularity). Longest matching prefix wins. See [Per-registry credentials](#per-registry-credentials) below. |

Registry credentials are forwarded to Trivy, Grype, and Syft as their native env vars (`TRIVY_USERNAME` / `TRIVY_PASSWORD`, `GRYPE_REGISTRY_AUTH_USERNAME` / `GRYPE_REGISTRY_AUTH_PASSWORD`, `SYFT_REGISTRY_AUTH_USERNAME` / `SYFT_REGISTRY_AUTH_PASSWORD`) for both the local-binary and container-fallback execution paths. For back-compat, Argus also reads the top-level credential fields from `scanners.container.*` — the canonical `containers.*` location wins when both are set.

### Per-registry credentials

When scanning images from multiple registries (or different repo paths within one registry that need different credentials), declare a `registry_auth` map. Keys are matched as **path-component prefixes** of the image reference — `registry.example.com/internal/restricted` matches `.../restricted/repo` but not `.../restrictedX/repo`. The **longest matching key wins**.

Each entry uses the prefix-less field names `username` / `username_env` / `password` / `password_env` (the `registry_` prefix is implied by context):

```yaml
containers:
  registry_auth:
    # Bare host — default for any repo at this registry.
    "registry.example.com":
      username_env: REGISTRY_DEFAULT_USER
      password_env: REGISTRY_DEFAULT_TOKEN

    # More specific path — wins for repos under internal/restricted/
    # even though the bare host also matches.
    "registry.example.com/internal/restricted":
      username_env: REGISTRY_RESTRICTED_USER
      password_env: REGISTRY_RESTRICTED_TOKEN

    "ghcr.io/myorg":
      username_env: GHCR_USER
      password_env: GHCR_TOKEN
  images:
    - image: registry.example.com/public/app@sha256:...                  # uses REGISTRY_DEFAULT_*
    - image: registry.example.com/internal/restricted/app@sha256:...     # uses REGISTRY_RESTRICTED_*
    - image: ghcr.io/myorg/worker@sha256:...                              # uses GHCR_*
```

**No silent fallback to a broader entry.** If a more-specific entry matches but its credentials don't resolve (e.g. the referenced env var is unset), Argus logs a `WARNING` naming the missing variable and the scan attempts anonymously rather than falling back to a broader entry's creds. Same rule Kubernetes `imagePullSecrets` follows: silently widening the auth surface against a repo the operator explicitly marked as needing different access is a privilege-misuse risk.

The top-level `registry_username` / `registry_password` (and their `*_env` references) act as the default for any image that matches no entry in `registry_auth`. Setting both a map and the top-level fields gives you "specific overrides + global default" in one config block.

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

### Private registry example

```yaml
# Export REGISTRY_USER and REGISTRY_TOKEN in the shell / CI step
# before running. argus reads the env vars by name at scan time and
# forwards the resolved values to every sub-scanner.
containers:
  registry_username_env: REGISTRY_USER
  registry_password_env: REGISTRY_TOKEN
  images:
    - image: registry.example.com/myorg/app@sha256:f1e2d3c4...
  scanners: [trivy, grype, syft]
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
# yaml-language-server: $schema=https://raw.githubusercontent.com/huntridge-labs/argus/1.7.0/argus-config.schema.json
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
