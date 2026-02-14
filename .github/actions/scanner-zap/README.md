# ZAP DAST Scanner Composite Action

Dynamic Application Security Testing (DAST) using [ZAP (Zed Attack Proxy)](https://www.zaproxy.org/).

## Overview

This composite action runs ZAP to scan running web applications for security vulnerabilities. It supports:

- Scan modes: `url`, `docker-run`, `compose`
- Scan types: `baseline`, `full`, `api`
- Dynamic artifact naming with hashed inputs
- Optional PR comments and summary artifacts

## Usage

### URL Mode (Baseline)

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-zap@feat/migrate-to-composite-actions
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    scan_type: baseline
    target_url: 'http://localhost:8080'
    fail_on_severity: 'high'
```

### Docker-Run Mode (Image)

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-zap@feat/migrate-to-composite-actions
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    scan_mode: docker-run
    scan_type: full
    app_image_ref: ghcr.io/acme/app:latest
    app_ports: '8080:8080'
    target_url: 'http://127.0.0.1:8080'
    registry_username: ${{ secrets.REGISTRY_USER }}
    registry_password: ${{ secrets.REGISTRY_TOKEN }}
```

### Docker-Run Mode (Local Build)

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-zap@feat/migrate-to-composite-actions
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    scan_mode: docker-run
    scan_type: baseline
    app_build_context: .
    app_dockerfile: Dockerfile
    app_image_tag: local-app:${{ github.sha }}
    app_ports: '8080:8080'
    target_url: 'http://127.0.0.1:8080'
```

### Compose Mode

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-zap@feat/migrate-to-composite-actions
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    scan_mode: compose
    scan_type: baseline
    compose_file: docker-compose.yml
    compose_build: 'true'
    target_url: 'http://127.0.0.1:8080'
```

### API Scan

```yaml
- uses: huntridge-labs/argus/.github/actions/scanner-zap@feat/migrate-to-composite-actions
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    scan_type: api
    api_spec: 'http://127.0.0.1:8080/openapi.json'
    fail_on_severity: 'medium'
```

### Multi-Target Matrix

```yaml
jobs:
  zap-scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        target:
          - { url: 'http://localhost:8080', name: 'web', type: 'baseline' }
          - { url: 'http://localhost:3000', name: 'api', type: 'full' }
    steps:
      - uses: actions/checkout@v6
      - uses: huntridge-labs/argus/.github/actions/scanner-zap@feat/migrate-to-composite-actions
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          target_url: ${{ matrix.target.url }}
          scan_name: ${{ matrix.target.name }}
          scan_type: ${{ matrix.target.type }}
```

### Config-Driven Multi-Scan

```yaml
jobs:
  parse-zap:
    runs-on: ubuntu-latest
    outputs:
      matrix: ${{ steps.parse.outputs.matrix }}
      has_scans: ${{ steps.parse.outputs.has_scans }}
    steps:
      - uses: actions/checkout@v6
      - uses: huntridge-labs/argus/.github/actions/parse-zap-config@feat/migrate-to-composite-actions
        id: parse
        with:
          config_file: .zap/config.yml

  zap-scan:
    runs-on: ubuntu-latest
    needs: parse-zap
    if: needs.parse-zap.outputs.has_scans == 'true'
    strategy:
      matrix: ${{ fromJson(needs.parse-zap.outputs.matrix) }}
    steps:
      - uses: actions/checkout@v6
      - uses: huntridge-labs/argus/.github/actions/scanner-zap@feat/migrate-to-composite-actions
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          scan_name: ${{ matrix.name }}
          scan_mode: ${{ matrix.mode }}
          scan_type: ${{ matrix.scan_type }}
          target_url: ${{ matrix.target_url }}
          api_spec: ${{ matrix.api_spec }}
          app_image_ref: ${{ matrix.image }}
          app_ports: ${{ matrix.ports }}
          app_build_context: ${{ matrix.build_context }}
          app_dockerfile: ${{ matrix.build_dockerfile }}
          app_image_tag: ${{ matrix.build_tag }}
          compose_file: ${{ matrix.compose_file }}
          compose_build: ${{ matrix.compose_build }}
          registry_username: ${{ matrix.registry_username }}
          registry_password: ${{ secrets[matrix.registry_auth_secret] }}
          healthcheck_url: ${{ matrix.healthcheck_url }}
          max_duration_minutes: ${{ matrix.max_duration_minutes }}
          rules_file_name: ${{ matrix.rules_file }}
          cmd_options: ${{ matrix.cmd_options }}
          fail_on_severity: ${{ matrix.fail_on_severity }}
          allow_failure: ${{ matrix.allow_failure }}
          post_pr_comment: ${{ matrix.post_pr_comment }}

# IMPORTANT: When using secret references in the config, use `secrets: inherit` in the caller workflow.
```

**Shared target tip:** If you want multiple scans against a single started target (for example, one docker-run or compose stack), start the target once in a separate job and run scans with `scan_mode: url` against the shared `target_url`.

## Inputs

| Input | Description | Required | Default |
| --- | --- | --- | --- |
| `scan_name` | Unique scan identifier (for artifacts) | No | `zap-scan` |
| `scan_mode` | `url`, `docker-run`, `compose` | No | `url` |
| `scan_type` | `baseline`, `full`, `api` | No | `baseline` |
| `target_url` | Target URL for baseline/full scans | Conditionally | `''` |
| `api_spec` | OpenAPI/Swagger spec URL (api scans) | Conditionally | `''` |
| `healthcheck_url` | URL to poll until target ready | No | `''` |
| `app_image_ref` | Container image for docker-run | Conditionally | `''` |
| `app_build_context` | Docker build context | No | `''` |
| `app_dockerfile` | Dockerfile path | No | `''` |
| `app_image_tag` | Tag for locally built image | No | `''` |
| `app_ports` | Port mappings (e.g., `8080:8080`) | No | `8080:8080` |
| `compose_file` | Docker compose file path | No | `docker-compose.yml` |
| `compose_build` | Run docker compose with `--build` | No | `true` |
| `registry_username` | Registry username (private images) | No | `''` |
| `registry_password` | Registry password/token (private images) | No | `''` |
| `max_duration_minutes` | Max scan duration in minutes | No | `10` |
| `rules_file_name` | ZAP rules file to ignore alerts (.tsv) | No | `''` |
| `cmd_options` | Additional ZAP command-line options | No | `''` |
| `fail_on_severity` | `none`, `low`, `medium`, `high`, `critical` | No | `none` |
| `allow_failure` | Continue on scan failure (`true`/`false`) | No | `false` |
| `post_pr_comment` | Post results as PR comment (`true`/`false`) | No | `false` |
| `job_id` | Job ID for artifact naming | No | `${{ github.job }}` |

## Outputs

| Output | Description |
| --- | --- |
| `findings_count` | Total number of findings (high+medium+low) |
| `high_count` | Number of high severity findings |
| `medium_count` | Number of medium severity findings |
| `low_count` | Number of low severity findings |
| `info_count` | Number of informational findings |
| `scan_status` | `passed`, `failed`, or `skipped` |

## Reports Generated

The action generates multiple report formats (JSON/HTML/Markdown/SARIF) and uploads them as artifacts with a hashed prefix.

## Notes on Secrets

Composite actions cannot access secrets directly. Pass secrets as inputs, for example:

```yaml
with:
  registry_username: ${{ secrets.REGISTRY_USER }}
  registry_password: ${{ secrets.REGISTRY_TOKEN }}
```

## Troubleshooting

- **Connection Refused**: verify the target is running and reachable from the runner.
- **Compose file not found**: ensure `compose_file` points to a file in the repo.
- **Timeout waiting for readiness**: set `healthcheck_url` or increase startup time.

## Related Documentation

- [ZAP Documentation](https://www.zaproxy.org/docs/)
- [ZAP Baseline Scan](https://www.zaproxy.org/docs/docker/baseline-scan/)
- [Complete Example Workflow](../../examples/composite-actions-example.yml)
- [ZAP Podinfo Example](../../examples/scanner-zap-podinfo.yml)
