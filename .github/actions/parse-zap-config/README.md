# Parse ZAP Config Composite Action

Parse a ZAP DAST configuration file (YAML, JSON, or JS) and output a GitHub Actions matrix.

## Usage

```yaml
jobs:
  parse-zap:
    runs-on: ubuntu-latest
    outputs:
      matrix: ${{ steps.parse.outputs.matrix }}
      has_scans: ${{ steps.parse.outputs.has_scans }}
    steps:
      - uses: actions/checkout@v6
      - uses: huntridge-labs/argus/.github/actions/parse-zap-config@0.2.1
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
      - uses: huntridge-labs/argus/.github/actions/scanner-zap@0.2.1
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

# IMPORTANT: When using secret references in the config, the caller must pass all secrets:
#   secrets: inherit
```

## Inputs

| Input | Description | Required | Default |
| --- | --- | --- | --- |
| `config_file` | Path to the ZAP config file (YAML, JSON, or JS) | Yes | `.zap/config.yml` |

## Outputs

| Output | Description |
| --- | --- |
| `matrix` | JSON matrix for use with `strategy.matrix` |
| `groups` | JSON list of group metadata |
| `group_count` | Number of scan groups |
| `has_scans` | Whether any scans were found (`true`/`false`) |
| `scan_count` | Total number of scans |
| `post_pr_comment` | Whether any scan has PR comments enabled |
| `enable_code_security` | Whether SARIF upload is enabled |

## Notes

- Config files may be YAML, JSON, or JS modules.
- Use `secrets: inherit` in caller workflows when secret names are referenced in the config.
- See examples under examples/ for config templates.
