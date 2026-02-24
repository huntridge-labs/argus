# Parse Container Config Composite Action

Parse a container-config file and output a GitHub Actions matrix.

## Overview

This action validates and parses a container-config file (YAML, JSON, or JS) and emits JSON matrices for sequential or parallel container scans.

## Usage

```yaml
jobs:
  parse:
    runs-on: ubuntu-latest
    outputs:
      matrix: ${{ steps.parse.outputs.matrix }}
      has_containers: ${{ steps.parse.outputs.has_containers }}
    steps:
      - uses: actions/checkout@v6
      - uses: huntridge-labs/argus/.github/actions/parse-container-config@0.3.0
        id: parse
        with:
          config_file: container-config.yml

  scan:
    needs: parse
    if: needs.parse.outputs.has_containers == 'true'
    strategy:
      matrix: ${{ fromJson(needs.parse.outputs.matrix) }}
    runs-on: ubuntu-latest
    steps:
      - uses: huntridge-labs/argus/.github/actions/scanner-container@0.3.0
        with:
          image_ref: ${{ matrix.image }}
          container_name: ${{ matrix.name }}
          registry_username: ${{ matrix.registry_username }}
          registry_password: ${{ secrets[matrix.registry_auth_secret] }}
          scanners: ${{ matrix.scanners }}
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `config_file` | Path to the container config file (YAML, JSON, or JS) | Yes | `container-config.yml` |

## Outputs

| Output | Description |
|--------|-------------|
| `matrix` | JSON matrix for sequential scanners (one entry per container) |
| `scan_matrix` | JSON matrix for parallel scanning (one entry per container+scanner) |
| `has_containers` | Whether any containers were found (`true`/`false`) |
| `container_count` | Number of containers in the config |

## Requirements

- Repository must be checked out before running this action

## Support

- [Report Issues](https://github.com/huntridge-labs/argusissues)
- [Contributing Guide](../../CONTRIBUTING.md)
