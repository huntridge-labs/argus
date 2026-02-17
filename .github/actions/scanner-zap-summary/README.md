# ZAP Summary Generator Action

Composite action to aggregate and summarize results from multiple ZAP DAST scans.

## Usage

```yaml
- name: Generate ZAP Summary
  uses: huntridge-labs/argus/.github/actions/scanner-zap-summary@0.2.1
  id: summary

- name: Check findings
  run: |
    echo "Critical: ${{ steps.summary.outputs.total_critical }}"
    echo "High: ${{ steps.summary.outputs.total_high }}"
    echo "Total scans: ${{ steps.summary.outputs.scan_count }}"
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `artifact_pattern` | Pattern to match ZAP report artifacts | No | `zap-reports-*` |
| `summary_pattern` | Pattern to match scanner summary artifacts | No | `scanner-summary-zap-*` |
| `output_name` | Name for the combined summary artifact | No | `zap-combined-summary` |
| `retention_days` | Days to retain the summary artifact | No | `30` |
| `write_step_summary` | Write summary to GITHUB_STEP_SUMMARY | No | `true` |
| `post_pr_comment` | Post results as PR comment | No | `true` |

## Outputs

| Output | Description |
|--------|-------------|
| `summary_path` | Path to the generated summary file |
| `total_critical` | Total critical findings across all scans |
| `total_high` | Total high findings across all scans |
| `total_medium` | Total medium findings across all scans |
| `total_low` | Total low findings across all scans |
| `total_info` | Total informational findings across all scans |
| `scan_count` | Number of scans processed |
| `has_findings` | Whether any findings were detected |

## Example: Config-Driven Multi-Scan Workflow

```yaml
name: ZAP Multi-Scan

on:
  workflow_dispatch:
    inputs:
      config_file:
        description: 'ZAP config file'
        default: 'zap-config.yml'

jobs:
  parse-config:
    runs-on: ubuntu-latest
    outputs:
      matrix: ${{ steps.parse.outputs.matrix }}
      has_scans: ${{ steps.parse.outputs.has_scans }}
    steps:
      - uses: actions/checkout@v6
      - uses: huntridge-labs/argus/.github/actions/parse-zap-config@0.2.1
        id: parse
        with:
          config_file: ${{ inputs.config_file }}

  zap-scan:
    needs: parse-config
    if: needs.parse-config.outputs.has_scans == 'true'
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix: ${{ fromJson(needs.parse-config.outputs.matrix) }}
    steps:
      - uses: actions/checkout@v6
      - uses: huntridge-labs/argus/.github/actions/scanner-zap@0.2.1
        with:
          scan_name: ${{ matrix.name }}
          scan_mode: ${{ matrix.mode }}
          scan_type: ${{ matrix.scan_type }}
          target_url: ${{ matrix.target_url }}

  summary:
    needs: [parse-config, zap-scan]
    if: always()
    runs-on: ubuntu-latest
    steps:
      - uses: huntridge-labs/argus/.github/actions/scanner-zap-summary@0.2.1
        id: summary

      - name: Fail on critical findings
        if: steps.summary.outputs.total_critical > 0
        run: |
          echo "::error::Found ${{ steps.summary.outputs.total_critical }} critical findings"
          exit 1
```

## Artifact Structure

This action expects ZAP report artifacts in the following structure:

```
zap-downloads/
├── zap-reports-{hash}-{scan_type}-{target_hash}/
│   └── report_json.json
├── zap-reports-{hash2}-{scan_type2}-{target_hash2}/
│   └── report_json.json
└── ...
```

The action will:
1. Download all artifacts matching the `artifact_pattern`
2. Parse each `report_json.json` file
3. Aggregate findings across all scans
4. Generate a combined markdown summary
5. Upload the summary as an artifact
6. Optionally write to `GITHUB_STEP_SUMMARY`

## GHES Compatibility

This action is fully compatible with GitHub Enterprise Server (GHES) environments. Since it's a composite action, all scripts are bundled and referenced via `${{ github.action_path }}`, eliminating the need to checkout external repositories.
