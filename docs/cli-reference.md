# Argus CLI Reference (v0.7.0)

> Auto-generated from argparse definitions on 2026-04-12.
> Do not edit manually — run `python scripts/gen_cli_docs.py` to regenerate.

Argus Security Scanner — comprehensive security scanning for your codebase

## Usage

```
argus [--version] [--help] <command> [options]
```

## Global Options

| Flag | Description | Default |
|------|-------------|---------|
| `--version` | show program's version number and exit |  |

## Commands

### `argus scan`

Run one or more security scanners and generate results.

For source code scanning:
  argus scan                    # all enabled scanners
  argus scan bandit             # specific scanner

For container image scanning:
  argus scan container --image nginx:latest
  argus scan container --discover ./
  argus scan container --discover docker/

```
argus scan [-h] [--path PATH] [--config CONFIG]
                  [--output-dir OUTPUT_DIR]
                  [--severity-threshold {critical,high,medium,low,none}]
                  [--format {terminal,markdown,sarif,json}] [--list]
                  [--verbose] [--discover [PATH]] [--image REF]
                  [--scanners SCANNERS] [--target URL] [--port PORT]
                  [--env KEY=VALUE] [--scan-type {baseline,full}]
                  [--startup-timeout STARTUP_TIMEOUT]
                  [scanner]
```

**Arguments:**

- `scanner` — Specific scanner to run (omit to run all enabled scanners). Use 'container' with --discover or --image for container scanning.

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--path`, `-p` | Path to scan (default: current directory) | `.` |
| `--config`, `-c` | Path to argus.yml config file |  |
| `--output-dir`, `-o` | Output directory for results (default: ./argus-results) |  |
| `--severity-threshold`, `-s` | Fail threshold severity level (default: from config) (critical, high, medium, low, none) |  |
| `--format`, `-f` | Output format (can be repeated; default: terminal) (terminal, markdown, sarif, json) |  |
| `--list` | List available scanners and exit | `false` |
| `--verbose`, `-v` | Enable verbose output | `false` |

**Container Scanning:**

| Flag | Description | Default |
|------|-------------|---------|
| `--discover` | Discover Dockerfiles in PATH (default: current directory) |  |
| `--image` | Container image to scan (can be repeated) |  |
| `--scanners` | Sub-scanners for container scanning: trivy,grype,syft (default: trivy,grype) |  |

**Dast Scanning:**

| Flag | Description | Default |
|------|-------------|---------|
| `--target` | URL of a running target to scan (e.g., http://localhost:3000) |  |
| `--port` | Override the exposed port when using --image with zap |  |
| `--env` | Environment variable for the target container (can be repeated) |  |
| `--scan-type` | ZAP scan type (default: baseline) (baseline, full) | `baseline` |
| `--startup-timeout` | Seconds to wait for target container to become healthy (default: 60) | `60` |

### `argus report`

Generate formatted reports from previously captured scan results.

```
argus report [-h] [--results-dir RESULTS_DIR] [--output-dir OUTPUT_DIR]
                    [--verbose]
                    {terminal,markdown,sarif,json}
```

**Arguments:**

- `format` — Output format for the report (choices: terminal, markdown, sarif, json)

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--results-dir`, `-r` | Directory containing scan results JSON (default: ./argus-results) | `./argus-results` |
| `--output-dir`, `-o` | Output directory for generated reports (default: same as results-dir) |  |
| `--verbose`, `-v` | Enable verbose output | `false` |

## Quick Reference

```bash
# Source code scanning
argus scan                                    # all enabled scanners
argus scan bandit                             # specific scanner
argus scan --list                             # list available scanners
argus scan --config argus.yml --verbose       # with config and debug output

# Container image scanning
argus scan container --discover ./            # find and scan all Dockerfiles
argus scan container --image nginx:latest     # scan specific image

# DAST scanning
argus scan zap --target http://localhost:3000 # scan running target
argus scan zap --image myapp:latest           # auto-discover ports, scan

# Reports
argus report terminal --results-dir ./argus-results
argus report sarif --results-dir ./argus-results
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | Scan passed — no findings above severity threshold |
| `1`  | Findings detected above severity threshold |
| `2`  | Error — scan could not complete |
