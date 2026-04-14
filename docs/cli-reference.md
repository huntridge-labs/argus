# Argus CLI Reference (v0.7.0)

> Auto-generated from argparse definitions on 2026-04-14.
> Do not edit manually — run `python -m scripts.ci.gen_cli_docs` to regenerate.

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

### `argus init`

Detect your project's languages, frameworks, and infrastructure,
then generate a tailored argus.yml with the right scanners enabled.

Examples:
  argus init                          # auto-detect and generate argus.yml
  argus init --platform github        # also generate GitHub Actions workflow
  argus init --force                   # overwrite existing argus.yml
  argus init --no-detect               # generate with defaults only

```
argus init [-h] [--platform {github,gitlab,jenkins,none}] [--force]
                  [--no-detect]
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--platform` | Generate a CI workflow file for the specified platform (default: none) (github, gitlab, jenkins, none) | `none` |
| `--force` | Overwrite an existing argus.yml file | `false` |
| `--no-detect` | Skip auto-detection and generate a config with defaults only | `false` |

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
                  [--verbose] [--no-spinner] [--no-timestamp]
                  [--output-vars FILE] [--fail-fast] [--timeout SECONDS]
                  [--discover [PATH]] [--image REF] [--scanners SCANNERS]
                  [--target URL] [--port PORT] [--env KEY=VALUE]
                  [--scan-type {baseline,full}]
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
| `--no-spinner` | Disable animated spinner output | `false` |
| `--no-timestamp` | Write output directly to --output-dir without a timestamped subdirectory. Useful in CI where a predictable output path is needed. | `false` |
| `--output-vars` | Write scan result counts as key=value pairs to FILE. Useful in CI: cat FILE >> $GITHUB_OUTPUT. Keys: critical_count, high_count, medium_count, low_count, total_count, passed. |  |
| `--fail-fast` | Abort immediately if any scanner fails instead of continuing. | `false` |
| `--timeout` | Per-scanner timeout in seconds. Scanners exceeding this limit are killed. |  |

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

### `argus collect`

Aggregate per-scanner results into a unified audit package.

In CI, each scanner job produces its own argus-results/ directory.
This command merges them into one structured directory with:
  - Combined JSONL log (sorted by timestamp)
  - Combined audit manifest (all provenance and findings)
  - Per-scanner subdirectories with individual results

Example:
  argus collect ./downloaded-artifacts/ -o ./argus-audit-package/

```
argus collect [-h] [--output-dir OUTPUT_DIR] [--verbose] input_dir
```

**Arguments:**

- `input_dir` — Directory containing per-scanner result directories (argus-results-*)

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--output-dir`, `-o` | Output directory for the combined audit package (default: ./argus-audit-package) | `./argus-audit-package` |
| `--verbose`, `-v` | Enable verbose output | `false` |

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

### `argus validate`

Check an argus.yml config file for errors and warnings.
Catches typos, invalid values, and unknown keys before scanning.

```
argus validate [-h] [--config CONFIG] [--check-tools] [--strict]
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--config`, `-c` | Path to argus.yml config file (default: auto-detect) |  |
| `--check-tools` | Also check scanner tool availability (local + Docker) | `false` |
| `--strict` | Treat warnings as errors (exit non-zero). Useful in CI. | `false` |

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
