# Argus CLI Reference (v1.7.0)

> Auto-generated from argparse definitions on 2026-06-24.
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

## Output and verbosity

`argus scan` exposes four flags that compose orthogonally — `--quiet` controls log verbosity, `--no-spinner` controls UI rendering, and `--debug` (alias `--verbose`) is the explicit troubleshooting opt-in. The four most useful modes:

| Invocation | When to use | What you see |
|---|---|---|
| `argus scan` | Default — interactive terminal | Phase-aware spinner that updates per image and per scan phase |
| `argus scan --quiet` | Daily runs you don't want narrating | Spinner stays drawing, but per-phase chatter is suppressed; only WARNING/ERROR lines and the final summary print |
| `argus scan --no-spinner` | CI logs, step-away monitoring | Persistent `[idx/total] name — phase (Ns)` lines on stderr instead of a self-overwriting spinner |
| `argus scan --debug` (or `--verbose`) | Troubleshooting | Full firehose: subprocess output, vulnerability-DB updates, every engine log line |

Compose flags for additional modes — `--quiet --no-spinner` is the fully-silent CI exit-code-only combination; `--debug --no-spinner` is identical to `--debug` since debug auto-disables the spinner.

## Commands

### `argus init`

Detect your project's languages, frameworks, and infrastructure,
then generate a tailored argus.yml with the right scanners enabled.

Examples:
  argus init                # auto-detect and generate argus.yml
  argus init --force        # overwrite existing argus.yml
  argus init --no-detect    # generate with defaults only

```
argus init [-h] [--no-update-check] [--force] [--no-detect]
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--no-update-check` | Skip the once-per-day check for a newer argus release. The check runs in the background (zero latency cost) and prints a soft notice at the end of the command when an upgrade is available. Also disabled by setting the ARGUS_NO_UPDATE_CHECK environment variable, which is the right move for CI / air-gapped environments. Override the PyPI URL via ARGUS_UPDATE_CHECK_URL for TestPyPI or private mirrors. | `false` |
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
argus scan [-h] [--no-update-check] [--path PATH] [--config CONFIG]
                  [--output-dir OUTPUT_DIR]
                  [--severity-threshold {critical,high,medium,low,none}]
                  [--format {terminal,markdown,sarif,json,github,gitlab,junit,openvex}]
                  [--list] [--verbose] [--debug] [--quiet] [--no-spinner]
                  [--no-timestamp] [--output-vars FILE] [--exclude PATTERNS]
                  [--no-default-excludes] [--dry-run] [--sbom PATH]
                  [--interface {terminal,browser}] [--fail-fast]
                  [--fail-on-scanner-error] [--timeout SECONDS]
                  [--no-parallel] [--allow-local-versions] [--no-cache]
                  [--keep-raw | --no-keep-raw] [--registry-password-stdin]
                  [--zap-auth-password-stdin] [--discover [PATH]]
                  [--image REF] [--scanners SCANNERS] [--target URL]
                  [--port PORT] [--env KEY=VALUE]
                  [--scan-type {baseline,full}]
                  [--startup-timeout STARTUP_TIMEOUT]
                  [scanner]
```

**Arguments:**

- `scanner` — Specific scanner to run (omit to run all enabled scanners). Use 'container' with --discover or --image for container scanning.

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--no-update-check` | Skip the once-per-day check for a newer argus release. The check runs in the background (zero latency cost) and prints a soft notice at the end of the command when an upgrade is available. Also disabled by setting the ARGUS_NO_UPDATE_CHECK environment variable, which is the right move for CI / air-gapped environments. Override the PyPI URL via ARGUS_UPDATE_CHECK_URL for TestPyPI or private mirrors. | `false` |
| `--path`, `-p` | Path to scan (default: current directory) | `.` |
| `--config`, `-c` | Path to argus.yml config file |  |
| `--output-dir`, `-o` | Output directory for results (default: ./argus-results) |  |
| `--severity-threshold`, `-s` | Fail threshold severity level (default: from config) (critical, high, medium, low, none) |  |
| `--format`, `-f` | Output format (can be repeated; default: terminal) (terminal, markdown, sarif, json, github, gitlab, junit, openvex) |  |
| `--list` | List available scanners and exit | `false` |
| `--verbose` | Alias for --debug. Full firehose: subprocess output, vulnerability-DB updates, every engine log line. | `false` |
| `--debug` | Full firehose: subprocess output, vulnerability-DB updates, every engine log line. Use when troubleshooting; the default phase-aware progress is enough for normal scans. | `false` |
| `--quiet`, `-q` | Suppress per-phase progress lines. The spinner still draws (use --no-spinner to suppress that too). Final summary still prints. Compose with --no-spinner for fully silent CI exit-code-only mode. | `false` |
| `--no-spinner` | Disable animated spinner output | `false` |
| `--no-timestamp` | Write output directly to --output-dir without a timestamped subdirectory. Useful in CI where a predictable output path is needed. | `false` |
| `--output-vars` | Write scan result counts as key=value pairs to FILE. Useful in CI: cat FILE >> $GITHUB_OUTPUT. Keys: critical_count, high_count, medium_count, low_count, info_count, total_count, passed. |  |
| `--exclude`, `-e` | Comma-separated paths or patterns to exclude from scanning. Added on top of .gitignore, .dockerignore, and built-in defaults. | `` |
| `--no-default-excludes` | Drop built-in exclusions (node_modules, .git, ...) and .gitignore / .dockerignore patterns. Only --exclude and argus.yml exclude: take effect. Use when you explicitly want to scan what the defaults would normally skip. | `false` |
| `--dry-run` | Resolve config and print the planned scanner invocations without executing them. Useful for verifying which per-scanner config files, paths, and excludes Argus will use. | `false` |
| `--sbom` | Scan a pre-built SBOM or directory of SBOMs (CycloneDX JSON/XML, SPDX JSON/tag-value, or Syft JSON). When PATH is a directory, argus walks it recursively, sniffs each file, and scans every SBOM it finds. Auto-enables all SBOM-capable scanners (osv, grype, trivy) regardless of argus.yml. Filesystem scanners (bandit, gitleaks, ...) are skipped since they have nothing to scan. |  |
| `--interface`, `-i` | After the scan completes, open a viewer on the just-written results. 'terminal' launches the TUI (requires 'argus-security[terminal]'); 'browser' launches the local web UI (requires 'argus-security[browser]'). (terminal, browser) |  |
| `--fail-fast` | Abort immediately if any scanner fails instead of continuing. | `false` |
| `--fail-on-scanner-error` | Exit non-zero when any scanner produced no output (typically a uid-mismatch on /output, container crash, or wrong entrypoint). Default behavior treats these as warnings so partial scans still surface findings; opt in for hard CI gates that require every configured scanner to actually run. | `false` |
| `--timeout` | Per-scanner timeout in seconds. Scanners exceeding this limit are killed. |  |
| `--no-parallel` | Run scanners sequentially instead of concurrently. | `false` |
| `--allow-local-versions` | Allow local tool versions that differ from argus-pinned versions. Use in airgapped environments where tool updates are constrained. | `false` |
| `--no-cache` | Disable DB cache volume mounts. Forces scanners to re-download vulnerability databases on every container run. | `false` |
| `--keep-raw`, `--no-keep-raw` | Persist each scanner's raw output files (results.json / *.sarif / stdout.txt) under <output_dir>/raw/<scanner>/ alongside the canonical argus-results.json. Container scans drop trivy-results.json / grype-results.json / syft-sbom.json under <output_dir>/raw/<image>/. Default OFF — scanners like gitleaks write the literal matched secret bytes into raw output, so persisting raw by default turned argus-results into a secret-leak vector. The canonical argus-results.json is always written and is pattern-redacted. Pass --keep-raw for forensic / triage workflows that need the unredacted per-scanner artifacts. The same effect is available via 'reporting.keep_raw: true' in argus.yml. Use --no-keep-raw to explicitly override a config-file opt-in. |  |
| `--registry-password-stdin` | Read the private-registry password from stdin and use it for any scanner that needs registry auth (container, zap with app_image_ref). Overrides registry_password / registry_password_env in argus.yml. | `false` |
| `--zap-auth-password-stdin` | Read the ZAP web-app authentication password from stdin. Overrides scanners.zap.auth.password / password_env in argus.yml. | `false` |

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

### `argus classify`

Analyze infrastructure-as-code changes between two git refs
and classify them according to compliance rules (FedRAMP SCN).

Examples:
  argus classify                              # compare HEAD vs main
  argus classify --base main --head HEAD      # explicit refs
  argus classify --config .github/scn.yml     # custom profile
  argus classify --format json                # JSON output

```
argus classify [-h] [--no-update-check] [--base BASE] [--head HEAD]
                      [--config CONFIG] [--format {terminal,markdown,json}]
                      [--output-dir OUTPUT_DIR] [--output-vars FILE]
                      [--enable-ai] [--verbose]
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--no-update-check` | Skip the once-per-day check for a newer argus release. The check runs in the background (zero latency cost) and prints a soft notice at the end of the command when an upgrade is available. Also disabled by setting the ARGUS_NO_UPDATE_CHECK environment variable, which is the right move for CI / air-gapped environments. Override the PyPI URL via ARGUS_UPDATE_CHECK_URL for TestPyPI or private mirrors. | `false` |
| `--base` | Base git ref for comparison (default: main) | `main` |
| `--head` | Head git ref for comparison (default: HEAD) | `HEAD` |
| `--config`, `-c` | Path to SCN configuration/profile file |  |
| `--format`, `-f` | Output format (default: terminal) (terminal, markdown, json) | `terminal` |
| `--output-dir`, `-o` | Output directory for report files |  |
| `--output-vars` | Write classification counts as key=value pairs to FILE |  |
| `--enable-ai` | Use AI for ambiguous change classification (requires API key) | `false` |
| `--verbose`, `-v` | Enable verbose output | `false` |

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
argus collect [-h] [--no-update-check] [--output-dir OUTPUT_DIR]
                     [--verbose]
                     input_dir
```

**Arguments:**

- `input_dir` — Directory containing per-scanner result directories (argus-results-*)

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--no-update-check` | Skip the once-per-day check for a newer argus release. The check runs in the background (zero latency cost) and prints a soft notice at the end of the command when an upgrade is available. Also disabled by setting the ARGUS_NO_UPDATE_CHECK environment variable, which is the right move for CI / air-gapped environments. Override the PyPI URL via ARGUS_UPDATE_CHECK_URL for TestPyPI or private mirrors. | `false` |
| `--output-dir`, `-o` | Output directory for the combined audit package (default: ./argus-audit-package) | `./argus-audit-package` |
| `--verbose`, `-v` | Enable verbose output | `false` |

### `argus report`

Generate formatted reports from previously captured scan results.

```
argus report [-h] [--no-update-check] [--results-dir RESULTS_DIR]
                    [--output-dir OUTPUT_DIR] [--verbose]
                    {terminal,markdown,sarif,json,github,gitlab,junit,openvex}
```

**Arguments:**

- `format` — Output format for the report (choices: terminal, markdown, sarif, json, github, gitlab, junit, openvex)

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--no-update-check` | Skip the once-per-day check for a newer argus release. The check runs in the background (zero latency cost) and prints a soft notice at the end of the command when an upgrade is available. Also disabled by setting the ARGUS_NO_UPDATE_CHECK environment variable, which is the right move for CI / air-gapped environments. Override the PyPI URL via ARGUS_UPDATE_CHECK_URL for TestPyPI or private mirrors. | `false` |
| `--results-dir`, `-r` | Directory containing scan results JSON (default: ./argus-results) | `./argus-results` |
| `--output-dir`, `-o` | Output directory for generated reports (default: same as results-dir) |  |
| `--verbose`, `-v` | Enable verbose output | `false` |

### `argus validate`

Check an argus.yml config file for errors and warnings.
Catches typos, invalid values, and unknown keys before scanning.

```
argus validate [-h] [--no-update-check] [--config CONFIG] [--schema]
                      [--check-tools] [--deep] [--verbose] [--strict]
                      [--report-issue]
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--no-update-check` | Skip the once-per-day check for a newer argus release. The check runs in the background (zero latency cost) and prints a soft notice at the end of the command when an upgrade is available. Also disabled by setting the ARGUS_NO_UPDATE_CHECK environment variable, which is the right move for CI / air-gapped environments. Override the PyPI URL via ARGUS_UPDATE_CHECK_URL for TestPyPI or private mirrors. | `false` |
| `--config`, `-c` | Path to argus.yml config file (default: auto-detect) |  |
| `--schema` | Run schema validation only (default behavior; explicit form for scripting). | `false` |
| `--check-tools` | Also check scanner tool availability (local + Docker) | `false` |
| `--deep` | Live validation of config settings: scanner tools, registry / registry_map reachability, and on-disk paths. Implies --check-tools. Requires Docker on PATH for registry probes. | `false` |
| `--verbose`, `-v` | Show full image references including the 64-character @sha256 digest. Default truncates digests for readability. | `false` |
| `--strict` | Treat warnings as errors (exit non-zero). Useful in CI. | `false` |
| `--report-issue` | Create or update a living issue on GitHub/GitLab with validation results. Requires GITHUB_TOKEN or CI_JOB_TOKEN. | `false` |

### `argus mcp`

Start the Argus MCP (Model Context Protocol) server.

The server communicates via stdio and provides tools for
AI assistants (Claude, Copilot, Cursor) to run security scans,
validate configs, and detect project characteristics.

Setup in Claude Code:
  Add to .claude/settings.json mcpServers:
    "argus": {"command": "argus", "args": ["mcp"]}

```
argus mcp [-h] [--no-update-check]
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--no-update-check` | Skip the once-per-day check for a newer argus release. The check runs in the background (zero latency cost) and prints a soft notice at the end of the command when an upgrade is available. Also disabled by setting the ARGUS_NO_UPDATE_CHECK environment variable, which is the right move for CI / air-gapped environments. Override the PyPI URL via ARGUS_UPDATE_CHECK_URL for TestPyPI or private mirrors. | `false` |

### `argus completion`

Generate a shell completion script for argus.

Once installed, pressing <Tab> will complete:
  - subcommands (scan, view, report, classify, cache, ...)
  - scanner and linter names (bandit, gitleaks, lint-yaml, ...)
  - common flags (--config, --scanners, --severity, ...)

Install (persistent — remember to reload your shell):
  argus completion zsh  >> ~/.zshrc  && source ~/.zshrc
  argus completion bash >> ~/.bashrc && source ~/.bashrc

Activate for current session only:
  eval "$(argus completion zsh)"

Completions are generated from the live scanner registry, so
newly added scanners appear after re-running this command.

```
argus completion [-h] [--no-update-check] {bash,zsh}
```

**Arguments:**

- `shell` — Shell type to generate completions for (choices: bash, zsh)

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--no-update-check` | Skip the once-per-day check for a newer argus release. The check runs in the background (zero latency cost) and prints a soft notice at the end of the command when an upgrade is available. Also disabled by setting the ARGUS_NO_UPDATE_CHECK environment variable, which is the right move for CI / air-gapped environments. Override the PyPI URL via ARGUS_UPDATE_CHECK_URL for TestPyPI or private mirrors. | `false` |

### `argus cache`

Manage cached vulnerability databases used by container-based scanners.

Argus caches scanner databases (Trivy, Grype, Checkov, etc.) in the system
temp directory so container runs don't re-download hundreds of MB each time.
The cache persists across runs within a session but is cleaned on reboot.

Cache location: $TMPDIR/argus-cache (override with ARGUS_CACHE_DIR)
For persistent caching: export ARGUS_CACHE_DIR=~/.argus/cache

```
argus cache [-h] [--no-update-check] {info,clean} ...
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--no-update-check` | Skip the once-per-day check for a newer argus release. The check runs in the background (zero latency cost) and prints a soft notice at the end of the command when an upgrade is available. Also disabled by setting the ARGUS_NO_UPDATE_CHECK environment variable, which is the right move for CI / air-gapped environments. Override the PyPI URL via ARGUS_UPDATE_CHECK_URL for TestPyPI or private mirrors. | `false` |

### `argus view`

Open a human-readable view of argus-results.json:
  argus view                                  # terminal interface, ./argus-results/
  argus view terminal                         # explicit terminal
  argus view browser                          # local web UI (127.0.0.1)
  argus view --interface=terminal             # flag form
  argus view browser ./run-2026-04-24/        # interface + path
  argus view --interface=browser --port 9090
  argus view browser --no-open      # don't auto-open the browser

Terminal interface keyboard shortcuts:
  / search · 1/2/3/4 filter by severity · s sort · e export CSV · q quit

Browser interface is bound to 127.0.0.1 only — no auth, no mutations.

Install:
  pip install 'argus-security[terminal]'      # terminal interface
  pip install 'argus-security[browser]'       # browser interface

```
argus view [-h] [--no-update-check] [--path PATH]
                  [--interface {terminal,browser}] [--port PORT] [--no-open]
                  [--check]
                  [INTERFACE|PATH] [PATH]
```

**Arguments:**

- `interface_or_path` — Either an interface keyword (terminal | browser) or a results path. If a path is given here without an interface keyword, the interface defaults to terminal.
- `path_arg` — Results directory or argus-results.json path when the first positional is an interface keyword (default: ./argus-results/)

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--no-update-check` | Skip the once-per-day check for a newer argus release. The check runs in the background (zero latency cost) and prints a soft notice at the end of the command when an upgrade is available. Also disabled by setting the ARGUS_NO_UPDATE_CHECK environment variable, which is the right move for CI / air-gapped environments. Override the PyPI URL via ARGUS_UPDATE_CHECK_URL for TestPyPI or private mirrors. | `false` |
| `--path`, `-p` | Results directory or argus-results.json path. Equivalent to the positional form ``argus view <iface> <path>`` but robust to argparse's ordering quirks — use this when a flag-with-value (e.g. ``--port``) sits between the interface keyword and the path (issue #168-D5). |  |
| `--interface`, `-i` | Interface to open: terminal \| browser (alternative to positional) (terminal, browser) |  |
| `--port` | TCP port for the browser interface (default: 8080) | `8080` |
| `--no-open` | Don't auto-open the default web browser after startup (browser interface only). By default, the browser opens when stdout is a TTY; CI and other non-interactive contexts already skip auto-open without this flag. | `false` |
| `--check` | Validate that the resolved scan directory contains argus-results.json and print actionable remediation if not. Doesn't launch the viewer — useful in CI and pre-flight checks. | `false` |

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
