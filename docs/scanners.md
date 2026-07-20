<div align=center>

# Scanner Configuration Reference

Complete configuration reference for all available security scanners.

</div>

## Architecture

The argus Python SDK (`argus scan`) is the primary interface for running scanners. Composite actions remain available for GitHub Actions users.

- **Argus SDK** (`argus/`) - Primary interface, works locally and in any CI
- **Composite Actions** (`.github/actions/scanner-*/`) - GitHub Actions integration
- **Example Workflows** (`examples/github-enterprise/`) - Templates for GHES users

**SDK usage (recommended)**:

```bash
pip install argus-security
argus scan gitleaks bandit --severity-threshold high
```

**Post-scan triage**: Once you have `argus-results.json`, run
[`argus view terminal`](view-terminal.md) for an interactive terminal UI — filter by
severity, product, or scanner; export to CSV/JSON/Markdown/SARIF; open an
executive dashboard. Install via `pip install 'argus-security[terminal]'`,
or combine with scanning in one shot: `argus scan --interface=terminal`.

**Composite action usage (GitHub Actions)**:

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - uses: huntridge-labs/argus/.github/actions/scanner-gitleaks@1.9.2
        with:
          enable_code_security: true
          fail_on_severity: high
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

See [examples/github-enterprise/](../examples/github-enterprise/) for GHES templates.

---

## Table of Contents

- [SAST Scanners](#sast-scanners)
  - [CodeQL](#codeql)
  - [Gitleaks](#gitleaks)
  - [Bandit](#bandit)
  - [gosec](#gosec)
  - [OpenGrep (Semgrep)](#opengrep-semgrep)
  - [MUMPS / M language](#mumps--m-language-mumps)
- [Container Scanners](#container-scanners)
  - [Trivy Container](#trivy-container)
  - [Grype](#grype)
  - [Syft (SBOM)](#syft-sbom)
- [Infrastructure Scanners](#infrastructure-scanners)
  - [Trivy IaC](#trivy-iac)
  - [Checkov](#checkov)
  - [KICS](#kics)
- [Malware Scanner](#malware-scanner)
  - [ClamAV](#clamav)
- [DAST Scanners](#dast-scanners)
  - [ZAP](#zap)
- [LLM-Security Scanners](#llm-security-scanners)
  - [promptfoo](#promptfoo)
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

### gosec

Go-native security linter — the Go equivalent of Bandit. Inspects the Go AST for security anti-patterns such as hardcoded credentials (G101), SQL injection via string formatting (G201), and file path traversal (G304), with deeper precision than pattern-based scanning.

**Supported languages:** `go`

**Severity levels:** LOW, MEDIUM, HIGH

<details>
<summary><strong>Configuration & Examples</strong></summary>

**Configuration:**

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `enable_code_security` | Upload to GitHub Security tab | `false` | No |
| `post_pr_comment` | Post findings as PR comments | `true` | No |
| `fail_on_severity` | Fail on any finding | `none` | No |

**SDK config (`argus.yml`):**

```yaml
scanners:
  - gosec
scan_path: "."
fail_on_severity: high
```

Optional per-scanner keys: `config_file` (path to a gosec config passed via `-conf`) and `exclude` (comma-separated rule IDs passed via `-exclude`).

**Example:**

```yaml
with:
  scanners: gosec
  enable_code_security: true
  fail_on_severity: high
```

> **Secret redaction:** for the G101 (hardcoded-credentials) rule, gosec's `code` excerpt and `details` string contain the matched literal. Argus drops the code excerpt and scrubs the literal from the description before the finding reaches any reporter, export, or the MCP server.

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

### MUMPS / M language (`mumps`)

OSS SAST for the MUMPS / M language (VistA, YottaDB, GT.M, FileMan). Phase 1+ ships 28 rules (7 security M001-M007, 21 diagnostics M101-M102 and M201-M219) backed by [`janus-llm/tree-sitter-mumps`](https://github.com/janus-llm/tree-sitter-mumps) (Apache-2.0, MITRE Public Release 23-4084) pinned at `345f3fb2`. Target audience is federal / healthcare orgs whose procurement posture rules out closed-source MUMPS SAST.

**Supported languages:** `mumps`

**File extensions:** `.m` (Caché `.mac` / `.int` arrive in Phase 2 alongside ObjectScript dialect support)

**Severity levels:** INFO, LOW, MEDIUM, HIGH, CRITICAL

| Rule | Title | Severity | CWE |
|------|-------|----------|-----|
| `M001` | XECUTE of tainted expression | HIGH | CWE-95 |
| `M002` | Expression indirection (`@(...)`) of a tainted value | HIGH | CWE-94 |
| `M003` | OPEN / USE of tainted device (PIPE=CRITICAL, socket=HIGH, file/generic=MEDIUM) | CRITICAL–MEDIUM | CWE-78 |
| `M004` | Hard-coded credential in MUMPS global | CRITICAL | CWE-798 |
| `M005` | DO of READ-tainted indirection (dynamic routine dispatch) | CRITICAL | CWE-95 |
| `M006` | Tainted argument to external (`$&` / `$ZF`) call (exec helper=CRITICAL) | CRITICAL/HIGH | CWE-78 |
| `M007` | Tainted source loaded/compiled as code (ZLINK / ZINSERT / ZCOMPILE) | HIGH | CWE-95 |
| `M101` | Duplicate label declared in routine | INFO | n/a |
| `M102` | Unreachable code after unconditional QUIT / HALT | INFO | n/a |
| `M201` | DO / GOTO to undeclared label | INFO | n/a |
| `M202` | Routine name does not match filename | INFO | n/a |
| `M203` | Local variable read before it was defined | INFO | n/a (off by default) |
| `M204` | Local variable declared (NEW/READ) but never read | INFO | n/a |
| `M205` | Label body falls through into the following label | INFO | n/a (off by default) |
| `M206` | KILL of an entire global tree (no subscript) | INFO | n/a |
| `M207` | Bare KILL command deletes every local variable | INFO | n/a |
| `M208` | Bare NEW command stacks every local variable | INFO | n/a |
| `M209` | Call passes more arguments than the entry declares | MEDIUM | n/a |
| `M210` | Duplicate variable in a single NEW argument list | LOW | n/a |
| `M211` | Scratch global (`^TMP`/`^UTILITY`) written without `$J` | INFO | CWE-362 |
| `M212` | Argumentless FOR with no loop exit (infinite loop) | HIGH | CWE-835 |
| `M213` | QUIT with an argument inside a FOR loop | MEDIUM | n/a |
| `M214` | Naked global reference (`^(sub)`) | INFO | n/a (off by default) |
| `M215` | Non-portable Z-command (`ZSYSTEM`/`ZGOTO`/…) | LOW | n/a |
| `M216` | Non-portable `$Z` intrinsic function | INFO | n/a (off by default) |
| `M217` | Non-portable `$Z` special variable | INFO | n/a (off by default) |
| `M218` | Executable code on the routine label (first) line | LOW | n/a |
| `M219` | Source line exceeds the SAC 245-char limit | LOW | n/a |

The security rules above cover the MUMPS-specific code-injection sinks — XECUTE (M001), expression indirection (M002), OPEN/USE device arguments (M003), dynamic routine dispatch (M005), external `$&` / `$ZF` calls (M006), and source load/compile via ZLINK/ZINSERT (M007) — plus data-at-rest credential leaks (M004). Together they exceed the public mHawk taint-sink surface for intra-procedural detection. The diagnostic rules (M101–M102, M201–M219) cover structural, control-flow (infinite FOR, value-QUIT-in-FOR), def-use, call-arity, scratch-global concurrency, VistA SAC, and portability checks — 21 diagnostics toward mHawk's ~32. Rules marked *off by default* (M203, M205, M214, M216, M217) are opt-in via `rules.<id>.enabled: true` because they are idiomatic in legacy VistA (naked refs, fallthrough), portability-inventory only, or — for M203 (read-before-def) — too sensitive to the grammar's misparse of complex routines for an unattended default. (M002, M201, and M204 were previously off for being false-positive-dominant at scale; the precision work described below made them trustworthy enough to ship on.)

**Default profile precision (validated at scale).** The default profile is tuned so a clean codebase stays quiet and a real one yields actionable signal rather than a wall of noise. It was validated against **six real MUMPS projects totalling 1,162 routines** — a utility library, a MUMPS web server, two YottaDB projects, and the VistA **Kernel** (signon, device handling, `$ZF` callouts, the XECUTE-driven menu system) and Programmer Environment — with every distinct finding class adjudicated against the real source. The default profile produces **234 findings across all 1,162 routines, down from 1,628 before precision tuning** (85 security findings — 34 CRITICAL, 18 HIGH), while the genuine security signal is preserved: real shell-injection sinks in the Kernel (`OPEN "lsof"/"kill"/"ps":(shell=…:command=<tainted>)`, `$ZF(-1,…)` with a tainted command) are caught by M003/M006, READ→XECUTE injection by M001, expression indirection by M002, and code-load injection by M007. Three rules previously off-by-default for being false-positive-dominant are now precise enough to ship on, each validated by a corpus re-run showing the false positives gone: **M002** is position-aware — it fires only on the `@(<expr>)` expression form in a value position (name/glvn indirection like `S @X=…` and `@X@(sub)`, and X/D/G dispatch owned by M001/M005, are suppressed; 52→0 FPs on the Kernel); **M201** uses a text-scanned column-0 label index plus call-graph cross-routine resolution (48→0); **M204** treats a NEW-scoped variable as live whenever the file makes any `^ROUTINE` call that could inherit it via implicit-`NEW` (832→6, all genuine dead declarations). Taint sanitization is **flow-sensitive**: a charset pattern-match guard (`I X?1A.7AN`) or numeric coercion (`S N=+X`) clears a value, but a charset guard cleans only sinks that follow it in the same label body — so a validation gap on a *different* entry path still fires (it surfaced a real cross-entry expression injection the earlier flow-insensitive version hid).

**Known limitations on the on-by-default rules (refinements tracked).** A few rules that remain on are accurate enough to ship but still carry a residual false-positive fraction pending deeper work: **M003** does not yet distinguish socket/`|TCP|` and plain-file OPENs from shell `|PIPE|` command devices (only the latter is true command injection), **M005** still flags some by-design menu-driver dispatch beyond the `$TEXT`-table form already suppressed, **M202** suppresses `%`-routine platform-variant families but not every multi-platform naming convention, and **M211** treats only literal `$J` (not a job-id-bearing subscript such as `JOB`) as process-private. Tune per-finding severity or disable a specific rule via the config below if any is noisy on your codebase.

**Known Phase-1 limitation (cross-file request dispatch).** Web-framework request routing where the handler is selected across files — `do @ROUTINE` driven by a URL map, or `X %WCALL` reached through `$$RPC^XWBPRS()` — needs inter-procedural array-flow that the one-hop `interprocedural.enabled` pass does not yet model, so those dispatch sinks are not flagged by default. The roadmap's multi-hop / return-value taint work closes this; until then, extend `taint_sources.patterns` with your framework's request global if you want the intra-file portion of those chains surfaced.

<details>
<summary><strong>Configuration & Examples</strong></summary>

**SDK config (`argus.yml`):**

```yaml
scanners:
  - mumps
scan_path: ./routines
fail_on_severity: high
```

Optional per-scanner keys:
- `extensions` — file extensions to scan (defaults to `[".m"]`).
- `taint_sources.patterns` — list of regex strings appended to the built-in taint-source set. Any assignment whose RHS matches one of these patterns taints its LHS. Use for site-specific intrinsics or HTTP globals beyond `READ` / `$ZARGV` / `^%CGI` / `^%REQUEST` / `^%session`.
- `taint_sources.formals_untrusted` — **attack-surface audit mode** (default off). Seeds every entry-label formal parameter as an untrusted boundary input, so a sink fed by a parameter whose taint origin is in a *caller* (e.g. `DEL(FILE) … S RC=$ZF(-1,"rm "_FILE)`) still fires. Off by default because it widens the source surface to all API entry points and is far noisier (on the VistA Kernel it surfaces ~200 additional parameter-derived sinks vs. the precise default); turn it on for a deliberate boundary-input audit. This is the practical recall lever for the formal-argument / multi-hop sinks the default intra-file model does not chase.
- `sanitizers` — list of function / intrinsic names that *remove* taint when applied. A variable assigned from an expression that calls one of these is treated as clean by every taint-aware rule. Pair with the existing source-patterns config to make the full taint flow tunable per codebase.
- `rules.<id>.severity` — per-rule severity override. Replaces the rule's default baseline severity. Per-finding precision (M003's PIPE bump to CRITICAL) is preserved — only baseline severity is user-tunable. Accepts `critical` / `high` / `medium` / `low` / `info`.
- `profile` — a rule preset selectable in config or via CLI: `security-only` (just the M00x security rules), `lint-only` (just the diagnostics), `strict` (every rule, including the off-by-default ones), or `default`. An explicit `rules.<id>.enabled` always overrides the profile.
- `rules.<id>.enabled` — turn an individual rule on or off. Most rules are on by default; **M203, M205, M214, M216, and M217 ship off by default.** M203 (read-before-def) is the noisiest rule on real code — enable it for a deliberate implicit-declaration audit. M205 (label fallthrough) is off because top-to-bottom fallthrough between labels is the intended idiom in old-style linear VistA routines (it was ~69% false-positive on the VistA Kernel). M214/M216/M217 are portability-inventory checks, opt-in for migration audits. (M002, M201, and M204 are now on by default following the precision work above.)
- **Inline suppression** — a `;argus:ignore` comment silences every finding on its line (and the line below it); `;argus:ignore[M002]` or `;argus:ignore[M002,M211]` silences only the listed rules. Suppressions are counted in `metadata.suppressed`, never dropped silently.
- `known_external_vars` — list of variable names treated as externally defined / read (extends the built-in VistA / FileMan / Kernel allowlist used by M003 / M203 / M204).
- `flag_generic_indirection` — when `true`, M002 also emits an INFO advisory for indirection of a *non-tainted* non-constant expression (default `false`). By default M002 fires HIGH only on indirection of a tainted variable; the generic stream is for audit / modernization sweeps and never counts toward a severity gate.
- `scratch_globals` — list of shared scratch globals that must be `$J`-subscripted (M211); defaults to `["^TMP", "^UTILITY"]`.
- `max_line_length` — SAC line-length limit for M219 (default 245).
- `rules.M202.ignore_patterns` — regex list of routine-name families to exclude from the filename-mismatch check (M202).
- `interprocedural.enabled` / `interprocedural.max_depth` — opt in to one-hop cross-routine taint propagation (default off; `max_depth` default 1). When on, a tainted actual argument passed to `LABEL^ROUTINE(...)` taints the callee's matching formal parameter, so the callee's sinks (XECUTE / OPEN-USE / dispatch / external call of that formal) fire. Yields on parameter-passing code; codebases using the classic shared-scratch-variable calling convention (much of legacy VistA) see little additional signal.

```yaml
scanners:
  mumps:
    taint_sources:
      patterns:
        - "\\$ZIO\\b"             # YottaDB pending input
        - "\\^MyApp\\.input\\b"   # site-specific HTTP global
    sanitizers:
      - "$$ESCAPE^HTML"           # output-encoder
      - "$$VALIDATE^INPUT"        # input-validator
    rules:
      M203:
        enabled: true             # opt in to read-before-def audit (off by default)
      M001:
        severity: critical        # promote XECUTE in this codebase
      M205:
        enabled: true             # opt in (off by default)
      M202:
        enabled: false            # silence a rule entirely
```

**Installation paths:**

The scanner needs a compiled `mumps.so` shared library. The `scanner-mumps` container image (built by `docker/Dockerfile.mumps`) bundles a prebuilt grammar at `/opt/argus/grammars/mumps.so`, so the container path needs no local toolchain. Three ways to run it:

1. **Container, via the SDK (recommended).** With Docker available, the engine pulls and runs the image automatically - no grammar build:
   ```bash
   pip install 'argus-security[mumps]'
   argus scan mumps --path ./routines
   ```

2. **Container, directly.** No Python or Argus install at all:
   ```bash
   docker run --rm -v "$PWD:/workspace:ro" \
     ghcr.io/huntridge-labs/argus/scanner-mumps:mumps-preview \
     scan mumps --path /workspace
   ```

3. **Local execution.** Run in-process; compile the grammar once (needs a C compiler + git):
   ```bash
   pip install 'argus-security[mumps]'
   ./scripts/build-mumps-grammar.sh
   # Drops mumps.so at ~/.cache/argus/grammars/
   argus scan mumps --path ./routines   # backend: local, or no Docker present
   ```

The `ARGUS_MUMPS_GRAMMAR` environment variable overrides the grammar lookup path when a CI pipeline pins a custom build.

> **Preview image:** `:mumps-preview` is a pre-merge build published from the `feat/scanner-m-mumps` branch (mutable tag, workstation-built - no cosign / SLSA attestations yet). On merge the release pipeline republishes it multi-arch with attestations under the versioned `scanner-mumps:<version>` tag, and `argus/containers.py` is repinned to that digest.

**Example:**

```yaml
scanners:
  - mumps
scan_path: ./routines
fail_on_severity: high
reporters:
  - terminal
  - sarif
```

> **Secret redaction:** for the M004 (hard-coded credentials) rule, the matched literal value is replaced with the redaction placeholder before the finding is constructed. Defense-in-depth: `Finding.__post_init__` runs the pattern-based redactor as a second pass. The literal never reaches any reporter, export, or the MCP server. Integration test `test_literal_value_is_redacted` enforces this contract.

> **Taint scope:** Phase 1 taint *detection* is intra-file. Recognized taint sources are `READ` (terminal input), `$ZARGV` (YottaDB / GT.M process arguments), and the HTTP context globals `^%CGI`, `^%REQUEST`, `^%session`. The collector is shared between M001 / M002 / M003 / M005 / M006 so every taint-sink rule sees the full source surface uniformly. The **inter-procedural call graph** is built on every multi-file scan (`argus/scanners/mumps/callgraph.py`); M001 findings carry an `inter_procedural_callers` metadata list naming the routines that reach the sink. **One-hop taint propagation** across that graph is available via `interprocedural.enabled` (opt-in): a tainted actual argument flows into the callee's formal parameter (recursion-safe monotone worklist, `max_depth`-capped). Deeper multi-hop propagation, return-value taint, and per-finding provenance remain on the roadmap.

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

### Exposed-port surface

Reports the network endpoints a container image declares via Dockerfile
`EXPOSE` — separate from whether those endpoints have known CVEs. "Image
exposes 6379/tcp" is a different question from "image has a vulnerable
Redis package" and most security reviewers want both. Runs as a
sub-scanner inside the container scanner (no new module); the data is
free since the container scanner already runs `docker inspect` on every
pull.

**Output shape:** one `Finding` per declared port:

```
INFO   EXPOSE-8080-tcp    Port 8080/tcp declared exposed
MEDIUM EXPOSE-22-tcp      Port 22/tcp (SSH) declared exposed
MEDIUM EXPOSE-3306-tcp    Port 3306/tcp (MySQL) declared exposed
```

Findings flow through every reporter (terminal, markdown, sarif, json,
github, gitlab, junit), `--severity-threshold` filtering, audit trail,
and the view-terminal / view-browser UIs without per-reporter custom
code.

**Built-in risky-defaults watchlist** (MEDIUM severity by default — each
entry's rationale is cited in `argus/scanners/container.py::RISKY_PORTS`):

| Port | Service | Port | Service |
|------|---------|------|---------|
| 21/tcp | FTP | 3306/tcp | MySQL |
| 22/tcp | SSH | 3389/tcp | RDP |
| 23/tcp | Telnet | 5432/tcp | PostgreSQL |
| 25/tcp | SMTP | 6379/tcp | Redis |
| 110/tcp | POP3 | 9200/tcp | Elasticsearch |
| 143/tcp | IMAP | 11211/tcp | Memcached |
| 161/udp | SNMP | 27017/tcp | MongoDB |
| 389/tcp | LDAP | | |
| 445/tcp | SMB | | |

**Configuring via argus.yml:**

```yaml
scanners:
  container:
    image_ref: "myapp:latest"
    # Default sub-scanner set; remove "exposure" to opt out
    scanners: "trivy,grype,syft,exposure,services"
    # Override the built-in WARN list (replaces the defaults).
    # Pass [] to demote every declared port to INFO.
    expose_warn_ports:
      - 22/tcp
      - 3306/tcp
      - 8080/tcp           # promote app port to WARN
    # Suppress findings entirely for ports the team has accepted.
    expose_ignore_ports:
      - 443/tcp
      - 9090/tcp
```

Both lists accept `"PORT/PROTO"` strings; bare `"PORT"` defaults to tcp.
Schema validator errors on malformed entries at config-load time. See
[`docs/config-reference.md`](config-reference.md) for the full schema.

**Out of scope:** *runtime* port enumeration (start the container, probe
with `nmap`/`ss`). Static `EXPOSE` data is the bulk of the value at a
fraction of the operational cost.

### Service enumeration

Walks the container image's filesystem at scan time, parses systemd
unit files (`/etc/systemd/system`, `/lib/systemd/system`,
`/usr/lib/systemd/system`) and SysV init scripts (`/etc/init.d/`),
and emits one `Finding` per declared service. Runs as a sub-scanner
inside the container scanner — same Docker requirement, no new
heavy dependencies. Works on distroless / scratch images because
file extraction goes through `docker create` + `docker cp` (tar
stream) rather than `docker run`. Per-file reads are bounded at 1
MB to prevent hostile-image memory blow-up.

**Output shape:** one `Finding` per service:

```
INFO   SVC-nginx       Service "nginx" declared (systemd unit)
MEDIUM SVC-sshd        Service "sshd" declared (systemd unit)
MEDIUM SVC-postgresql  Service "postgresql" declared (systemd unit)
```

Findings flow through every reporter (terminal, markdown, sarif,
json, github, gitlab, junit), `--severity-threshold` filtering,
audit trail, and the view-terminal / view-browser UIs without
per-reporter custom code.

**Built-in risky-defaults watchlist** (MEDIUM severity by default —
each entry cites a "why" in
`argus/scanners/container.py::RISKY_SERVICES`):

| Service | Service | Service |
|---------|---------|---------|
| sshd | postgresql | redis-server |
| telnetd | mysqld | redis |
| vsftpd | mariadb | mongod |
| memcached | elasticsearch | snmpd |
| rpcbind | nfs-server | |

**Configuring via argus.yml:**

```yaml
scanners:
  container:
    image_ref: "myapp:latest"
    # Default sub-scanner set; remove "services" to opt out
    scanners: "trivy,grype,syft,exposure,services"
    # Override the built-in WARN list (replaces the defaults).
    # Pass [] to demote every declared service to INFO.
    services_warn:
      - sshd
      - postgresql
      - nginx               # promote app service to WARN
    # Suppress findings entirely for services the team has accepted.
    services_ignore:
      - cron
      - rsyslog
```

Matching is case-insensitive. `.timer`, `.socket`, `.target`, and
`.mount` units are skipped (only `.service` units and init.d
scripts are reported). Schema validator errors on malformed entries
at config-load time. See
[`docs/config-reference.md`](config-reference.md) for the full schema.

**Out of scope:** *runtime* service probing (start the container,
observe what binds). Static unit-file declarations are the bulk of
the value at a fraction of the operational cost.

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

### KICS

Checkmarx KICS (Keeping Infrastructure as Code Secure) — multi-format IaC scanner with ~3000 built-in queries (Apache-2.0). Covers formats `trivy-iac`/`checkov` handle poorly or not at all, most notably **Ansible**.

**Supported frameworks:** Ansible, Bicep, Helm, Terraform, Kubernetes, Dockerfile, CloudFormation, OpenAPI, Tekton, Buildah, and server-side template engines.

KICS, `trivy-iac`, and `checkov` are designed to run concurrently — they catch different things on the same target. Scope KICS to `--scanners kics` if you only want the formats the other two miss.

<details>
<summary><strong>Configuration & Examples</strong></summary>

**SDK usage:**

```bash
# Run KICS on its own
argus scan kics --path infrastructure/

# Run the full IaC trio
argus scan trivy-iac checkov kics
```

**Severity levels:** HIGH, MEDIUM, LOW, INFO (mapped directly to Argus severities).

**Config (`argus.yml`):**

| Key | Description | Default |
|-----|-------------|---------|
| `config_file` | Path to a KICS config file (`--config`) | `''` |
| `exclude` | Comma-separated paths to exclude (`--exclude-paths`) | `''` |

```yaml
scanners:
  kics:
    exclude: "examples,vendor"
```

> **Secrets handling:** KICS echoes the offending source snippet in each match's `actual_value` / `search_value` fields, which for a secrets-class query is the secret itself. Argus redacts all per-match value fields before they reach a finding — the `file:line` location and query name remain as triage signal.

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

**2. Run the scan**:

```bash
# Via SDK
python -m argus scan zap --config argus.yml
```

Or via composite action in GitHub Actions:

```yaml
jobs:
  zap-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: huntridge-labs/argus/.github/actions/scanner-zap@1.9.2
        with:
          zap_config_file: .github/zap-config.yml
```

---

#### Configuring ZAP via `argus.yml` (recommended for SDK users)

ADR-024 decided that ZAP-specific tuning lives in the standard `argus.yml`
under `scanners.zap.*`, working identically across SDK-direct, composite-
action, and any-CI use. The composite action surface stays minimal
(target identification + common cross-scanner inputs); everything else
configures from one place.

```yaml
scanners:
  zap:
    enabled: true
    target_url: "https://app.example.com"

    # Tuning (container backend; all optional)
    scan_type: baseline                 # baseline | full | api (api is implicit
                                         # when api_spec is set)
    api_spec: "https://app.example.com/openapi.json"
    rules_file: ".zap/rules.tsv"         # mounted at /zap/wrk/rules.tsv
    max_duration_minutes: 30
    cmd_options:
      - "-z"
      - "-config view.locale=en_GB"

    # Registry auth for app_image_ref pulls (private images).
    # Name the env var; argus reads os.environ at scan time.
    # Setting registry_password directly is back-compat-supported
    # but warned at config-load if the value looks like a vendor secret.
    registry_username_env: REGISTRY_USER
    registry_password_env: REGISTRY_TOKEN

    # Web-app authentication — ZAP context-file passthrough.
    # User authors the context file (DOM selectors, logged-in regex,
    # session management); argus mounts it and exports ZAP_AUTH_USERNAME
    # / ZAP_AUTH_PASSWORD into the container for the {%username%} /
    # {%password%} placeholders to substitute.
    auth:
      context_file: ".zap/context.xml"
      username_env: ZAP_APP_USER
      password_env: ZAP_APP_PASSWORD
```

See [`docs/config-reference.md`](config-reference.md#credential-fields) for
the full credential-field contract and the list of every `scanners.zap.*`
key.

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
| `allow_failure` | Allow workflow to continue on failures | `false` | No |
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

```bash
# Via SDK
python -m argus scan zap --config argus.yml
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

For simple single-scan scenarios via composite actions, you can pass inputs directly (no config file):

**URL-only scan:**

```yaml
jobs:
  zap-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: huntridge-labs/argus/.github/actions/scanner-zap@1.9.2
        with:
          zap_scan_mode: url
          zap_target_urls: https://example.com
          fail_on_severity: medium
```

> **Note**: Input-based configuration is limited to single scans. Use config files for multiple scans or advanced features.

</details>


## LLM-Security Scanners

### promptfoo

[promptfoo](https://github.com/promptfoo/promptfoo) is an OSS LLM eval and
red-team framework with 60+ plugins aligned to the
[OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
(prompt injection, jailbreaks, PII leakage, hallucination, bias). Argus
runs it container-first, so the Node.js runtime stays inside the promptfoo
image and never touches Argus core.

> **Opt-in scanner.** promptfoo is **not** included in `all`. It requires
> provider API keys (OpenAI, Anthropic, etc.) **and network access at scan
> time** — every probe is a live request to the configured model endpoint.
> Enable it explicitly and budget for provider API usage.

**Key Features:**
- Red-team probes (prompt injection, jailbreak, PII, RBAC/BOLA, SSRF, …) and plain eval assertions
- Failed red-team probes map to `HIGH`; failed eval assertions to `MEDIUM`
- Adversarial prompts and model responses are **never** echoed into Argus findings — only structural metadata (plugin id, assertion type, provider) is surfaced, so secrets/PII in prompts or responses don't leak into reports

---

#### Quick Start

**1. Author a promptfoo config** (e.g. `promptfooconfig.yaml`) per the
[promptfoo docs](https://www.promptfoo.dev/docs/configuration/guide/) —
declare your providers, prompts, and red-team plugins there.

**2. Configure Argus** (`argus.yml`):

```yaml
scanners:
  promptfoo:
    enabled: true
    config_file: "promptfooconfig.yaml"   # mounted at /app/promptfooconfig.yaml

    # Provider API keys — name the env var; argus reads os.environ at
    # scan time and exports it into the container. The literal value
    # never appears in argus.yml.
    openai_api_key_env: OPENAI_API_KEY
    anthropic_api_key_env: ANTHROPIC_API_KEY

    # Any additional provider: map the provider's native env-var name
    # to the host env var holding the secret.
    api_keys:
      MISTRAL_API_KEY: MY_MISTRAL_SECRET

    cmd_options:
      - "--max-concurrency"
      - "2"
```

**3. Run the scan**:

```bash
OPENAI_API_KEY=sk-... argus scan promptfoo --config argus.yml
```

The scanner invokes `promptfoo eval -c <config> -o /output/results.json
--no-progress-bar` inside the container and normalizes failing results
into Argus findings.

---

## Supply-Chain Scanners

### GuardDog (`guarddog`)

[GuardDog](https://github.com/DataDog/guarddog) (Datadog, OSS) flags
**malicious** packages — install-time code execution, typosquatting,
obfuscation, exfiltration, suspicious metadata — using source-code (Semgrep)
and metadata heuristics. This is a different signal from the CVE-based SCA
scanners (`osv` / `grype` / `trivy`): those find *known vulnerabilities*,
GuardDog finds packages that look *malicious*. Run both.

It walks the scan path for dependency manifests and runs
`guarddog <ecosystem> verify` on each:

| Manifest | Ecosystem |
|----------|-----------|
| `requirements.txt` | pypi |
| `package.json` | npm |
| `go.mod` | go |
| `Gemfile.lock` | rubygems |

```yaml
scanners:
  - guarddog
```

```yaml
# Optional tuning
scanners:
  guarddog:
    rules: [exec-base64, code-execution]        # run only these heuristics
    exclude_rules: [repository_integrity_mismatch]   # suppress a noisy rule
```

**Execution:** local binary — `pip install guarddog`. There is no bundled
container image yet (GuardDog needs `pygit2`/libgit2 in the base image);
until that lands, the scanner runs where `guarddog` is installed and is
gracefully skipped otherwise. Findings are `HIGH` severity; GuardDog is
malicious-indicator detection, not CVE matching, so it has no VEX support —
suppress false positives with `exclude_rules`.

> **Note:** matched source excerpts from a flagged package are deliberately
> **not** copied into `argus-results.json` (only rule/package/location) so a
> malicious payload can't leak into scan artifacts. Re-run
> `guarddog <ecosystem> scan <package>` locally to inspect the code.

---

## Common Configuration Patterns

### Enable GitHub Security Tab (Actions)

Upload SARIF results when using composite actions:

```yaml
with:
  enable_code_security: true
```

### Disable PR Comments (Actions)

Useful for scheduled scans using composite actions:

```yaml
with:
  post_pr_comment: false
```

### Scanner Selection Patterns

**SDK:**

```bash
# SAST only
python -m argus scan codeql opengrep bandit gitleaks

# Infrastructure only
python -m argus scan trivy-iac checkov kics

# Container only
python -m argus scan container

# Focused mix
python -m argus scan gitleaks trivy-iac checkov
```

**Composite actions:** Use individual `scanner-*` actions in your workflow steps.
