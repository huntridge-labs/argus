# govulncheck Go Vulnerability Scanner

Reachability-aware Go vulnerability scanning using [govulncheck](https://go.dev/security/vuln/), Go's official vulnerability tool, run through the Argus SDK.

## Why this exists

Presence-based scanners (grype, trivy, osv-scanner) report **every** known vulnerability in **every** dependency in a Go module's graph — even when the affected function is never called. That produces a large class of false positives: "the vulnerable package is in `go.mod`, so it's flagged," regardless of whether your code can reach the vulnerable code path.

`govulncheck` builds the program **call graph from source** and reports a vulnerability only when the affected symbol is actually reachable. That reachability filter is the difference between "you import a library that has a CVE somewhere" and "your code calls the vulnerable function."

## Finding tiers

| Tier | Meaning | Severity in Argus |
|------|---------|-------------------|
| **Called / reachable** | govulncheck found a call path to the vulnerable symbol | Real (OSV-derived) severity — gates on `fail_on_severity` |
| **Imported, not called** | The vulnerable module/package is in the build graph but the affected symbol isn't called | `INFO` — visible for audit, never gates |

`metadata.reachable` (`true`/`false`) and, for reachable findings, `metadata.call_stack` (entry point → vulnerable symbol) are attached to every finding.

## Requirements

- A Go module (a `go.mod`). govulncheck's source mode type-checks and builds the target packages to compute reachability, so it needs the Go toolchain and the module's dependencies resolvable (network access to the module proxy and to `https://vuln.go.dev`).
- This action sets up Go and installs govulncheck for you.

## Usage

```yaml
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6
- uses: huntridge-labs/argus/.github/actions/scanner-govulncheck@1.4.0
  with:
    scan_path: '.'
    fail_on_severity: 'high'
    enable_code_security: true
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `scan_path` | Path to the Go module to scan (directory containing `go.mod`) | `.` |
| `go_version` | Go version to set up | `stable` |
| `govulncheck_version` | govulncheck version to install | `latest` |
| `fail_on_severity` | Fail at/above this severity (`none`, `low`, `medium`, `high`, `critical`) | `none` |
| `enable_code_security` | Upload SARIF to the GitHub Security tab | `false` |
| `post_pr_comment` | Post results as a PR comment | `false` |
| `job_id` | Job ID for artifact naming | `${{ github.job }}` |

To narrow the scan to a sub-package (e.g. `./cmd/...`), set `scanners.govulncheck.scan_target` in `argus.yml` — the SDK reads it from the per-scanner config block.

## Outputs

| Output | Description |
|--------|-------------|
| `critical_count` / `high_count` / `medium_count` / `low_count` | Findings by severity |
| `total_count` | Total findings (reachable + imported-not-called) |
| `scan_status` | `clean` or `vulnerable` |

## Severity note

Go advisories (`GO-YYYY-NNNN`) frequently carry no machine-readable severity. When that's the case a reachable finding is reported as `UNKNOWN` (not guessed), so it won't trip `fail_on_severity: high`. Pair govulncheck with `scanner-osv` if you need CVSS-derived severities for gating, and rely on govulncheck for the reachability signal.

## Relationship to other scanners

- **`scanner-gosec`** — Go SAST (code anti-patterns like SQL string-building). Complementary; not dependency CVEs.
- **`scanner-osv`** — presence-based dependency CVEs across many ecosystems. Broader coverage, no reachability.
- **`scanner-govulncheck`** (this) — Go-only, reachability-filtered dependency CVEs. The lowest false-positive Go dependency signal.
