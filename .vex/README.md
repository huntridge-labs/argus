# CLI container VEX — evidence & justification (DRAFT — needs sign-off)

Scope: the CLI container's CRITICAL findings that are **not attributable to
Argus's own code** — every one lives in a vendored Go dependency inside a
**bundled third-party security-tool binary**, not in the Argus Python package.
Evidence below is from the GitHub code-scanning alerts for category
`container-cli` (SARIF emitted by the container scan), which carry per-finding
binary attribution (`location.path`).

## Binary attribution (evidence)

| Vulnerable component | Bundled binary | Source |
|---|---|---|
| `golang.org/x/crypto@v0.35.0` (CVE-2025-47913 / -47914 / -58181 + Grype GHSA/GO aliases) | `usr/local/bin/gitleaks` | code-scanning alert `location.path` |
| `stdlib@go1.24.11` (CVE-2025-68121 / GO-2026-4337) | `usr/local/bin/gitleaks` | code-scanning alert `location.path` |
| `stdlib@go1.26.1` (highs) | `usr/local/bin/actionlint` | " |
| `stdlib@go1.26.3` (highs) | `usr/local/bin/grype`, `usr/local/bin/syft` | " |

The 12 CRITICALs collapse to two root causes, both in **gitleaks** (an old
build — `zricethezav/gitleaks:v8.30.1`, compiled with Go 1.24.11 and vendoring
`x/crypto` v0.35.0):

1. **`golang.org/x/crypto` v0.35.0** — the `x/crypto/ssh` advisory cluster
   (Grype rates CRITICAL; Trivy rates the same CVEs HIGH).
2. **Go stdlib 1.24.11** — CVE-2025-68121.

## Justification: `not_affected` / `vulnerable_code_not_in_execute_path`

Argus invokes gitleaks as a **one-shot, offline secret scanner over the
already-checked-out local working tree**. It does not open a network listener,
serve requests, or initiate SSH connections. The `x/crypto/ssh` handshake code
(the affected path for the x/crypto cluster) and the stdlib path for
CVE-2025-68121 are therefore never reached in Argus's usage.

⚠️ **Per-CVE reachability must be confirmed before this is treated as final.**
Each `x/crypto` CVE's specific affected function should be checked against
gitleaks' actual call graph (gitleaks *can* clone remote repos, which would
exercise SSH — Argus's pipeline scans the local checkout, so it does not, but
that is a usage assumption worth pinning). This draft encodes the assumption;
sign-off = confirming it holds for your invocation.

## ⭐ Recommended first: fix, don't suppress

These are **fixable by bumping the bundled tool**, which is better than a VEX:

- Bump **gitleaks** in `docker/Dockerfile.cli` / `argus/containers.py` to a
  release built against Go ≥ 1.24.13 and `x/crypto` ≥ 0.52.0 — that clears the
  x/crypto cluster **and** CVE-2025-68121 outright (10 of the 12 criticals).
- Bump **actionlint** / confirm **grype**/**syft** are on current builds for
  the stdlib highs.

VEX should cover only the residue that has **no** rebuilt upstream release yet.
If a gitleaks bump clears these, this document is unnecessary.

## How to apply (once signed off)

Commit as `.vex/argus-cli.openvex.json` and point the scan at it:

```yaml
# argus.yml
containers:
  vex: .vex/argus-cli.openvex.json          # container-lifecycle scan
scanners:
  grype: { vex: .vex/argus-cli.openvex.json }   # source/SBOM scans (PR #365)
  trivy: { vex: .vex/argus-cli.openvex.json }
```

Both Trivy and Grype resolve CVE↔GHSA↔GO aliases, but statements are included
under all three ID schemes for belt-and-suspenders matching.
