# Spike: VEX output for container/SCA scans

Design note for [#229](https://github.com/huntridge-labs/argus/issues/229). Records the
prototype shipped in this PR, the finding→OpenVEX mapping, what the corpus of real
scanner output told us about PURL coverage, and the recommendations the spike was
asked to produce (OpenVEX-vs-CSAF sequencing, `lib4vex` fit, exploitability-status
source).

## What shipped (prototype)

- A built-in **`openvex`** reporter (`argus/reporters/openvex.py`), so
  `argus scan ... --format openvex` writes one consolidated `argus-results.openvex.json`
  (OpenVEX v0.2.0) for the whole scan.
- PURL propagation through the normalization tier (`argus/scanners/_vuln_parsers.py`):
  Trivy `PkgIdentifier.PURL` and Grype `artifact.purl` now land in `Finding.metadata["purl"]`.

It serializes at the Argus normalization tier, not per scanner — exactly the approach the
issue proposed. Trivy's native VEX is Trivy-scoped and Grype is consume-only, so neither
gives a single Argus-wide document; consolidating in our tier does.

## Finding → OpenVEX statement mapping

A statement is emitted only for a finding that carries **a CVE *and* a component
identifier**. That shape is unique to the container/SCA scanners (trivy, grype, osv,
container); SAST / IaC / secrets / DAST findings have no CVE+component pair and are
excluded by construction — no scanner-name allowlist needed.

| OpenVEX field            | Source |
|--------------------------|--------|
| `statements[].vulnerability.name` | `Finding.cve` |
| `statements[].products[].@id`     | `Finding.metadata["purl"]`, else a PURL synthesized from `package`/`package_name` + version + `ecosystem` |
| `statements[].status`             | `affected` (default — see *Exploitability status* below) |
| `@id`                             | `sha256(statements)[:16]` — deterministic, so re-running a scan yields the same document id |
| `timestamp`                       | scan time (UTC) |

Statements are deduped by `(CVE, product)`: the same vulnerable component is routinely
reported by more than one scanner or across multiple targets.

## PURL coverage (the open question)

Confirmed against the scanners' real output shapes:

- **Grype** emits `artifact.purl` directly — full coverage.
- **Trivy** emits `PkgIdentifier.PURL` (0.40+) — full coverage on modern Trivy; older output
  or OS packages without a PkgIdentifier yield an empty PURL (edge case).
- **OSV** does not emit a PURL, but carries `ecosystem` + `package_name` + `package_version`,
  from which the reporter synthesizes one (`pkg:<type>/<name>@<version>`) via a small
  ecosystem→purl-type map. Unknown ecosystems fall back to a lowercased token.
- A finding with a CVE but no resolvable component (no PURL, no package name) is skipped
  rather than emitting a product-less statement.

Metadata-key inconsistency surfaced and was worked around in the reporter, not papered over:
trivy/grype use `package`/`installed_version`; osv uses `package_name`/`package_version`.
Normalizing those keys is a separate cleanup, noted but out of scope for the spike.

## Recommendations

**OpenVEX first, CSAF as a fast-follow — confirmed.** OpenVEX v0.2.0 is a small, stable
schema (seven top-level fields + statements) and is the right interop default. CSAF 2.0 is
a substantially larger OASIS schema; defer it until a federal consumer concretely needs it.

**Hand-roll OpenVEX; reach for `lib4vex` only when CSAF lands.** The prototype serializes
OpenVEX in ~40 lines with zero new dependencies — which matches the project's dependency
posture (pinned versions, minimum-release-age, minimal supply-chain surface). `lib4vex`
would add a dependency tree to emit a schema we can serialize trivially. Its value is the
*CSAF* generator: when CSAF is prioritized, adopt `lib4vex` for that format (CSAF is too
complex to hand-roll safely) and keep the hand-rolled OpenVEX path. So `lib4vex` is a
"yes, later, for CSAF" — not for OpenVEX.

**Exploitability status source — needs a decision and a small wiring change.** The
prototype emits `affected` for every matched CVE: the scanner's ground truth (the
vulnerable component is present). The value of VEX is the human/triage overlay of
`not_affected` (with a justification) / `fixed` decisions. Recommended next step: a manual
override file (`vex_overrides.yml` keyed by `(cve, purl)` → `{status, justification}`) as
the first decision source, with AutoGRC/AutoISSO decision-capture as the follow-on. This
needs config threaded into the reporter (reporters currently receive only the
`ScanSummary`) — either a small protocol extension or a pre-reporter enrichment pass that
stamps the decision onto `Finding.metadata`. Tracked as the primary follow-up.

## Out of scope (unchanged from the issue)

- VEX for SAST/IaC/secrets/DAST (category mismatch).
- VEX **consumption** (filtering findings via upstream VEX, e.g. Trivy VEX Hub) — separate issue.
- Auto-remediation.
