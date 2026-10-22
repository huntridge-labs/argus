# CLI container VEX: evidence and justification

`argus-cli.openvex.json` declares `not_affected` for vulnerabilities in Go code
compiled into the **gitleaks** binary we bundle in the CLI image
(`usr/local/bin/gitleaks`, gitleaks v8.30.1, built with Go 1.24.11 and
vendoring `golang.org/x/crypto` v0.35.0). None of it is Argus's own code.
gitleaks' latest upstream release is still v8.30.1, so there is no rebuilt
version to move to yet.

It is applied in two places:

- `.github/workflows/build-containers.yml` passes `--vex` to the CI container
  scan that renders the PR comment and the `container-cli` SARIF.
- `argus.yml` (`containers.vex`) applies it to `argus scan container` runs.

Sign-off is the approving review on the PR that changes this document. A
statement change without that review should not merge.

## What is covered

| Statements | Component | Affected code |
|---|---|---|
| CVE-2025-47913, CVE-2025-47914, CVE-2025-58181, GO-2026-5005, GO-2026-5019, GO-2026-5020 and their GHSA aliases | `golang.org/x/crypto@v0.35.0` | `x/crypto/ssh` and `x/crypto/ssh/agent` |
| CVE-2025-68121 / GO-2026-4337 | Go stdlib 1.24.11 | `crypto/tls` handshake (session resumption) |

## Evidence (2026-10-19)

Run with govulncheck v1.1.4 in source mode against the gitleaks v8.30.1 tag
(`GOTOOLCHAIN=go1.24.11 govulncheck -show traces ./...`), so the call graph is
gitleaks' own code with the toolchain the shipped binary was built with:

- **x/crypto:** no call path from gitleaks code to any of the x/crypto
  vulnerabilities above. govulncheck lists them only under "packages you
  import ... your code doesn't appear to call". `x/crypto` is an indirect
  dependency in gitleaks' `go.mod`.
- **crypto/tls (GO-2026-4337):** the only call path is
  `cmd/diagnostics.go` `StartHttpHandler`, the profiling server behind
  `--diagnostics=http`. A second trace through `sources/git.go`
  `blobReader.Close` reaches `tls.Conn.Read` only through `io.Reader`
  interface dispatch; at runtime that reader is the `git` subprocess pipe, not
  a TLS connection.

Argus runs gitleaks as `gitleaks detect --source <workspace> --report-format
json ...` (`argus/scanners/gitleaks.py`). It never passes `--diagnostics`,
never points gitleaks at a remote, and makes no SSH or TLS connection through
it. That is the basis for `vulnerable_code_not_in_execute_path`.

Static call graphs miss reflection and cgo paths, so this is evidence for the
usage claim, not proof of it (see ADR-035). If Argus ever starts passing
gitleaks a remote URL or `--diagnostics`, these statements stop being true.

## Keeping it honest

- **Remove statements when gitleaks ships a rebuild.** A gitleaks release
  built with Go >= 1.24.13 and `x/crypto` >= 0.52.0 clears every finding here,
  and this document should then be deleted, not carried forward.
- **These statements are not scoped to gitleaks.** CI passes this document
  to every image it builds, and each statement names only the component
  (`pkg:golang/stdlib@1.24.11`, `pkg:golang/golang.org/x/crypto@v0.35.0`).
  Any Go binary built with those versions has the same findings hidden, even
  though the evidence above covers gitleaks alone. As of 2026-10-22 gitleaks
  is the only binary in the CLI image on either version (trivy, grype, syft
  and actionlint are on Go 1.26).
  Neither trivy nor grype can scope an OpenVEX statement to one binary, so
  check that before bumping any bundled Go tool. Moving these to path-scoped
  `.trivyignore.yaml` / `.grype.yaml` rules on `usr/local/bin/gitleaks` is
  tracked as a follow-up.
- **PURL spelling must match the scanners.** trivy and grype only drop a
  finding when the product PURL is an exact match, and say nothing when it is
  not. For the Go toolchain trivy reports `pkg:golang/stdlib@v1.24.11` and
  grype `pkg:golang/stdlib@1.24.11`, so stdlib statements list both. The
  `go1.24.11` spelling (govulncheck's) matches neither, which is why the two
  stdlib criticals stayed visible until 2026-10-19.
- `tests/unit/test_cli_vex_document.py` lints the spellings, and
  `scripts/ci/render_container_summary.py` fails the container scan when a
  statement names a reported finding that the scanners still returned.
- Statements are listed under CVE, GHSA and GO IDs because trivy and grype key
  findings on different ID schemes.
