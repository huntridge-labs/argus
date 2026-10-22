# CLI container ignore rules: evidence and justification

`argus-cli.trivyignore.yaml` (trivy) and `argus-cli.grype.yaml` (grype)
ignore vulnerabilities in Go code compiled into the **gitleaks** binary we
bundle in the CLI image (`usr/local/bin/gitleaks`, gitleaks v8.30.1, built
with Go 1.24.11 and vendoring `golang.org/x/crypto` v0.35.0). None of it is
Argus's own code. gitleaks' latest upstream release is still v8.30.1, so
there is no rebuilt version to move to yet.

Every rule is scoped to that one path. The same CVE in any other binary in
the image stays visible.

They are applied in two places:

- `.github/workflows/build-containers.yml` passes `--trivy-ignore-file` and
  `--grype-config-file` to the CI container scan of the `cli` image only.
  That scan renders the PR comment and the `container-cli` SARIF.
- `argus.yml` (`containers.trivy_ignore_file` / `containers.grype_config_file`)
  applies them to `argus scan container` runs.

Sign-off is the approving review on the PR that changes this document or
either rule file. A rule change without that review should not merge.

## What is covered

| trivy rule | grype rule | Component | Affected code |
|---|---|---|---|
| CVE-2025-47913, CVE-2025-47914, CVE-2025-58181 | none (grype does not report x/crypto in gitleaks) | `golang.org/x/crypto@v0.35.0` | `x/crypto/ssh` and `x/crypto/ssh/agent` |
| CVE-2025-68121 | GO-2026-4337 | Go stdlib 1.24.11 | `crypto/tls` handshake (session resumption) |

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
it. That is the basis for treating these as not reachable.

Static call graphs miss reflection and cgo paths, so this is evidence for the
usage claim, not proof of it (see ADR-035). If Argus ever starts passing
gitleaks a remote URL or `--diagnostics`, these rules stop being true.

## Keeping it honest

- **Delete the rules when gitleaks ships a rebuild.** A gitleaks release
  built with Go >= 1.24.13 and `x/crypto` >= 0.52.0 clears every finding here.
  The rule files and this document should then be deleted, not carried
  forward.
- **Scoped to gitleaks, not to a Go version.** These used to be OpenVEX
  statements in `argus-cli.openvex.json`. OpenVEX names only a component
  (`pkg:golang/stdlib@1.24.11`), and neither trivy nor grype can tie a
  statement to one binary, so the statements hid the same CVEs in any Go
  binary built with those versions. The trivy `paths` and grype
  `package.location` fields scope each rule to `usr/local/bin/gitleaks`.
  Checked 2026-10-22 against `ghcr.io/huntridge-labs/argus/cli:1.12.8`: the
  same rules pointed at `usr/local/bin/actionlint` leave the gitleaks
  findings visible.
- **Path spelling differs per tool.** trivy `paths` have no leading slash
  (`usr/local/bin/gitleaks`); grype `location` has one
  (`/usr/local/bin/gitleaks`). A rule with the wrong spelling matches
  nothing.
- **ID scheme differs per tool.** trivy reports Go findings by CVE ID. grype
  reports them by GO- (or GHSA-) ID and lists the CVE only as a related
  vulnerability; a grype rule on the CVE ID does not match.
- **Ignored findings stay visible.** trivy runs with `--show-suppressed` and
  grype lists `ignoredMatches`, so the PR comment shows each ignored finding,
  with the reason from these files, in an "Ignored" table that does not count
  toward the totals.
- `tests/unit/test_cli_ignore_files.py` lints the scoping and spellings, and
  `scripts/ci/render_container_summary.py` fails the CLI container scan when
  a rule matched nothing, so a stale or misspelled rule cannot sit there
  doing nothing.
