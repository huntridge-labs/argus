module argus.test/govulncheck-fixture

go 1.21

// Pinned to a version with a KNOWN, REACHABLE advisory so the govulncheck
// E2E test has a deterministic finding to assert on:
//   GO-2022-1059 (CVE-2022-32149) — golang.org/x/text < 0.3.8, in
//   golang.org/x/text/language. main.go calls language.ParseAcceptLanguage,
//   which makes the vulnerable symbol reachable (not merely imported), so
//   govulncheck reports it as a reachable/actionable finding rather than the
//   INFO "[imported, not called]" tier. Do not bump this dependency.
require golang.org/x/text v0.3.7
