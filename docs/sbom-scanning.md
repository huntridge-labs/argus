<div align=center>

# SBOM Scanning

Scan a pre-built SBOM for known vulnerabilities with `argus scan --sbom`.

</div>

## Overview

`argus scan --sbom PATH` hands an SBOM (or every SBOM in a directory) to the SBOM-capable scanners: osv-scanner, grype and trivy. Filesystem scanners are skipped, since there is no source tree to scan.

```bash
argus scan --sbom image.spdx.json          # every SBOM-capable scanner
argus scan grype --sbom image.spdx.json    # one scanner
argus scan --sbom vendor-sboms/            # every SBOM under a directory
```

Supported formats: CycloneDX (JSON, XML), SPDX (JSON, tag-value) and Syft JSON. Argus sniffs the content, so file names don't matter.

## Incomplete results

A matcher can read an SBOM, fail to work out which operating system its packages belong to, and skip every OS package without an error. Its zero findings for those packages don't mean they're clean; they were never checked.

Argus checks for this on every SBOM-mode result. An OS package carries a `distro=` qualifier in its purl (for example `pkg:rpm/amzn/openssl-libs@3.0.8-1.amzn2023.0.3?distro=amzn-2023`). When the SBOM has OS packages and the matcher's own report shows it didn't evaluate them, the result is marked **incomplete**:

| Matcher | How Argus knows it skipped the OS packages |
|---------|---------------------------------------------|
| trivy | Its JSON report has no `os-pkgs` result |
| grype | Its JSON report names no distro grype supports, and no match is for an OS package |

An incomplete result is never a pass:

- The terminal and markdown reports show `Status: INCOMPLETE` and the reason, for example `trivy did not evaluate the SBOM's 103 OS package(s) (amzn-2023); it read the OS as 'none'`.
- `argus-results.json` has `"passed": false`, `"complete": false` and `"incomplete_scanners": [...]`. The scanner's result carries `"incomplete": true` and its metadata has `incomplete_reason`.
- SARIF adds an `error`-level `toolExecutionNotifications` entry (`argus/incomplete-scan`) to that scanner's run. JUnit adds an `incomplete` error testcase.
- `argus scan` exits **2**, with or without `--fail-on-scanner-error`. Findings at or above the severity threshold still exit 1 first.

### Known cases (pinned tools)

Measured against `amazonlinux:2023.1.20230705.0` with syft v1.54.1, trivy 0.76.0 and grype v0.120.1:

| SBOM | trivy | grype |
|------|-------|-------|
| syft SPDX JSON | incomplete (reads the OS as `none`) | 237 findings |
| syft CycloneDX JSON | incomplete (`amzn` is unsupported) | 237 findings |
| Syft JSON | fails: trivy can't read the format | 237 findings |
| trivy CycloneDX JSON | 504 findings | incomplete (can't map `amazon`) |
| trivy SPDX JSON | 504 findings | incomplete (can't map `amazon`) |

The fix is to scan with the matcher that reads the SBOM's generator: grype for syft SBOMs, trivy for trivy SBOMs.
