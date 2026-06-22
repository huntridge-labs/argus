# Security Policy

How argus handles user secrets, container image provenance, and the
threat model it defends against. Companion to
[`docs/config-reference.md`](config-reference.md) — where credentials
go in config.

---

## TL;DR

| Concern | What argus does |
|---|---|
| Credentials in `argus.yml` | Three forms accepted (literal / `<field>_env` / CLI stdin). Validator warns at config-load if a literal looks like a vendor secret (gh\*, AKIA, AIza, etc.). |
| Credential values on `docker run` argv | Never. The engine passes `-e NAME` (no value); values live in the python subprocess's private env, inherited by docker by name. |
| Credential values in logs / audit / findings | Never. `secrets.py` logs field *names* only. `Finding.__post_init__` redacts vendor-prefix tokens (ADR-022). Audit trail captures structured metadata, not env dicts or command lines. |
| Container image provenance | Argus-owned images are cosign-verified (Sigstore keyless). Third-party images with `@sha256:` digest pins are verified by Docker's pull-time content-hash match. Tag-only third-party images surface a single WARNING per scan. |
| Scanner output that contains literal secrets (e.g. gitleaks match field) | Per-scanner redaction at parse time + a pattern-based safety net at `Finding` construction (ADR-022). |

If you're configuring argus, the practical advice is one line: **use
`<field>_env: ENV_VAR_NAME` for credentials, set the env var in the
runner's environment, never paste literals into VCS-tracked YAML.**

---

## Threat model

### What argus defends against

1. **Local users on the scan host scraping argv.** `ps -ef`,
   `/proc/<pid>/cmdline`, `docker inspect` — all of these expose
   process argv to any local user. Argus passes credentials by name
   only (`-e NAME`); values live in a subprocess env dict accessible
   only to the python process and its docker child.
2. **VCS-tracked YAML leaking credentials.** The validator warns on
   vendor-shaped literals at config-load time. The `<field>_env`
   pattern keeps credential *values* out of the file entirely.
3. **Log files / audit trail leaking credentials.** `argus.core.secrets`
   never logs values. `argus/audit/logger.py` and
   `argus/audit/manifest.py` do not capture command lines or env
   dicts. The engine's debug log of the docker invocation joins
   `container_args` (post-image scanner argv) — the `-e NAME` flags
   live in `docker_cmd` before the image and are not part of that
   log.
4. **Scanner output echoing literal secrets into findings.** The
   redact module ([`argus/core/redact.py`](../argus/core/redact.py))
   runs at `Finding.__post_init__`, scrubbing vendor-prefix tokens
   from `title`, `description`, and every string in `metadata`
   before downstream consumers see them. Per-scanner first-pass
   redaction sits upstream of this safety net for known leak fields
   (gitleaks's `Match`, bandit's B105/106/107 hardcoded-credential
   `issue_text`, etc.).
5. **Supply-chain attacks via tampered argus-owned images.** The 4
   container images argus publishes (`scanner-bandit`,
   `scanner-opengrep`, `scanner-supply-chain`, `cli`) are
   cosign-signed at release with keyless Sigstore. Argus verifies
   each pull against the publishing workflow's certificate identity
   and the GitHub Actions OIDC issuer. Verification failure aborts
   the scanner.
6. **Tracebacks / crash dumps leaking values.** Env vars are set at
   process-spawn time, not on the python call stack — exceptions
   raised inside scanners don't capture them in tracebacks.

### What argus does NOT defend against

These are out of scope. If your threat model includes them, argus is
one of several layers and you'll need additional controls.

1. **Root or same-uid attacker on the scan host.** A user with
   `/proc/<pid>/environ` read access can extract the subprocess env
   directly. This is a strictly tighter access set than what `ps`
   gives the average local user, but not zero — root, or another
   process running as the same uid, can still see the env.
2. **Compromised scanner image.** If `aquasec/trivy@sha256:...` is
   itself malicious (e.g., upstream account compromise), argus hands
   it the credentials we resolved for registry auth. The container
   has full read on `/workspace` and any env vars we passed. We pin
   third-party scanner versions via Dependabot/Renovate but cannot
   independently verify upstream image attestations — that's an
   upstream trust problem.
3. **Malicious YAML literal that doesn't match a vendor prefix.**
   The validator's "looks like a literal secret" heuristic catches
   vendor-prefixed tokens (`gh*`, `AKIA*`, `AIza*`, `glpat-*`,
   `sk_live_*`, `npm_*`, `xox*-`). It does not catch generic
   high-entropy strings, basic-auth passwords like `hunter2`, or
   custom-format internal tokens. Those still work via the back-compat
   literal path but with no warning — gitleaks's domain, not ours.
4. **Network-level interception of credentials.** Argus passes
   credentials to scanners which may transmit them to registries
   over HTTPS. We don't pin TLS certs or enforce mTLS at the argus
   layer; that's the underlying tool's responsibility.
5. **Memory scraping after credential resolution.** Python strings
   are immutable and remain in memory until GC. Argus does not zero
   credential strings explicitly — this is a fundamental Python
   limitation, not unique to argus.
6. **Renovate/Dependabot account compromise.** Image updates flow
   through these automation paths. Verification on pull catches
   tampering of *argus-owned* images. Third-party image updates rely
   on Renovate's signature verification (where available) and digest
   pinning (where we've migrated to it).

---

## Where credentials can live — precedence

Highest precedence first; the first available path wins.

### 1. CLI stdin (`--*-password-stdin`)

```bash
echo "$REGISTRY_TOKEN"   | argus scan --registry-password-stdin  --config argus.yml
echo "$APP_PASSWORD"     | argus scan zap --zap-auth-password-stdin --target https://app
```

Mirrors `docker login --password-stdin`. The value:

- Is **read once** from stdin (a single trailing newline is stripped;
  multi-line tokens like PEM contents are preserved exactly).
- Lives in a process-local slot registry in
  [`argus/core/secrets.py`](../argus/core/secrets.py); scanners pull
  it at scan time via `get_stdin_override(slot)`.
- **Never** reaches the per-scanner config dict, so it cannot leak
  into `argus-audit.json` or `argus.log`.
- Has highest precedence — overrides both `<field>_env` and literal
  `<field>` in `argus.yml`.

At most one `--*-password-stdin` flag per invocation (stdin is a
single stream). Argus errors out with a usage hint if more than one is
set, if stdin is a TTY, or if stdin is empty.

### 2. Env-var name reference (`<field>_env: ENV_VAR_NAME`)

```yaml
scanners:
  container:
    registry_username_env: REGISTRY_USER
    registry_password_env: REGISTRY_TOKEN
  zap:
    auth:
      username_env: ZAP_APP_USER
      password_env: ZAP_APP_PASSWORD
```

- The YAML holds only the *name* of an env var. The actual value
  lives in the runner's environment.
- Argus reads `os.environ[NAME]` at scan time.
- Recommended pattern for CI workflows — wire `${{ secrets.X }}` (on
  GitHub) or equivalent into the runner's `env:` block, then
  reference the env-var name from `argus.yml`.

```yaml
# GitHub Actions example
- name: Run argus scan
  env:
    REGISTRY_USER: ${{ secrets.REGISTRY_USER }}
    REGISTRY_TOKEN: ${{ secrets.REGISTRY_TOKEN }}
  run: argus scan --config argus.yml
```

Validator rules:
- `<field>_env` must be a valid POSIX shell identifier
  (`[A-Za-z_][A-Za-z0-9_]*`). Invalid names are a config error.
- Setting *both* `<field>` and `<field>_env` is a warning; the
  `_env` form takes precedence.
- An unset env-var-name reference resolves to `None`. Argus logs a
  WARNING and skips the credential — the scan still runs (graceful
  degradation; useful for optional credentials).

### 3. Literal `<field>: "value"` (back-compat — discouraged)

```yaml
scanners:
  container:
    registry_password: "literal-value-not-recommended"
```

Still accepted, but:

- The validator warns at config-load time if the value matches a
  known vendor secret prefix (`gh*`, `AKIA*`, `AIza*`, etc.).
- The literal is visible to anyone reading the YAML file — including
  anyone with VCS read access.

This path exists for backward compatibility. New configurations
should use `<field>_env` exclusively.

---

## Container image provenance

Every image argus pulls goes through one of three verification paths
before the scanner is allowed to run.

### Argus-owned images (cosign verify, fail-on-failure)

Four images are published from this repository to
`ghcr.io/huntridge-labs/argus/*`:

- `scanner-bandit`
- `scanner-opengrep`
- `scanner-supply-chain`
- `cli`

They are signed at release time via [keyless Sigstore][sigstore] —
the publishing GitHub Actions workflow obtains a short-lived
certificate from Fulcio, signs the image, and the signature lands in
the Rekor transparency log.

At pull time, argus runs:

```
cosign verify ghcr.io/huntridge-labs/argus/scanner-bandit:1.6.0 \
  --certificate-identity-regexp '^https://github\.com/huntridge-labs/argus/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

If verification fails, argus aborts the scanner with a fatal error —
the scan does not run. The user gets the cosign output (truncated to
500 chars) so they can diagnose: an unsigned tag, a workflow change
that hasn't been re-signed, network access to Rekor blocked, etc.

If the cosign binary is missing on PATH and verification is enabled,
argus fails up front with an install hint.

### Third-party images with `@sha256:` digest pin (trust-by-content)

```yaml
# Example digest-pinned image in argus/containers.py:
"trivy": "aquasec/trivy@sha256:abcdef..."
```

Docker enforces the digest match at pull time — if the image's
content hash doesn't equal the pinned digest, the pull itself fails.
This is cryptographically equivalent to a signature check against a
fixed identity, with no external trust roots needed (no Sigstore /
Rekor round-trip).

Argus runs no cosign call for these images; the pull is the
verification.

### Third-party images with tag-only pin (warn-once)

```yaml
# Most third-party images today look like this:
"trivy": "aquasec/trivy:0.70.0"
```

A tag pin is mutable — `aquasec/trivy:0.70.0` today resolves to one
digest; tomorrow it could resolve to another if the publisher
re-tags. Argus pulls these images as-is (no extra verification
possible without a signing contract with the upstream publisher) and
emits a single WARNING per scan run listing all tag-pinned images.

We're migrating third-party images to digest pins in
`argus/containers.py` — Renovate keeps the digests current.

### Opting out: air-gapped environments

Environments without network access to Sigstore / Rekor can't run
cosign verify. Disable signature checking wholesale:

```yaml
# argus.yml
execution:
  verify_image_signatures: false
```

This skips the argus-owned image cosign verify path. Third-party
digest-pin verification (which is just Docker's pull-time content
hash check) continues to work because it has no external network
dependency.

### Recorded in the results (toolchain provenance)

Verification above happens at pull time and *gates the scan*. Argus also
**records** the outcome in `argus-results.json` under a top-level `toolchain`
block, so a consumer can confirm *which* scanner images produced the findings
and whether they were genuine published tooling — defending against someone
who clones the repo, modifies a `Dockerfile`, builds the scanner images
locally, and scans (their images won't match our published digests):

```json
"toolchain": {
  "images": [
    {
      "image": "ghcr.io/huntridge-labs/argus/scanner-bandit:1.6.0@sha256:…",
      "digest": "sha256:…",
      "verification": "verified_cosign",
      "argus_owned": true,
      "digest_matches_published_pin": true
    }
  ],
  "argus_images_all_verified": true,
  "warnings": []
}
```

- `digest_matches_published_pin` compares the image's content digest against
  the digests Argus publishes in `argus/containers.py` — by **content**, so a
  same-content registry mirror still matches while a rebuilt/modified image
  does not.
- `argus_images_all_verified` is `true` only when every argus-owned image
  pulled was signature/digest verified **and** matched a published pin;
  `false` if any failed or mismatched (with a `warnings` entry); `null` when no
  argus-owned image was involved (so verification is never *implied*).
- The block reflects **container pulls only**. An all-local-binary run
  (`execution.backend: local`, or a tool on `PATH`) pulls nothing, so no
  `toolchain` block is emitted — its absence means "no container toolchain was
  recorded," not "verified."

Recording is the *precondition* for verifiable provenance; signing the whole
package (`cosign attest`, planned) is what makes it tamper-evident against a
hostile runner. This is the "scanned *with what*" half of attestation —
complementary to the scanned-image content digest ("scanned *what*"). See the
[attestation epic](https://github.com/huntridge-labs/argus/issues/242).

### Signing the attestation (cosign, opt-in)

Recording provenance lets a *trusted-runner* verifier check a package; it does
not stop a hostile runner from forging the JSON. Enabling
`reporting.attest: true` makes the provenance **tamper-evident**: argus wraps
the OpenVEX predicate in an [in-toto Statement][in-toto] — `subject` = the
scanned image content digests (#237) + the repo commit — and signs it with
**keyless cosign** (a short-lived Fulcio cert via ambient OIDC, the same
mechanism the release workflow uses to sign images; no key to manage).

Two artifacts are produced in the output dir:

- `argus-attestation.intoto.json` — the unsigned statement (always written, so
  it's inspectable even where cosign/OIDC is absent).
- `argus-attestation.bundle` — the cosign `sign-blob` signature bundle for the
  statement (**standalone** mode — works for locally-built images and repo
  scans alike).

And, for any scanned image that is a *pushed* registry ref, a
**registry-attached** attestation via `cosign attest` (verifiable directly off
the image).

```bash
# Standalone bundle — verify signature + Argus's signing identity:
cosign verify-blob \
  --bundle argus-attestation.bundle \
  --certificate-identity-regexp '^https://github\.com/huntridge-labs/argus/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  argus-attestation.intoto.json

# Registry-attached — verify the attestation on the image:
cosign verify-attestation --type 'https://openvex.dev/ns/v0.2.0' \
  --certificate-identity-regexp '^https://github\.com/huntridge-labs/argus/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/org/app@sha256:…
```

A verifier then confirms the deployed image digest matches a `subject`, and
that the scanner digests in the predicate's toolchain block match Argus's
published pins — closing the loop against substituted images *and* tampered
tooling. Keyless signing needs OIDC, so it runs in CI (`id-token: write`);
**off by default** (network + registry side effects). With cosign absent or no
OIDC, argus still writes the unsigned statement and logs that it wasn't signed.

[in-toto]: https://in-toto.io/

---

## Alert routing — paging and escalation

argus stays out of the paging-channel business. The composite
actions emit findings to:

- The job's stdout / step summary (always)
- A SARIF artifact (always)
- The PR as an aggregated comment when `post_pr_comment: true`
- The GitHub Security tab when `enable_code_security: true`

argus does **not** `@`-mention specific users, post directly to
Slack / PagerDuty / Opsgenie, or otherwise pick a notification
channel on the team's behalf. The 0.6.x `gitleaks_notify_user_list`
input that routed secret-detection events through GitHub
`@`-mentions was removed intentionally — `@`-mention escalation
gets noisy fast (transient false positives ping the whole security
team on every PR), is tightly coupled to GitHub-as-notification,
and doesn't compose with the alert pipelines most teams already
own.

If you need broader-than-PR-comment escalation, pipe argus output
into your existing alert system at the workflow level. SARIF and
`argus-results.json` are both stable schemas; one extra workflow
step is usually enough:

```yaml
- name: Run argus
  uses: huntridge-labs/argus/.github/actions/scanner-gitleaks@1.6.0
  id: scan
  with:
    enable_code_security: true
    fail_on_severity: high

- name: Page on-call (only on high-severity findings)
  if: failure() && steps.scan.outputs.high_count > 0
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_SECURITY_WEBHOOK }}
  run: |
    curl -X POST -H 'Content-Type: application/json' \
      -d @argus-results.json "$SLACK_WEBHOOK_URL"
```

This keeps the paging decision (who, when, how loud) owned by the
team's alerting config rather than the scanner's config.

---

## What argus doesn't cover (offline VM images)

argus is a source-code and **container-artifact** scanner. If
your OS arrives as a container (stock base image like
`ubuntu:24.04` / `alpine:3.19` / `redhat/ubi9`, or a multi-service
/ systemd-in-container bundle), argus's container scanner already
covers it: CVE scanning via Trivy + Grype, SBOM via Syft, declared
ports via the `exposure` sub-scanner, and (planned) service
enumeration via the `services` sub-scanner.

argus **does not** ship offline scanning for VM-shaped artifacts —
AWS AMIs, Azure VHDs, GCP disk images, on-prem VMware OVA/VMDK,
ISO files, or raw disk dumps. The operational profile
(libguestfs at hundreds of MB, Linux-only host, multi-minute scan
latency) fundamentally doesn't match argus's PR-CI / dev-loop
posture, and purpose-built tools already cover this space well.
This is an explicit non-goal — see [ADR-025](../../.ai/decisions.yaml).

If you need offline VM-image scanning, reach for these instead:

| Use case | Recommended tool |
|---|---|
| Offline mount + STIG/CIS-profile audit (any cloud, on-prem) | [OpenSCAP](https://www.open-scap.org/) (`oscap-vm` / `oscap-docker`) |
| AWS AMIs, no host install | [AWS Inspector v2](https://docs.aws.amazon.com/inspector/latest/user/scanning-ec2.html) |
| Azure VHDs / cloud workloads | [Microsoft Defender for Cloud](https://azure.microsoft.com/en-us/products/defender-for-cloud) |
| GCP disk images / cloud workloads | [GCP Security Command Center](https://cloud.google.com/security-command-center) |
| CIS-benchmark compliance | [CIS-CAT](https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro) (free tier; commercial for prod use) |
| Lighter offline audit on a mounted root filesystem | [Lynis](https://cisofy.com/lynis/) |

Note: this is about the **artifact shape**, not the OS itself.
argus scans `ubuntu:24.04` (container) fine; argus is not the right
tool for the same OS packaged as an AMI. If a Packer pipeline
produces both — scan the container artifact with argus, and the
AMI with one of the tools above.

---

## Reporting a vulnerability

Security issues with argus itself (the CLI, SDK, MCP server, or
composite actions) should be reported via
[GitHub Security Advisories][gh-sa] on the
`huntridge-labs/argus` repository. Do not file a public issue.

For vulnerabilities in the scanners argus wraps (Trivy, Grype, ZAP,
etc.), report upstream to the respective project.

[sigstore]: https://docs.sigstore.dev/cosign/overview/
[gh-sa]: https://github.com/huntridge-labs/argus/security/advisories/new
