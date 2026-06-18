# Plugin sandbox — threat model & design

Argus can run **third-party plugins**. Because Argus is a security tool that
runs inside sensitive environments (and often with repo/credential access
nearby), a plugin is treated as **untrusted code** and executed in a locked-down
container. This document is the threat model and the security contract.

> Status: **prototype** — `argus.core.plugin_runtime` implements the sandbox and
> output validation (see [ADR-031](../.ai/decisions.yaml)). The stable
> entry-point contract (`argus.plugins.v1`) and cosign image-signature
> verification are follow-ups.

## Trust boundary

```
┌─────────────── Argus host (trusted) ───────────────┐
│  engine → plugin_runtime                            │
│     • builds hardened `docker run` argv             │
│     • validates + sanitizes the plugin's output     │
│     • records the plugin in the attestation         │
└───────────────┬────────────────────────────────────┘
                │  (only: scan target read-only @ /scan; findings JSON on stdout)
        ┌───────▼────────┐
        │ plugin container│  ← UNTRUSTED
        │  no net · ro fs │
        │  no caps · nobody│
        └─────────────────┘
```

Everything crossing the boundary is minimized: the plugin receives **only** the
scan target (read-only) and returns **only** a findings JSON document on stdout.
Nothing else — no network, no host filesystem, no env, no secrets.

## The contract (`argus.plugin.v1`)

- **Input:** the scan target is mounted read-only at `/scan` (the container's
  workdir). No arguments carry host paths or secrets.
- **Output:** a single JSON document on **stdout**:
  ```json
  {
    "schema": "argus.plugin.v1",
    "findings": [
      {"id": "...", "severity": "high", "title": "...", "description": "...",
       "location": "src/app.py:42", "cwe": "CWE-89", "cve": "CVE-..."}
    ]
  }
  ```
- Exit non-zero or malformed output → the run **degrades** to a failed result;
  it never crashes the scan.

## Sandbox hardening (enforced in `build_sandbox_argv`)

| Control | Flag | Why |
|---|---|---|
| No egress (default) | `--network none` | the single biggest anti-exfiltration control |
| Read-only rootfs | `--read-only` + `--tmpfs /tmp:rw,noexec,nosuid` | no tampering, no dropped executables |
| Drop privileges | `--cap-drop ALL`, `--security-opt no-new-privileges` | no capability abuse / setuid escalation |
| Non-root | `--user 65534:65534` (nobody) | owns nothing on the host |
| Resource caps | `--memory`, `--cpus`, `--pids-limit` | DoS containment |
| Read-only input | `-v <target>:/scan:ro` | plugin can read the code, not modify it |
| No host reach | **no `-e`**, **no `docker.sock`**, **never `--privileged`** | no secrets, no host control, no escape |
| Pinned image | `repo@sha256:...` required | no mutable-tag swap |

Network egress is **opt-in** per plugin and is **denied outright for unverified
plugins** unless the operator explicitly opts in.

## Untrusted output validation (`validate_findings`)

A plugin's output is attacker-controlled data that flows into SARIF, Markdown,
the browser viewer, and the PDF report — so it is validated and sanitized at the
boundary, not on render alone:

- Envelope + `schema` checked; `findings` must be a list; **count is capped**.
- **Severity is coerced** to the known enum (unknown → `UNKNOWN`); never trusted
  verbatim.
- Free-text fields are **length-bounded** and **stripped of control characters**
  (defence-in-depth vs terminal / Markdown / HTML injection).
- `location` is **rejected if absolute or contains `..`** — a plugin cannot
  claim a host path or escape the scan root.
- Every finding is tagged `metadata.untrusted = true` and `scanner = plugin/<name>`.

## Trust tiers

| Tier | Source | Sandbox | Attestation label | Run policy |
|---|---|---|---|---|
| `first-party` | Huntridge-signed | hardened | first-party | default |
| `verified` | third-party, Huntridge-reviewed + signed | hardened | verified | default |
| `unverified` | third-party, unreviewed | hardened (max) | **unverified** | **explicit opt-in**, no network |

Unverified plugins never run silently and are flagged in the attestation so
downstream consumers can weight the results.

## Attestation & audit

Every plugin run is recorded (`plugin_provenance`) into the scan results and
flows into the in-toto / OpenVEX cosign attestation, extending the existing
toolchain-provenance block:

```json
{"plugin": {"name": "...", "version": "...", "image": "repo@sha256:...",
            "digest": "sha256:...", "trust_tier": "unverified",
            "signature_verified": false, "sandboxed": true, "network": "none"}}
```

A consumer of the attestation can therefore see *exactly* which plugins ran, by
digest and trust tier, and whether any were unverified.

## Image supply chain

Plugin images must be **digest-pinned**; the planned cosign step verifies the
image signature before run (mirroring how Argus already cosign-verifies its own
images and digest-pins third-party ones). `PluginSpec.signature_verified` is the
hook the verifier sets, and it is surfaced in the attestation.

## Residual risks (be honest)

- **Container escape** is the ultimate risk; the hardening above closes the
  common vectors (privileged, socket, caps, root) but a kernel 0-day could still
  defeat namespace isolation. Run untrusted plugins on hosts you can afford to
  treat as compromised, or on a microVM runtime (gVisor / Kata) for a stronger
  boundary — a future option, not assumed here.
- **DoS** is contained (limits + timeout) but not eliminated.
- **Malicious findings** are validated/sanitized, but renderers must still
  escape output — this is defence-in-depth, not a substitute for output encoding.
- Network-allowed plugins can exfiltrate by definition — only grant it to
  trusted tiers with a clear reason.
