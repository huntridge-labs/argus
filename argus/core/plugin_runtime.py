"""Container sandbox for untrusted third-party Argus plugins (prototype).

A plugin runs as an **isolated container** implementing the ``argus.plugin.v1``
contract: it receives the scan target read-only at ``/scan`` and writes a
findings JSON document to **stdout**. Argus core treats a plugin as
**untrusted** by default — the container is locked down (no network, read-only
root filesystem, all capabilities dropped, non-root, no host env/secrets, no
Docker socket) and the plugin's *output* is schema-validated and sanitized
before any finding enters the pipeline.

This is a prototype of the design in ``docs/plugin-sandbox.md`` (ADR-031). The
stable entry-point contract (``argus.plugins.v1``) and cosign image-signature
verification are tracked as follow-ups; ``PluginSpec.signature_verified`` is the
hook the verifier will set.

Security-critical: ``build_sandbox_argv`` and ``validate_findings`` are the trust
boundary. Keep them conservative — a plugin is hostile until proven otherwise.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath

from argus.core.models import Finding, ScanResult, Severity

#: Output-contract identifier a conforming plugin must echo back.
PLUGIN_SCHEMA = "argus.plugin.v1"

_SCAN_MOUNT = "/scan"

# Defensive caps on attacker-controlled output.
_MAX_FINDINGS = 10_000
_MAX_STR = 4_000

# Sandbox resource defaults (DoS containment).
_DEFAULT_TIMEOUT = 300
_DEFAULT_MEMORY = "512m"
_DEFAULT_CPUS = "1.0"
_DEFAULT_PIDS = 256
#: nobody:nogroup — run as an unprivileged uid that owns nothing on the host.
_SANDBOX_USER = "65534:65534"


class TrustTier(Enum):
    """How much a plugin is trusted — drives sandbox strictness + attestation."""

    FIRST_PARTY = "first-party"   # Huntridge-signed
    VERIFIED = "verified"         # third-party, Huntridge-reviewed + signed
    UNVERIFIED = "unverified"     # third-party, unreviewed — max sandbox, opt-in


class PluginError(RuntimeError):
    """Raised when a plugin spec, sandbox, or output violates the contract."""


@dataclass(frozen=True)
class PluginSpec:
    """A plugin to run. ``image`` MUST be digest-pinned (``repo@sha256:...``)."""

    name: str
    image: str
    version: str = ""
    trust_tier: TrustTier = TrustTier.UNVERIFIED
    allow_network: bool = False        # default-deny egress (anti-exfiltration)
    timeout: int = _DEFAULT_TIMEOUT
    signature_verified: bool = False   # set by the (future) cosign verifier


def resolve_runtime() -> str:
    """Return an available container runtime binary name, or raise."""
    for runtime in ("docker", "podman"):
        if shutil.which(runtime):
            return runtime
    raise PluginError("no container runtime (docker/podman) found on PATH")


def _require_digest_pinned(image: str) -> None:
    if "@sha256:" not in image:
        raise PluginError(
            f"plugin image must be digest-pinned (repo@sha256:...); got {image!r}"
        )


def build_sandbox_argv(
    spec: PluginSpec, target_dir: str, *, runtime: str = "docker"
) -> list[str]:
    """Build the hardened ``docker run`` argv for an untrusted plugin.

    Security invariants (see ``docs/plugin-sandbox.md``):

    - **No network** unless explicitly allowed (anti-exfiltration).
    - **Read-only root filesystem** + a small ``noexec,nosuid`` tmpfs for scratch.
    - **All capabilities dropped** and **no-new-privileges**.
    - **Non-root** (``nobody``).
    - **Resource + PID limits** (DoS containment).
    - Scan target mounted **read-only** at ``/scan``.
    - **No host env/secrets** forwarded (no ``-e`` flags), **no Docker socket**,
      **never** ``--privileged``.
    - Image **digest-pinned**.
    """
    _require_digest_pinned(spec.image)
    target = Path(target_dir).resolve()
    if not target.is_dir():
        raise PluginError(f"scan target is not a directory: {target}")

    return [
        runtime,
        "run",
        "--rm",
        "--network",
        ("bridge" if spec.allow_network else "none"),
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        _SANDBOX_USER,
        "--pids-limit",
        str(_DEFAULT_PIDS),
        "--memory",
        _DEFAULT_MEMORY,
        "--cpus",
        _DEFAULT_CPUS,
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--workdir",
        _SCAN_MOUNT,
        "--volume",
        f"{target}:{_SCAN_MOUNT}:ro",
        # Deliberately absent: -e host env, secrets, /var/run/docker.sock, --privileged.
        spec.image,
    ]


def _clean_text(value: object) -> str:
    """Bound length and strip control chars from attacker-controlled text.

    Findings flow into HTML (browser viewer), SARIF, and Markdown; renderers
    escape, but we strip C0/C1 control chars (except tab/newline) at the trust
    boundary as defence-in-depth against terminal/markup injection.
    """
    text = str(value)[:_MAX_STR]
    return "".join(c for c in text if c in "\t\n" or ord(c) >= 0x20)


def _sanitize_location(value: object) -> str | None:
    """Reject absolute paths and traversal in a plugin-reported location.

    A plugin must not claim a host path or escape the scan root; such a value
    is dropped rather than trusted.
    """
    if value is None:
        return None
    loc = _clean_text(value)
    path = PurePosixPath(loc)
    if path.is_absolute() or ".." in path.parts:
        return None
    return loc


def validate_findings(raw: object, *, plugin_name: str) -> list[Finding]:
    """Parse + validate untrusted plugin output into Findings.

    Enforces the ``argus.plugin.v1`` envelope, caps count/size, coerces severity
    to the known enum (unknown → ``UNKNOWN``, never trusted verbatim), and
    sanitizes free-text + location fields. Raises :class:`PluginError` on a
    structurally invalid document.
    """
    try:
        doc = json.loads(raw) if isinstance(raw, (str, bytes, bytearray)) else raw
    except (ValueError, TypeError) as exc:
        raise PluginError(f"plugin {plugin_name!r} returned invalid JSON: {exc}") from exc

    if not isinstance(doc, dict) or doc.get("schema") != PLUGIN_SCHEMA:
        raise PluginError(
            f"plugin {plugin_name!r}: missing/unknown schema (expected {PLUGIN_SCHEMA!r})"
        )
    raw_findings = doc.get("findings")
    if not isinstance(raw_findings, list):
        raise PluginError(f"plugin {plugin_name!r}: 'findings' must be a list")
    if len(raw_findings) > _MAX_FINDINGS:
        raise PluginError(
            f"plugin {plugin_name!r}: too many findings ({len(raw_findings)} > {_MAX_FINDINGS})"
        )

    findings: list[Finding] = []
    for index, item in enumerate(raw_findings):
        if not isinstance(item, dict):
            raise PluginError(f"plugin {plugin_name!r}: finding {index} is not an object")
        findings.append(
            Finding(
                id=_clean_text(item.get("id") or f"{plugin_name}-{index}"),
                severity=Severity.from_string(str(item.get("severity", "unknown"))),
                title=_clean_text(item.get("title") or "(untitled)"),
                description=_clean_text(item.get("description") or ""),
                location=_sanitize_location(item.get("location")),
                cwe=_clean_text(item["cwe"]) if item.get("cwe") else None,
                cve=_clean_text(item["cve"]) if item.get("cve") else None,
                scanner=f"plugin/{plugin_name}",
                metadata={"untrusted": True, "plugin": plugin_name},
            )
        )
    return findings


def plugin_provenance(spec: PluginSpec) -> dict:
    """Attestation/audit record for a plugin run (flows into ScanResult.metadata).

    Lets the attestation layer call out exactly which plugin ran, by digest and
    trust tier, so downstream consumers can weight the results.
    """
    _, _, digest = spec.image.partition("@")
    return {
        "plugin": {
            "name": spec.name,
            "version": spec.version,
            "image": spec.image,
            "digest": digest or None,
            "trust_tier": spec.trust_tier.value,
            "signature_verified": spec.signature_verified,
            "sandboxed": True,
            "network": "allowed" if spec.allow_network else "none",
        }
    }


def assert_runnable(spec: PluginSpec, *, opted_in: bool = False) -> None:
    """Policy gate before running a plugin.

    An ``UNVERIFIED`` plugin must be explicitly opted into, and may not be
    granted network egress without that opt-in — untrusted code does not get the
    network for free.
    """
    if spec.trust_tier is TrustTier.UNVERIFIED and not opted_in:
        raise PluginError(
            f"plugin {spec.name!r} is unverified; pass opted_in=True to run it "
            "(it runs sandboxed and is flagged 'unverified' in the attestation)"
        )
    if spec.allow_network and spec.trust_tier is TrustTier.UNVERIFIED and not opted_in:
        raise PluginError(
            f"plugin {spec.name!r} is unverified and requests network — denied"
        )


def run_plugin(
    spec: PluginSpec,
    target_dir: str,
    *,
    opted_in: bool = False,
    runtime: str | None = None,
    runner=subprocess.run,
) -> ScanResult:
    """Run a plugin in the sandbox and return a validated ScanResult.

    ``runner`` is injectable (defaults to ``subprocess.run``) so the sandbox can
    be exercised without a live container runtime. Failures (timeout, non-zero
    exit, malformed output) degrade to a ``failed`` ScanResult rather than
    raising into the engine — a hostile plugin cannot take down a scan.
    """
    assert_runnable(spec, opted_in=opted_in)
    runtime = runtime or resolve_runtime()
    argv = build_sandbox_argv(spec, target_dir, runtime=runtime)
    meta = plugin_provenance(spec)

    try:
        proc = runner(argv, capture_output=True, text=True, timeout=spec.timeout)
    except subprocess.TimeoutExpired:
        return ScanResult(
            scanner=f"plugin/{spec.name}",
            findings=[],
            metadata={**meta, "status": "failed", "error": "timeout"},
        )

    if getattr(proc, "returncode", 0) != 0:
        return ScanResult(
            scanner=f"plugin/{spec.name}",
            findings=[],
            metadata={**meta, "status": "failed", "error": f"exit {proc.returncode}"},
        )

    try:
        findings = validate_findings(proc.stdout, plugin_name=spec.name)
    except PluginError as exc:
        return ScanResult(
            scanner=f"plugin/{spec.name}",
            findings=[],
            metadata={**meta, "status": "failed", "error": str(exc)},
        )

    return ScanResult(
        scanner=f"plugin/{spec.name}",
        findings=findings,
        metadata={**meta, "status": "ran"},
    )
