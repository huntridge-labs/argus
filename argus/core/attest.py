"""Sign the scan attestation (issue #241, epic #242).

The capstone of the attestation work. #237 records *what was scanned* (target
image content digests) and #240 records *what scanned it* (toolchain
provenance); this module wraps the OpenVEX predicate Argus already emits in an
in-toto Statement whose subjects name the scanned artifacts, and signs it with
cosign — keyless (CI OIDC), opt-in — so the recorded provenance becomes
*tamper-evident* rather than merely informational.

Two distribution modes are produced when enabled:

* **standalone** — an in-toto Statement (subject = target image digests +
  repo commit; predicate = the OpenVEX doc) is written to the output dir and
  signed with ``cosign sign-blob`` into a bundle. Works for locally-built
  images, pushed images, and repo/SAST scans alike. Verify with
  ``cosign verify-blob --bundle …``.
* **registry-attached** — for each scanned image that is a *pushed* registry
  ref, ``cosign attest --predicate <openvex> --type <openvex-uri>
  <image>@<digest>`` attaches the signed attestation to the image. Verify with
  ``cosign verify-attestation``.

Opt-in via ``reporting.attest`` (default off — signing has network + registry
side effects). No-op with a clear status when disabled, when cosign isn't on
PATH, or when there's nothing to bind to. The unsigned in-toto Statement is
always written when enabled, so the attestation is inspectable even where
cosign / OIDC is unavailable (e.g. local runs).

Signing is keyless: cosign obtains a short-lived Fulcio cert via ambient OIDC
(GitHub Actions ``id-token: write``), mirroring the release workflow's image
signing — there is no signing key to manage. The live keyless round-trip
requires OIDC and is exercised in CI; unit tests drive an injected
``cosign_runner`` and assert the argv + gating behaviour.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Optional

from argus.core.models import ScanSummary

INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
OPENVEX_PREDICATE_TYPE = "https://openvex.dev/ns/v0.2.0"

STATEMENT_FILENAME = "argus-attestation.intoto.json"
BUNDLE_FILENAME = "argus-attestation.bundle"
PREDICATE_FILENAME = "argus-attestation.openvex.json"


def _default_cosign_runner(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)


def _image_subjects(summary: ScanSummary) -> list[dict]:
    """in-toto subjects for the scanned container images (#237).

    One entry per unique (image-name, digest) carried in finding metadata.
    The repo-relative tag is dropped from the name; the content digest is the
    binding.
    """
    seen: dict[tuple, dict] = {}
    for result in summary.results:
        for finding in result.findings:
            digest = finding.metadata.get("image_digest")
            ref = finding.metadata.get("image_ref", "")
            if not digest or not digest.startswith("sha256:"):
                continue
            name = ref.split("@", 1)[0].rsplit(":", 1)[0] if ref else "image"
            key = (name, digest)
            if key not in seen:
                seen[key] = {
                    "name": name,
                    "digest": {"sha256": digest.split(":", 1)[1]},
                }
    return [seen[k] for k in sorted(seen)]


def _commit_subject(summary: ScanSummary) -> Optional[dict]:
    """in-toto subject for the repo commit the scan saw (from scan_context)."""
    ctx = summary.scan_context
    sha = getattr(ctx, "commit_sha", "") if ctx else ""
    if not sha:
        return None
    return {"name": "git-commit", "digest": {"gitCommit": sha}}


def build_subjects(summary: ScanSummary) -> list[dict]:
    """Everything the attestation binds to: scanned image digests + commit."""
    subjects = _image_subjects(summary)
    commit = _commit_subject(summary)
    if commit:
        subjects.append(commit)
    return subjects


def build_statement(openvex_doc: dict, subjects: list[dict]) -> dict:
    """Wrap the OpenVEX predicate in an in-toto Statement v1."""
    return {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": OPENVEX_PREDICATE_TYPE,
        "predicate": openvex_doc,
    }


def pushed_image_refs(summary: ScanSummary) -> list[str]:
    """Scanned images that look like *pushed* registry refs (host + digest).

    Only these can carry a registry-attached attestation; a bare local tag
    (``app:scan-<sha>``) has no registry to attach to and is covered by the
    standalone bundle instead. Conservative: requires a registry-host-shaped
    first path component (contains ``.`` or ``:``) and a known digest.
    """
    refs: dict[str, str] = {}
    for result in summary.results:
        for finding in result.findings:
            digest = finding.metadata.get("image_digest", "")
            ref = finding.metadata.get("image_ref", "")
            if not ref or not digest.startswith("sha256:"):
                continue
            repo = ref.split("@", 1)[0].rsplit(":", 1)[0]
            host = repo.split("/", 1)[0]
            if "/" not in repo or not ("." in host or ":" in host):
                continue  # bare/local name — no registry to attach to
            refs[repo] = f"{repo}@{digest}"
    return [refs[k] for k in sorted(refs)]


def attest_scan(
    summary: ScanSummary,
    output_dir: str | Path,
    *,
    enabled: bool,
    cosign_runner: Optional[Callable[[list[str]], subprocess.CompletedProcess]] = None,
) -> dict:
    """Build + sign the scan attestation. Returns a status dict (never raises).

    Status values: ``disabled``, ``skipped`` (nothing to bind to),
    ``unsigned`` (statement written, cosign unavailable), ``signed``, or
    ``sign_failed``.
    """
    if not enabled:
        return {"status": "disabled"}

    subjects = build_subjects(summary)
    if not subjects:
        return {
            "status": "skipped",
            "reason": "no image digest or commit to bind the attestation to",
        }

    # Build the OpenVEX predicate from the same logic the reporter uses.
    from argus.reporters.openvex import OpenVexReporter
    openvex_doc = OpenVexReporter()._build(summary)
    statement = build_statement(openvex_doc, subjects)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    statement_path = out / STATEMENT_FILENAME
    statement_path.write_text(
        json.dumps(statement, indent=2) + "\n", encoding="utf-8",
    )
    predicate_path = out / PREDICATE_FILENAME
    predicate_path.write_text(
        json.dumps(openvex_doc, indent=2) + "\n", encoding="utf-8",
    )

    result: dict = {
        "status": "unsigned",
        "statement": str(statement_path),
        "subjects": len(subjects),
        "signed": [],
    }

    if cosign_runner is None:
        if shutil.which("cosign") is None:
            result["reason"] = (
                "cosign not on PATH — wrote the unsigned in-toto statement "
                "only. Install cosign and run in a context with OIDC "
                "(e.g. CI with id-token: write) to sign."
            )
            return result
        cosign_runner = _default_cosign_runner

    signed: list[dict] = []
    failures: list[str] = []

    # Standalone: keyless sign-blob over the in-toto statement → bundle.
    bundle_path = out / BUNDLE_FILENAME
    try:
        rc = cosign_runner([
            "cosign", "sign-blob", "--yes",
            "--bundle", str(bundle_path), str(statement_path),
        ])
        if rc.returncode == 0:
            signed.append({"mode": "standalone", "bundle": str(bundle_path)})
        else:
            failures.append(f"standalone sign-blob exited {rc.returncode}")
    except (OSError, subprocess.SubprocessError) as exc:
        failures.append(f"standalone sign-blob: {exc}")

    # Registry-attached: keyless attest for each pushed image ref.
    for ref in pushed_image_refs(summary):
        try:
            rc = cosign_runner([
                "cosign", "attest", "--yes",
                "--predicate", str(predicate_path),
                "--type", OPENVEX_PREDICATE_TYPE,
                ref,
            ])
            if rc.returncode == 0:
                signed.append({"mode": "registry", "image": ref})
            else:
                failures.append(f"attest {ref} exited {rc.returncode}")
        except (OSError, subprocess.SubprocessError) as exc:
            failures.append(f"attest {ref}: {exc}")

    result["signed"] = signed
    if failures:
        result["failures"] = failures
    result["status"] = "signed" if signed else "sign_failed"
    return result
