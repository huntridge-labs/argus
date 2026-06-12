"""Scanner-toolchain provenance for the attestation package (issue #240).

Records which scanner container images (and at what digests) produced a scan,
plus their supply-chain verification status, so a downstream consumer can tell
whether results came from genuine, published, cosign-verified Argus tooling or
from a rebuilt/modified local image. This is the "scanned *with what*" half of
provenance — complementary to the target-image digest binding (#237, "scanned
*what*").

It is built from the engine's per-image ``VerifyResult`` list, which only
covers container pulls. An all-local-binary run produces no verify results, so
``build_toolchain_provenance`` returns ``None`` — the absence is itself
informative (no container toolchain was recorded for the scan), and is *not*
silently reported as "verified".
"""

from __future__ import annotations

from typing import Optional

from argus.containers import CUSTOM_IMAGES
from argus.core.image_verify import VerifyResult, VerifyStatus, is_argus_owned

_VERIFIED = {VerifyStatus.VERIFIED_COSIGN, VerifyStatus.VERIFIED_DIGEST_PIN}


def _published_argus_digests() -> set[str]:
    """The ``sha256:...`` digests Argus publishes for its own images.

    A matching digest means the scanner image is byte-identical to what the
    release pipeline published — independent of registry host, so a mirror
    with the same content still matches while a rebuilt/modified image does
    not.
    """
    digests = set()
    for ref in CUSTOM_IMAGES.values():
        _, _, digest = ref.partition("@")
        if digest:
            digests.add(digest)
    return digests


def build_toolchain_provenance(
    verify_results: list[VerifyResult],
) -> Optional[dict]:
    """Summarize the scanner images that produced a scan + their verification.

    Returns ``None`` when no container image was verified (e.g. an
    all-local-binary run) so the output never implies a verification that
    didn't happen.
    """
    if not verify_results:
        return None

    published = _published_argus_digests()
    images: list[dict] = []
    warnings: list[str] = []
    argus_seen = False
    argus_all_ok = True
    seen: set[str] = set()

    for v in verify_results:
        # The same image can be verified once per scanner that uses it.
        if v.image in seen:
            continue
        seen.add(v.image)

        _, _, digest = v.image.partition("@")
        owned = is_argus_owned(v.image)
        verified = v.status in _VERIFIED
        entry: dict = {
            "image": v.image,
            "digest": digest,
            "verification": v.status.value,
            "argus_owned": owned,
        }

        if owned:
            argus_seen = True
            matches_pin = digest in published
            entry["digest_matches_published_pin"] = matches_pin
            if not verified:
                argus_all_ok = False
                warnings.append(
                    f"argus-owned scanner image '{v.image}' is not "
                    f"signature/digest verified ({v.status.value})"
                )
            if not matches_pin:
                argus_all_ok = False
                warnings.append(
                    f"argus-owned scanner image digest "
                    f"'{digest or '(none)'}' does not match any published "
                    f"release pin — rebuilt or overridden image?"
                )
        images.append(entry)

    return {
        "images": images,
        # True only when ≥1 argus-owned image was pulled AND every one
        # verified and matched a published pin. None when no argus-owned
        # image was involved — don't imply verification that didn't happen.
        "argus_images_all_verified": (argus_all_ok if argus_seen else None),
        "warnings": warnings,
    }
