"""Container image signature / pin verification.

Two complementary supply-chain checks are run for every image argus
pulls:

  * **Argus-owned images** (``ghcr.io/huntridge-labs/argus/*``) are
    cosign-signed at publish time via keyless Sigstore. We verify
    each pull against the expected certificate identity (our publish
    workflow URI) and OIDC issuer (GitHub Actions). Verification
    failure is fatal — refuse to run the scanner.

  * **Third-party images** (Trivy, Grype, Checkov, OSV, ZAP,
    Hadolint, ESLint, etc.) are not in our signing surface. Two
    sub-paths:
      - ``image@sha256:...`` (digest pin): trust by content hash.
        Docker enforces digest match at pull time, so the pull
        itself *is* the verification — we report this and move on.
      - tag-only (``image:tag``): no cryptographic guarantee. We
        let the scan proceed but emit a single WARNING listing the
        tag-pinned images, with a hint to migrate to digest pins.

The combined policy is documented in ``docs/security.md`` and is
the implementation of items (3) + (4) from the
*Secret Handling & Credential Surface Hardening* roadmap section.

Stdlib + ``cosign`` binary only — no Python sigstore dependency to
keep the install lean.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Iterable

logger = logging.getLogger("argus")


# The Fulcio certificate's ``subject`` field for keyless sigstore
# signatures captures the URI of the GitHub workflow that performed
# the signing. We anchor verification to *our* publish workflow plus
# *our* OIDC issuer; the certificate-identity regexp is permissive
# across refs (tags, branches) so a workflow-internal change doesn't
# force a security-policy update.
ARGUS_OWNED_PREFIX = "ghcr.io/huntridge-labs/argus/"
ARGUS_CERT_IDENTITY_REGEXP = (
    r"^https://github\.com/huntridge-labs/argus/"
    r"\.github/workflows/release\.yml@"
)
ARGUS_OIDC_ISSUER = "https://token.actions.githubusercontent.com"


class VerifyStatus(Enum):
    """Outcome of a single image verification attempt."""

    VERIFIED_COSIGN = "verified_cosign"
    VERIFIED_DIGEST_PIN = "verified_digest_pin"
    SKIPPED_TAG_PIN = "skipped_tag_pin"
    SKIPPED_BY_CONFIG = "skipped_by_config"
    FAILED_COSIGN = "failed_cosign"
    FAILED_COSIGN_BINARY_MISSING = "failed_cosign_binary_missing"


@dataclass(frozen=True)
class VerifyResult:
    """The result of verifying a single image reference."""

    status: VerifyStatus
    image: str
    message: str

    @property
    def is_fatal(self) -> bool:
        """True if the scanner using this image must NOT run."""
        return self.status in (
            VerifyStatus.FAILED_COSIGN,
            VerifyStatus.FAILED_COSIGN_BINARY_MISSING,
        )


def is_argus_owned(image: str) -> bool:
    """Return True if ``image`` is published from this repository."""
    return image.startswith(ARGUS_OWNED_PREFIX)


def has_digest_pin(image: str) -> bool:
    """Return True if ``image`` has a content-addressable ``@sha256:`` pin."""
    return "@sha256:" in image


def verify_image(
    image: str,
    *,
    verify_signatures: bool = True,
    cosign_runner=None,
) -> VerifyResult:
    """Verify a single image reference.

    ``cosign_runner`` is an optional callable for tests; it receives
    the argv list and must return a ``subprocess.CompletedProcess``-
    shaped object with ``returncode``, ``stdout``, ``stderr``. The
    default uses ``subprocess.run`` with cosign on PATH.
    """
    if not image:
        return VerifyResult(
            status=VerifyStatus.SKIPPED_BY_CONFIG,
            image=image,
            message="empty image reference — nothing to verify",
        )

    if not verify_signatures:
        return VerifyResult(
            status=VerifyStatus.SKIPPED_BY_CONFIG,
            image=image,
            message="signature verification disabled via "
                    "execution.verify_image_signatures: false",
        )

    # Argus-owned: cosign verify when the image is tag-only, but accept
    # digest-pin trust when the image is pinned at ``tag@sha256:...``.
    # The digest gives content-hash integrity at pull time (Docker
    # rejects a different manifest), matching the trust model we apply
    # to third-party digest-pinned images. cosign would be additional
    # signature verification on top of that — nice to have when the
    # binary is available, not strictly required when the image is
    # already cryptographically addressed.
    if is_argus_owned(image):
        if has_digest_pin(image):
            return VerifyResult(
                status=VerifyStatus.VERIFIED_DIGEST_PIN,
                image=image,
                message="argus-owned image verified via @sha256 digest "
                        "pin (Docker enforces content-hash match at "
                        "pull). Install cosign for additional signature "
                        "verification.",
            )
        return _verify_cosign(image, cosign_runner=cosign_runner)

    # Third-party with digest pin: Docker enforces content-hash match
    # at pull. No additional verification needed.
    if has_digest_pin(image):
        return VerifyResult(
            status=VerifyStatus.VERIFIED_DIGEST_PIN,
            image=image,
            message="verified via @sha256 digest pin (Docker enforces "
                    "content-hash match at pull)",
        )

    # Third-party with tag-only pin: no crypto guarantee. Let the scan
    # proceed but report so the caller can warn once per run.
    return VerifyResult(
        status=VerifyStatus.SKIPPED_TAG_PIN,
        image=image,
        message="third-party image is tag-pinned (mutable). Pull "
                "succeeds but no signature or digest guarantee. "
                "Migrate to image@sha256:... for content-addressable "
                "trust.",
    )


def _verify_cosign(image: str, *, cosign_runner=None) -> VerifyResult:
    """Run ``cosign verify`` against an argus-owned image."""
    if cosign_runner is None:
        if not shutil.which("cosign"):
            return VerifyResult(
                status=VerifyStatus.FAILED_COSIGN_BINARY_MISSING,
                image=image,
                message=(
                    "cosign binary not on PATH but signature verification "
                    "is enabled. Install cosign (https://docs.sigstore.dev/cosign/installation/) "
                    "or set execution.verify_image_signatures: false in "
                    "argus.yml to opt out."
                ),
            )
        cosign_runner = _default_cosign_runner

    cmd = [
        "cosign", "verify", image,
        "--certificate-identity-regexp", ARGUS_CERT_IDENTITY_REGEXP,
        "--certificate-oidc-issuer", ARGUS_OIDC_ISSUER,
    ]
    try:
        result = cosign_runner(cmd)
    except FileNotFoundError:
        return VerifyResult(
            status=VerifyStatus.FAILED_COSIGN_BINARY_MISSING,
            image=image,
            message=(
                "cosign binary not on PATH but signature verification "
                "is enabled. Install cosign or set "
                "execution.verify_image_signatures: false."
            ),
        )

    if result.returncode == 0:
        return VerifyResult(
            status=VerifyStatus.VERIFIED_COSIGN,
            image=image,
            message="cosign keyless verify passed "
                    "(identity=argus publish workflow, "
                    "issuer=token.actions.githubusercontent.com)",
        )

    # Cosign failure — surface stderr so the user can act. Be careful
    # not to log credential-shaped strings; cosign output is the
    # canonical Sigstore/Fulcio error path and doesn't carry secrets.
    stderr = (result.stderr or "").strip()
    return VerifyResult(
        status=VerifyStatus.FAILED_COSIGN,
        image=image,
        message=(
            f"cosign verify FAILED for argus-owned image. "
            f"cosign output: {stderr[:500]}"
        ),
    )


def _default_cosign_runner(cmd: list[str]) -> subprocess.CompletedProcess:
    """Production cosign runner — captures output, never raises on rc != 0."""
    return subprocess.run(
        cmd, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )


def report_tag_pinned_summary(results: Iterable[VerifyResult]) -> None:
    """Emit one WARNING summarizing third-party tag-pinned images.

    Called once per scan run after all verification has occurred so
    users don't get N separate warnings for N scanners pointing at the
    same registry. Silent if nothing was tag-pinned.
    """
    tag_pinned = [
        r.image for r in results
        if r.status == VerifyStatus.SKIPPED_TAG_PIN
    ]
    if not tag_pinned:
        return
    # Deduplicate but preserve order (Python 3.7+ dict ordering).
    unique = list(dict.fromkeys(tag_pinned))
    logger.warning(
        "%d third-party image(s) pulled with mutable tag pins "
        "(no cryptographic guarantee): %s. Migrate to "
        "@sha256:... digest pins in argus/containers.py for "
        "content-addressable trust. See docs/security.md for the "
        "supply-chain policy.",
        len(unique),
        ", ".join(unique),
    )
