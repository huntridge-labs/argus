"""Container image manifest for argus scanners.

All container image references are centralized here for:
1. Single-point version updates
2. Dependabot/Renovate tracking
3. Registry override support
4. DB cache volume mounts for persistent vulnerability databases
"""

import os
from pathlib import Path

# Official images from tool authors (used directly, not rebuilt by argus).
#
# Every entry is pinned to a ``tag@sha256:...`` digest reference so that
# Docker's pull-time content-hash check enforces the exact bytes we
# tested against — making the image content-addressable and tamper-
# evident regardless of whether the publisher re-tags the same tag
# later. This pairs with ``argus.core.image_verify``: third-party
# images with a digest pin take the ``VERIFIED_DIGEST_PIN`` path
# instead of the ``SKIPPED_TAG_PIN`` warn-only path, closing the
# supply-chain gap surfaced in the post-PR-146 audit.
#
# Renovate (.github/renovate.json) keeps both the tag and the digest current
# on a 7-day stability lag — when the upstream publisher cuts a new
# release, Renovate rewrites BOTH the version segment and the digest
# segment in a single PR.
OFFICIAL_IMAGES = {
    "trivy": "aquasec/trivy:0.72.0@sha256:cffe3f5161a47a6823fbd23d985795b3ed72a4c806da4c4df16266c02accdd6f",
    "grype": "anchore/grype:v0.116.1@sha256:1e71065c0a4cff3e6bd3b8add525ffac4343eb4971694eb90a31cf6d4d3e85db",
    "syft": "anchore/syft:v1.50.0@sha256:1288ea4c8b38767b4e620c1e312c8cb26b6e887a99b4f07ab6cd19fc6f225026",
    "gitleaks": "zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f",
    "clamav": "clamav/clamav:1.5.3@sha256:d06c1d6a451d616e1dd79b42f44c8c8c291bba9cf4e75ebc4d0e43c1c6dd87bb",
    "checkov": "bridgecrew/checkov:3.3.9@sha256:12a62da01af22654883aee3b9da18ba4297f123f5122663bf65235db37934144",
    # KICS (Checkmarx) multi-format IaC scanner. The upstream
    # ``checkmarx/kics`` repo tags ``:latest`` mutably (no semver release
    # tag per build), so the digest pin below is the content-hash gate
    # that protects us between Renovate-driven bumps — same pattern as
    # the eslint entry.
    "kics": "checkmarx/kics:latest@sha256:3e5a268eb8adda2e5a483c9359ddfc4cd520ab856a7076dc0b1d8784a37e2602",
    "osv-scanner": "ghcr.io/google/osv-scanner:v2.4.0@sha256:5116601dedc01c1c580eb92371883ec052fc4c13c3fbc109d621a63ac416d475",
    # Upstream re-pushed the 2.17.0 tag (2026-08); the old index digest
    # no longer verifies against the registry. Pin refreshed to the
    # tag's current index digest, verified via `docker manifest inspect`.
    "zap": "ghcr.io/zaproxy/zaproxy:2.17.0@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef",
    # promptfoo LLM red-team / eval. Opt-in scanner; requires provider
    # API keys + network at scan time. Pinned to an immutable version tag
    # + digest (Renovate-managed), like every other image here — the
    # publisher's ``:latest`` is mutable and silently drifts.
    "promptfoo": "ghcr.io/promptfoo/promptfoo:0.121.19@sha256:50d3a796710e4db7a5ede90bf27dc28146ef022a7ebb83914c5105608396fd96",
    "hadolint": "hadolint/hadolint:v2.15.1@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d",
    # lint-shell via shellcheck. The koalaman/shellcheck-alpine image is
    # the official multi-arch distribution (~3 MB). shellcheck is GPL-3.0
    # but runs container-isolated, so the licence never touches Argus.
    "shellcheck": "koalaman/shellcheck-alpine:stable@sha256:c82fe42504fbc9fc68f15d36638e5ee2324ebb8b94e96a3c4e395bf361c49183",
    # gosec — Go-native SAST. The securego/gosec image tags ``:latest``
    # mutably, so the digest pin below is the content-hash gate that
    # protects us between Renovate-driven bumps.
    "gosec": "securego/gosec:latest@sha256:2cf71ea78210c496c65e3a987576a9c8317b68e20f2960520b3f6f8f9f539be5",
    # lint-terraform docker fallbacks. terraform fmt/validate run via
    # the official Hashicorp image; tflint via its official image.
    "terraform": "hashicorp/terraform:1.15.8@sha256:7ae513256f7ce67879e218ae8593d6fbe216ec9e123abe6c94e4e10704857963",
    "tflint": "ghcr.io/terraform-linters/tflint:v0.64.0@sha256:1c595f42d794c32c45a6ea8b58655fd66433d4ca3b1bc631c574a48d120bd19f",
    # lint-javascript via eslint. pipelinecomponents/eslint is the most
    # widely-used multi-arch eslint image. The upstream tags by commit
    # SHA + ``:latest`` + ``:edge``, not semver, so the ``:latest`` tag
    # is mutable — the digest pin below is the content-hash gate that
    # protects us between Renovate-driven bumps.
    "eslint": "pipelinecomponents/eslint:latest@sha256:0927aae5ab372691f2ba100ad56bd026b297b263c2fa19287547c33ee74013dd",
}

# Custom images built and published by Argus to ghcr.io/huntridge-labs/argus/
# Versions managed by release-it regex bumper
CUSTOM_IMAGES = {
    "bandit": "ghcr.io/huntridge-labs/argus/scanner-bandit:1.12.1@sha256:a977d214e116311f0f859efbf82a1980bf9a414c00beb69729122483da400fe0",
    "semgrep": "ghcr.io/huntridge-labs/argus/scanner-opengrep:1.12.1@sha256:77278e057fd05181fdb8d47c3ad99ffbf0e1f5d59d27058f386b8fff4fb0567f",
    "supply-chain": "ghcr.io/huntridge-labs/argus/scanner-supply-chain:1.12.1@sha256:4ad14f2137af3feee79cca01fb4c80fc1355bd71a0225c516a715d304233a954",
    "cli": "ghcr.io/huntridge-labs/argus/cli:1.12.1@sha256:0bea0981702afd317eb23c7aef395762225a01d22341d5dc20a44b80d5a74a2f",
    # PRE-MERGE PREVIEW. The MUMPS scanner image is published from the
    # feat/scanner-m-mumps branch under the mutable ``mumps-preview`` tag
    # so testers can run ``argus scan mumps`` with zero local toolchain
    # ahead of the merge. Unlike the other entries this is a workstation
    # build (no cosign / SLSA attestations yet); on merge the release
    # pipeline rebuilds it multi-arch with attestations and release-it
    # rewrites this line to the versioned ``scanner-mumps:<version>`` tag
    # + release digest. The digest pin below is still the content-hash
    # gate the manifest check verifies.
    "mumps": "ghcr.io/huntridge-labs/argus/scanner-mumps:1.12.1@sha256:0a3f5fbc54b9e6f1ea7fde28a73ae6b0907a31517991838187cc944205471e71",
}


# Aliases for scanners whose name differs from the image key
_ALIASES = {
    "opengrep": "semgrep",
    "trivy-iac": "trivy",
    "osv": "osv-scanner",
}


def get_image(scanner_name: str) -> str:
    """Get the container image for a scanner.

    Handles aliases (e.g. opengrep → semgrep image, osv → osv-scanner image).
    """
    key = _ALIASES.get(scanner_name, scanner_name)
    return OFFICIAL_IMAGES.get(key, CUSTOM_IMAGES.get(key, ""))


def expected_version(container_image: str) -> str | None:
    """Extract the expected tool version from a container image tag.

    Parses the tag portion of ``registry/repo:tag`` (optionally suffixed
    with ``@sha256:...``) and strips a leading ``v`` prefix so that the
    result can be compared directly against the version string returned
    by a scanner's ``tool_version()`` method.

    Returns ``None`` when the image string is empty or has no tag.
    """
    if not container_image:
        return None
    # Strip the digest suffix first so ``tag@sha256:...`` parses to
    # ``tag`` rather than ``sha256`` (the old rsplit would split on
    # the wrong ``:`` and capture the digest hex instead of the tag).
    ref = container_image.split("@", 1)[0]
    if ":" not in ref:
        return None
    tag = ref.rsplit(":", 1)[1]
    return tag.lstrip("v") if tag else None


def get_expected_version(scanner_name: str) -> str | None:
    """Extract the pinned tool version from the container image tag for a scanner.

    Convenience wrapper that resolves the scanner name to its container
    image via :func:`get_image`, then delegates to :func:`expected_version`.
    """
    image = get_image(scanner_name)
    return expected_version(image)


# Scanner → container cache path mappings.
# Keys are resolved via _ALIASES (same as get_image), values are the
# absolute path inside the container where the tool stores its DB/cache.
#
# Per-scanner notes:
#   - trivy   (aquasec/trivy:0.70.0)         runs as root; ``/root/.cache/trivy`` is the
#                                            default DB location. Mount works for ``trivy``
#                                            (vuln scan); ``trivy-iac`` does not populate
#                                            the DB so the dir stays empty for that path.
#   - grype   (anchore/grype:v0.112.0)       runs as root; standard XDG cache dir.
#   - semgrep (opengrep) — runs as root; cache at ``/root/.semgrep`` (rules + metadata).
#   - checkov (bridgecrew/checkov:3.2.526)   runs as root; ``/root/.checkov`` mostly
#                                            holds telemetry / version-check metadata —
#                                            persistence here is low-value but harmless.
#
# Clamav is deliberately NOT listed here. The official ``clamav/clamav`` image runs as
# the unprivileged ``clamav`` system user, which can't write to a host-owned bind mount
# at ``/var/lib/clamav`` — freshclam then segfaults with "Can't create freshclam.dat"
# (issue #168-N). The clamav scanner now writes its DB to ``/tmp/clamav-db`` per-run via
# ``freshclam --datadir`` (see argus/scanners/clamav.py); there is nothing host-side to
# cache, so listing clamav here only re-triggered the segfault by re-mounting the bad path.
CACHE_MOUNTS: dict[str, str] = {
    "trivy": "/root/.cache/trivy",
    "grype": "/root/.cache/grype",
    "semgrep": "/root/.semgrep",
    "checkov": "/root/.checkov",
}


def _default_cache_root() -> Path:
    """Return the host-side cache root directory.

    Uses ``ARGUS_CACHE_DIR`` env var if set, otherwise a temporary
    directory (``$TMPDIR/argus-cache``).  The temp dir is non-intrusive —
    it persists across runs within a session but is cleaned on reboot,
    avoiding permanent disk consumption on the host.
    """
    env = os.environ.get("ARGUS_CACHE_DIR")
    if env:
        return Path(env)
    import tempfile
    return Path(tempfile.gettempdir()) / "argus-cache"


def get_cache_mount(scanner_name: str) -> tuple[Path, str] | None:
    """Return (host_path, container_path) for a scanner's DB cache.

    Returns ``None`` if the scanner has no known cache directory.
    The host directory is created lazily if it does not exist.
    """
    key = _ALIASES.get(scanner_name, scanner_name)
    container_path = CACHE_MOUNTS.get(key)
    if container_path is None:
        return None

    host_dir = _default_cache_root() / key
    host_dir.mkdir(parents=True, exist_ok=True)
    return (host_dir, container_path)
