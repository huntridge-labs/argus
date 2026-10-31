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
    "trivy": "aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c",
    "grype": "anchore/grype:v0.121.0@sha256:621d56d1d68106b787022c81546f7e0a36202a25d1239f0c20195fab8c16f7ea",
    "syft": "anchore/syft:v1.55.0@sha256:4cc92b64ca74ffca4c94d4c8fcc01f217731375300be14d0b6eeb2e82eaa110a",
    "gitleaks": "zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f",
    "clamav": "clamav/clamav:1.5.4@sha256:bda39705e291105049c3936e2803ac90b955172af8030f94f05dce1252df6c6d",
    "checkov": "bridgecrew/checkov:3.3.30@sha256:4b65e89f1fde292249fc0aa0d0db43302c036dfe39f7370b2d3517571082b894",
    # KICS (Checkmarx) multi-format IaC scanner. Pinned to a semver tag:
    # ``:latest`` moves on every upstream push (2026-10-21), which breaks
    # the tag@digest manifest check even when the digest is unchanged.
    "kics": "checkmarx/kics:v2.2.0@sha256:ef29dbac14b046b1ef65f3280646112e927a61781c5f01bca1aeb723e0b96003",
    "osv-scanner": "ghcr.io/google/osv-scanner:v2.5.1@sha256:8108ae94eadea5a02c9bec6e646909d5b790b44bd62d7f5b7f0b1d6d0ffc7734",
    # Upstream re-pushes the 2.17.0 tag on rebuilds (2026-08, 2026-10 twice),
    # so `manifest inspect` of tag@digest stops verifying even though the
    # pinned digest still pulls. check_container_images flags that on
    # purpose (confirm the vendor pushed it, then re-pin); platform reads
    # go through `container_runtime.manifest_ref` and ask about the digest
    # alone. Re-pinned 2026-10-19 to the 2026-10-16 "Release Main Docker"
    # rebuild (dispatched by maintainer thc202; same amd64/arm64 set).
    "zap": "ghcr.io/zaproxy/zaproxy:2.17.0@sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238",
    # promptfoo LLM red-team / eval. Opt-in scanner; requires provider
    # API keys + network at scan time. Pinned to an immutable version tag
    # + digest (Renovate-managed), like every other image here — the
    # publisher's ``:latest`` is mutable and silently drifts.
    "promptfoo": "ghcr.io/promptfoo/promptfoo:0.122.0@sha256:53d9faa8813d9eecdc91a65dbb3dbdd87dd9e9aab9a9900c5a2cda3276909206",
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
    "terraform": "hashicorp/terraform:1.17.0@sha256:4d1b496a256f2989bccdb04b9104a4ede97234b10fba90259e173e905ec4fb58",
    "tflint": "ghcr.io/terraform-linters/tflint:v0.64.0@sha256:1c595f42d794c32c45a6ea8b58655fd66433d4ca3b1bc631c574a48d120bd19f",
    # lint-javascript via eslint. pipelinecomponents/eslint is the most
    # widely-used multi-arch eslint image. The upstream tags by commit
    # SHA + ``:latest`` + ``:edge``, not semver, so the ``:latest`` tag
    # is mutable — the digest pin below is the content-hash gate that
    # protects us between Renovate-driven bumps.
    "eslint": "pipelinecomponents/eslint:latest@sha256:7dbb5afec3be359fa1024a4cc76efc243fb6ce1333a9c5ab216b2d5a9039203a",
}

# Custom images built and published by Argus to ghcr.io/huntridge-labs/argus/
# Versions managed by release-it regex bumper
CUSTOM_IMAGES = {
    "bandit": "ghcr.io/huntridge-labs/argus/scanner-bandit:1.14.1@sha256:f5c963e3e7154b1ee7aa848b44ee2e994f3bc5ec0d03a75e9d362ee6f00b4881",
    "semgrep": "ghcr.io/huntridge-labs/argus/scanner-opengrep:1.14.1@sha256:e1126f354e3b67d11d7290b3fb54243a5234cf713c98f5dc8c94a9291892cb19",
    "supply-chain": "ghcr.io/huntridge-labs/argus/scanner-supply-chain:1.14.1@sha256:9a7094f8cefb8b1719279ab0cd3a94edbcab116d836dd59cf96b965729e06392",
    "cli": "ghcr.io/huntridge-labs/argus/cli:1.14.1@sha256:03f917046a0b8f34b960506caa9a1dd25ccdc3a983981f0790bf16972042e16b",
    # PRE-MERGE PREVIEW. The MUMPS scanner image is published from the
    # feat/scanner-m-mumps branch under the mutable ``mumps-preview`` tag
    # so testers can run ``argus scan mumps`` with zero local toolchain
    # ahead of the merge. Unlike the other entries this is a workstation
    # build (no cosign / SLSA attestations yet); on merge the release
    # pipeline rebuilds it multi-arch with attestations and release-it
    # rewrites this line to the versioned ``scanner-mumps:<version>`` tag
    # + release digest. The digest pin below is still the content-hash
    # gate the manifest check verifies.
    "mumps": "ghcr.io/huntridge-labs/argus/scanner-mumps:1.14.1@sha256:ecba7f33160ef2525ab53a8d456029293655d2823bfd7926b7d34e40d430f3b6",
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
