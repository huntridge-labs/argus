"""Discover container images to scan from the filesystem or config."""

import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("argus.container")

# Patterns that match Dockerfile variants
_DOCKERFILE_NAMES = {"Dockerfile"}
_DOCKERFILE_PREFIX = "Dockerfile."
_DOCKERFILE_SUFFIX = ".Dockerfile"

# Grype reserves a set of CLI source-scheme prefixes (``docker:``,
# ``podman:``, ``registry:``, etc.). When an image reference happens
# to start with one of these — e.g. ``docker:argus-scan`` (image name
# ``docker``, tag ``argus-scan``) — Grype mis-parses the colon as the
# scheme separator and looks for a non-existent image ``argus-scan``
# in the docker daemon, instead of an image ``docker`` with tag
# ``argus-scan``. Trivy doesn't have this ambiguity (positional arg,
# no scheme prefixes), so the collision is Grype-specific.
#
# We address it in two places:
#   1. Config-load: warn the user so they can rename before the scan
#      runs (less time wasted on a build that won't surface findings).
#   2. Runtime: when scanning a locally-built image, prefix the ref
#      with ``docker:`` so Grype's parser sees an explicit scheme
#      regardless of what the user named the image. ``docker:foo``
#      becomes ``docker:docker:foo`` — Grype treats the first as the
#      scheme and the rest as the image identifier.
GRYPE_RESERVED_PREFIXES: tuple[str, ...] = (
    "docker:",
    "podman:",
    "registry:",
    "dir:",
    "sbom:",
    "oci-archive:",
    "oci-dir:",
    "singularity:",
    "attestation:",
)


def warn_on_grype_prefix_collision(image_ref: str) -> str | None:
    """Return a remediation message when ``image_ref`` collides with a
    Grype source-scheme prefix; ``None`` otherwise.

    Surfaced at config-load time so users see the issue before the
    Docker build runs (saves them ~10s on a typical local build that
    will produce zero Grype findings).
    """
    if not isinstance(image_ref, str):
        return None
    for prefix in GRYPE_RESERVED_PREFIXES:
        if image_ref.startswith(prefix):
            # Suggest a rename that preserves the user's tag if any.
            tag = image_ref[len(prefix):] if ":" in image_ref else "dev"
            suggested = f"argus-app:{tag or 'dev'}"
            return (
                f"image '{image_ref}' starts with the Grype source-scheme "
                f"prefix '{prefix}' — Grype will mis-parse this as a "
                f"scheme request and look for an image named "
                f"'{image_ref[len(prefix):]}' in the docker daemon, "
                f"instead of an image '{prefix.rstrip(':')}' with tag "
                f"'{image_ref[len(prefix):]}'. Rename to e.g. "
                f"'{suggested}' or 'myorg/{image_ref.split(':', 1)[-1] or 'app'}:dev' "
                f"to avoid the collision."
            )
    return None


@dataclass
class ContainerTarget:
    """A container image to scan.

    ``cleanup`` overrides the engine's global ``cleanup:`` default for
    this single target. ``None`` (the default) defers to the global
    setting; ``True``/``False`` is an explicit per-target choice. Useful
    for the case where a long-lived base image should stay cached
    across runs while ad-hoc dev images are torn down — set
    ``cleanup: false`` on the base entry, leave the others alone.
    """

    name: str
    image_ref: str
    dockerfile: Path | None = None
    context: Path | None = None
    cleanup: bool | None = None


def discover_dockerfiles(search_paths: list[str]) -> list[ContainerTarget]:
    """Find Dockerfiles in the given paths.

    Looks for: Dockerfile, Dockerfile.*, *.Dockerfile, docker/Dockerfile*
    Returns a ContainerTarget for each, with name derived from path.
    """
    targets: list[ContainerTarget] = []
    seen_paths: set[Path] = set()

    for search_path in search_paths:
        root = Path(search_path).resolve()
        if not root.exists():
            logger.warning("Search path does not exist: %s", search_path)
            continue

        dockerfiles = _find_dockerfiles(root)
        for dockerfile in dockerfiles:
            resolved = dockerfile.resolve()
            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)

            name = _derive_name(dockerfile, root)
            target = ContainerTarget(
                name=name,
                image_ref=f"{name}:argus-scan",
                dockerfile=dockerfile,
                context=dockerfile.parent,
            )
            targets.append(target)

    return targets


def parse_container_config(config: dict) -> list[ContainerTarget]:
    """Parse container targets from argus.yml config.

    Accepts both shapes:

    Wrapped — full ``argus.yml`` mapping with the top-level
    ``containers:`` key still in place::

        {"containers": {"images": [...], "discover": true, ...}}

    Unwrapped — just the inner ``containers:`` mapping (the shape the
    CLI's ``_load_container_config`` returns after extracting the
    section and merging CLI overrides in place)::

        {"images": [...], "discover": true, ...}

    The engine's other config accessors (``self.config.get("images")``,
    ``self.config.get("search_paths")``, etc.) operate on the
    unwrapped shape — leaving this function strict on the wrapped
    shape silently dropped config-driven targets when the CLI handed
    in the unwrapped form. Tolerate both so the parser can't be the
    only place in the dispatch path that disagrees about config
    layout.
    """
    nested = config.get("containers")
    if isinstance(nested, dict):
        containers = nested
    else:
        # Unwrapped shape — treat the input as already-the-inner mapping.
        containers = config if isinstance(config, dict) else {}

    targets: list[ContainerTarget] = []

    for entry in containers.get("images", []):
        if not isinstance(entry, dict):
            continue

        image_ref_explicit = entry.get("image", "")
        dockerfile_path = entry.get("dockerfile")
        cleanup_override = entry.get("cleanup")
        if cleanup_override is not None and not isinstance(cleanup_override, bool):
            cleanup_override = None  # validator already warned; ignore here

        if image_ref_explicit and dockerfile_path:
            # Schema validator rejects this combination; defensive skip
            # so a stale config (pre-option-A) doesn't crash the parser.
            logger.warning(
                "Skipping container entry: 'image:' and 'dockerfile:' "
                "are mutually exclusive (entry: %s).", entry,
            )
            continue

        if image_ref_explicit:
            # Remote-pull entry. ``image_ref`` is what we hand to
            # trivy/grype/syft directly; ``name`` is a sanitized
            # human-readable identifier used in result rows.
            collision = warn_on_grype_prefix_collision(image_ref_explicit)
            if collision:
                logger.warning(collision)

            name = image_ref_explicit.split(":")[0].replace("/", "-")
            targets.append(ContainerTarget(
                name=name,
                image_ref=image_ref_explicit,
                cleanup=cleanup_override,
            ))
            continue

        if dockerfile_path:
            # Build-then-scan entry. Derive the build tag the same way
            # ``--discover`` does so explicit-config and auto-discovery
            # produce the same on-disk image names — easier debugging
            # for users grepping ``docker images | grep :argus-scan``.
            df_path = Path(dockerfile_path)
            root = Path(entry.get("context", df_path.parent))
            name = entry.get("name") or _derive_name(df_path, root)
            image_ref = f"{name}:argus-scan"
            targets.append(ContainerTarget(
                name=name,
                image_ref=image_ref,
                dockerfile=df_path,
                context=root if entry.get("context") else None,
                cleanup=cleanup_override,
            ))
            continue

        # Neither image: nor dockerfile: — schema validator surfaced
        # this; skip silently to avoid double-noise.

    if containers.get("discover", False):
        search_paths = containers.get("search_paths", ["."])
        discovered = discover_dockerfiles(search_paths)
        existing_names = {t.name for t in targets}
        for target in discovered:
            if target.name not in existing_names:
                targets.append(target)

    return targets


def _find_dockerfiles(root: Path) -> list[Path]:
    """Walk a directory tree and return all Dockerfile variants."""
    results: list[Path] = []

    if root.is_file():
        if _is_dockerfile(root):
            results.append(root)
        return results

    for path in sorted(root.rglob("*")):
        if path.is_file() and _is_dockerfile(path):
            results.append(path)

    return results


def _is_dockerfile(path: Path) -> bool:
    """Check if a file path matches Dockerfile naming patterns."""
    name = path.name
    if name in _DOCKERFILE_NAMES:
        return True
    if name.startswith(_DOCKERFILE_PREFIX):
        return True
    if name.endswith(_DOCKERFILE_SUFFIX):
        return True
    return False


def _derive_name(dockerfile: Path, root: Path) -> str:
    """Derive a container name from a Dockerfile path.

    Examples:
        Dockerfile            -> root dir name
        Dockerfile.worker     -> worker
        api.Dockerfile        -> api
        docker/Dockerfile.web -> web
    """
    name = dockerfile.name

    if name == "Dockerfile":
        # Use the parent directory name as the container name
        parent = dockerfile.parent
        if parent == root:
            return root.name
        try:
            relative = dockerfile.parent.relative_to(root)
            return str(relative).replace("/", "-").replace("\\", "-")
        except ValueError:
            return parent.name

    if name.startswith(_DOCKERFILE_PREFIX):
        return name[len(_DOCKERFILE_PREFIX):]

    if name.endswith(_DOCKERFILE_SUFFIX):
        return name[: -len(_DOCKERFILE_SUFFIX)]

    return name
