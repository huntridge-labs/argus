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
    """A container image to scan."""

    name: str
    image_ref: str
    dockerfile: Path | None = None
    context: Path | None = None


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
        image_ref = entry.get("image", "")
        if not image_ref:
            continue

        # Surface Grype prefix-collisions at config-load — well before
        # the build runs. The warning is non-fatal so users with
        # build-only or trivy-only flows aren't blocked by a Grype-
        # specific naming issue.
        collision = warn_on_grype_prefix_collision(image_ref)
        if collision:
            logger.warning(collision)

        dockerfile_path = entry.get("dockerfile")
        context_path = entry.get("context")

        name = image_ref.split(":")[0].replace("/", "-")
        target = ContainerTarget(
            name=name,
            image_ref=image_ref,
            dockerfile=Path(dockerfile_path) if dockerfile_path else None,
            context=Path(context_path) if context_path else None,
        )
        targets.append(target)

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
