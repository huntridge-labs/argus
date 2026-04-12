"""Discover container images to scan from the filesystem or config."""

import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("argus.container")

# Patterns that match Dockerfile variants
_DOCKERFILE_NAMES = {"Dockerfile"}
_DOCKERFILE_PREFIX = "Dockerfile."
_DOCKERFILE_SUFFIX = ".Dockerfile"


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

    Config format::

        containers:
          images:
            - image: myapp:latest
              dockerfile: Dockerfile
            - image: worker:latest
              dockerfile: docker/Dockerfile.worker
              context: .
          discover: true
          search_paths: [".", "docker/"]
    """
    containers = config.get("containers", {})
    if not isinstance(containers, dict):
        return []

    targets: list[ContainerTarget] = []

    for entry in containers.get("images", []):
        if not isinstance(entry, dict):
            continue
        image_ref = entry.get("image", "")
        if not image_ref:
            continue

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
