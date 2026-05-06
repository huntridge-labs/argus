"""Configuration schema validation for argus.yml.

Validates structure, types, allowed values, and warns on unknown keys.
Catches misconfigurations before the scan runs — a typo like
'sevrity_threshold' won't silently become an ignored extra field.

No external dependencies — pure Python stdlib.
"""

import logging
from typing import Any

logger = logging.getLogger("argus")

# ── Schema definition ────────────────────────────────────────────────
# Each key maps to: type, required, allowed_values, default, description

_SEVERITY_VALUES = {"critical", "high", "medium", "low", "none"}
_BACKEND_VALUES = {"auto", "local", "docker"}
_PULL_POLICY_VALUES = {"always", "if-not-present", "never"}
_FORMAT_VALUES = {"terminal", "markdown", "sarif", "json"}

# Known top-level keys
_TOP_LEVEL_KEYS = {"version", "scanners", "reporting", "execution", "containers", "dast"}

# Known scanner config keys (anything else goes to 'extra' but we warn)
_SCANNER_KNOWN_KEYS = {
    "enabled", "path", "severity_threshold", "config_file",
    "exclude",  # Universal exclude (engine filters post-scan)
    # Scanner-specific keys that are valid in extra
    "image_ref", "target_url", "scanners", "scan_type",
    "framework", "check", "skip_check", "config",
    "registry_username", "registry_password",
}

# Known reporting keys
_REPORTING_KEYS = {"formats", "severity_threshold", "output_dir"}

# Known execution keys
_EXECUTION_KEYS = {"backend", "registry", "pull_policy"}

# Top-level containers block keys
_CONTAINERS_KEYS = {"images", "discover", "search_paths", "scanners"}

# Per-image entry keys (under containers.images[*])
_CONTAINER_IMAGE_KEYS = {"image", "dockerfile", "context", "name", "cleanup"}

# Sub-scanners argus scan container can dispatch to
_CONTAINER_SUB_SCANNERS = {"trivy", "grype", "syft"}


class ConfigError:
    """A single configuration issue."""

    def __init__(self, path: str, message: str, level: str = "error"):
        self.path = path
        self.message = message
        self.level = level  # error, warning

    def __str__(self) -> str:
        prefix = "ERROR" if self.level == "error" else "WARNING"
        return f"[{prefix}] {self.path}: {self.message}"


def validate_config(data: dict) -> list[ConfigError]:
    """Validate an argus.yml config dict.

    Returns a list of ConfigError objects. Empty list means valid.
    Errors are fatal (scan should not proceed).
    Warnings are informational (scan proceeds but user is notified).
    """
    if not isinstance(data, dict):
        return [ConfigError("", "Config must be a YAML mapping (dict)")]

    errors: list[ConfigError] = []

    # Check for unknown top-level keys
    for key in data:
        if key not in _TOP_LEVEL_KEYS:
            errors.append(ConfigError(
                key,
                f"Unknown top-level key '{key}'. "
                f"Valid keys: {', '.join(sorted(_TOP_LEVEL_KEYS))}",
                level="warning",
            ))

    # Version
    version = data.get("version")
    if version is not None and str(version) not in ("1.0", "1"):
        errors.append(ConfigError(
            "version",
            f"Unsupported config version '{version}'. Expected '1.0'.",
            level="warning",
        ))

    # Scanners
    scanners = data.get("scanners")
    if scanners is not None:
        if not isinstance(scanners, dict):
            errors.append(ConfigError("scanners", "Must be a mapping of scanner names to config"))
        else:
            for name, scanner_data in scanners.items():
                errors.extend(_validate_scanner(f"scanners.{name}", scanner_data))

    # Reporting
    reporting = data.get("reporting")
    if reporting is not None:
        errors.extend(_validate_reporting("reporting", reporting))

    # Execution
    execution = data.get("execution")
    if execution is not None:
        errors.extend(_validate_execution("execution", execution))

    # Containers (top-level lifecycle targets for ``argus scan container``)
    containers = data.get("containers")
    if containers is not None:
        errors.extend(_validate_containers("containers", containers))

    return errors


def _validate_scanner(path: str, data: Any) -> list[ConfigError]:
    """Validate a single scanner config block."""
    errors: list[ConfigError] = []

    if not isinstance(data, dict):
        if data is None:
            return []  # scanner: null means use defaults
        errors.append(ConfigError(path, f"Must be a mapping, got {type(data).__name__}"))
        return errors

    # Type checks
    if "enabled" in data and not isinstance(data["enabled"], bool):
        errors.append(ConfigError(f"{path}.enabled", "Must be a boolean (true/false)"))

    if "path" in data and not isinstance(data["path"], str):
        errors.append(ConfigError(f"{path}.path", "Must be a string"))

    if "severity_threshold" in data:
        val = str(data["severity_threshold"]).lower()
        if val not in _SEVERITY_VALUES:
            errors.append(ConfigError(
                f"{path}.severity_threshold",
                f"Invalid value '{data['severity_threshold']}'. "
                f"Must be one of: {', '.join(sorted(_SEVERITY_VALUES))}",
            ))

    if "config_file" in data and not isinstance(data["config_file"], str):
        errors.append(ConfigError(f"{path}.config_file", "Must be a string"))

    if "exclude" in data and not isinstance(data["exclude"], str):
        errors.append(ConfigError(f"{path}.exclude", "Must be a comma-separated string"))

    # Warn on unknown keys
    for key in data:
        if key not in _SCANNER_KNOWN_KEYS:
            errors.append(ConfigError(
                f"{path}.{key}",
                f"Unknown scanner key '{key}'. Will be passed as extra config.",
                level="warning",
            ))

    return errors


def _validate_reporting(path: str, data: Any) -> list[ConfigError]:
    """Validate the reporting config block."""
    errors: list[ConfigError] = []

    if not isinstance(data, dict):
        errors.append(ConfigError(path, f"Must be a mapping, got {type(data).__name__}"))
        return errors

    # Unknown keys
    for key in data:
        if key not in _REPORTING_KEYS:
            errors.append(ConfigError(
                f"{path}.{key}",
                f"Unknown reporting key '{key}'. "
                f"Valid keys: {', '.join(sorted(_REPORTING_KEYS))}",
                level="warning",
            ))

    # Formats
    if "formats" in data:
        formats = data["formats"]
        if not isinstance(formats, list):
            errors.append(ConfigError(f"{path}.formats", "Must be a list"))
        else:
            for i, fmt in enumerate(formats):
                if fmt not in _FORMAT_VALUES:
                    errors.append(ConfigError(
                        f"{path}.formats[{i}]",
                        f"Invalid format '{fmt}'. "
                        f"Must be one of: {', '.join(sorted(_FORMAT_VALUES))}",
                    ))

    # Severity threshold
    if "severity_threshold" in data:
        val = str(data["severity_threshold"]).lower()
        if val not in _SEVERITY_VALUES:
            errors.append(ConfigError(
                f"{path}.severity_threshold",
                f"Invalid value '{data['severity_threshold']}'. "
                f"Must be one of: {', '.join(sorted(_SEVERITY_VALUES))}",
            ))

    # Output dir
    if "output_dir" in data and not isinstance(data["output_dir"], str):
        errors.append(ConfigError(f"{path}.output_dir", "Must be a string"))

    return errors


def _validate_execution(path: str, data: Any) -> list[ConfigError]:
    """Validate the execution config block."""
    errors: list[ConfigError] = []

    if not isinstance(data, dict):
        errors.append(ConfigError(path, f"Must be a mapping, got {type(data).__name__}"))
        return errors

    # Unknown keys
    for key in data:
        if key not in _EXECUTION_KEYS:
            errors.append(ConfigError(
                f"{path}.{key}",
                f"Unknown execution key '{key}'. "
                f"Valid keys: {', '.join(sorted(_EXECUTION_KEYS))}",
                level="warning",
            ))

    # Backend
    if "backend" in data:
        val = str(data["backend"]).lower()
        if val not in _BACKEND_VALUES:
            errors.append(ConfigError(
                f"{path}.backend",
                f"Invalid value '{data['backend']}'. "
                f"Must be one of: {', '.join(sorted(_BACKEND_VALUES))}",
            ))

    # Pull policy
    if "pull_policy" in data:
        val = str(data["pull_policy"]).lower()
        if val not in _PULL_POLICY_VALUES:
            errors.append(ConfigError(
                f"{path}.pull_policy",
                f"Invalid value '{data['pull_policy']}'. "
                f"Must be one of: {', '.join(sorted(_PULL_POLICY_VALUES))}",
            ))

    return errors


def _validate_containers(path: str, data: Any) -> list[ConfigError]:
    """Validate the top-level ``containers:`` block.

    Catches the common authoring mistakes that previously only surfaced
    at scan time (or got silently ignored): typo'd image-entry keys,
    discover without search_paths, an empty images list, sub-scanner
    names that aren't trivy/grype/syft, and image entries that name
    neither a registry ref nor a Dockerfile.
    """
    errors: list[ConfigError] = []

    if not isinstance(data, dict):
        errors.append(ConfigError(
            path, f"Must be a mapping, got {type(data).__name__}",
        ))
        return errors

    # Unknown keys
    for key in data:
        if key not in _CONTAINERS_KEYS:
            errors.append(ConfigError(
                f"{path}.{key}",
                f"Unknown containers key '{key}'. "
                f"Valid keys: {', '.join(sorted(_CONTAINERS_KEYS))}",
                level="warning",
            ))

    images = data.get("images")
    discover = data.get("discover", False)

    # At least one source of targets must be configured.
    if not images and not discover:
        errors.append(ConfigError(
            path,
            "containers: must declare at least one of `images:` (a list) "
            "or `discover: true` — otherwise `argus scan container --config` "
            "has no targets to scan.",
        ))

    # images: list of mappings
    if images is not None:
        if not isinstance(images, list):
            errors.append(ConfigError(
                f"{path}.images", "Must be a list of image entries",
            ))
        elif len(images) == 0:
            errors.append(ConfigError(
                f"{path}.images",
                "Empty images list — drop the key entirely or add at least one entry.",
                level="warning",
            ))
        else:
            for i, entry in enumerate(images):
                errors.extend(
                    _validate_container_image_entry(f"{path}.images[{i}]", entry)
                )

    # discover requires search_paths (or defaults to ["."])
    if "search_paths" in data:
        sp = data["search_paths"]
        if not isinstance(sp, list) or not all(isinstance(p, str) for p in sp):
            errors.append(ConfigError(
                f"{path}.search_paths",
                "Must be a list of path strings",
            ))

    # scanners: must be a list of valid sub-scanner names
    if "scanners" in data:
        sc = data["scanners"]
        if not isinstance(sc, list):
            errors.append(ConfigError(
                f"{path}.scanners",
                f"Must be a list. Valid values: "
                f"{', '.join(sorted(_CONTAINER_SUB_SCANNERS))}",
            ))
        else:
            for i, s in enumerate(sc):
                if s not in _CONTAINER_SUB_SCANNERS:
                    errors.append(ConfigError(
                        f"{path}.scanners[{i}]",
                        f"Unknown container sub-scanner '{s}'. "
                        f"Valid values: {', '.join(sorted(_CONTAINER_SUB_SCANNERS))}",
                    ))

    return errors


def _validate_container_image_entry(path: str, entry: Any) -> list[ConfigError]:
    """Validate a single ``containers.images[*]`` entry.

    Schema option A — ``image:`` and ``dockerfile:`` are *mutually
    exclusive*. ``image:`` means "pull this from a registry";
    ``dockerfile:`` (+ optional ``context:`` and ``name:``) means
    "build locally and scan the result". The previous shape doubled
    ``image:`` as both "pull source" and "tag the build as" — the
    docker-compose precedent — and the doubling was the source of the
    UX confusion that motivated this change. Argus doesn't push images
    after building, so the compose semantic was never load-bearing for
    us; the cleaner separation reflects what the tool actually does.
    """
    errors: list[ConfigError] = []

    if not isinstance(entry, dict):
        errors.append(ConfigError(
            path,
            f"Must be a mapping with either 'image:' or 'dockerfile:', "
            f"got {type(entry).__name__}",
        ))
        return errors

    # Unknown keys
    for key in entry:
        if key not in _CONTAINER_IMAGE_KEYS:
            errors.append(ConfigError(
                f"{path}.{key}",
                f"Unknown image-entry key '{key}'. "
                f"Valid keys: {', '.join(sorted(_CONTAINER_IMAGE_KEYS))}",
                level="warning",
            ))

    has_image = "image" in entry
    has_dockerfile = "dockerfile" in entry

    if not has_image and not has_dockerfile:
        errors.append(ConfigError(
            path,
            "Image entry must declare either 'image:' (remote registry "
            "reference, pulled and scanned) or 'dockerfile:' (built "
            "locally from a Dockerfile, then scanned).",
        ))
    elif has_image and has_dockerfile:
        errors.append(ConfigError(
            path,
            "Image entry has both 'image:' and 'dockerfile:' set — these "
            "are mutually exclusive. Use 'image:' for remote pulls; use "
            "'dockerfile:' (+ optional 'context:' and 'name:') for local "
            "builds. Argus does not push the build to a registry, so the "
            "'image:' tag-after-build semantic from docker-compose is not "
            "supported.",
        ))

    # ``context:`` / ``name:`` only make sense for build-mode entries.
    if has_image and not has_dockerfile:
        for build_only in ("context", "name"):
            if build_only in entry:
                errors.append(ConfigError(
                    f"{path}.{build_only}",
                    f"'{build_only}:' only applies to dockerfile-build "
                    f"entries; ignored when 'image:' is set.",
                    level="warning",
                ))

    # Type checks for present fields
    for field in ("image", "dockerfile", "context", "name"):
        if field in entry and not isinstance(entry[field], str):
            errors.append(ConfigError(
                f"{path}.{field}", "Must be a string",
            ))

    if "cleanup" in entry and not isinstance(entry["cleanup"], bool):
        errors.append(ConfigError(
            f"{path}.cleanup", "Must be a boolean (true/false)",
        ))

    return errors


def report_validation(errors: list[ConfigError]) -> bool:
    """Log validation errors/warnings and return True if config is valid.

    Errors are logged at ERROR level and cause the scan to abort.
    Warnings are logged at WARNING level but the scan proceeds.
    """
    warnings = [e for e in errors if e.level == "warning"]
    fatal = [e for e in errors if e.level == "error"]

    for w in warnings:
        logger.warning("Config: %s", w)

    for e in fatal:
        logger.error("Config: %s", e)

    if fatal:
        logger.error(
            "%d config error(s) found. Fix argus.yml and retry.",
            len(fatal),
        )

    return len(fatal) == 0
