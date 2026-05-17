"""Configuration schema validation for argus.yml.

Validates structure, types, allowed values, and warns on unknown keys.
Catches misconfigurations before the scan runs — a typo like
'sevrity_threshold' won't silently become an ignored extra field.

No external dependencies — pure Python stdlib.
"""

import logging
from typing import Any

from argus.core.secrets import (
    looks_like_literal_secret,
    validate_env_var_name,
)

logger = logging.getLogger("argus")

# ── Schema definition ────────────────────────────────────────────────
# Each key maps to: type, required, allowed_values, default, description

_SEVERITY_VALUES = {"critical", "high", "medium", "low", "none"}
_BACKEND_VALUES = {"auto", "local", "docker"}
_PULL_POLICY_VALUES = {"always", "if-not-present", "never"}


def _get_format_values() -> set[str]:
    """Resolve the valid ``reporting.formats`` values from the reporter
    registry at call time. This stays in lock-step with whatever
    reporters are registered (built-ins + ``argus.reporters``
    entry-point plugins) so the validator can't reject a format the
    CLI's ``--format`` flag would happily accept. Import is deferred
    to avoid an import-time cycle (schema is a core module imported
    early; reporters depend on optional packages for some entries)."""
    try:
        from argus.reporters import available_reporters
        return set(available_reporters())
    except Exception:  # pragma: no cover — defensive
        return {"terminal", "markdown", "sarif", "json"}


def _get_scanner_names() -> set[str]:
    """Resolve the set of known scanner / linter names from
    ``SCANNER_REGISTRY``. Used to reject unknown scanner names in
    ``argus.yml`` up-front rather than silently accepting them with
    only a downstream warning about unknown keys (issue #168-F).
    Returns the empty set on import failure so validation degrades
    rather than panics in environments where ``argus.scanners``
    can't load."""
    try:
        from argus.scanners import SCANNER_REGISTRY
        return set(SCANNER_REGISTRY.keys())
    except Exception:  # pragma: no cover — defensive
        return set()

# Known top-level keys
_TOP_LEVEL_KEYS = {
    "version", "scanners", "reporting", "execution", "containers", "dast", "view",
}

# argus view (terminal / browser) UX knobs
_VIEW_KEYS = {"cve_source", "open_location", "editor"}
_CVE_SOURCE_VALUES = {"nvd", "cve_org", "github", "mitre"}
_OPEN_LOCATION_VALUES = {"ask", "local", "remote"}

# Known scanner config keys (anything else goes to 'extra' but we warn)
_SCANNER_KNOWN_KEYS = {
    "enabled", "path", "severity_threshold", "config_file",
    "exclude",  # Universal exclude (engine filters post-scan)
    # Scanner-specific keys that are valid in extra
    "image_ref", "target_url", "scanners", "scan_type",
    "framework", "check", "skip_check", "config",
    # Credential fields (either form: literal or <field>_env)
    "registry_username", "registry_password",
    "registry_username_env", "registry_password_env",
    # Container exposure sub-scanner tuning
    "expose_warn_ports", "expose_ignore_ports",
    # Container services sub-scanner tuning (ADR-025)
    "services_warn", "services_ignore",
    # ZAP-specific tuning (decided in ADR-024)
    "api_spec", "rules_file", "cmd_options",
    "max_duration_minutes", "healthcheck_url",
    "app_image_ref", "app_ports",
    "auth",  # nested block; sub-keys validated separately
}

# ZAP web-app auth sub-block keys (under scanners.zap.auth.*)
_ZAP_AUTH_KEYS = {
    "context_file",
    "username", "username_env",
    "password", "password_env",
}

# Credential fields per scanner — drives validate_secret_field rules.
# Each entry is (scanner_name, field_path).
_CREDENTIAL_FIELDS: dict[str, tuple[str, ...]] = {
    "container": ("registry_username", "registry_password"),
    "zap": ("registry_username", "registry_password"),
    # zap.auth.username / zap.auth.password handled separately
    # because they live in a nested block.
}

# Known reporting keys
_REPORTING_KEYS = {"formats", "severity_threshold", "output_dir"}

# Known execution keys
_EXECUTION_KEYS = {
    "backend",
    "registry",
    "pull_policy",
    "prewarm_images",
    "prewarm_workers",
    "verify_image_signatures",
}

# Top-level containers block keys
_CONTAINERS_KEYS = {"images", "discover", "search_paths", "scanners"}

# Per-image entry keys (under containers.images[*])
_CONTAINER_IMAGE_KEYS = {"image", "dockerfile", "context", "name", "cleanup"}

# Sub-scanners argus scan container can dispatch to
_CONTAINER_SUB_SCANNERS = {"trivy", "grype", "syft", "exposure", "services"}


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
            known_scanners = _get_scanner_names()
            for name, scanner_data in scanners.items():
                # Reject unknown scanner names up-front instead of silently
                # accepting them with a downstream warning about unknown keys
                # (issue #168-F). Skip when the registry can't be resolved
                # so this never bricks validation in degraded environments.
                if known_scanners and name not in known_scanners:
                    errors.append(ConfigError(
                        f"scanners.{name}",
                        f"Unknown scanner '{name}'. "
                        f"Available: {', '.join(sorted(known_scanners))}",
                    ))
                    continue
                errors.extend(_validate_scanner(f"scanners.{name}", scanner_data))

    # Reporting
    reporting = data.get("reporting")
    if reporting is not None:
        errors.extend(_validate_reporting("reporting", reporting))

    view = data.get("view")
    if view is not None:
        errors.extend(_validate_view("view", view))

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

    # Credential fields — validate either-form contract (literal or *_env).
    # Scanner name is the last path segment ("scanners.<name>").
    scanner_name = path.rsplit(".", 1)[-1]
    for cred_field in _CREDENTIAL_FIELDS.get(scanner_name, ()):
        errors.extend(_validate_secret_field(data, cred_field, path))

    # ZAP web-app auth sub-block (nested under scanners.zap.auth.*)
    if scanner_name == "zap" and "auth" in data:
        errors.extend(_validate_zap_auth(f"{path}.auth", data["auth"]))

    # ZAP cmd_options must be a list of strings
    if scanner_name == "zap" and "cmd_options" in data:
        opts = data["cmd_options"]
        if not isinstance(opts, list) or not all(isinstance(o, str) for o in opts):
            errors.append(ConfigError(
                f"{path}.cmd_options",
                "Must be a list of strings (passed verbatim to the ZAP CLI)",
            ))

    # ZAP max_duration_minutes must be a positive int
    if scanner_name == "zap" and "max_duration_minutes" in data:
        v = data["max_duration_minutes"]
        if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
            errors.append(ConfigError(
                f"{path}.max_duration_minutes",
                f"Must be a positive integer, got {v!r}",
            ))

    # Container exposure sub-scanner tuning — both lists must be
    # lists of ``"PORT/PROTO"`` strings (protocol defaults to tcp
    # when omitted; case-insensitive).
    if scanner_name == "container":
        for key in ("expose_warn_ports", "expose_ignore_ports"):
            if key not in data:
                continue
            value = data[key]
            if not isinstance(value, list):
                errors.append(ConfigError(
                    f"{path}.{key}",
                    f"Must be a list of \"PORT/PROTO\" strings, "
                    f"got {type(value).__name__}",
                ))
                continue
            for entry in value:
                if not isinstance(entry, str):
                    errors.append(ConfigError(
                        f"{path}.{key}",
                        f"Entry must be a string \"PORT/PROTO\", "
                        f"got {type(entry).__name__} ({entry!r})",
                    ))
                    continue
                # Validate via the scanner's parser so the schema and
                # the runtime agree on what's well-formed.
                from argus.scanners.container import _parse_port_proto
                if _parse_port_proto(entry) is None:
                    errors.append(ConfigError(
                        f"{path}.{key}",
                        f"'{entry}' is not a valid PORT/PROTO entry. "
                        "Expected '<port>/<tcp|udp|sctp>' (e.g. '22/tcp') "
                        "or bare '<port>' which defaults to tcp.",
                    ))

    # Container services sub-scanner tuning — both lists must be
    # lists of bare service names (e.g. ``sshd``, ``postgresql``).
    if scanner_name == "container":
        for key in ("services_warn", "services_ignore"):
            if key not in data:
                continue
            value = data[key]
            if not isinstance(value, list):
                errors.append(ConfigError(
                    f"{path}.{key}",
                    f"Must be a list of service-name strings, "
                    f"got {type(value).__name__}",
                ))
                continue
            for entry in value:
                if not isinstance(entry, str):
                    errors.append(ConfigError(
                        f"{path}.{key}",
                        f"Entry must be a string service name, "
                        f"got {type(entry).__name__} ({entry!r})",
                    ))
                    continue
                if not entry.strip():
                    errors.append(ConfigError(
                        f"{path}.{key}",
                        "Service-name entries must be non-empty",
                    ))

    # Warn on unknown keys (after credential / nested-block handling so
    # we don't double-warn on the keys we already validated).
    for key in data:
        if key not in _SCANNER_KNOWN_KEYS:
            errors.append(ConfigError(
                f"{path}.{key}",
                f"Unknown scanner key '{key}'. Will be passed as extra config.",
                level="warning",
            ))

    return errors


def _validate_secret_field(
    data: dict, field: str, path: str,
) -> list[ConfigError]:
    """Validate a credential field that follows the <field>/<field>_env contract.

    - ``<field>_env`` must be a valid POSIX shell identifier.
    - ``<field>`` literal is allowed but warned if it looks like a
      known vendor secret (gh*, AKIA, AIza, etc.).
    - Both set is a warning (the resolver uses _env).
    """
    errors: list[ConfigError] = []
    env_field = f"{field}_env"

    if env_field in data:
        name = data[env_field]
        if not isinstance(name, str):
            errors.append(ConfigError(
                f"{path}.{env_field}",
                f"Must be a string environment variable name, "
                f"got {type(name).__name__}",
            ))
        elif not validate_env_var_name(name):
            errors.append(ConfigError(
                f"{path}.{env_field}",
                f"'{name}' is not a valid environment variable name "
                f"(must match [A-Za-z_][A-Za-z0-9_]*)",
            ))

    if field in data:
        value = data[field]
        if isinstance(value, str) and looks_like_literal_secret(value):
            errors.append(ConfigError(
                f"{path}.{field}",
                f"Looks like a literal vendor secret. Prefer "
                f"'{env_field}: <ENV_VAR_NAME>' to keep credentials "
                f"out of argus.yml.",
                level="warning",
            ))

    if field in data and env_field in data:
        errors.append(ConfigError(
            f"{path}.{field}",
            f"Both '{field}' and '{env_field}' are set — only one "
            f"should be used. '{env_field}' takes precedence at resolution.",
            level="warning",
        ))

    return errors


def _validate_zap_auth(path: str, data: Any) -> list[ConfigError]:
    """Validate the ``scanners.zap.auth`` sub-block.

    Holds the ZAP context-file path plus credential references for
    web-app authentication. Credentials follow the same <field> /
    <field>_env contract as registry auth.
    """
    errors: list[ConfigError] = []

    if not isinstance(data, dict):
        errors.append(ConfigError(
            path, f"Must be a mapping, got {type(data).__name__}",
        ))
        return errors

    for key in data:
        if key not in _ZAP_AUTH_KEYS:
            errors.append(ConfigError(
                f"{path}.{key}",
                f"Unknown auth key '{key}'. "
                f"Valid keys: {', '.join(sorted(_ZAP_AUTH_KEYS))}",
                level="warning",
            ))

    if "context_file" in data and not isinstance(data["context_file"], str):
        errors.append(ConfigError(
            f"{path}.context_file", "Must be a string path",
        ))

    errors.extend(_validate_secret_field(data, "username", path))
    errors.extend(_validate_secret_field(data, "password", path))

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
            valid_formats = _get_format_values()
            for i, fmt in enumerate(formats):
                if fmt not in valid_formats:
                    errors.append(ConfigError(
                        f"{path}.formats[{i}]",
                        f"Invalid format '{fmt}'. "
                        f"Must be one of: {', '.join(sorted(valid_formats))}",
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

    # Pre-warm flag — bool
    if "prewarm_images" in data and not isinstance(data["prewarm_images"], bool):
        errors.append(ConfigError(
            f"{path}.prewarm_images",
            f"Must be a boolean (true/false), got "
            f"{type(data['prewarm_images']).__name__}",
        ))

    # Pre-warm workers — positive int
    if "prewarm_workers" in data:
        workers = data["prewarm_workers"]
        if not isinstance(workers, int) or isinstance(workers, bool) or workers < 1:
            errors.append(ConfigError(
                f"{path}.prewarm_workers",
                f"Must be a positive integer (>=1), got {workers!r}",
            ))

    # Supply-chain signature verification flag — bool
    if "verify_image_signatures" in data and not isinstance(
        data["verify_image_signatures"], bool,
    ):
        errors.append(ConfigError(
            f"{path}.verify_image_signatures",
            f"Must be a boolean (true/false), got "
            f"{type(data['verify_image_signatures']).__name__}",
        ))

    return errors


def _validate_view(path: str, data: Any) -> list[ConfigError]:
    """Validate the ``view:`` block — argus view terminal / browser UX."""
    errors: list[ConfigError] = []

    if not isinstance(data, dict):
        errors.append(ConfigError(
            path, f"Must be a mapping, got {type(data).__name__}",
        ))
        return errors

    for key in data:
        if key not in _VIEW_KEYS:
            errors.append(ConfigError(
                f"{path}.{key}",
                f"Unknown view key '{key}'. "
                f"Valid keys: {', '.join(sorted(_VIEW_KEYS))}",
                level="warning",
            ))

    if "cve_source" in data:
        val = str(data["cve_source"]).lower()
        if val not in _CVE_SOURCE_VALUES:
            errors.append(ConfigError(
                f"{path}.cve_source",
                f"Invalid value '{data['cve_source']}'. "
                f"Must be one of: {', '.join(sorted(_CVE_SOURCE_VALUES))}",
            ))

    if "open_location" in data:
        val = str(data["open_location"]).lower()
        if val not in _OPEN_LOCATION_VALUES:
            errors.append(ConfigError(
                f"{path}.open_location",
                f"Invalid value '{data['open_location']}'. "
                f"Must be one of: {', '.join(sorted(_OPEN_LOCATION_VALUES))}",
            ))

    if "editor" in data and not isinstance(data["editor"], str):
        errors.append(ConfigError(
            f"{path}.editor",
            f"Must be a string (editor command, e.g. 'code -g'), got "
            f"{type(data['editor']).__name__}",
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
