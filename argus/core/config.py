"""Configuration loader for Argus — reads argus.yml."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, IO, Union

import yaml

from .models import Severity


_DEFAULT_CONFIG_NAMES = ["argus.yml", "argus.yaml", ".argus.yml", ".argus.yaml"]


class StrictSafeLoader(yaml.SafeLoader):
    """``yaml.SafeLoader`` that rejects duplicate mapping keys.

    PyYAML's default mapping constructor silently keeps only the last
    value when a key is duplicated. For argus.yml that means a
    second ``execution:`` block (or any other accidental
    duplication, at any nesting level) overwrites the user's earlier
    settings — the schema validator never sees the conflict and
    happily reports the config valid.

    This loader catches the duplication at parse time so the user
    gets a clear error naming the duplicated key and the line where
    the second occurrence sits. Same constructor override applies
    at every nesting level because PyYAML calls
    ``construct_mapping`` for every mapping node it encounters,
    not just the root.
    """


def _construct_mapping_strict(loader: yaml.SafeLoader, node, deep: bool = False) -> dict:
    """Mapping constructor that raises on the second occurrence of a key.

    Line numbers are 1-indexed in the error so they match what the
    user sees in their editor; PyYAML's internal ``start_mark.line``
    is 0-indexed.
    """
    if not isinstance(node, yaml.MappingNode):
        raise yaml.constructor.ConstructorError(
            None, None,
            f"expected a mapping node, but found {node.id}",
            node.start_mark,
        )
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            hash(key)
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark,
                f"found unhashable key ({exc})", key_node.start_mark,
            )
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark,
                f"found duplicate key {key!r} "
                f"(line {key_node.start_mark.line + 1}, "
                f"column {key_node.start_mark.column + 1})",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping_strict,
)


def load_strict_yaml(stream: Union[str, IO]) -> object:
    """Parse YAML with duplicate-key detection.

    Drop-in replacement for ``yaml.safe_load`` that uses
    ``StrictSafeLoader``. Raises ``yaml.constructor.ConstructorError``
    when a duplicate mapping key is encountered at any nesting level;
    callers that already catch ``yaml.YAMLError`` (the base class)
    pick up the new failure mode for free with no try/except changes.
    """
    return yaml.load(stream, Loader=StrictSafeLoader)


@dataclass
class ScannerConfig:
    """Configuration for a single scanner."""

    enabled: bool = True
    path: str = "."
    severity_threshold: Optional[Severity] = None
    config_file: Optional[str] = None
    extra: dict = field(default_factory=dict)


@dataclass
class ExecutionConfig:
    """Configuration for scanner execution backend.

    auto (default): containers for immutable execution, local fallback if no image
    local: use locally installed tools (user accepts version risk)
    docker: containers only, fail if unavailable
    """

    backend: str = "auto"  # auto | local | docker
    # Single-mirror override (legacy). Every image gets rewritten to
    # ``<registry>/<original-path>``. Adequate when one mirror proxies
    # *every* upstream argus uses (Docker Hub + GHCR). For setups where
    # each proxy cache tracks a single upstream — the default shape of
    # Harbor / Artifactory / ECR — use ``registry_map`` instead.
    registry: str = ""
    # Per-upstream registry mirrors. Keyed by the upstream host the
    # image originates from (``docker.io``, ``ghcr.io``, etc.); value
    # is the mirror prefix to swap in. Resolves correctly across
    # argus's mixed image set (Docker Hub + GHCR) without forcing
    # users to populate a single Harbor project from two upstreams
    # manually. ``registry_map`` wins on conflict with the flat
    # ``registry`` setting (issue #178).
    registry_map: dict = field(default_factory=dict)
    pull_policy: str = "if-not-present"  # always | if-not-present | never
    # Pre-warm container images in the background before scanning.
    # Off-by-default would penalise the common case (most users have
    # broadband and want their multi-scanner runs to be as fast as
    # possible); on-by-default + opt-out matches the existing parallel
    # mode default. Users on metered connections set this to False.
    prewarm_images: bool = True
    # Concurrency cap for the pre-warm thread pool. 4 is registry-friendly:
    # enough overlap to win on a 5-scanner run with distinct images, low
    # enough that ghcr.io / dockerhub don't throttle.
    prewarm_workers: int = 4
    # Supply-chain: cosign-verify argus-owned container images on pull
    # (third-party with @sha256: digest pins are trusted by Docker's
    # pull-time content match; tag-only third-party images log one
    # WARNING per scan run). Default True — fail-closed for the
    # 4 images argus itself publishes. Opt out wholesale by setting
    # this to False (e.g., air-gapped environments with no Sigstore /
    # Rekor network access). See docs/security.md.
    verify_image_signatures: bool = True


@dataclass
class ReportingConfig:
    """Configuration for result reporting."""

    formats: list[str] = field(default_factory=lambda: ["terminal"])
    severity_threshold: Optional[Severity] = None
    output_dir: str = "./argus-results"
    # When True, the engine persists each scanner's raw output files
    # (results.json / *.sarif / stdout.txt) under
    # ``<output_dir>/raw/<scanner>/`` alongside the canonical
    # ``argus-results.json``. Default OFF because scanners like
    # ``gitleaks`` write the literal matched secret bytes into their
    # raw JSON; persisting those by default turned ``argus-results``
    # into a secret-leak vector. The canonical ``argus-results.json``
    # is always written and is pattern-redacted, so the common case
    # (developer + CI) loses nothing. Forensic / triage users who
    # need raw output opt in with ``--keep-raw`` (CLI) or
    # ``reporting.keep_raw: true`` (argus.yml).
    keep_raw: bool = False


@dataclass
class ViewConfig:
    """Configuration for the post-scan triage interfaces.

    ``argus view terminal`` (Textual TUI) and ``argus view browser``
    (FastAPI web UI) both consume these knobs. Defaults aim for the
    least-friction UX for a developer running on a workstation with
    Git, a browser, and an editor available.

    cve_source: where clicked CVE IDs open
      - nvd (default): https://nvd.nist.gov/vuln/detail/<CVE-ID>
      - cve_org:       https://www.cve.org/CVERecord?id=<CVE-ID>
      - github:        github.com/advisories?query=<CVE-ID>
      - mitre:         legacy MITRE record page

    open_location: how clicked file:line cells resolve
      - ask (default): tiny modal lets the user pick per click
      - local:         shell out to $VISUAL / $EDITOR / VS Code (-g)
      - remote:        open the file at the scan's commit SHA on the
                       repo's origin remote (GitHub / GitLab blob URL)

    editor: explicit editor command (e.g. "code", "code -w", "nvim").
            When empty, falls through to $VISUAL → $EDITOR → VS Code
            on PATH → xdg-open / open.
    """

    cve_source: str = "nvd"
    open_location: str = "ask"
    editor: str = ""


@dataclass
class ArgusConfig:
    """Top-level Argus configuration."""

    version: str = "1.0"
    scanners: dict[str, ScannerConfig] = field(default_factory=dict)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    view: ViewConfig = field(default_factory=ViewConfig)

    @classmethod
    def _auto_detect_config(cls) -> "ArgusConfig":
        """Auto-detect the project and generate a tailored config.

        Uses the same detection logic as 'argus init' to analyze
        the project and enable appropriate scanners. Returns a config
        without writing any files.
        """
        try:
            from argus.init import detect_project, generate_config

            signals = detect_project(Path("."))
            config_text = generate_config(signals)
            data = load_strict_yaml(config_text)
            if isinstance(data, dict):
                return cls.from_dict(data)
        except Exception:
            pass
        return cls()

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> "ArgusConfig":
        """Load config from an argus.yml file.

        If *config_path* is None, searches the current directory for
        common config filenames. When no file is found, auto-detects
        the project and generates a tailored config on the fly.
        """
        import logging

        if config_path is not None:
            path = Path(config_path)
            if not path.exists():
                logging.getLogger("argus").warning(
                    "Config file not found: %s — using auto-detected config",
                    config_path,
                )
                return cls._auto_detect_config()
            return cls._load_file(path)

        for name in _DEFAULT_CONFIG_NAMES:
            path = Path(name)
            if path.exists():
                logging.getLogger("argus").debug(
                    "Loaded config from %s", path,
                )
                return cls._load_file(path)

        logging.getLogger("argus").info(
            "No argus.yml found — auto-detecting project and applying "
            "tailored config. Run 'argus init' to save it permanently.",
        )
        return cls._auto_detect_config()

    @classmethod
    def _load_file(cls, path: Path) -> "ArgusConfig":
        """Read, validate, and parse a YAML config file."""
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = load_strict_yaml(fh)
        except yaml.YAMLError as exc:
            # Covers ConstructorError raised by load_strict_yaml on
            # duplicate keys plus any other PyYAML parse failure. Wrap
            # in ValueError so the caller's existing
            # "invalid argus config" handling path catches it,
            # without a bare PyYAML traceback leaking to the user.
            raise ValueError(f"Invalid YAML in {path}: {exc}") from exc
        if not isinstance(data, dict):
            return cls()

        # Validate before parsing — catch misconfigurations early
        from .schema import validate_config, report_validation
        errors = validate_config(data)
        if errors:
            valid = report_validation(errors)
            if not valid:
                raise ValueError(
                    f"Invalid argus config: {sum(1 for e in errors if e.level == 'error')} error(s). "
                    "See log output for details."
                )

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "ArgusConfig":
        """Create an ArgusConfig from a raw dictionary."""
        version = str(data.get("version", "1.0"))

        scanners: dict[str, ScannerConfig] = {}
        for name, raw in data.get("scanners", {}).items():
            if not isinstance(raw, dict):
                continue
            scanners[name] = _parse_scanner_config(raw)

        reporting = _parse_reporting_config(data.get("reporting", {}))
        execution = _parse_execution_config(data.get("execution", {}))
        view = _parse_view_config(data.get("view", {}))

        return cls(
            version=version,
            scanners=scanners,
            reporting=reporting,
            execution=execution,
            view=view,
        )

    def get_scanner_config(self, scanner_name: str) -> ScannerConfig:
        """Return config for *scanner_name*, falling back to defaults.

        When the scanner is explicitly named in the config, return its
        settings. Otherwise return a default — enabled=True if the user
        provided a config file (they chose to omit it, meaning "use
        defaults"), enabled=False if the config was auto-generated
        (only explicitly detected scanners should run).
        """
        if scanner_name in self.scanners:
            return self.scanners[scanner_name]
        # If scanners dict is populated (auto-detect or user config),
        # unknown scanners are disabled by default
        if self.scanners:
            return ScannerConfig(enabled=False)
        # Empty dict = bare default config, enable everything
        return ScannerConfig(enabled=True)


def _parse_severity(value: str | None) -> Optional[Severity]:
    """Parse a severity string or return None.

    "none" is treated as no threshold (returns None), not as
    Severity.UNKNOWN — this matches the CLI semantics where
    --severity-threshold none means "never fail on findings".
    """
    if value is None:
        return None
    if str(value).strip().lower() == "none":
        return None
    return Severity.from_string(str(value))


def _parse_scanner_config(raw: dict) -> ScannerConfig:
    """Build a ScannerConfig from a raw dict."""
    known_keys = {"enabled", "path", "severity_threshold", "config_file"}
    extra = {k: v for k, v in raw.items() if k not in known_keys}

    return ScannerConfig(
        enabled=raw.get("enabled", True),
        path=raw.get("path", "."),
        severity_threshold=_parse_severity(raw.get("severity_threshold")),
        config_file=raw.get("config_file"),
        extra=extra,
    )


def _parse_reporting_config(raw: dict | None) -> ReportingConfig:
    """Build a ReportingConfig from a raw dict."""
    if not isinstance(raw, dict):
        return ReportingConfig()

    return ReportingConfig(
        formats=raw.get("formats", ["terminal"]),
        severity_threshold=_parse_severity(raw.get("severity_threshold")),
        output_dir=raw.get("output_dir", "./argus-results"),
        keep_raw=bool(raw.get("keep_raw", False)),
    )


def _parse_execution_config(raw: dict | None) -> ExecutionConfig:
    """Build an ExecutionConfig from a raw dict."""
    if not isinstance(raw, dict):
        return ExecutionConfig()

    raw_map = raw.get("registry_map") or {}
    if not isinstance(raw_map, dict):
        raw_map = {}
    # Coerce values to strings so the engine can rely on a clean
    # ``str -> str`` mapping without re-validating at each call site.
    registry_map = {str(k): str(v) for k, v in raw_map.items() if v}
    return ExecutionConfig(
        backend=raw.get("backend", "auto"),
        registry=raw.get("registry", ""),
        registry_map=registry_map,
        pull_policy=raw.get("pull_policy", "if-not-present"),
        prewarm_images=bool(raw.get("prewarm_images", True)),
        prewarm_workers=int(raw.get("prewarm_workers", 4)),
        verify_image_signatures=bool(raw.get("verify_image_signatures", True)),
    )


def _parse_view_config(raw: dict | None) -> ViewConfig:
    """Build a ViewConfig from a raw dict."""
    if not isinstance(raw, dict):
        return ViewConfig()

    return ViewConfig(
        cve_source=str(raw.get("cve_source", "nvd")).strip().lower() or "nvd",
        open_location=str(raw.get("open_location", "ask")).strip().lower() or "ask",
        editor=str(raw.get("editor", "")).strip(),
    )
