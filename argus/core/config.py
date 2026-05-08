"""Configuration loader for Argus — reads argus.yml."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from .models import Severity


_DEFAULT_CONFIG_NAMES = ["argus.yml", "argus.yaml", ".argus.yml", ".argus.yaml"]


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
    registry: str = ""  # override for private registries
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


@dataclass
class ReportingConfig:
    """Configuration for result reporting."""

    formats: list[str] = field(default_factory=lambda: ["terminal"])
    severity_threshold: Optional[Severity] = None
    output_dir: str = "./argus-results"
    # When True, the engine persists each scanner's raw output files
    # (results.json / *.sarif / stdout.txt) under
    # ``<output_dir>/raw/<scanner>/`` alongside the canonical
    # ``argus-results.json``. Default ON since most users running
    # ``argus scan`` would expect the artifacts to be available for
    # forensics or manual triage; opt out via ``--no-keep-raw`` (CLI)
    # or ``reporting.keep_raw: false`` for tight CI environments.
    keep_raw: bool = True


@dataclass
class ArgusConfig:
    """Top-level Argus configuration."""

    version: str = "1.0"
    scanners: dict[str, ScannerConfig] = field(default_factory=dict)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)

    @classmethod
    def _auto_detect_config(cls) -> "ArgusConfig":
        """Auto-detect the project and generate a tailored config.

        Uses the same detection logic as 'argus init' to analyze
        the project and enable appropriate scanners. Returns a config
        without writing any files.
        """
        try:
            from argus.init import detect_project, generate_config
            import yaml as _yaml

            signals = detect_project(Path("."))
            config_text = generate_config(signals)
            data = _yaml.safe_load(config_text)
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
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
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

        return cls(
            version=version,
            scanners=scanners,
            reporting=reporting,
            execution=execution,
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
        keep_raw=bool(raw.get("keep_raw", True)),
    )


def _parse_execution_config(raw: dict | None) -> ExecutionConfig:
    """Build an ExecutionConfig from a raw dict."""
    if not isinstance(raw, dict):
        return ExecutionConfig()

    return ExecutionConfig(
        backend=raw.get("backend", "auto"),
        registry=raw.get("registry", ""),
        pull_policy=raw.get("pull_policy", "if-not-present"),
        prewarm_images=bool(raw.get("prewarm_images", True)),
        prewarm_workers=int(raw.get("prewarm_workers", 4)),
    )
