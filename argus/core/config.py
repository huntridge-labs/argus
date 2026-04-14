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


@dataclass
class ReportingConfig:
    """Configuration for result reporting."""

    formats: list[str] = field(default_factory=lambda: ["terminal"])
    severity_threshold: Optional[Severity] = None
    output_dir: str = "./argus-results"


@dataclass
class ArgusConfig:
    """Top-level Argus configuration."""

    version: str = "1.0"
    scanners: dict[str, ScannerConfig] = field(default_factory=dict)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> "ArgusConfig":
        """Load config from an argus.yml file.

        If *config_path* is None, searches the current directory for
        common config filenames. Returns default config when no file
        is found — individual scanners still work via CLI flags.
        """
        import logging

        if config_path is not None:
            path = Path(config_path)
            if not path.exists():
                logging.getLogger("argus").warning(
                    "Config file not found: %s — using defaults", config_path,
                )
                return cls()
            return cls._load_file(path)

        for name in _DEFAULT_CONFIG_NAMES:
            path = Path(name)
            if path.exists():
                logging.getLogger("argus").debug(
                    "Loaded config from %s", path,
                )
                return cls._load_file(path)

        logging.getLogger("argus").info(
            "No argus.yml found — using defaults. "
            "Run 'argus init' to generate a config.",
        )
        return cls()

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
        """Return config for *scanner_name*, falling back to defaults."""
        return self.scanners.get(scanner_name, ScannerConfig())


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
    )


def _parse_execution_config(raw: dict | None) -> ExecutionConfig:
    """Build an ExecutionConfig from a raw dict."""
    if not isinstance(raw, dict):
        return ExecutionConfig()

    return ExecutionConfig(
        backend=raw.get("backend", "auto"),
        registry=raw.get("registry", ""),
        pull_policy=raw.get("pull_policy", "if-not-present"),
    )
