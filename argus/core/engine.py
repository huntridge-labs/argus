"""Argus engine — orchestrates scanner execution and result aggregation."""

import logging

from .config import ArgusConfig
from .models import ScanResult, ScanSummary
from .scanner import Scanner

logger = logging.getLogger("argus")


class ArgusEngine:
    """Orchestrates registered scanners and aggregates their results."""

    def __init__(self, config: ArgusConfig):
        self.config = config
        self._scanners: dict[str, Scanner] = {}

    def register_scanner(self, scanner: Scanner) -> None:
        """Register a scanner instance for use by the engine."""
        self._scanners[scanner.name] = scanner

    def run(
        self,
        scanner_names: list[str] | None = None,
        path: str | None = None,
    ) -> ScanSummary:
        """Run scanners and return an aggregated ScanSummary.

        If *scanner_names* is None, all registered scanners whose config
        has ``enabled=True`` are executed. If *path* is provided it
        overrides the per-scanner path from config.
        """
        names_to_run = self._resolve_scanner_names(scanner_names)
        results: list[ScanResult] = []

        for name in names_to_run:
            scanner = self._scanners.get(name)
            if scanner is None:
                logger.warning("Scanner '%s' is not registered — skipping", name)
                continue

            if not scanner.is_available():
                cmd = scanner.install_command()
                hint = f" Install with: {cmd}" if cmd else ""
                logger.warning(
                    "Scanner '%s' is not available — skipping.%s", name, hint
                )
                continue

            scanner_config = self.config.get_scanner_config(name)
            scan_path = path if path is not None else scanner_config.path
            config_dict = self._build_scanner_config_dict(scanner_config)

            try:
                result = scanner.scan(scan_path, config=config_dict)
                results.append(result)
            except Exception:
                logger.exception("Scanner '%s' failed", name)

        return ScanSummary(
            results=results,
            severity_threshold=self.config.reporting.severity_threshold,
        )

    def get_available_scanners(self) -> list[str]:
        """Return names of registered scanners that are currently available."""
        return [
            name
            for name, scanner in self._scanners.items()
            if scanner.is_available()
        ]

    def _resolve_scanner_names(self, requested: list[str] | None) -> list[str]:
        """Determine which scanners to run."""
        if requested is not None:
            return requested

        return [
            name
            for name in self._scanners
            if self.config.get_scanner_config(name).enabled
        ]

    @staticmethod
    def _build_scanner_config_dict(scanner_config) -> dict:
        """Flatten a ScannerConfig into a plain dict for the scanner."""
        config_dict: dict = {}
        if scanner_config.config_file:
            config_dict["config_file"] = scanner_config.config_file
        if scanner_config.severity_threshold:
            config_dict["severity_threshold"] = scanner_config.severity_threshold.value
        if scanner_config.extra:
            config_dict.update(scanner_config.extra)
        return config_dict
