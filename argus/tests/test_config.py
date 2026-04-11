"""Tests for argus.core.config — ArgusConfig, ScannerConfig, ReportingConfig."""

import pytest

from argus.core.config import ArgusConfig, ScannerConfig, ReportingConfig
from argus.core.models import Severity


class TestArgusConfigFromDict:
    """Test ArgusConfig.from_dict with various structures."""

    def test_minimal_dict(self):
        config = ArgusConfig.from_dict({})
        assert config.version == "1.0"
        assert config.scanners == {}
        assert config.reporting.formats == ["terminal"]

    def test_version_override(self):
        config = ArgusConfig.from_dict({"version": "2.0"})
        assert config.version == "2.0"

    def test_scanner_config_parsed(self):
        data = {
            "scanners": {
                "bandit": {
                    "enabled": True,
                    "path": "src",
                    "severity_threshold": "high",
                },
                "gitleaks": {
                    "enabled": False,
                },
            },
        }
        config = ArgusConfig.from_dict(data)
        assert "bandit" in config.scanners
        assert config.scanners["bandit"].enabled is True
        assert config.scanners["bandit"].path == "src"
        assert config.scanners["bandit"].severity_threshold == Severity.HIGH
        assert config.scanners["gitleaks"].enabled is False

    def test_scanner_config_extra_keys(self):
        data = {
            "scanners": {
                "bandit": {
                    "enabled": True,
                    "custom_option": "value",
                },
            },
        }
        config = ArgusConfig.from_dict(data)
        assert config.scanners["bandit"].extra == {"custom_option": "value"}

    def test_reporting_config_parsed(self):
        data = {
            "reporting": {
                "formats": ["terminal", "markdown", "sarif"],
                "severity_threshold": "medium",
                "output_dir": "/tmp/results",
            },
        }
        config = ArgusConfig.from_dict(data)
        assert config.reporting.formats == ["terminal", "markdown", "sarif"]
        assert config.reporting.severity_threshold == Severity.MEDIUM
        assert config.reporting.output_dir == "/tmp/results"

    def test_non_dict_scanner_entry_skipped(self):
        data = {
            "scanners": {
                "bandit": "invalid",
            },
        }
        config = ArgusConfig.from_dict(data)
        assert "bandit" not in config.scanners

    def test_non_dict_reporting_returns_defaults(self):
        data = {"reporting": "invalid"}
        config = ArgusConfig.from_dict(data)
        assert config.reporting.formats == ["terminal"]


class TestArgusConfigLoad:
    """Test ArgusConfig.load from file."""

    def test_load_from_yaml_file(self, tmp_path):
        config_file = tmp_path / "argus.yml"
        config_file.write_text(
            "version: '2.0'\n"
            "scanners:\n"
            "  bandit:\n"
            "    enabled: true\n"
            "    path: src\n"
            "reporting:\n"
            "  formats:\n"
            "    - terminal\n"
            "    - json\n"
        )
        config = ArgusConfig.load(config_file)
        assert config.version == "2.0"
        assert "bandit" in config.scanners
        assert config.reporting.formats == ["terminal", "json"]

    def test_load_nonexistent_file_returns_defaults(self):
        config = ArgusConfig.load("/nonexistent/path/argus.yml")
        assert config.version == "1.0"
        assert config.scanners == {}

    def test_load_none_returns_defaults(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        config = ArgusConfig.load(None)
        assert config.version == "1.0"

    def test_load_empty_yaml_returns_defaults(self, tmp_path):
        config_file = tmp_path / "argus.yml"
        config_file.write_text("")
        config = ArgusConfig.load(config_file)
        assert config.version == "1.0"


class TestGetScannerConfig:
    """Test ArgusConfig.get_scanner_config."""

    def test_existing_scanner(self):
        config = ArgusConfig.from_dict({
            "scanners": {
                "bandit": {"enabled": True, "path": "src"},
            },
        })
        sc = config.get_scanner_config("bandit")
        assert sc.enabled is True
        assert sc.path == "src"

    def test_missing_scanner_returns_defaults(self):
        config = ArgusConfig.from_dict({})
        sc = config.get_scanner_config("nonexistent")
        assert isinstance(sc, ScannerConfig)
        assert sc.enabled is True
        assert sc.path == "."
        assert sc.severity_threshold is None
        assert sc.config_file is None


class TestScannerConfigDefaults:
    """Test ScannerConfig default values."""

    def test_defaults(self):
        sc = ScannerConfig()
        assert sc.enabled is True
        assert sc.path == "."
        assert sc.severity_threshold is None
        assert sc.config_file is None
        assert sc.extra == {}


class TestReportingConfigDefaults:
    """Test ReportingConfig default values."""

    def test_defaults(self):
        rc = ReportingConfig()
        assert rc.formats == ["terminal"]
        assert rc.severity_threshold is None
        assert rc.output_dir == "./argus-results"
