"""Tests for argus.core.config — ArgusConfig, ScannerConfig, ReportingConfig."""

import pytest

from argus.core.config import ArgusConfig, ExecutionConfig, ScannerConfig, ReportingConfig
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

    def test_severity_threshold_none_string_is_no_threshold(self):
        """severity_threshold: 'none' in config means no threshold (not UNKNOWN)."""
        data = {
            "reporting": {"severity_threshold": "none"},
        }
        config = ArgusConfig.from_dict(data)
        assert config.reporting.severity_threshold is None

    def test_severity_threshold_none_value_is_no_threshold(self):
        """severity_threshold: null in YAML means no threshold."""
        data = {
            "reporting": {"severity_threshold": None},
        }
        config = ArgusConfig.from_dict(data)
        assert config.reporting.severity_threshold is None

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

    def test_keep_raw_defaults_off(self):
        """keep_raw defaults to False because scanners like gitleaks write
        literal matched secret bytes into raw output, so persisting raw by
        default leaks data the canonical argus-results.json already
        pattern-redacts. See issue #168-B."""
        config = ArgusConfig.from_dict({})
        assert config.reporting.keep_raw is False

    def test_keep_raw_opt_in_via_config(self):
        """Forensic / triage workflows opt in via reporting.keep_raw: true."""
        config = ArgusConfig.from_dict({"reporting": {"keep_raw": True}})
        assert config.reporting.keep_raw is True


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

    def test_load_nonexistent_file_auto_detects(self):
        config = ArgusConfig.load("/nonexistent/path/argus.yml")
        assert config.version == "1.0"
        # Auto-detect generates a tailored config, not empty
        assert isinstance(config.scanners, dict)

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
        # Empty scanners dict = bare config, defaults to enabled
        assert sc.enabled is True

    def test_unknown_scanner_disabled_when_config_has_entries(self):
        """When config has explicit scanner entries, unknown scanners are disabled."""
        config = ArgusConfig.from_dict({
            "scanners": {
                "bandit": {"enabled": True},
                "gitleaks": {"enabled": True},
            },
        })
        sc = config.get_scanner_config("nonexistent")
        assert sc.enabled is False
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


class TestExecutionConfig:
    """Test ExecutionConfig defaults and parsing."""

    def test_defaults(self):
        ec = ExecutionConfig()
        assert ec.backend == "auto"
        assert ec.registry == ""
        assert ec.pull_policy == "if-not-present"

    def test_from_dict(self):
        data = {
            "execution": {
                "backend": "docker",
                "registry": "registry.internal.corp/argus",
                "pull_policy": "always",
            },
        }
        config = ArgusConfig.from_dict(data)
        assert config.execution.backend == "docker"
        assert config.execution.registry == "registry.internal.corp/argus"
        assert config.execution.pull_policy == "always"

    def test_non_dict_execution_returns_defaults(self):
        config = ArgusConfig.from_dict({"execution": "invalid"})
        assert config.execution.backend == "auto"

    def test_load_execution_from_yaml(self, tmp_path):
        config_file = tmp_path / "argus.yml"
        config_file.write_text(
            "execution:\n"
            "  backend: local\n"
            "  pull_policy: never\n"
        )
        config = ArgusConfig.load(config_file)
        assert config.execution.backend == "local"
        assert config.execution.pull_policy == "never"


# ───────────────────────────────────────────────
# Strict YAML loader — duplicate-key detection (#177)
# ───────────────────────────────────────────────
#
# PyYAML's default mapping constructor silently keeps the last value
# when a key is duplicated. For argus.yml that means a second
# ``execution:`` block (or any other accidental duplication at any
# nesting level) overwrites the user's earlier settings — the schema
# validator never sees the conflict and reports the config valid.
# load_strict_yaml catches the duplication at parse time.


class TestStrictYamlLoaderRejectsDuplicateKeys:
    """``load_strict_yaml`` raises a YAMLError on any duplicate key."""

    def test_top_level_duplicate_raises(self):
        from argus.core.config import load_strict_yaml
        import yaml

        text = (
            "version: \"1.0\"\n"
            "execution:\n"
            "  registry: registry.internal.corp/argus\n"
            "  backend: docker\n"
            "execution:\n"
            "  backend: docker\n"
        )
        with pytest.raises(yaml.YAMLError) as excinfo:
            load_strict_yaml(text)
        # Message must name the duplicated key + the line of the
        # second occurrence so the user can find it in their editor.
        msg = str(excinfo.value)
        assert "duplicate key 'execution'" in msg
        assert "line 5" in msg

    def test_nested_duplicate_raises(self):
        # The same constructor override applies at every nesting
        # level — PyYAML calls construct_mapping for every mapping
        # node, not just the root.
        from argus.core.config import load_strict_yaml
        import yaml

        text = (
            "scanners:\n"
            "  bandit:\n"
            "    enabled: true\n"
            "    enabled: false\n"
        )
        with pytest.raises(yaml.YAMLError) as excinfo:
            load_strict_yaml(text)
        msg = str(excinfo.value)
        assert "duplicate key 'enabled'" in msg
        assert "line 4" in msg

    def test_unique_keys_load_normally(self):
        # Regression guard: the strict loader must NOT change behavior
        # for well-formed config — same dict the default safe_load
        # would have produced.
        from argus.core.config import load_strict_yaml

        text = (
            "version: \"1.0\"\n"
            "scanners:\n"
            "  bandit:\n"
            "    enabled: true\n"
            "  gitleaks:\n"
            "    enabled: false\n"
            "execution:\n"
            "  backend: docker\n"
        )
        data = load_strict_yaml(text)
        assert data["version"] == "1.0"
        assert data["scanners"]["bandit"]["enabled"] is True
        assert data["scanners"]["gitleaks"]["enabled"] is False
        assert data["execution"]["backend"] == "docker"

    def test_argus_config_load_surfaces_duplicate_as_value_error(
        self, tmp_path,
    ):
        # End-to-end: ArgusConfig.load wraps the YAMLError in a clean
        # ValueError that names the file so the user can pin the
        # error without seeing a PyYAML traceback.
        config_file = tmp_path / "argus.yml"
        config_file.write_text(
            "version: \"1.0\"\n"
            "execution:\n"
            "  backend: docker\n"
            "execution:\n"
            "  backend: local\n"
        )
        with pytest.raises(ValueError) as excinfo:
            ArgusConfig.load(config_file)
        msg = str(excinfo.value)
        assert "Invalid YAML" in msg
        assert str(config_file) in msg
        assert "duplicate key 'execution'" in msg

    def test_unhashable_key_is_reported_not_silently_ignored(self):
        # Defensive guard for an exotic case: a mapping key that
        # isn't hashable (e.g. a flow-style list used as a key) would
        # crash the default constructor with a confusing TypeError.
        # The strict loader reports it as a normal YAML error.
        from argus.core.config import load_strict_yaml
        import yaml

        text = "? [a, b]\n: value\n"
        with pytest.raises(yaml.YAMLError):
            load_strict_yaml(text)
