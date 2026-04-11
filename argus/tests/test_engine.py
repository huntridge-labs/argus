"""Tests for argus.core.engine — ArgusEngine."""

import pytest

from argus.core.config import ArgusConfig, ScannerConfig
from argus.core.engine import ArgusEngine
from argus.core.models import Finding, ScanResult, Severity, ScanSummary


class MockScanner:
    """A mock scanner that returns canned results."""

    def __init__(self, name, findings=None, available=True):
        self.name = name
        self._findings = findings or []
        self._available = available
        self.scan_called_with = None

    def scan(self, path, config=None):
        self.scan_called_with = (path, config)
        return ScanResult(scanner=self.name, findings=self._findings)

    def is_available(self):
        return self._available

    def install_command(self):
        return f"pip install {self.name}"


class TestArgusEngine:
    """Test ArgusEngine orchestration."""

    def _make_engine(self, scanners_config=None, reporting_config=None):
        data = {}
        if scanners_config:
            data["scanners"] = scanners_config
        if reporting_config:
            data["reporting"] = reporting_config
        config = ArgusConfig.from_dict(data)
        return ArgusEngine(config)

    def test_register_scanner(self):
        engine = self._make_engine()
        scanner = MockScanner("bandit")
        engine.register_scanner(scanner)
        assert "bandit" in engine._scanners

    def test_run_all_enabled_scanners(self):
        engine = self._make_engine(
            scanners_config={
                "bandit": {"enabled": True},
                "gitleaks": {"enabled": True},
            }
        )
        findings_a = [Finding(id="1", severity=Severity.HIGH, title="f1")]
        findings_b = [Finding(id="2", severity=Severity.LOW, title="f2")]

        engine.register_scanner(MockScanner("bandit", findings=findings_a))
        engine.register_scanner(MockScanner("gitleaks", findings=findings_b))

        summary = engine.run()
        assert isinstance(summary, ScanSummary)
        assert len(summary.results) == 2
        assert summary.total_count == 2

    def test_run_specific_scanners(self):
        engine = self._make_engine(
            scanners_config={
                "bandit": {"enabled": True},
                "gitleaks": {"enabled": True},
            }
        )
        findings = [Finding(id="1", severity=Severity.HIGH, title="f1")]
        engine.register_scanner(MockScanner("bandit", findings=findings))
        engine.register_scanner(MockScanner("gitleaks"))

        summary = engine.run(scanner_names=["bandit"])
        assert len(summary.results) == 1
        assert summary.results[0].scanner == "bandit"

    def test_run_skips_disabled_scanners(self):
        engine = self._make_engine(
            scanners_config={
                "bandit": {"enabled": True},
                "gitleaks": {"enabled": False},
            }
        )
        engine.register_scanner(MockScanner("bandit"))
        engine.register_scanner(MockScanner("gitleaks"))

        summary = engine.run()
        assert len(summary.results) == 1
        assert summary.results[0].scanner == "bandit"

    def test_run_skips_unavailable_scanners(self):
        engine = self._make_engine(
            scanners_config={"bandit": {"enabled": True}}
        )
        engine.register_scanner(MockScanner("bandit", available=False))

        summary = engine.run()
        assert len(summary.results) == 0

    def test_run_skips_unregistered_scanners(self):
        engine = self._make_engine()
        summary = engine.run(scanner_names=["nonexistent"])
        assert len(summary.results) == 0

    def test_run_with_path_override(self):
        engine = self._make_engine(
            scanners_config={"bandit": {"enabled": True, "path": "default"}}
        )
        mock = MockScanner("bandit")
        engine.register_scanner(mock)

        engine.run(path="/override/path")
        assert mock.scan_called_with[0] == "/override/path"

    def test_run_uses_config_path(self):
        engine = self._make_engine(
            scanners_config={"bandit": {"enabled": True, "path": "src"}}
        )
        mock = MockScanner("bandit")
        engine.register_scanner(mock)

        engine.run()
        assert mock.scan_called_with[0] == "src"

    def test_get_available_scanners(self):
        engine = self._make_engine()
        engine.register_scanner(MockScanner("bandit", available=True))
        engine.register_scanner(MockScanner("gitleaks", available=False))
        engine.register_scanner(MockScanner("trivy-iac", available=True))

        available = engine.get_available_scanners()
        assert "bandit" in available
        assert "trivy-iac" in available
        assert "gitleaks" not in available

    def test_run_handles_scanner_exception(self):
        engine = self._make_engine(
            scanners_config={"bad": {"enabled": True}}
        )

        class FailingScanner:
            name = "bad"

            def scan(self, path, config=None):
                raise RuntimeError("Scanner exploded")

            def is_available(self):
                return True

            def install_command(self):
                return None

        engine.register_scanner(FailingScanner())
        summary = engine.run()
        assert len(summary.results) == 0
