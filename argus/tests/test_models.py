"""Tests for argus.core.models — Severity, Finding, ScanResult, ScanSummary."""

import pytest

from argus.core.models import Severity, Finding, ScanResult, ScanSummary


class TestSeverityFromString:
    """Test Severity.from_string with various inputs."""

    @pytest.mark.parametrize("input_str,expected", [
        ("critical", Severity.CRITICAL),
        ("CRITICAL", Severity.CRITICAL),
        ("Critical", Severity.CRITICAL),
        ("high", Severity.HIGH),
        ("HIGH", Severity.HIGH),
        ("medium", Severity.MEDIUM),
        ("MEDIUM", Severity.MEDIUM),
        ("moderate", Severity.MEDIUM),
        ("low", Severity.LOW),
        ("LOW", Severity.LOW),
        ("info", Severity.INFO),
        ("informational", Severity.INFO),
        ("error", Severity.HIGH),
        ("warning", Severity.MEDIUM),
        ("note", Severity.LOW),
        ("unknown", Severity.UNKNOWN),
    ])
    def test_known_inputs(self, input_str, expected):
        assert Severity.from_string(input_str) == expected

    def test_garbage_input_returns_unknown(self):
        assert Severity.from_string("garbage") == Severity.UNKNOWN

    def test_empty_string_returns_unknown(self):
        assert Severity.from_string("") == Severity.UNKNOWN

    def test_whitespace_handling(self):
        assert Severity.from_string("  high  ") == Severity.HIGH


class TestSeverityComparison:
    """Test Severity ordering comparisons."""

    def test_critical_greater_than_high(self):
        assert Severity.CRITICAL > Severity.HIGH

    def test_high_greater_than_medium(self):
        assert Severity.HIGH > Severity.MEDIUM

    def test_medium_greater_than_low(self):
        assert Severity.MEDIUM > Severity.LOW

    def test_low_greater_than_info(self):
        assert Severity.LOW > Severity.INFO

    def test_info_greater_than_unknown(self):
        assert Severity.INFO > Severity.UNKNOWN

    def test_critical_ge_critical(self):
        assert Severity.CRITICAL >= Severity.CRITICAL

    def test_low_le_high(self):
        assert Severity.LOW <= Severity.HIGH

    def test_unknown_lt_info(self):
        assert Severity.UNKNOWN < Severity.INFO

    def test_full_ordering(self):
        ordered = [
            Severity.UNKNOWN,
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        for i in range(len(ordered) - 1):
            assert ordered[i] < ordered[i + 1]


class TestFinding:
    """Test Finding dataclass."""

    def test_creation_minimal(self):
        finding = Finding(
            id="TEST-001",
            severity=Severity.HIGH,
            title="Test finding",
        )
        assert finding.id == "TEST-001"
        assert finding.severity == Severity.HIGH
        assert finding.title == "Test finding"
        assert finding.description == ""
        assert finding.location is None
        assert finding.cwe is None
        assert finding.cve is None
        assert finding.scanner == ""
        assert finding.metadata == {}

    def test_creation_full(self):
        finding = Finding(
            id="CVE-2024-0001",
            severity=Severity.CRITICAL,
            title="Critical vuln",
            description="A critical vulnerability",
            location="src/app.py:42",
            cwe="CWE-79",
            cve="CVE-2024-0001",
            scanner="bandit",
            metadata={"confidence": "HIGH"},
        )
        assert finding.cve == "CVE-2024-0001"
        assert finding.cwe == "CWE-79"
        assert finding.scanner == "bandit"

    def test_to_dict(self):
        finding = Finding(
            id="B102",
            severity=Severity.HIGH,
            title="Use of exec",
            location="app.py:25",
            scanner="bandit",
        )
        d = finding.to_dict()
        assert d["id"] == "B102"
        assert d["severity"] == "high"
        assert d["title"] == "Use of exec"
        assert d["location"] == "app.py:25"
        assert d["scanner"] == "bandit"

    def test_frozen_immutable(self):
        finding = Finding(id="X", severity=Severity.LOW, title="T")
        with pytest.raises(AttributeError):
            finding.id = "Y"


class TestScanResult:
    """Test ScanResult dataclass."""

    def _make_findings(self):
        return [
            Finding(id="1", severity=Severity.CRITICAL, title="crit"),
            Finding(id="2", severity=Severity.HIGH, title="high1"),
            Finding(id="3", severity=Severity.HIGH, title="high2"),
            Finding(id="4", severity=Severity.MEDIUM, title="med"),
            Finding(id="5", severity=Severity.LOW, title="low"),
        ]

    def test_empty_result(self):
        result = ScanResult(scanner="test")
        assert result.critical_count == 0
        assert result.high_count == 0
        assert result.medium_count == 0
        assert result.low_count == 0
        assert result.total_count == 0

    def test_severity_counts(self):
        result = ScanResult(scanner="test", findings=self._make_findings())
        assert result.critical_count == 1
        assert result.high_count == 2
        assert result.medium_count == 1
        assert result.low_count == 1
        assert result.total_count == 5

    def test_to_dict(self):
        result = ScanResult(
            scanner="bandit",
            findings=[Finding(id="B102", severity=Severity.HIGH, title="exec")],
        )
        d = result.to_dict()
        assert d["scanner"] == "bandit"
        assert d["total_count"] == 1
        assert d["high_count"] == 1
        assert len(d["findings"]) == 1
        assert d["findings"][0]["severity"] == "high"


class TestScanSummary:
    """Test ScanSummary dataclass."""

    def _make_summary(self, threshold=None):
        result_a = ScanResult(
            scanner="scanner-a",
            findings=[
                Finding(id="1", severity=Severity.CRITICAL, title="crit"),
                Finding(id="2", severity=Severity.HIGH, title="high"),
            ],
        )
        result_b = ScanResult(
            scanner="scanner-b",
            findings=[
                Finding(id="3", severity=Severity.MEDIUM, title="med"),
                Finding(id="4", severity=Severity.LOW, title="low"),
            ],
        )
        return ScanSummary(
            results=[result_a, result_b],
            severity_threshold=threshold,
        )

    def test_aggregated_counts(self):
        summary = self._make_summary()
        assert summary.critical_count == 1
        assert summary.high_count == 1
        assert summary.medium_count == 1
        assert summary.low_count == 1
        assert summary.total_count == 4

    def test_passed_no_threshold(self):
        summary = self._make_summary(threshold=None)
        assert summary.passed is True

    def test_passed_threshold_below_findings(self):
        summary = self._make_summary(threshold=Severity.CRITICAL)
        assert summary.passed is False

    def test_passed_threshold_above_findings(self):
        result = ScanResult(
            scanner="test",
            findings=[
                Finding(id="1", severity=Severity.LOW, title="low"),
            ],
        )
        summary = ScanSummary(
            results=[result],
            severity_threshold=Severity.HIGH,
        )
        assert summary.passed is True

    def test_passed_threshold_exact_match(self):
        result = ScanResult(
            scanner="test",
            findings=[
                Finding(id="1", severity=Severity.HIGH, title="high"),
            ],
        )
        summary = ScanSummary(
            results=[result],
            severity_threshold=Severity.HIGH,
        )
        assert summary.passed is False

    def test_to_dict(self):
        summary = self._make_summary(threshold=Severity.HIGH)
        d = summary.to_dict()
        assert d["total_count"] == 4
        assert d["severity_threshold"] == "high"
        assert d["passed"] is False
        assert len(d["results"]) == 2

    def test_empty_summary(self):
        summary = ScanSummary()
        assert summary.total_count == 0
        assert summary.passed is True

    def test_from_dict_round_trips_findings_and_threshold(self):
        # Offline consumers (argus view terminal / external dashboards) read
        # a persisted argus-results.json back into a ScanSummary via
        # from_dict. Round-trip must preserve findings, severity
        # threshold, and per-scanner grouping.
        source = self._make_summary(threshold=Severity.HIGH)
        serialized = source.to_dict()
        restored = ScanSummary.from_dict(serialized)
        assert restored.severity_threshold == Severity.HIGH
        assert len(restored.results) == 2
        assert restored.total_count == 4
        # Finding identities survive — the CLI-less browser workflow
        # needs stable ids so pre-scan triage notes stay linked.
        restored_ids = {f.id for r in restored.results for f in r.findings}
        assert restored_ids == {"1", "2", "3", "4"}

    def test_from_dict_unrecognized_severity_becomes_unknown(self):
        # ``Severity.from_string`` returns ``UNKNOWN`` for values it
        # doesn't recognize (it normalizes via an alias table rather
        # than raising). So a hand-edited or forward-compatible
        # threshold loads as UNKNOWN instead of dying on import —
        # downstream consumers can still compare against it.
        payload = {
            "severity_threshold": "bogus",
            "results": [],
        }
        restored = ScanSummary.from_dict(payload)
        assert restored.severity_threshold == Severity.UNKNOWN
        assert restored.results == []

    def test_from_dict_missing_threshold_keeps_none(self):
        # severity_threshold is optional; from_dict should accept
        # payloads without it (older scan files pre-threshold).
        restored = ScanSummary.from_dict({"results": []})
        assert restored.severity_threshold is None

    def test_from_dict_empty_threshold_stays_none(self):
        # Explicit empty string is treated as "no threshold" — the
        # ``if raw_threshold:`` guard skips the parse entirely.
        restored = ScanSummary.from_dict({"severity_threshold": "", "results": []})
        assert restored.severity_threshold is None
