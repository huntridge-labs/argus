"""Tests for argus.core.models — Severity, Finding, ScanResult, ScanSummary."""

import pytest

from argus.core.models import (
    Finding,
    PhaseResult,
    ScanResult,
    ScanSummary,
    Severity,
)


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


class TestPhaseResultAndPartialFailure:
    """PhaseResult serialization and ScanResult.partial_failure plumbing.

    Locks in the multi-phase shape behind issues #169 / #170 — every
    consumer downstream of the engine (terminal, markdown, SARIF,
    JSON, viewer) keys off ``partial_failure`` and ``failed_phases``,
    so the dataclass guarantees need explicit coverage rather than
    relying on the terraform/container integration tests.
    """

    def test_phase_result_to_dict_roundtrip(self):
        phase = PhaseResult(
            phase="terraform-fmt",
            status="failed",
            findings=[
                Finding(id="x", severity=Severity.INFO, title="t"),
            ],
            error="image pull failed",
        )
        d = phase.to_dict()
        assert d["phase"] == "terraform-fmt"
        assert d["status"] == "failed"
        assert d["error"] == "image pull failed"
        assert len(d["findings"]) == 1
        assert d["findings"][0]["severity"] == "info"

    def test_scan_result_partial_failure_false_without_phases(self):
        # Single-phase scanners leave phase_results=None — they must
        # never report partial_failure=True, otherwise every legacy
        # scanner suddenly enters the "did not run cleanly" bucket.
        result = ScanResult(scanner="bandit")
        assert result.partial_failure is False
        assert result.failed_phases == []

    def test_scan_result_partial_failure_true_when_phase_failed(self):
        result = ScanResult(
            scanner="lint-terraform",
            phase_results=[
                PhaseResult(phase="terraform-fmt", status="ran"),
                PhaseResult(
                    phase="terraform-validate",
                    status="failed",
                    error="image pull failed",
                ),
                PhaseResult(phase="tflint", status="skipped"),
            ],
        )
        assert result.partial_failure is True
        failed = result.failed_phases
        assert len(failed) == 1
        assert failed[0].phase == "terraform-validate"

    def test_scan_result_to_dict_includes_phase_results(self):
        # phase_results + partial_failure only appear when there's
        # something to report — keeps the JSON contract stable for
        # single-phase scanners.
        result = ScanResult(
            scanner="lint-terraform",
            phase_results=[
                PhaseResult(phase="terraform-fmt", status="ran"),
                PhaseResult(
                    phase="terraform-validate",
                    status="failed",
                    error="image pull failed",
                ),
            ],
        )
        d = result.to_dict()
        assert d["partial_failure"] is True
        assert len(d["phase_results"]) == 2
        assert d["phase_results"][1]["status"] == "failed"
        assert d["phase_results"][1]["error"] == "image pull failed"

    def test_scan_result_to_dict_omits_phase_results_when_none(self):
        result = ScanResult(scanner="bandit")
        d = result.to_dict()
        assert "phase_results" not in d
        assert "partial_failure" not in d

    def test_scan_result_from_dict_rehydrates_phase_results(self):
        # The from_dict branch lit by phase-aware scanners must
        # rebuild full PhaseResult objects, not raw dicts — otherwise
        # downstream consumers calling result.partial_failure or
        # result.failed_phases blow up on AttributeError.
        payload = {
            "scanner": "lint-terraform",
            "findings": [],
            "phase_results": [
                {
                    "phase": "terraform-fmt",
                    "status": "ran",
                    "findings": [],
                    "error": None,
                },
                {
                    "phase": "terraform-validate",
                    "status": "failed",
                    "findings": [
                        {
                            "id": "tf-1",
                            "severity": "info",
                            "title": "diag",
                            "description": "",
                            "scanner": "lint-terraform",
                        },
                    ],
                    "error": "boom",
                },
            ],
        }
        result = ScanResult.from_dict(payload)
        assert result.partial_failure is True
        assert len(result.phase_results) == 2
        validate_phase = result.failed_phases[0]
        assert validate_phase.phase == "terraform-validate"
        assert validate_phase.error == "boom"
        assert len(validate_phase.findings) == 1
        assert validate_phase.findings[0].severity == Severity.INFO

    def test_scan_result_from_dict_without_phase_results(self):
        # Legacy payloads (no phase_results key) round-trip cleanly.
        payload = {"scanner": "bandit", "findings": []}
        result = ScanResult.from_dict(payload)
        assert result.phase_results is None
        assert result.partial_failure is False
