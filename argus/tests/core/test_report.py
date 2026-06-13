"""Phase B4 — formal vulnerability report model (UI-free).

No viewer extra needed: the model is pure data built from a ScanSummary, so
these run without FastAPI / WeasyPrint installed.
"""

from __future__ import annotations

from datetime import datetime, timezone

from argus.core.models import (
    Finding,
    ScanContext,
    ScanResult,
    ScanSummary,
    Severity,
)
from argus.core.report import build_report

_FIXED_TIME = datetime(2026, 6, 13, 14, 30, 0, tzinfo=timezone.utc)


def _finding(fid, severity, *, cve=None, scanner="osv", package=None):
    meta = {"sbom_source": "app.spdx"} if package else {}
    if package:
        meta["package"] = package
    return Finding(
        id=fid, severity=Severity.from_string(severity), title=f"{fid} title",
        cve=cve, scanner=scanner, metadata=meta,
    )


def _summary(findings, *, threshold=None, context=None, toolchain=None):
    return ScanSummary(
        results=[ScanResult(scanner="osv", findings=findings)],
        severity_threshold=Severity.from_string(threshold) if threshold else None,
        scan_context=context,
        toolchain=toolchain,
    )


def _flat(summary):
    return [f for r in summary.results for f in r.findings]


class TestProvenance:
    def test_version_and_timestamp_are_injectable(self):
        summary = _summary([_finding("A", "high")])
        report = build_report(
            summary, _flat(summary),
            argus_version="9.9.9", generated_at=_FIXED_TIME,
        )
        assert report.provenance.argus_version == "9.9.9"
        assert report.provenance.generated_at == "2026-06-13T14:30:00Z"

    def test_commit_short_truncates(self):
        ctx = ScanContext(commit_sha="0123456789abcdef0123456789abcdef01234567")
        summary = _summary([_finding("A", "high")], context=ctx)
        report = build_report(summary, _flat(summary), argus_version="1.0")
        assert report.provenance.commit_sha.startswith("0123456789ab")
        assert report.provenance.commit_short == "0123456789ab"

    def test_missing_commit_is_empty_not_fabricated(self):
        summary = _summary([_finding("A", "high")])
        report = build_report(summary, _flat(summary), argus_version="1.0")
        assert report.provenance.commit_sha == ""
        assert report.provenance.commit_short == ""

    def test_toolchain_surfaced(self):
        toolchain = {
            "images": [{"image": "ghcr.io/x/bandit@sha256:abc", "digest": "sha256:abc",
                        "verification": "verified_cosign"}],
            "argus_images_all_verified": True,
            "warnings": [],
        }
        summary = _summary([_finding("A", "high")], toolchain=toolchain)
        report = build_report(summary, _flat(summary), argus_version="1.0")
        assert report.provenance.toolchain_all_verified is True
        assert report.provenance.toolchain_images[0]["digest"] == "sha256:abc"


class TestAttestationDetection:
    def test_signed_bundle_detected(self, tmp_path):
        scan = tmp_path / "argus-results.json"
        scan.write_text("{}")
        (tmp_path / "argus-attestation.bundle").write_text("x")
        summary = _summary([_finding("A", "high")])
        report = build_report(summary, _flat(summary), scan_file=scan, argus_version="1.0")
        assert report.provenance.attestation == "signed"

    def test_unsigned_statement_detected(self, tmp_path):
        scan = tmp_path / "argus-results.json"
        scan.write_text("{}")
        (tmp_path / "argus-attestation.intoto.json").write_text("{}")
        summary = _summary([_finding("A", "high")])
        report = build_report(summary, _flat(summary), scan_file=scan, argus_version="1.0")
        assert report.provenance.attestation == "unsigned"

    def test_none_when_absent(self, tmp_path):
        scan = tmp_path / "argus-results.json"
        scan.write_text("{}")
        summary = _summary([_finding("A", "high")])
        report = build_report(summary, _flat(summary), scan_file=scan, argus_version="1.0")
        assert report.provenance.attestation == "none"

    def test_none_for_in_memory_scan(self):
        summary = _summary([_finding("A", "high")])
        report = build_report(summary, _flat(summary), argus_version="1.0")
        assert report.provenance.attestation == "none"


class TestSummaryAndGrouping:
    def test_counts_match_findings(self):
        findings = [
            _finding("C1", "critical"), _finding("H1", "high"),
            _finding("H2", "high"), _finding("L1", "low"),
        ]
        summary = _summary(findings)
        report = build_report(summary, findings, argus_version="1.0")
        assert report.total == 4
        assert report.by_severity["critical"] == 1
        assert report.by_severity["high"] == 2
        assert report.by_severity["low"] == 1

    def test_groups_ordered_critical_first(self):
        findings = [_finding("L1", "low"), _finding("C1", "critical"), _finding("H1", "high")]
        summary = _summary(findings)
        report = build_report(summary, findings, argus_version="1.0")
        order = [g.value for g in report.severity_groups]
        assert order == ["critical", "high", "low"]
        assert report.severity_groups[0].count == 1
        assert report.finding_count == 3

    def test_empty_scan_has_no_groups(self):
        summary = _summary([])
        report = build_report(summary, [], argus_version="1.0")
        assert report.severity_groups == []
        assert report.total == 0

    def test_threshold_and_pass_fail(self):
        findings = [_finding("H1", "high")]
        passing = _summary(findings, threshold="critical")
        failing = _summary(findings, threshold="high")
        assert build_report(passing, findings, argus_version="1.0").passed is True
        assert build_report(failing, findings, argus_version="1.0").passed is False
        assert build_report(failing, findings, argus_version="1.0").severity_threshold == "high"

    def test_groups_deterministic_within_severity(self):
        # Same severity, ids out of order → sorted by id for stable output.
        findings = [_finding("Z", "high"), _finding("A", "high"), _finding("M", "high")]
        summary = _summary(findings)
        report = build_report(summary, findings, argus_version="1.0")
        ids = [f.id for f in report.severity_groups[0].findings]
        assert ids == ["A", "M", "Z"]
