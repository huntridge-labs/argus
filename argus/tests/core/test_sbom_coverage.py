"""Tests for argus.core.sbom_coverage: the SBOM-mode coverage guard.

Fixtures are trimmed real outputs from the pinned tools (syft v1.54.1,
trivy 0.76.0, grype v0.120.1) against ``amazonlinux:2023.1.20230705.0``:

- ``tests/fixtures/sbom/*`` are the SBOMs (3 rpm packages + 1 pypi package)
- ``tests/fixtures/scanner-outputs/{trivy,grype}/sbom-*.json`` are what each
  matcher wrote for that SBOM
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus.core.models import ScanResult
from argus.core.sbom_coverage import (
    apply_coverage_guard,
    grype_coverage,
    trivy_coverage,
)

ROOT = Path(__file__).resolve().parents[3] / "tests" / "fixtures"
SBOMS = ROOT / "sbom"
OUTPUTS = ROOT / "scanner-outputs"


def _output(tool: str, sbom_name: str) -> dict:
    stem = sbom_name.removesuffix(".json")
    return json.loads((OUTPUTS / tool / f"sbom-{stem}.json").read_text())


class TestTrivyCoverage:
    def test_syft_spdx_os_read_as_none(self):
        cov = trivy_coverage(_output("trivy", "syft-amzn2023.spdx.json"))
        assert cov == {"os_packages_evaluated": False, "matcher_os": "none"}

    def test_syft_cyclonedx_os_unsupported(self):
        cov = trivy_coverage(_output("trivy", "syft-amzn2023.cdx.json"))
        assert cov == {"os_packages_evaluated": False, "matcher_os": "amzn 2023"}

    @pytest.mark.parametrize("name", ["trivy-amzn2023.cdx.json", "trivy-amzn2023.spdx.json"])
    def test_trivy_sbom_evaluates_os_packages(self, name):
        cov = trivy_coverage(_output("trivy", name))
        assert cov["os_packages_evaluated"] is True
        assert cov["matcher_os"] == "amazon 2023 (Amazon Linux)"

    def test_clean_os_result_still_counts_as_evaluated(self):
        # An os-pkgs result with no vulnerabilities is a clean OS, not a gap.
        data = {
            "Metadata": {"OS": {"Family": "debian", "Name": "12.5"}},
            "Results": [{"Class": "os-pkgs", "Vulnerabilities": None}],
        }
        assert trivy_coverage(data)["os_packages_evaluated"] is True

    def test_missing_metadata(self):
        assert trivy_coverage({}) == {"os_packages_evaluated": False, "matcher_os": "none"}


class TestGrypeCoverage:
    @pytest.mark.parametrize("name", [
        "syft-amzn2023.spdx.json",
        "syft-amzn2023.cdx.json",
        "syft-amzn2023.syft.json",
    ])
    def test_syft_sboms_evaluate_os_packages(self, name):
        cov = grype_coverage(_output("grype", name))
        assert cov == {"os_packages_evaluated": True, "matcher_os": "amazonlinux 2023"}

    @pytest.mark.parametrize("name", ["trivy-amzn2023.cdx.json", "trivy-amzn2023.spdx.json"])
    def test_trivy_sboms_distro_not_recognized(self, name):
        cov = grype_coverage(_output("grype", name))
        assert cov == {
            "os_packages_evaluated": False,
            "matcher_os": "amazon 2023 (Amazon Linux)",
        }

    def test_unknown_distro_with_os_matches_counts_as_evaluated(self):
        # A distro name grype added after our pin: if it matched OS
        # packages, it evaluated them.
        data = {
            "distro": {"name": "newdistro", "version": "1"},
            "matches": [{"artifact": {"type": "rpm", "purl": "pkg:rpm/x/y@1?distro=newdistro-1"}}],
        }
        assert grype_coverage(data)["os_packages_evaluated"] is True

    def test_no_distro(self):
        assert grype_coverage({"matches": []}) == {
            "os_packages_evaluated": False,
            "matcher_os": "none",
        }


class TestApplyCoverageGuard:
    def _result(self, scanner: str, sbom_name: str, **meta) -> ScanResult:
        tool = scanner
        metadata = {**(trivy_coverage if tool == "trivy" else grype_coverage)(
            _output(tool, sbom_name)), **meta}
        return ScanResult(scanner=scanner, metadata=metadata)

    @pytest.mark.parametrize("scanner,sbom_name", [
        ("trivy", "syft-amzn2023.spdx.json"),
        ("trivy", "syft-amzn2023.cdx.json"),
        ("grype", "trivy-amzn2023.cdx.json"),
        ("grype", "trivy-amzn2023.spdx.json"),
    ])
    def test_marks_skipped_os_packages_incomplete(self, scanner, sbom_name):
        result = apply_coverage_guard(
            self._result(scanner, sbom_name), SBOMS / sbom_name,
        )
        assert result.incomplete is True
        assert result.metadata["incomplete"] is True
        assert result.metadata["incomplete_os_packages"] == 3
        reason = result.metadata["incomplete_reason"]
        assert scanner in reason
        assert "3 OS package(s)" in reason
        assert "not clean" in reason

    @pytest.mark.parametrize("scanner,sbom_name", [
        ("grype", "syft-amzn2023.spdx.json"),
        ("grype", "syft-amzn2023.cdx.json"),
        ("grype", "syft-amzn2023.syft.json"),
        ("trivy", "trivy-amzn2023.cdx.json"),
        ("trivy", "trivy-amzn2023.spdx.json"),
    ])
    def test_leaves_covered_results_alone(self, scanner, sbom_name):
        result = apply_coverage_guard(
            self._result(scanner, sbom_name), SBOMS / sbom_name,
        )
        assert result.incomplete is False
        assert "incomplete" not in result.metadata

    def test_sbom_without_os_packages_is_never_incomplete(self, tmp_path):
        sbom = tmp_path / "app.cdx.json"
        sbom.write_text(
            '{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": ['
            '{"name": "requests", "purl": "pkg:pypi/requests@2.31.0"}]}'
        )
        result = ScanResult(
            scanner="trivy",
            metadata={"os_packages_evaluated": False, "matcher_os": "none"},
        )
        assert apply_coverage_guard(result, sbom).incomplete is False

    def test_scanner_without_coverage_signal_is_left_alone(self):
        # osv-scanner reports no coverage keys; the guard has nothing to go on.
        result = ScanResult(scanner="osv", metadata={})
        guarded = apply_coverage_guard(result, SBOMS / "syft-amzn2023.spdx.json")
        assert guarded.incomplete is False

    def test_failed_scanner_is_not_double_reported(self):
        result = ScanResult(
            scanner="trivy",
            metadata={"execution_failed": True, "os_packages_evaluated": False},
        )
        guarded = apply_coverage_guard(result, SBOMS / "syft-amzn2023.spdx.json")
        assert guarded.incomplete is False

    def test_unreadable_sbom_is_left_alone(self, tmp_path):
        result = ScanResult(scanner="trivy", metadata={"os_packages_evaluated": False})
        guarded = apply_coverage_guard(result, tmp_path / "missing.json")
        assert guarded.incomplete is False
