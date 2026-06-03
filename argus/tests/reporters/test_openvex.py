"""Tests for the OpenVEX reporter (issue #229 spike).

Asserts: registered as a built-in; emits a valid OpenVEX v0.2.0 document keyed
by PURL; dedups (CVE, product) across scanners; synthesizes a PURL for OSV
findings; excludes non-CVE / non-component findings (SAST/IaC/secrets/DAST);
and produces a deterministic @id for the same findings.
"""

import json

from argus.core.models import Finding, ScanResult, ScanSummary, Severity
from argus.reporters import available_reporters, get_reporter
from argus.reporters.openvex import OPENVEX_CONTEXT, OpenVexReporter


def _finding(cve, scanner, **meta):
    return Finding(
        id=cve or "x", severity=Severity.HIGH, title="t",
        cve=cve, scanner=scanner, metadata=meta,
    )


def _summary(findings):
    return ScanSummary(results=[ScanResult(scanner="multi", findings=findings)])


class TestOpenVexRegistration:
    def test_registered_as_builtin(self):
        assert "openvex" in available_reporters()
        assert type(get_reporter("openvex")).__name__ == "OpenVexReporter"


class TestOpenVexEmission:
    def test_emits_valid_openvex_document(self, tmp_path):
        finding = _finding(
            "CVE-2021-44228", "grype", package="log4j-core", installed_version="2.14.1",
            purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        )
        path = OpenVexReporter().report(_summary([finding]), tmp_path)
        assert path.name == "argus-results.openvex.json"
        doc = json.loads(path.read_text())
        assert doc["@context"] == OPENVEX_CONTEXT
        assert doc["@id"].startswith("https://")
        assert doc["version"] == 1
        assert "timestamp" in doc
        assert len(doc["statements"]) == 1
        statement = doc["statements"][0]
        assert statement["vulnerability"]["name"] == "CVE-2021-44228"
        assert statement["products"][0]["@id"] == (
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
        )
        assert statement["status"] == "affected"

    def test_dedups_same_cve_and_product_across_scanners(self, tmp_path):
        purl = "pkg:maven/log4j-core@2.14.1"
        findings = [
            _finding("CVE-2021-44228", "grype", package="log4j-core", purl=purl),
            _finding("CVE-2021-44228", "trivy", package="log4j-core", purl=purl),
        ]
        doc = json.loads(OpenVexReporter().report(_summary(findings), tmp_path).read_text())
        assert len(doc["statements"]) == 1

    def test_synthesizes_purl_for_osv_from_ecosystem(self, tmp_path):
        finding = _finding(
            "CVE-2020-8203", "osv",
            package_name="lodash", package_version="4.17.15", ecosystem="npm",
        )
        doc = json.loads(OpenVexReporter().report(_summary([finding]), tmp_path).read_text())
        assert doc["statements"][0]["products"][0]["@id"] == "pkg:npm/lodash@4.17.15"

    def test_excludes_non_cve_and_non_component_findings(self, tmp_path):
        findings = [
            _finding(None, "mumps", taint_sources=["X"]),  # SAST: no CVE
            _finding(None, "bandit"),                       # no CVE
            _finding("CVE-1", "grype"),                     # CVE but no component -> no product
        ]
        doc = json.loads(OpenVexReporter().report(_summary(findings), tmp_path).read_text())
        assert doc["statements"] == []

    def test_id_is_deterministic_for_same_findings(self, tmp_path):
        finding = _finding("CVE-1", "grype", package="p", purl="pkg:pypi/p@1")
        doc_a = json.loads(OpenVexReporter().report(_summary([finding]), tmp_path / "a").read_text())
        doc_b = json.loads(OpenVexReporter().report(_summary([finding]), tmp_path / "b").read_text())
        assert doc_a["@id"] == doc_b["@id"]
