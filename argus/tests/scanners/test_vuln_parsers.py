"""PURL propagation in the shared trivy/grype vuln parsers (issue #229).

The package URL is the canonical product key for VEX / SBOM correlation;
these assert the normalization tier carries it through from raw tool output.
"""

import json
from pathlib import Path

from argus.scanners._vuln_parsers import (
    grype_db_built,
    parse_grype_match,
    parse_grype_report,
    parse_trivy_report,
    parse_trivy_vuln,
    trivy_db_built,
)


def test_trivy_propagates_purl_from_pkg_identifier():
    finding = parse_trivy_vuln({
        "VulnerabilityID": "CVE-2021-44228", "PkgName": "log4j-core",
        "InstalledVersion": "2.14.1", "FixedVersion": "2.17.1", "Severity": "CRITICAL",
        "PkgIdentifier": {"PURL": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
    })
    assert finding.cve == "CVE-2021-44228"
    assert finding.metadata["purl"] == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


def test_trivy_missing_purl_is_empty_string():
    finding = parse_trivy_vuln(
        {"VulnerabilityID": "CVE-1", "PkgName": "x", "InstalledVersion": "1"},
    )
    assert finding.metadata["purl"] == ""


def test_grype_propagates_purl_from_artifact():
    finding = parse_grype_match({
        "vulnerability": {"id": "CVE-2020-8203", "severity": "High",
                          "fix": {"versions": ["4.17.20"]}},
        "artifact": {"name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"},
    })
    assert finding.cve == "CVE-2020-8203"
    assert finding.metadata["purl"] == "pkg:npm/lodash@4.17.15"


# ---------------------------------------------------------------------------
# Triage fields (#495): advisory id, related CVEs, OS-package flag, matcher,
# data source, vulnerability DB build date. Fixtures are trimmed real output
# from grype v0.120.1 / trivy 0.76.0 on amazonlinux:2023.1.20230705.0.
# ---------------------------------------------------------------------------

_OUTPUTS = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "scanner-outputs"
_EXISTING_KEYS = {"tool", "package", "installed_version", "fixed_version", "purl"}


def _load(tool, name):
    return json.loads((_OUTPUTS / tool / name).read_text())


class TestGrypeTriageFields:
    def _finding(self):
        findings = parse_grype_report(_load("grype", "amzn2023-alas-match.json"))
        assert len(findings) == 1
        return findings[0]

    def test_advisory_id_and_related_cves(self):
        finding = self._finding()
        assert finding.id == "ALAS2023-2023-377"
        assert finding.metadata["advisory_id"] == "ALAS2023-2023-377"
        assert finding.metadata["related_cves"] == [
            {"id": "CVE-2023-38545", "severity": "critical"},
            {"id": "CVE-2023-38546", "severity": "low"},
        ]

    def test_os_package_matcher_and_source(self):
        meta = self._finding().metadata
        assert meta["os_package"] is True
        assert meta["matcher"] == "grype/rpm-matcher"
        assert meta["match_type"] == "exact-direct-match"
        assert meta["data_source"] == "amazon:distro:amazonlinux:2023"

    def test_db_build_date(self):
        assert self._finding().metadata["vulnerability_db_built"] == "2026-10-23T06:30:15Z"

    def test_existing_keys_and_values_unchanged(self):
        finding = self._finding()
        assert _EXISTING_KEYS <= finding.metadata.keys()
        assert finding.metadata["tool"] == "grype"
        assert finding.metadata["package"] == "curl-minimal"
        assert finding.cve is None  # an ALAS id is still not a CVE

    def test_cve_finding_has_no_advisory_id(self):
        finding = parse_grype_match({
            "vulnerability": {"id": "CVE-2020-8203", "severity": "High"},
            "artifact": {"name": "lodash", "version": "4.17.15", "type": "npm",
                         "purl": "pkg:npm/lodash@4.17.15"},
            "relatedVulnerabilities": [{"id": "CVE-2020-8203", "severity": "High"}],
        })
        assert finding.metadata["advisory_id"] == ""
        assert finding.metadata["os_package"] is False
        assert finding.metadata["related_cves"] == [{"id": "CVE-2020-8203", "severity": "high"}]
        assert finding.metadata["matcher"] == "grype"

    def test_ghsa_finding(self):
        finding = parse_grype_match({
            "vulnerability": {"id": "GHSA-jfh8-c2jp-5v3q", "severity": "Critical"},
            "artifact": {"name": "log4j-core", "version": "2.14.1", "type": "java-archive"},
            "relatedVulnerabilities": [
                {"id": "CVE-2021-44228", "severity": "Critical"},
                {"id": "GHSA-other", "severity": "High"},
            ],
        })
        assert finding.metadata["advisory_id"] == "GHSA-jfh8-c2jp-5v3q"
        assert finding.metadata["related_cves"] == [{"id": "CVE-2021-44228", "severity": "critical"}]

    def test_db_date_legacy_descriptor(self):
        assert grype_db_built({"descriptor": {"db": {"built": "2024-01-02T03:04:05Z"}}}) == (
            "2024-01-02T03:04:05Z"
        )
        assert grype_db_built({}) == ""


class TestTrivyTriageFields:
    def test_os_vulnerability(self):
        findings = parse_trivy_report(_load("trivy", "amzn2023-os-vuln.json"), db_built="2026-10-23T00:00:00Z")
        meta = findings[0].metadata
        assert findings[0].id == "CVE-2023-37920"
        assert meta["advisory_id"] == ""
        assert meta["related_cves"] == [{"id": "CVE-2023-37920", "severity": "critical"}]
        assert meta["os_package"] is True
        assert meta["matcher"] == "trivy"
        assert meta["data_source"] == "amazon"
        assert meta["vulnerability_db_built"] == "2026-10-23T00:00:00Z"
        assert _EXISTING_KEYS <= meta.keys()

    def test_vendor_advisory_id(self):
        finding = parse_trivy_vuln({
            "VulnerabilityID": "CVE-2023-4911", "VendorIDs": ["DSA-5514-1"],
            "PkgName": "libc6", "InstalledVersion": "2.36-9", "Severity": "HIGH",
            "VendorSeverity": {"nvd": 3, "debian": 3},
            "PkgIdentifier": {"PURL": "pkg:deb/debian/libc6@2.36-9?distro=debian-12"},
        })
        assert finding.metadata["advisory_id"] == "DSA-5514-1"
        assert finding.metadata["related_cves"] == [{"id": "CVE-2023-4911", "severity": "high"}]
        assert finding.metadata["os_package"] is True

    def test_language_package_from_result_class(self):
        report = {"Results": [{"Class": "lang-pkgs", "Vulnerabilities": [{
            "VulnerabilityID": "GHSA-xxxx-yyyy-zzzz", "PkgName": "requests",
            "InstalledVersion": "2.0.0", "Severity": "MEDIUM",
        }]}]}
        meta = parse_trivy_report(report)[0].metadata
        assert meta["os_package"] is False
        assert meta["advisory_id"] == "GHSA-xxxx-yyyy-zzzz"
        assert meta["related_cves"] == []
        assert meta["vulnerability_db_built"] == ""

    def test_cve_without_nvd_severity_uses_finding_severity(self):
        finding = parse_trivy_vuln({"VulnerabilityID": "CVE-1", "Severity": "LOW"})
        assert finding.metadata["related_cves"] == [{"id": "CVE-1", "severity": "low"}]


class TestTrivyDbBuilt:
    def _write_meta(self, root, updated, downloaded):
        db = root / "db"
        db.mkdir(parents=True)
        (db / "metadata.json").write_text(json.dumps({
            "Version": 2, "UpdatedAt": updated, "DownloadedAt": downloaded,
        }))

    def test_reads_newest_download(self, tmp_path, monkeypatch):
        old, new = tmp_path / "old", tmp_path / "new"
        self._write_meta(old, "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z")
        self._write_meta(new, "2026-10-23T00:00:00Z", "2026-10-23T01:00:00Z")
        assert trivy_db_built([old, new]) == "2026-10-23T00:00:00Z"

    def test_no_metadata(self, tmp_path):
        assert trivy_db_built([tmp_path / "missing"]) == ""

    def test_default_candidates_honor_env(self, tmp_path, monkeypatch):
        self._write_meta(tmp_path, "2026-10-20T00:00:00Z", "2026-10-20T01:00:00Z")
        monkeypatch.setenv("TRIVY_CACHE_DIR", str(tmp_path))
        monkeypatch.setenv("ARGUS_CACHE_DIR", str(tmp_path / "argus-none"))
        monkeypatch.setenv("HOME", str(tmp_path / "home-none"))
        assert trivy_db_built() == "2026-10-20T00:00:00Z"


class TestRedactionStillApplies:
    def test_secret_in_new_fields_is_redacted(self):
        token = "ghp_" + "a" * 36
        finding = parse_grype_match({
            "vulnerability": {"id": "GHSA-1", "severity": "High", "namespace": f"ns-{token}"},
            "artifact": {"name": "x", "version": "1"},
        })
        assert token not in json.dumps(finding.to_dict())


class TestEveryModeGetsTheFields:
    """SBOM mode and container mode share the parsers, so both get the fields."""

    def test_sbom_grype_scanner(self):
        from argus.scanners.grype import GrypeScanner

        parsed = GrypeScanner().parse_results(_OUTPUTS / "grype" / "amzn2023-alas-match.json")
        findings = parsed[0] if isinstance(parsed, tuple) else parsed
        assert findings[0].metadata["vulnerability_db_built"] == "2026-10-23T06:30:15Z"
        assert findings[0].metadata["advisory_id"] == "ALAS2023-2023-377"

    def test_sbom_trivy_scanner(self, monkeypatch):
        from argus.scanners import trivy as trivy_module
        from argus.scanners.trivy import TrivyScanner

        monkeypatch.setattr(trivy_module, "trivy_db_built", lambda: "2026-10-22T00:00:00Z")
        parsed = TrivyScanner().parse_results(_OUTPUTS / "trivy" / "amzn2023-os-vuln.json")
        findings = parsed[0] if isinstance(parsed, tuple) else parsed
        assert findings[0].metadata["os_package"] is True
        assert findings[0].metadata["vulnerability_db_built"] == "2026-10-22T00:00:00Z"

    def test_container_scanner_grype(self):
        from argus.scanners.container import ContainerScanner

        findings = ContainerScanner().parse_grype_results(
            _OUTPUTS / "grype" / "amzn2023-alas-match.json",
        )
        assert findings[0].scanner == "container"
        assert findings[0].metadata["related_cves"][0]["id"] == "CVE-2023-38545"
        assert findings[0].metadata["vulnerability_db_built"] == "2026-10-23T06:30:15Z"

    def test_container_scanner_trivy(self, monkeypatch):
        from argus.scanners import container as container_module
        from argus.scanners.container import ContainerScanner

        monkeypatch.setattr(container_module, "trivy_db_built", lambda: "2026-10-22T00:00:00Z")
        findings = ContainerScanner().parse_trivy_results(
            _OUTPUTS / "trivy" / "amzn2023-os-vuln.json",
        )
        assert findings[0].metadata["os_package"] is True
        assert findings[0].metadata["matcher"] == "trivy"
        assert findings[0].metadata["vulnerability_db_built"] == "2026-10-22T00:00:00Z"
