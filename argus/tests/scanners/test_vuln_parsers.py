"""PURL propagation in the shared trivy/grype vuln parsers (issue #229).

The package URL is the canonical product key for VEX / SBOM correlation;
these assert the normalization tier carries it through from raw tool output.
"""

from argus.scanners._vuln_parsers import parse_grype_match, parse_trivy_vuln


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
