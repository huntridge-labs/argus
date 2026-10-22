"""Tests for argus.core.vex — the shared OpenVEX resolution helpers."""

from __future__ import annotations

from pathlib import Path

from argus.core.vex import (
    resolve_vex_documents,
    vex_cli_flags,
    vex_container_mounts,
)


def _doc(tmp_path: Path, name: str) -> Path:
    p = tmp_path / name
    p.write_text("{}")
    return p


# --------------------------------------------------------------------- #
# resolve_vex_documents                                                 #
# --------------------------------------------------------------------- #


def test_resolve_empty_without_config():
    assert resolve_vex_documents(None) == []
    assert resolve_vex_documents({}) == []
    assert resolve_vex_documents({"vex": None}) == []
    assert resolve_vex_documents({"vex": []}) == []


def test_resolve_single_str(tmp_path):
    doc = _doc(tmp_path, "v.json")
    assert resolve_vex_documents({"vex": str(doc)}) == [doc.resolve()]


def test_resolve_list_preserves_order(tmp_path):
    a, b = _doc(tmp_path, "a.json"), _doc(tmp_path, "b.json")
    assert resolve_vex_documents({"vex": [str(a), str(b)]}) == [a.resolve(), b.resolve()]


def test_resolve_skips_missing(tmp_path):
    present = _doc(tmp_path, "here.json")
    missing = tmp_path / "gone.json"
    assert resolve_vex_documents({"vex": [str(missing), str(present)]}) == [present.resolve()]


# --------------------------------------------------------------------- #
# vex_container_mounts                                                  #
# --------------------------------------------------------------------- #


def test_container_mounts_pairs_and_indexing(tmp_path):
    a, b = _doc(tmp_path, "a.json"), _doc(tmp_path, "b.json")
    mounts = vex_container_mounts({"vex": [str(a), str(b)]})
    assert mounts == [
        (str(a.resolve()), "/vex/doc0.json"),
        (str(b.resolve()), "/vex/doc1.json"),
    ]


def test_container_mounts_empty_without_vex():
    assert vex_container_mounts({}) == []


# --------------------------------------------------------------------- #
# vex_cli_flags                                                         #
# --------------------------------------------------------------------- #


def test_cli_flags_in_container_uses_mount_paths(tmp_path):
    a, b = _doc(tmp_path, "a.json"), _doc(tmp_path, "b.json")
    flags = vex_cli_flags({"vex": [str(a), str(b)]}, in_container=True)
    assert flags == ["--vex", "/vex/doc0.json", "--vex", "/vex/doc1.json"]


def test_cli_flags_local_uses_host_paths(tmp_path):
    doc = _doc(tmp_path, "v.json")
    flags = vex_cli_flags({"vex": str(doc)}, in_container=False)
    assert flags == ["--vex", str(doc.resolve())]


def test_cli_flags_empty_without_vex():
    assert vex_cli_flags(None, in_container=True) == []
    assert vex_cli_flags({}, in_container=False) == []


def test_flags_and_mounts_index_agree(tmp_path):
    """The Nth --vex flag must reference the Nth mount's container path."""
    a, b = _doc(tmp_path, "a.json"), _doc(tmp_path, "b.json")
    cfg = {"vex": [str(a), str(b)]}
    mount_targets = [container for _host, container in vex_container_mounts(cfg)]
    flag_targets = vex_cli_flags(cfg, in_container=True)[1::2]  # every value after "--vex"
    assert flag_targets == mount_targets


# --------------------------------------------------------------------- #
# unapplied_statements                                                  #
# --------------------------------------------------------------------- #


def _vex_doc(tmp_path: Path, product: str, vuln: str = "CVE-2025-68121") -> Path:
    import json

    p = tmp_path / "vex.json"
    p.write_text(json.dumps({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "statements": [{
            "vulnerability": {"name": vuln},
            "products": [{"@id": product}],
            "status": "not_affected",
            "justification": "vulnerable_code_not_in_execute_path",
        }],
    }))
    return p


def _vuln(vuln_id: str, purl: str, tool: str = "trivy"):
    from argus.core.models import Finding, Severity

    return Finding(
        id=vuln_id, severity=Severity.CRITICAL, title=vuln_id,
        metadata={"tool": tool, "purl": purl},
    )


def test_unapplied_flags_go_version_spelling_mismatch(tmp_path):
    """The bug that kept the CLI criticals visible: the statement said
    ``go1.24.11`` while trivy reports ``v1.24.11``, so trivy never matched."""
    from argus.core.vex import unapplied_statements

    doc = _vex_doc(tmp_path, "pkg:golang/stdlib@go1.24.11")
    findings = [_vuln("CVE-2025-68121", "pkg:golang/stdlib@v1.24.11")]

    misses = unapplied_statements(findings, {"vex": str(doc)})

    assert len(misses) == 1
    assert misses[0].vulnerability == "CVE-2025-68121"
    assert misses[0].statement_product == "pkg:golang/stdlib@go1.24.11"
    assert misses[0].reported_purl == "pkg:golang/stdlib@v1.24.11"
    assert misses[0].tool == "trivy"


def test_unapplied_ignores_other_packages_and_versions(tmp_path):
    from argus.core.vex import unapplied_statements

    doc = _vex_doc(tmp_path, "pkg:golang/stdlib@1.24.11")
    findings = [
        _vuln("CVE-2025-68121", "pkg:golang/stdlib@v1.26.1"),
        _vuln("CVE-2025-68121", "pkg:golang/golang.org/x/net@v1.24.11"),
        _vuln("CVE-2099-0001", "pkg:golang/stdlib@1.24.11"),
    ]

    assert unapplied_statements(findings, {"vex": str(doc)}) == []


def test_unapplied_ignores_purl_qualifiers(tmp_path):
    from argus.core.vex import unapplied_statements

    doc = _vex_doc(tmp_path, "pkg:golang/stdlib@1.24.11")
    findings = [_vuln("CVE-2025-68121", "pkg:golang/stdlib@1.24.11?arch=amd64", "grype")]

    assert len(unapplied_statements(findings, {"vex": str(doc)})) == 1


def test_unapplied_skips_affected_statements(tmp_path):
    """Only not_affected / fixed statements suppress, so only they can miss."""
    import json

    from argus.core.vex import unapplied_statements

    doc = _vex_doc(tmp_path, "pkg:golang/stdlib@1.24.11")
    data = json.loads(doc.read_text())
    data["statements"][0]["status"] = "affected"
    doc.write_text(json.dumps(data))
    findings = [_vuln("CVE-2025-68121", "pkg:golang/stdlib@v1.24.11")]

    assert unapplied_statements(findings, {"vex": str(doc)}) == []


def test_unapplied_empty_without_vex_or_purl(tmp_path):
    from argus.core.vex import unapplied_statements

    doc = _vex_doc(tmp_path, "pkg:golang/stdlib@1.24.11")
    assert unapplied_statements([_vuln("CVE-2025-68121", "")], {"vex": str(doc)}) == []
    assert unapplied_statements([_vuln("CVE-2025-68121", "pkg:golang/stdlib@1.24.11")], None) == []


def test_unapplied_tolerates_unreadable_document(tmp_path):
    from argus.core.vex import unapplied_statements

    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    findings = [_vuln("CVE-2025-68121", "pkg:golang/stdlib@1.24.11")]

    assert unapplied_statements(findings, {"vex": str(bad)}) == []


# --------------------------------------------------------------------- #
# Guard through the real container parse path                           #
# --------------------------------------------------------------------- #

# Trimmed trivy / grype JSON for the gitleaks Go stdlib hit, in each tool's
# own PURL spelling. Run through the same parser instance ``scan_image``
# uses, so the guard is exercised on findings shaped exactly like CI's.
_TRIVY_GO_STDLIB = {
    "Results": [{
        "Target": "usr/bin/gitleaks",
        "Class": "lang-pkgs",
        "Type": "gobinary",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2025-68121",
            "PkgName": "stdlib",
            "PkgIdentifier": {"PURL": "pkg:golang/stdlib@v1.24.11"},
            "InstalledVersion": "v1.24.11",
            "FixedVersion": "1.24.12",
            "Severity": "CRITICAL",
        }],
    }],
}

_GRYPE_GO_STDLIB = {
    "matches": [{
        "vulnerability": {
            "id": "CVE-2025-68121",
            "severity": "Critical",
            "fix": {"versions": ["1.24.12"], "state": "fixed"},
        },
        "artifact": {
            "name": "stdlib",
            "version": "go1.24.11",
            "type": "go-module",
            "purl": "pkg:golang/stdlib@1.24.11",
        },
    }],
}


def _scan_image_findings(tmp_path: Path):
    import json

    from argus.container.scanner import _parser

    trivy = tmp_path / "trivy.json"
    grype = tmp_path / "grype.json"
    trivy.write_text(json.dumps(_TRIVY_GO_STDLIB))
    grype.write_text(json.dumps(_GRYPE_GO_STDLIB))
    return _parser.parse_trivy_results(trivy) + _parser.parse_grype_results(grype)


def test_scan_image_parse_path_carries_purl(tmp_path):
    findings = _scan_image_findings(tmp_path)

    assert [f.metadata["purl"] for f in findings] == [
        "pkg:golang/stdlib@v1.24.11",
        "pkg:golang/stdlib@1.24.11",
    ]


def test_unapplied_flags_old_spelling_on_scan_image_findings(tmp_path):
    """The old ``go1.24.11`` statement matched neither tool, and the guard
    must say so for findings coming out of the container parse path."""
    from argus.core.vex import unapplied_statements

    doc = _vex_doc(tmp_path, "pkg:golang/stdlib@go1.24.11")

    misses = unapplied_statements(_scan_image_findings(tmp_path), {"vex": str(doc)})

    assert sorted(m.tool for m in misses) == ["grype", "trivy"]


# --------------------------------------------------------------------- #
# _purl_key                                                             #
# --------------------------------------------------------------------- #


def test_purl_key_strips_go_version_prefixes():
    from argus.core.vex import _purl_key

    assert _purl_key("pkg:golang/stdlib@go1.24.11") == ("pkg:golang/stdlib", "1.24.11")
    assert _purl_key("pkg:golang/stdlib@v1.24.11") == ("pkg:golang/stdlib", "1.24.11")
    assert _purl_key("pkg:golang/stdlib@1.24.11") == ("pkg:golang/stdlib", "1.24.11")


def test_purl_key_keeps_scoped_npm_namespace():
    from argus.core.vex import _purl_key

    assert _purl_key("pkg:npm/@babel/core@7.26.0") == ("pkg:npm/@babel/core", "7.26.0")


def test_purl_key_versionless_purls_have_empty_version():
    """A scoped npm namespace carries an ``@`` that is not the version
    separator, so a versionless purl must not split on it."""
    from argus.core.vex import _purl_key

    assert _purl_key("pkg:npm/@babel/core") == ("pkg:npm/@babel/core", "")
    assert _purl_key("pkg:golang/stdlib") == ("pkg:golang/stdlib", "")
    assert _purl_key("pkg:npm/@babel/core?repository_url=x#sub") == ("pkg:npm/@babel/core", "")
