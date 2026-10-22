"""Tests for ``scripts/ci/render_container_summary.py``.

Regression lock for the PR-comment false negative: the old inline heredoc
in ``build-containers.yml`` parsed only Trivy output, so Grype findings
were dropped and the container markdown reporter rendered
"No vulnerabilities detected by Grype" for every image. These tests prove
the SDK-backed replacement surfaces Grype findings — including a
Grype-only CVE that Trivy never reported — in the per-image section, the
severity counts, and the combined SARIF.
"""

from __future__ import annotations

import json
from pathlib import Path


from argus.container.scanner import ContainerScanResult, deduplicate_findings
from argus.core.models import Finding, Severity

from scripts.ci import render_container_summary as rcs


# --------------------------------------------------------------------- #
# Fixtures                                                              #
# --------------------------------------------------------------------- #


def _cve(cve: str, severity: Severity, tool: str, pkg: str = "openssl") -> Finding:
    return Finding(
        id=cve,
        severity=severity,
        title=f"{cve} in {pkg}",
        cve=cve,
        scanner="container",
        metadata={"tool": tool, "package": pkg, "installed_version": "1.0"},
    )


def _result_with_grype_only_critical() -> ContainerScanResult:
    """A result where Grype finds a CRITICAL that Trivy never reported.

    This is the exact scenario the bug hid: Trivy sees a single medium,
    Grype sees a distinct critical. The deduped ``combined_findings`` must
    contain both.
    """
    trivy = [_cve("CVE-2024-0001", Severity.MEDIUM, "trivy")]
    grype = [_cve("CVE-2024-9999", Severity.CRITICAL, "grype")]
    return ContainerScanResult(
        name="cli",
        image_ref="ghcr.io/huntridge-labs/argus/cli:testsha",
        trivy_findings=trivy,
        grype_findings=grype,
        combined_findings=deduplicate_findings(trivy, grype),
    )


# --------------------------------------------------------------------- #
# build_count_summary                                                   #
# --------------------------------------------------------------------- #


def test_count_summary_includes_grype_only_cve():
    result = _result_with_grype_only_critical()
    summary = rcs.build_count_summary(result)

    # The Grype-only critical must be counted — the old Trivy-only path
    # reported critical=0 here.
    assert summary["critical"] == 1
    assert summary["medium"] == 1
    assert summary["total"] == 2
    assert summary["name"] == "cli"
    assert summary["image_ref"].endswith("cli:testsha")
    assert summary["build_success"] is True


def test_count_summary_keys_match_combine_step():
    """The combine step reads these exact keys back — lock the contract."""
    summary = rcs.build_count_summary(_result_with_grype_only_critical())
    for key in ("name", "image_ref", "build_success", "critical", "high", "medium", "low"):
        assert key in summary


# --------------------------------------------------------------------- #
# write_pr_comment_artifacts                                            #
# --------------------------------------------------------------------- #


def test_section_surfaces_grype_findings(tmp_path: Path):
    rcs.write_pr_comment_artifacts(_result_with_grype_only_critical(), tmp_path)

    md = (tmp_path / "cli.md").read_text(encoding="utf-8")

    # The Grype subsection must show the real finding, NOT the false
    # "no vulnerabilities" line that the bug produced.
    assert "CVE-2024-9999" in md
    assert "No vulnerabilities detected by Grype" not in md
    # Trivy's finding is still present.
    assert "CVE-2024-0001" in md


def test_json_counts_written(tmp_path: Path):
    rcs.write_pr_comment_artifacts(_result_with_grype_only_critical(), tmp_path)

    data = json.loads((tmp_path / "cli.json").read_text(encoding="utf-8"))
    assert data["critical"] == 1
    assert data["total"] == 2


def test_clean_image_reports_no_grype_findings_truthfully(tmp_path: Path):
    """When Grype genuinely finds nothing, the honest line is fine."""
    clean = ContainerScanResult(
        name="cli",
        image_ref="ghcr.io/huntridge-labs/argus/cli:testsha",
        trivy_findings=[],
        grype_findings=[],
        combined_findings=[],
    )
    rcs.write_pr_comment_artifacts(clean, tmp_path)
    md = (tmp_path / "cli.md").read_text(encoding="utf-8")
    assert "No vulnerabilities detected by Grype" in md


# --------------------------------------------------------------------- #
# write_sarif                                                           #
# --------------------------------------------------------------------- #


def test_sarif_includes_grype_only_cve(tmp_path: Path):
    path = rcs.write_sarif(_result_with_grype_only_critical(), tmp_path)
    assert path.exists()
    sarif = json.loads(path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    # The Grype-only critical must reach the Security tab too.
    assert "CVE-2024-9999" in json.dumps(sarif)


# --------------------------------------------------------------------- #
# run / main (scan_image monkeypatched — no Docker in unit tests)       #
# --------------------------------------------------------------------- #


def test_run_uses_scan_image_and_writes_all_artifacts(tmp_path: Path, monkeypatch):
    captured = {}

    def fake_scan_image(target, scanners, sbom, config=None):
        captured["target"] = target
        captured["scanners"] = scanners
        captured["sbom"] = sbom
        captured["config"] = config
        return _result_with_grype_only_critical()

    monkeypatch.setattr(rcs, "scan_image", fake_scan_image)

    out_dir = tmp_path / "summaries"
    sarif_dir = tmp_path / "sarif"
    result = rcs.run(
        image_name="cli",
        image_ref="ghcr.io/huntridge-labs/argus/cli:testsha",
        out_dir=out_dir,
        sarif_dir=sarif_dir,
    )

    # Dogfoods the SDK's scan_image with the CVE-only sub-scanner set.
    assert captured["scanners"] == ("trivy", "grype")
    assert captured["sbom"] is False
    assert captured["config"] is None  # no --vex passed
    assert captured["target"].image_ref.endswith("cli:testsha")
    assert captured["target"].dockerfile is None

    assert (out_dir / "cli.md").exists()
    assert (out_dir / "cli.json").exists()
    assert (sarif_dir / "argus-results.sarif").exists()
    assert result.critical_count == 1


def test_run_without_sarif_dir_skips_sarif(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        rcs, "scan_image",
        lambda target, scanners, sbom, config=None: _result_with_grype_only_critical(),
    )
    out_dir = tmp_path / "summaries"
    rcs.run("cli", "ref:tag", out_dir, sarif_dir=None)
    assert (out_dir / "cli.md").exists()
    assert not (tmp_path / "sarif").exists()


def test_main_exit_zero_on_clean_run(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        rcs, "scan_image",
        lambda target, scanners, sbom, config=None: _result_with_grype_only_critical(),
    )
    rc = rcs.main([
        "--image-name", "cli",
        "--image-ref", "ghcr.io/huntridge-labs/argus/cli:testsha",
        "--out-dir", str(tmp_path / "out"),
    ])
    assert rc == 0


def test_main_exit_nonzero_on_scanner_error(tmp_path: Path, monkeypatch):
    def scan_with_error(target, scanners, sbom, config=None):
        r = _result_with_grype_only_critical()
        r.scanner_errors = {"grype": "grype produced 0-byte output"}
        return r

    monkeypatch.setattr(rcs, "scan_image", scan_with_error)
    rc = rcs.main([
        "--image-name", "cli",
        "--image-ref", "ref:tag",
        "--out-dir", str(tmp_path / "out"),
    ])
    # A sub-scanner failure must not be reported as a clean pass.
    assert rc == 1


def test_run_threads_vex_into_scan_image_config(tmp_path: Path, monkeypatch):
    captured = {}

    def fake_scan_image(target, scanners, sbom, config=None):
        captured["config"] = config
        return _result_with_grype_only_critical()

    monkeypatch.setattr(rcs, "scan_image", fake_scan_image)
    rcs.run(
        image_name="cli",
        image_ref="ref:tag",
        out_dir=tmp_path / "out",
        vex=[".vex/argus-cli.openvex.json"],
    )
    assert captured["config"] == {"vex": [".vex/argus-cli.openvex.json"]}


def test_main_forwards_vex_flag(tmp_path: Path, monkeypatch):
    captured = {}

    def fake_scan_image(target, scanners, sbom, config=None):
        captured["config"] = config
        return _result_with_grype_only_critical()

    monkeypatch.setattr(rcs, "scan_image", fake_scan_image)
    rcs.main([
        "--image-name", "cli",
        "--image-ref", "ref:tag",
        "--out-dir", str(tmp_path / "out"),
        "--vex", "a.json",
        "--vex", "b.json",
    ])
    assert captured["config"] == {"vex": ["a.json", "b.json"]}


def test_main_exit_nonzero_when_vex_statement_did_not_apply(tmp_path: Path, monkeypatch, capsys):
    """A VEX statement the scanners silently failed to match must fail CI.

    The CLI VEX spelled Go's version ``go1.24.11``; trivy reports
    ``v1.24.11`` and grype ``1.24.11``, so two criticals the document
    covers stayed in every PR comment for months with nothing going red.
    """
    vex = tmp_path / "vex.json"
    vex.write_text(json.dumps({
        "statements": [{
            "vulnerability": {"name": "CVE-2025-68121"},
            "products": [{"@id": "pkg:golang/stdlib@go1.24.11"}],
            "status": "not_affected",
            "justification": "vulnerable_code_not_in_execute_path",
        }],
    }))

    def scan_with_unmatched_vex(target, scanners, sbom, config=None):
        hit = Finding(
            id="CVE-2025-68121", severity=Severity.CRITICAL, title="tls",
            cve="CVE-2025-68121", scanner="container",
            metadata={"tool": "trivy", "purl": "pkg:golang/stdlib@v1.24.11"},
        )
        return ContainerScanResult(
            name="cli", image_ref="ref:tag",
            trivy_findings=[hit], grype_findings=[],
            combined_findings=[hit],
        )

    monkeypatch.setattr(rcs, "scan_image", scan_with_unmatched_vex)
    rc = rcs.main([
        "--image-name", "cli",
        "--image-ref", "ref:tag",
        "--out-dir", str(tmp_path / "out"),
        "--vex", str(vex),
    ])

    assert rc == 1
    err = capsys.readouterr().err
    assert "CVE-2025-68121" in err
    assert "pkg:golang/stdlib@go1.24.11" in err


# --------------------------------------------------------------------- #
# Native ignore files (path-scoped trivy / grype rules)                 #
# --------------------------------------------------------------------- #


def _ignored(tool: str, vuln: str, source: str, path: str) -> Finding:
    return Finding(
        id=vuln, severity=Severity.CRITICAL, title=vuln, scanner="container",
        metadata={"tool": tool, "package": "stdlib", "ignored": True,
                  "ignore_reason": "not reached", "ignore_source": source,
                  "ignore_path": path},
    )


def test_count_summary_reports_ignored_separately():
    result = _result_with_grype_only_critical()
    result.ignored_findings = [_ignored("trivy", "CVE-2025-68121", "x", "y")]
    summary = rcs.build_count_summary(result)
    assert summary["ignored"] == 1
    assert summary["critical"] == 1  # unchanged: ignored findings never count


def test_main_forwards_ignore_files(tmp_path: Path, monkeypatch):
    captured = {}

    def fake_scan_image(target, scanners, sbom, config=None):
        captured["config"] = config
        return _result_with_grype_only_critical()

    monkeypatch.setattr(rcs, "scan_image", fake_scan_image)
    rcs.main([
        "--image-name", "cli",
        "--image-ref", "ghcr.io/huntridge-labs/argus/cli:sha",
        "--out-dir", str(tmp_path / "out"),
        "--trivy-ignore-file", "t.yaml",
        "--grype-config-file", "g.yaml",
    ])
    assert captured["config"] == {
        "trivy_ignore_file": "t.yaml", "grype_config_file": "g.yaml",
    }


def _write_rules(tmp_path: Path) -> tuple[Path, Path]:
    trivy = tmp_path / "t.yaml"
    trivy.write_text(
        "vulnerabilities:\n"
        "  - id: CVE-2025-68121\n"
        "    paths: [usr/local/bin/gitleaks]\n"
        "    statement: not reached\n"
    )
    grype = tmp_path / "g.yaml"
    grype.write_text(
        "ignore:\n"
        "  - vulnerability: GO-2026-4337\n"
        "    reason: not reached\n"
        "    package: {name: stdlib, location: /usr/local/bin/gitleaks}\n"
    )
    return trivy, grype


def test_main_exit_nonzero_when_ignore_rule_matched_nothing(
    tmp_path: Path, monkeypatch, capsys,
):
    trivy, grype = _write_rules(tmp_path)
    result = _result_with_grype_only_critical()
    # The grype rule fired; the trivy rule did not.
    result.ignored_findings = [
        _ignored("grype", "GO-2026-4337", str(grype.resolve()), "/usr/local/bin/gitleaks"),
    ]
    monkeypatch.setattr(rcs, "scan_image", lambda *a, **k: result)

    code = rcs.main([
        "--image-name", "cli",
        "--image-ref", "ghcr.io/huntridge-labs/argus/cli:sha",
        "--out-dir", str(tmp_path / "out"),
        "--trivy-ignore-file", str(trivy),
        "--grype-config-file", str(grype),
    ])

    assert code == 1
    err = capsys.readouterr().err
    assert "::error::" in err
    assert "CVE-2025-68121" in err
    assert "usr/local/bin/gitleaks" in err
    assert "GO-2026-4337" not in err


def test_main_exit_zero_when_every_ignore_rule_matched(tmp_path: Path, monkeypatch):
    trivy, grype = _write_rules(tmp_path)
    result = _result_with_grype_only_critical()
    result.ignored_findings = [
        _ignored("trivy", "CVE-2025-68121", str(trivy.resolve()), "usr/local/bin/gitleaks"),
        _ignored("grype", "GO-2026-4337", str(grype.resolve()), "/usr/local/bin/gitleaks"),
    ]
    monkeypatch.setattr(rcs, "scan_image", lambda *a, **k: result)

    code = rcs.main([
        "--image-name", "cli",
        "--image-ref", "ghcr.io/huntridge-labs/argus/cli:sha",
        "--out-dir", str(tmp_path / "out"),
        "--trivy-ignore-file", str(trivy),
        "--grype-config-file", str(grype),
    ])
    assert code == 0


def test_ignore_rules_for_a_failed_tool_are_not_judged(tmp_path: Path, monkeypatch):
    trivy, _ = _write_rules(tmp_path)
    result = _result_with_grype_only_critical()
    result.scanner_errors = {"trivy": "boom"}
    assert rcs.report_unmatched_ignore_rules(
        result, {"trivy_ignore_file": str(trivy)},
    ) is True
