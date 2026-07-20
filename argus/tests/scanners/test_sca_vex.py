"""VEX wiring for the standalone SCA scanners (grype, trivy).

Confirms each declares the ``supports_vex`` capability and threads
``config['vex']`` into both the containerized invocation (``container_args`` +
``container_mounts``) and the local-binary invocation (``scan``), using the
shared ``argus.core.vex`` helpers.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from argus.scanners.grype import GrypeScanner
from argus.scanners.trivy import TrivyScanner


def _doc(tmp_path: Path) -> Path:
    p = tmp_path / "argus.openvex.json"
    p.write_text("{}")
    return p


def _completed() -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")


def test_both_scanners_declare_supports_vex():
    assert GrypeScanner.supports_vex is True
    assert TrivyScanner.supports_vex is True


# --------------------------------------------------------------------- #
# container path: container_args + container_mounts                     #
# --------------------------------------------------------------------- #


def test_grype_container_args_and_mounts_carry_vex(tmp_path):
    doc = _doc(tmp_path)
    cfg = {"sbom_path": "sbom.json", "sbom_mount_path": "/workspace/sbom.json", "vex": str(doc)}
    args = GrypeScanner().container_args(cfg)
    assert "--vex" in args and "/vex/doc0.json" in args
    assert GrypeScanner().container_mounts(cfg) == [(str(doc.resolve()), "/vex/doc0.json")]


def test_trivy_container_args_and_mounts_carry_vex(tmp_path):
    doc = _doc(tmp_path)
    cfg = {"sbom_path": "sbom.json", "sbom_mount_path": "/workspace/sbom.json", "vex": str(doc)}
    args = TrivyScanner().container_args(cfg)
    assert "--vex" in args and "/vex/doc0.json" in args
    # trivy flags must precede the positional SBOM mount.
    assert args.index("--vex") < args.index("/workspace/sbom.json")
    assert TrivyScanner().container_mounts(cfg) == [(str(doc.resolve()), "/vex/doc0.json")]


def test_container_args_omit_vex_when_unset():
    cfg = {"sbom_path": "sbom.json", "sbom_mount_path": "/workspace/sbom.json"}
    assert "--vex" not in GrypeScanner().container_args(cfg)
    assert "--vex" not in TrivyScanner().container_args(cfg)
    assert GrypeScanner().container_mounts(cfg) == []
    assert TrivyScanner().container_mounts(cfg) == []


# --------------------------------------------------------------------- #
# local path: scan() cmd                                                #
# --------------------------------------------------------------------- #


def _capture_scan(scanner, cfg, results_name, results_body, monkeypatch):
    captured = {}

    def fake_run(cmd, *a, **k):
        captured["cmd"] = list(cmd)
        # Write the tool's --file / --output target so parsing succeeds.
        for flag in ("--file", "--output"):
            if flag in cmd:
                Path(cmd[cmd.index(flag) + 1]).write_text(results_body)
        return _completed()

    monkeypatch.setattr("subprocess.run", fake_run)
    scanner.scan("ignored", cfg)
    return captured["cmd"]


def test_grype_local_scan_passes_vex(tmp_path, monkeypatch):
    doc = _doc(tmp_path)
    cmd = _capture_scan(
        GrypeScanner(), {"sbom_path": "sbom.json", "vex": str(doc)},
        "grype-results.json", '{"matches": []}', monkeypatch,
    )
    assert "--vex" in cmd and str(doc.resolve()) in cmd


def test_trivy_local_scan_passes_vex(tmp_path, monkeypatch):
    doc = _doc(tmp_path)
    cmd = _capture_scan(
        TrivyScanner(), {"sbom_path": "sbom.json", "vex": str(doc)},
        "trivy-results.json", '{"Results": []}', monkeypatch,
    )
    assert "--vex" in cmd and str(doc.resolve()) in cmd
