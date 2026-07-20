"""Tests for OpenVEX filtering in the container scanner.

Covers ``_vex_args`` (path → docker-mount + ``--vex`` flag resolution) and
that ``_run_trivy`` / ``_run_grype`` thread the flag into the actual scan
command for both trivy and grype. The scanners themselves are mocked — we
assert command construction, not real tool behavior.
"""

from __future__ import annotations

import subprocess

from argus.container.scanner import _run_grype, _run_trivy, _vex_args


def _completed(returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout="", stderr="")


def _force_local_binary(monkeypatch):
    """Make shutil.which resolve so the runner takes the local-binary path."""
    monkeypatch.setattr(
        "argus.container.scanner.shutil.which",
        lambda tool: f"/usr/local/bin/{tool}",
    )


# --------------------------------------------------------------------- #
# _vex_args                                                             #
# --------------------------------------------------------------------- #


def test_vex_args_empty_without_config():
    assert _vex_args(None, use_container=False) == ([], [])
    assert _vex_args({}, use_container=False) == ([], [])
    assert _vex_args({"vex": None}, use_container=False) == ([], [])


def test_vex_args_local_single_path(tmp_path):
    vex = tmp_path / "vex.json"
    vex.write_text("{}")
    mounts, flags = _vex_args({"vex": str(vex)}, use_container=False)
    assert mounts == []
    assert flags == ["--vex", str(vex.resolve())]


def test_vex_args_container_mounts_and_flags(tmp_path):
    vex = tmp_path / "vex.json"
    vex.write_text("{}")
    mounts, flags = _vex_args({"vex": str(vex)}, use_container=True)
    assert mounts == ["-v", f"{vex.resolve()}:/vex/doc0.json:ro"]
    assert flags == ["--vex", "/vex/doc0.json"]


def test_vex_args_accepts_list_and_indexes_containers(tmp_path):
    a = tmp_path / "a.json"
    a.write_text("{}")
    b = tmp_path / "b.json"
    b.write_text("{}")
    mounts, flags = _vex_args({"vex": [str(a), str(b)]}, use_container=True)
    assert "/vex/doc0.json" in flags and "/vex/doc1.json" in flags
    assert mounts.count("-v") == 2


def test_vex_args_skips_missing_file(tmp_path):
    missing = tmp_path / "nope.json"
    mounts, flags = _vex_args({"vex": str(missing)}, use_container=False)
    assert (mounts, flags) == ([], [])


# --------------------------------------------------------------------- #
# _run_trivy / _run_grype wiring                                        #
# --------------------------------------------------------------------- #


def test_run_trivy_local_passes_vex_before_image_ref(tmp_path, monkeypatch):
    _force_local_binary(monkeypatch)
    vex = tmp_path / "vex.json"
    vex.write_text("{}")
    captured = {}

    def fake_run(cmd, *a, **k):
        captured["cmd"] = list(cmd)
        (tmp_path / "trivy-results.json").write_text('{"Results": []}')
        return _completed(0)

    monkeypatch.setattr("subprocess.run", fake_run)
    _run_trivy("img:tag", tmp_path, local=True, config={"vex": str(vex)})

    cmd = captured["cmd"]
    assert "--vex" in cmd
    assert str(vex.resolve()) in cmd
    # trivy syntax is ``trivy image [flags] <ref>`` — the flag must precede
    # the positional image reference.
    assert cmd.index("--vex") < cmd.index("img:tag")


def test_run_trivy_local_omits_vex_when_unset(tmp_path, monkeypatch):
    _force_local_binary(monkeypatch)
    captured = {}

    def fake_run(cmd, *a, **k):
        captured["cmd"] = list(cmd)
        (tmp_path / "trivy-results.json").write_text('{"Results": []}')
        return _completed(0)

    monkeypatch.setattr("subprocess.run", fake_run)
    _run_trivy("img:tag", tmp_path, local=True, config={})
    assert "--vex" not in captured["cmd"]


def test_run_grype_local_passes_vex_flag_from_list(tmp_path, monkeypatch):
    _force_local_binary(monkeypatch)
    vex = tmp_path / "vex.json"
    vex.write_text("{}")
    captured = {}

    def fake_run(cmd, *a, **k):
        captured["cmd"] = list(cmd)
        (tmp_path / "grype-results.json").write_text('{"matches": []}')
        return _completed(0)

    monkeypatch.setattr("subprocess.run", fake_run)
    _run_grype("docker:img:tag", tmp_path, local=True, config={"vex": [str(vex)]})

    cmd = captured["cmd"]
    assert "--vex" in cmd
    assert str(vex.resolve()) in cmd


def test_run_grype_local_omits_vex_when_unset(tmp_path, monkeypatch):
    _force_local_binary(monkeypatch)
    captured = {}

    def fake_run(cmd, *a, **k):
        captured["cmd"] = list(cmd)
        (tmp_path / "grype-results.json").write_text('{"matches": []}')
        return _completed(0)

    monkeypatch.setattr("subprocess.run", fake_run)
    _run_grype("docker:img:tag", tmp_path, local=True, config=None)
    assert "--vex" not in captured["cmd"]


# --------------------------------------------------------------------- #
# CLI wiring: --vex / containers.vex reach the scan config              #
# --------------------------------------------------------------------- #


def test_cli_vex_flag_lands_in_container_config():
    from argus.cli import _load_container_config, build_parser

    args = build_parser().parse_args(
        ["scan", "container", "--image", "img:tag", "--vex", "a.json", "--vex", "b.json"]
    )
    config = _load_container_config(args)
    assert config["vex"] == ["a.json", "b.json"]


def test_containers_vex_key_flows_from_config_file(tmp_path):
    from argus.cli import _load_container_config, build_parser

    cfg = tmp_path / "argus.yml"
    cfg.write_text(
        "containers:\n"
        "  images:\n"
        "    - image: img:tag\n"
        "  vex: .vex/argus.openvex.json\n"
    )
    args = build_parser().parse_args(["scan", "container", "--config", str(cfg)])
    config = _load_container_config(args)
    # config-file containers.vex flows through unchanged (scan_image reads config['vex']).
    assert config["vex"] == ".vex/argus.openvex.json"
