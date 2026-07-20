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
