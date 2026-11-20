"""Tests for scripts/ci/check_ai_index.py (generated .ai/index.yaml, ADR-555)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scripts.ci.check_ai_index import INDEX_FILE, ROUTING, build_index, main, render

REPO_ROOT = Path(__file__).resolve().parents[2]

ADR_BODY = {"title": "A decision", "status": "accepted",
            "context": "Some context for it.", "decision": "Do it."}


def _dump(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _write_ai(root: Path, *, records: dict | None = None) -> Path:
    ai = root / ".ai"
    _dump(ai / "context.yaml", {
        "version": "2.0", "schema": "x",
        "project": {"name": "demo", "description": "A demo\n  project."},
        "glossary": {}, "entrypoints": {},
    })
    _dump(ai / "architecture.yaml", {"version": "2.0", "components": {"b": {}, "a": {}}})
    _dump(ai / "workflows.yaml", {"version": "2.0", "workflows": {"run": {}, "build": {}}})
    _dump(ai / "errors.yaml", {"version": "2.0", "errors": {"Z_ERR": {}, "A_ERR": {}},
                               "scn_detector_errors": [{"x": 1}]})
    _dump(ai / "decisions.yaml", {"version": "2.0", "decisions": {
        "ADR-002": ADR_BODY, "ADR-001": ADR_BODY, "ADR-010": ADR_BODY}})
    for adr_id in records or {}:
        _dump(ai / "decisions" / f"{adr_id}.yaml", {"id": adr_id, **ADR_BODY})
    return root


class TestBuildIndex:
    def test_lists_every_key_sorted(self, tmp_path):
        index = build_index(_write_ai(tmp_path))
        assert index["version"] == "2.0"
        assert index["summary"] == "A demo project."
        assert index["keys"]["context"] == ["entrypoints", "glossary", "project"]
        assert index["keys"]["architecture"] == ["a", "b"]
        assert index["keys"]["workflows"] == ["build", "run"]
        assert index["keys"]["errors"] == ["A_ERR", "Z_ERR"]
        assert index["routing"] == ROUTING

    def test_covers_both_adr_stores_in_numeric_order(self, tmp_path):
        index = build_index(_write_ai(tmp_path, records={"ADR-1000": 1, "ADR-483": 1}))
        assert index["keys"]["decisions"] == ["ADR-001", "ADR-002", "ADR-010"]
        assert index["keys"]["decision_records"] == ["ADR-483", "ADR-1000"]

    def test_no_records_dir_gives_empty_list(self, tmp_path):
        assert build_index(_write_ai(tmp_path))["keys"]["decision_records"] == []

    def test_invalid_adr_store_raises(self, tmp_path):
        root = _write_ai(tmp_path)
        _dump(root / ".ai" / "decisions" / "ADR-5.yaml", {"id": "ADR-5", **ADR_BODY})
        with pytest.raises(ValueError, match="ADR stores are invalid"):
            build_index(root)

    def test_non_mapping_file_raises(self, tmp_path):
        root = _write_ai(tmp_path)
        (root / ".ai" / "workflows.yaml").write_text("- a\n", encoding="utf-8")
        with pytest.raises(ValueError, match="workflows.yaml"):
            build_index(root)


class TestMain:
    def test_fix_then_check_passes(self, tmp_path, capsys):
        root = _write_ai(tmp_path)
        assert main(["--repo-root", str(root), "--fix"]) == 0
        assert (root / INDEX_FILE).read_text(encoding="utf-8").startswith("# AUTO-GENERATED")
        assert main(["--repo-root", str(root)]) == 0
        assert "up to date" in capsys.readouterr().out

    def test_missing_index_fails(self, tmp_path, capsys):
        assert main(["--repo-root", str(_write_ai(tmp_path))]) == 1
        assert "does not exist" in capsys.readouterr().err

    def test_new_adr_without_fix_fails(self, tmp_path, capsys):
        root = _write_ai(tmp_path)
        main(["--repo-root", str(root), "--fix"])
        _dump(root / ".ai" / "decisions" / "ADR-600.yaml", {"id": "ADR-600", **ADR_BODY})
        assert main(["--repo-root", str(root)]) == 1
        assert "--fix" in capsys.readouterr().err

    def test_unbuildable_index_exits_2(self, tmp_path, capsys):
        assert main(["--repo-root", str(tmp_path)]) == 2
        assert "could not build" in capsys.readouterr().err


def test_committed_index_is_current():
    """The repo's own index matches what the generator builds."""
    expected = render(build_index(REPO_ROOT))
    assert (REPO_ROOT / INDEX_FILE).read_text(encoding="utf-8") == expected
