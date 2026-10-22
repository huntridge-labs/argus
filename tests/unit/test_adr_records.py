"""Tests for scripts/ci/adr_records.py (issue-keyed ADR records, ADR-483)."""

from __future__ import annotations

import datetime
import json
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts.ci import adr_records
from scripts.ci.adr_records import (
    ISSUE_KEYED_FLOOR,
    LEGACY_LAST,
    branch_errors,
    branch_issue,
    build_index,
    duplicate_errors,
    main,
    run_check,
    skeleton,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

LEGACY_BODY = {
    "title": "Legacy decision",
    "status": "accepted",
    "context": "Some context for the legacy decision.",
    "decision": "Do the thing.",
}


def _record(adr_id: str, **overrides) -> dict:
    return {"id": adr_id, **LEGACY_BODY, "title": f"Record {adr_id}", **overrides}


def _write_repo(root: Path, legacy: dict | None = None, records: dict | None = None) -> Path:
    ai = root / ".ai"
    ai.mkdir(parents=True, exist_ok=True)
    legacy = legacy if legacy is not None else {"ADR-001": LEGACY_BODY, "ADR-002": LEGACY_BODY}
    (ai / "decisions.yaml").write_text(
        yaml.safe_dump({"version": "2.0", "decisions": legacy}, sort_keys=False), encoding="utf-8",
    )
    (ai / "architecture.yaml").write_text(
        yaml.safe_dump({"version": "2.0", "components": {"argus-sdk": {}, "argus-mcp": {}}}),
        encoding="utf-8",
    )
    if records:
        (ai / "decisions").mkdir(exist_ok=True)
        for name, body in records.items():
            text = body if isinstance(body, str) else yaml.safe_dump(body)
            (ai / "decisions" / name).write_text(text, encoding="utf-8")
    return root


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com",
         "-c", "commit.gpgsign=false", *args],
        cwd=root, check=True, capture_output=True, text=True,
    ).stdout


class TestBranchIssue:
    @pytest.mark.parametrize("branch, issue", [
        ("feat/483-issue-keyed-records", 483),
        ("fix/12-x", 12),
        ("docs/700", 700),
        ("feat/483-a/b", 483),
    ])
    def test_issue_number_follows_prefix(self, branch, issue):
        assert branch_issue(branch) == issue

    @pytest.mark.parametrize("branch", [
        "", None, "main", "patch-1", "feat/add-login", "dependabot/pip/pyyaml-6.0.3",
        "renovate/python-3.x", "feat/0483-padded", "feat/483x", "483-no-prefix",
    ])
    def test_no_issue_number(self, branch):
        assert branch_issue(branch) is None


class TestBranchErrors:
    def test_matching_adr_passes(self):
        assert branch_errors([".ai/decisions/ADR-483.yaml"], "feat/483-x") == ([], [])

    def test_mismatched_adr_fails(self):
        errors, warnings = branch_errors([".ai/decisions/ADR-490.yaml"], "feat/483-x")
        assert warnings == []
        assert len(errors) == 1
        assert "issue #483" in errors[0] and "ADR-483.yaml" in errors[0]

    def test_no_issue_and_no_adr_only_warns(self):
        errors, warnings = branch_errors(["README.md"], "dependabot/npm/foo-1.2")
        assert errors == []
        assert len(warnings) == 1 and "no issue number" in warnings[0]

    def test_no_issue_with_adr_fails(self):
        errors, warnings = branch_errors([".ai/decisions/ADR-483.yaml"], "patch-1")
        assert warnings == []
        assert len(errors) == 1 and "patch-1" in errors[0]

    def test_files_outside_records_dir_ignored(self):
        assert branch_errors(["docs/ADR-1.yaml", ".ai/errors.yaml"], "feat/483-x") == ([], [])


class TestDuplicateErrors:
    def test_padded_and_unpadded_collide(self):
        errors = duplicate_errors(["ADR-044", "ADR-44"])
        assert len(errors) == 1 and "44" in errors[0]

    def test_unique_ids_pass(self):
        assert duplicate_errors(["ADR-001", "ADR-483", "not-an-adr"]) == []


class TestRunCheck:
    def test_clean_repo_passes(self, tmp_path):
        _write_repo(tmp_path, records={"ADR-483.yaml": _record("ADR-483")})
        assert run_check(tmp_path, None, None) == ([], [])

    def test_missing_stores_pass(self, tmp_path):
        assert run_check(tmp_path, None, None) == ([], [])

    def test_new_legacy_entry_rejected(self, tmp_path):
        legacy = {"ADR-001": LEGACY_BODY, f"ADR-{LEGACY_LAST + 1:03d}": LEGACY_BODY}
        _write_repo(tmp_path, legacy=legacy)
        errors, _ = run_check(tmp_path, None, None)
        assert any("closed to new ADRs" in e for e in errors)

    def test_unpadded_legacy_key_rejected(self, tmp_path):
        _write_repo(tmp_path, legacy={"ADR-1": LEGACY_BODY})
        errors, _ = run_check(tmp_path, None, None)
        assert any("closed to new ADRs" in e for e in errors)

    def test_duplicate_legacy_key_rejected(self, tmp_path):
        _write_repo(tmp_path)
        path = tmp_path / ".ai" / "decisions.yaml"
        dup = "  ADR-002:\n    title: Second copy\n"
        path.write_text(path.read_text() + dup, encoding="utf-8")
        errors, _ = run_check(tmp_path, None, None)
        assert any("duplicate key 'ADR-002'" in e for e in errors)

    def test_legacy_without_decisions_mapping(self, tmp_path):
        _write_repo(tmp_path)
        (tmp_path / ".ai" / "decisions.yaml").write_text("version: '2.0'\n", encoding="utf-8")
        errors, _ = run_check(tmp_path, None, None)
        assert any("expected a 'decisions' mapping" in e for e in errors)

    @pytest.mark.parametrize("name", ["ADR-0483.yaml", "adr-483.yaml", "ADR-483.yml", "notes.md"])
    def test_bad_record_file_names(self, tmp_path, name):
        _write_repo(tmp_path, records={name: _record("ADR-483")})
        errors, _ = run_check(tmp_path, None, None)
        assert any("named ADR-<issue>.yaml" in e for e in errors)

    def test_record_below_floor_rejected(self, tmp_path):
        low = ISSUE_KEYED_FLOOR - 1
        _write_repo(tmp_path, records={f"ADR-{low}.yaml": _record(f"ADR-{low}")})
        errors, _ = run_check(tmp_path, None, None)
        assert any(f"start at {ISSUE_KEYED_FLOOR}" in e for e in errors)

    def test_record_id_must_match_file(self, tmp_path):
        _write_repo(tmp_path, records={"ADR-483.yaml": _record("ADR-484")})
        errors, _ = run_check(tmp_path, None, None)
        assert any("'id' must be ADR-483" in e for e in errors)

    def test_record_not_a_mapping(self, tmp_path):
        _write_repo(tmp_path, records={"ADR-483.yaml": "- just\n- a list\n"})
        errors, _ = run_check(tmp_path, None, None)
        assert any("expected a mapping" in e for e in errors)

    def test_record_invalid_yaml(self, tmp_path):
        _write_repo(tmp_path, records={"ADR-483.yaml": "id: [unclosed\n"})
        errors, _ = run_check(tmp_path, None, None)
        assert any("ADR-483.yaml" in e for e in errors)

    def test_record_duplicate_key(self, tmp_path):
        text = yaml.safe_dump(_record("ADR-483")) + "title: again\n"
        _write_repo(tmp_path, records={"ADR-483.yaml": text})
        errors, _ = run_check(tmp_path, None, None)
        assert any("duplicate key 'title'" in e for e in errors)

    def test_required_fields(self, tmp_path):
        body = {"id": "ADR-483", "title": "x", "status": "done", "context": "short"}
        _write_repo(tmp_path, records={"ADR-483.yaml": body})
        errors, _ = run_check(tmp_path, None, None)
        joined = "\n".join(errors)
        for field in ("'title'", "'context'", "'decision'", "'status'"):
            assert field in joined

    def test_references(self, tmp_path):
        body = _record(
            "ADR-483", affects_components=["argus-sdk", "nope"],
            supersedes=["ADR-001", "ADR-999"], superseded_by="ADR-500",
        )
        _write_repo(tmp_path, records={"ADR-483.yaml": body})
        errors, _ = run_check(tmp_path, None, None)
        joined = "\n".join(errors)
        assert "unknown component 'nope'" in joined
        assert "unknown ADR 'ADR-999'" in joined
        assert "unknown ADR 'ADR-500'" in joined
        assert "ADR-001" not in joined and "argus-sdk" not in joined

    def test_legacy_cannot_point_at_record_successor(self, tmp_path):
        legacy = {"ADR-001": {**LEGACY_BODY, "superseded_by": "ADR-483"}}
        _write_repo(tmp_path, legacy=legacy, records={"ADR-483.yaml": _record("ADR-483")})
        errors, _ = run_check(tmp_path, None, None)
        assert any("'supersedes'" in e for e in errors)

    def test_branch_without_base_only_warns(self, tmp_path):
        _write_repo(tmp_path)
        errors, warnings = run_check(tmp_path, "patch-1", None)
        assert errors == [] and len(warnings) == 1


class TestAddedPaths:
    @pytest.fixture
    def repo(self, tmp_path):
        _write_repo(tmp_path)
        _git(tmp_path, "init", "-q", "-b", "main")
        _git(tmp_path, "add", ".")
        _git(tmp_path, "commit", "-q", "-m", "base")
        return tmp_path

    def test_detects_added_record(self, repo):
        _write_repo(repo, records={"ADR-483.yaml": _record("ADR-483")})
        _git(repo, "add", ".")
        _git(repo, "commit", "-q", "-m", "add")
        assert adr_records.added_paths(repo, "HEAD^1") == [".ai/decisions/ADR-483.yaml"]
        assert run_check(repo, "feat/483-x", "HEAD^1") == ([], [])
        errors, _ = run_check(repo, "feat/490-x", "HEAD^1")
        assert len(errors) == 1

    def test_edits_to_existing_records_are_not_new(self, repo):
        _write_repo(repo, records={"ADR-483.yaml": _record("ADR-483")})
        _git(repo, "add", ".")
        _git(repo, "commit", "-q", "-m", "add")
        _write_repo(repo, records={"ADR-483.yaml": _record("ADR-483", status="superseded")})
        _git(repo, "commit", "-q", "-am", "edit")
        assert adr_records.added_paths(repo, "HEAD^1") == []
        assert run_check(repo, "feat/490-x", "HEAD^1") == ([], [])


class TestIndex:
    def test_merges_both_stores_in_order(self, tmp_path):
        records = {
            "ADR-500.yaml": _record("ADR-500"),
            "ADR-483.yaml": _record("ADR-483", supersedes=["ADR-002"]),
        }
        _write_repo(tmp_path, records=records)
        rows = build_index(tmp_path)
        assert [r["id"] for r in rows] == ["ADR-001", "ADR-002", "ADR-483", "ADR-500"]
        assert rows[1]["superseded_by"] == "ADR-483"
        assert rows[1]["source"] == ".ai/decisions.yaml"
        assert rows[2]["source"] == ".ai/decisions/ADR-483.yaml"

    def test_real_repo_index_includes_legacy_and_records(self):
        ids = [r["id"] for r in build_index(REPO_ROOT)]
        assert "ADR-001" in ids and "ADR-483" in ids
        assert len(ids) == len(set(ids))


class TestSkeleton:
    def test_skeleton_passes_check(self, tmp_path):
        text = skeleton(483, 'A "quoted" title', datetime.date(2026, 10, 22))
        _write_repo(tmp_path, records={"ADR-483.yaml": text})
        assert run_check(tmp_path, None, None) == ([], [])
        assert yaml.safe_load(text)["title"] == 'A "quoted" title'


class TestCli:
    def test_check_ok(self, tmp_path, capsys):
        _write_repo(tmp_path)
        assert main(["--repo-root", str(tmp_path), "check"]) == 0
        assert "ADR records OK" in capsys.readouterr().out

    def test_check_errors_as_annotations(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        _write_repo(tmp_path, legacy={"ADR-1": LEGACY_BODY})
        assert main(["--repo-root", str(tmp_path), "check", "--branch", "patch-1"]) == 1
        out = capsys.readouterr().out
        assert "::error::" in out and "::warning::" in out

    def test_check_errors_locally(self, tmp_path, capsys, monkeypatch):
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        _write_repo(tmp_path, legacy={"ADR-1": LEGACY_BODY})
        assert main(["--repo-root", str(tmp_path), "check"]) == 1
        assert "error:" in capsys.readouterr().err

    @pytest.mark.parametrize("fmt", ["table", "yaml", "json"])
    def test_list_formats(self, tmp_path, capsys, fmt):
        records = {"ADR-483.yaml": _record("ADR-483", supersedes=["ADR-001"])}
        _write_repo(tmp_path, records=records)
        assert main(["--repo-root", str(tmp_path), "list", "--format", fmt]) == 0
        out = capsys.readouterr().out
        assert "ADR-483" in out
        if fmt == "json":
            assert json.loads(out)[0]["superseded_by"] == "ADR-483"
        if fmt == "table":
            assert "(superseded by ADR-483)" in out

    def test_new_from_flag(self, tmp_path):
        _write_repo(tmp_path)
        assert main(["--repo-root", str(tmp_path), "new", "--issue", "483"]) == 0
        assert (tmp_path / ".ai" / "decisions" / "ADR-483.yaml").exists()
        assert main(["--repo-root", str(tmp_path), "new", "--issue", "483"]) == 1

    def test_new_from_branch(self, tmp_path, monkeypatch):
        _write_repo(tmp_path)
        monkeypatch.setattr(adr_records, "current_branch", lambda root: "fix/512-thing")
        assert main(["--repo-root", str(tmp_path), "new", "--title", "Thing"]) == 0
        body = yaml.safe_load((tmp_path / ".ai" / "decisions" / "ADR-512.yaml").read_text())
        assert body["id"] == "ADR-512" and body["title"] == "Thing"

    def test_new_without_issue_fails(self, tmp_path, monkeypatch):
        monkeypatch.setattr(adr_records, "current_branch", lambda root: "main")
        assert main(["--repo-root", str(tmp_path), "new"]) == 1

    def test_current_branch_reads_git(self, tmp_path):
        _git(tmp_path, "init", "-q", "-b", "feat/9-x")
        _git(tmp_path, "commit", "-q", "--allow-empty", "-m", "init")
        assert adr_records.current_branch(tmp_path) == "feat/9-x"


def test_this_repo_passes_check():
    """The checked-in ADR stores are valid (no branch rule outside a PR)."""
    errors, _ = run_check(REPO_ROOT, None, None)
    assert errors == []
