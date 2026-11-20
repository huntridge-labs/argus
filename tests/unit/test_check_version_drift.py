"""Tests for scripts/ci/check_version_drift.py (ADR-555)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.ci.check_version_drift import current_version, find_drift, main, version_rules

REPO_ROOT = Path(__file__).resolve().parents[2]


def _release_it(*rules: dict) -> dict:
    return {"plugins": {"@release-it/bumper": {"out": [{"file": "version.yaml"}]},
                        "regex-bumper": {"out": list(rules)}}}


def _write_repo(root: Path, version: str, files: dict[str, str], *rules: dict) -> Path:
    (root / "version.yaml").write_text(f"{version} # x-release-it-version\n", encoding="utf-8")
    (root / ".release-it.json").write_text(json.dumps(_release_it(*rules)), encoding="utf-8")
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


CONTEXT_RULE = {
    "files": [".ai/context.yaml"],
    "search": {"pattern": '(^  version: ")\\d+\\.\\d+\\.\\d+(?:[-+][\\w.-]+)?(")', "flags": "m"},
    "replace": "${1}{{version}}${2}",
}
ACTION_RULE = {
    "files": ["docs/**/*.md"],
    "search": "(uses: org/repo/action)@[^\\s]+",
    "replace": "${1}@{{version}}",
}


class TestCurrentVersion:
    def test_reads_first_token(self, tmp_path):
        (tmp_path / "version.yaml").write_text("1.2.3-rc.1 # x\n", encoding="utf-8")
        assert current_version(tmp_path) == "1.2.3-rc.1"

    def test_rejects_garbage(self, tmp_path):
        (tmp_path / "version.yaml").write_text("nope\n", encoding="utf-8")
        with pytest.raises(ValueError):
            current_version(tmp_path)


class TestVersionRules:
    def test_only_rules_that_write_version(self, tmp_path):
        digest = {"files": ["x"], "search": "sha256:\\w+", "replace": "sha256:{{digest}}"}
        _write_repo(tmp_path, "1.0.0", {}, CONTEXT_RULE, ACTION_RULE, digest)
        assert len(version_rules(tmp_path)) == 2

    def test_skips_pattern_python_cannot_compile(self, tmp_path, capsys):
        bad = {"files": ["x"], "search": "(?<n>a)", "replace": "{{version}}"}
        _write_repo(tmp_path, "1.0.0", {}, bad)
        assert version_rules(tmp_path) == []
        assert "skipping rule" in capsys.readouterr().err


class TestFindDrift:
    def test_matching_versions_pass(self, tmp_path):
        root = _write_repo(tmp_path, "1.15.0", {
            ".ai/context.yaml": 'project:\n  version: "1.15.0"\n',
            "docs/a.md": "uses: org/repo/action@1.15.0\n",
        }, CONTEXT_RULE, ACTION_RULE)
        assert find_drift(root, "1.15.0", version_rules(root)) == []

    def test_reports_stale_file_with_line(self, tmp_path):
        root = _write_repo(tmp_path, "1.15.0", {
            ".ai/context.yaml": 'version: "2.0"\nproject:\n  version: "1.4.1"\n',
            "docs/sub/b.md": "intro\n\nuses: org/repo/action@1.14.0\n",
        }, CONTEXT_RULE, ACTION_RULE)
        assert find_drift(root, "1.15.0", version_rules(root)) == [
            ".ai/context.yaml:3: found 1.4.1",
            "docs/sub/b.md:3: found 1.14.0",
        ]

    def test_text_outside_rule_matches_is_ignored(self, tmp_path):
        root = _write_repo(tmp_path, "1.15.0", {
            ".ai/context.yaml": 'project:\n  version: "1.15.0"\nother: "0.9.0"\n',
        }, CONTEXT_RULE)
        assert find_drift(root, "1.15.0", version_rules(root)) == []


class TestMain:
    def test_clean_repo_exits_0(self, tmp_path):
        root = _write_repo(tmp_path, "1.0.0", {".ai/context.yaml": '  version: "1.0.0"\n'},
                           CONTEXT_RULE)
        assert main(["--repo-root", str(root)]) == 0

    def test_drift_exits_1(self, tmp_path, capsys):
        root = _write_repo(tmp_path, "1.0.0", {".ai/context.yaml": '  version: "0.9.0"\n'},
                           CONTEXT_RULE)
        assert main(["--repo-root", str(root)]) == 1
        assert "found 0.9.0" in capsys.readouterr().err

    def test_missing_config_exits_2(self, tmp_path):
        assert main(["--repo-root", str(tmp_path)]) == 2


def test_repo_has_no_drift():
    """Every release-it version reference in this repo matches version.yaml."""
    version = current_version(REPO_ROOT)
    assert find_drift(REPO_ROOT, version, version_rules(REPO_ROOT)) == []
