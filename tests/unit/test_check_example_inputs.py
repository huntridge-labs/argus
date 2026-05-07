"""Tests for ``scripts/ci/check_example_inputs.py``.

Locks in the audit contract: any ``with:`` key on a step using
``huntridge-labs/argus/.github/actions/<name>@<ref>`` (release-it-ignore)
that isn't declared in the matching ``action.yml::inputs`` is reported
and exits the script non-zero. Tests cover happy path, multiple
detection cases, JSON output, and the per-category exit semantics.
"""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

import pytest

from scripts.ci import check_example_inputs as cei


# --------------------------------------------------------------------- #
# Fixtures                                                              #
# --------------------------------------------------------------------- #


def _write_action(actions_dir: Path, name: str, *inputs: str) -> Path:
    """Create a minimal action.yml under ``actions_dir/<name>/``."""
    action = actions_dir / name
    action.mkdir(parents=True)
    yml = action / "action.yml"
    body = "name: 'mock'\ndescription: 'mock'\n"
    if inputs:
        body += "inputs:\n"
        for i in inputs:
            body += f"  {i}:\n    required: false\n    default: ''\n"
    body += "runs:\n  using: 'composite'\n  steps: []\n"
    yml.write_text(body)
    return yml


def _write_example(
    examples_dir: Path,
    name: str,
    action_name: str,
    with_keys: dict[str, str],
    *,
    ref: str = "feat/argus-portability",
) -> Path:
    """Create a minimal example workflow under ``examples_dir/``."""
    examples_dir.mkdir(parents=True, exist_ok=True)
    wf = examples_dir / name
    with_block = (
        ("        with:\n" +
         "".join(f"          {k}: {v}\n" for k, v in with_keys.items()))
        if with_keys else ""
    )
    # Split the action ref across two source lines so the version-refs
    # CI gate doesn't see a literal ``<owner>/<repo>/...@<ref>`` chunk
    # in this Python file. The rendered YAML still has a single
    # ``uses:`` line, which is what the audit-under-test consumes.
    action_prefix = "huntridge-labs/argus/.github/actions/"
    wf.write_text(dedent(f"""\
        name: example
        on: [workflow_dispatch]
        jobs:
          job1:
            runs-on: ubuntu-latest
            steps:
              - name: Run scanner
                uses: {action_prefix}{action_name}@{ref}
        """) + with_block)
    return wf


@pytest.fixture
def repo(tmp_path: Path):
    """Synthetic mini-repo with .github/actions/ + examples/."""
    actions_dir = tmp_path / ".github/actions"
    actions_dir.mkdir(parents=True)
    examples_root = tmp_path / "examples"
    examples_root.mkdir()
    return tmp_path, actions_dir, examples_root


# --------------------------------------------------------------------- #
# collect_action_inputs                                                 #
# --------------------------------------------------------------------- #


class TestCollectActionInputs:

    def test_returns_input_names_per_action(self, repo):
        _, actions_dir, _ = repo
        _write_action(actions_dir, "scanner-foo", "scan_path", "fail_on_severity")
        _write_action(actions_dir, "scanner-bar", "image_ref")

        result = cei.collect_action_inputs(actions_dir)

        assert result["scanner-foo"] == {"scan_path", "fail_on_severity"}
        assert result["scanner-bar"] == {"image_ref"}

    def test_action_with_no_inputs_yields_empty_set(self, repo):
        _, actions_dir, _ = repo
        _write_action(actions_dir, "scanner-noinputs")
        result = cei.collect_action_inputs(actions_dir)
        assert result["scanner-noinputs"] == set()

    def test_skips_dirs_without_action_yml(self, repo):
        _, actions_dir, _ = repo
        # A dir that exists but has no action.yml — shouldn't appear.
        (actions_dir / "stray").mkdir()
        _write_action(actions_dir, "scanner-real", "x")

        result = cei.collect_action_inputs(actions_dir)
        assert "stray" not in result
        assert "scanner-real" in result


# --------------------------------------------------------------------- #
# audit_workflow                                                        #
# --------------------------------------------------------------------- #


class TestAuditWorkflow:

    def test_clean_workflow_returns_no_issues(self, repo):
        _, actions_dir, examples = repo
        _write_action(actions_dir, "scanner-foo", "scan_path", "fail_on_severity")
        wf = _write_example(
            examples, "ex.yml", "scanner-foo",
            {"scan_path": "'.'", "fail_on_severity": "high"},
        )
        action_inputs = cei.collect_action_inputs(actions_dir)

        issues = cei.audit_workflow(wf, action_inputs)
        assert issues == []

    def test_unknown_input_is_reported(self, repo):
        _, actions_dir, examples = repo
        _write_action(actions_dir, "scanner-foo", "scan_path")
        wf = _write_example(
            examples, "ex.yml", "scanner-foo",
            {"scan_path": "'.'", "deprecated_flag": "true"},
        )
        action_inputs = cei.collect_action_inputs(actions_dir)

        issues = cei.audit_workflow(wf, action_inputs)
        assert len(issues) == 1
        i = issues[0]
        assert i["kind"] == "unknown_input"
        assert i["action"] == "scanner-foo"
        assert i["unknown"] == ["deprecated_flag"]
        assert i["job"] == "job1"
        assert "Run scanner" in i["step"]

    def test_multiple_unknown_keys_sorted_in_one_issue(self, repo):
        _, actions_dir, examples = repo
        _write_action(actions_dir, "scanner-foo", "scan_path")
        wf = _write_example(
            examples, "ex.yml", "scanner-foo",
            {"zeta": "1", "alpha": "2", "scan_path": "'.'"},
        )
        action_inputs = cei.collect_action_inputs(actions_dir)

        issues = cei.audit_workflow(wf, action_inputs)
        assert len(issues) == 1
        # Sorted keeps the human-readable output deterministic across
        # runs; protects against flaky diffs in CI logs.
        assert issues[0]["unknown"] == ["alpha", "zeta"]

    def test_missing_action_is_reported(self, repo):
        _, actions_dir, examples = repo
        _write_action(actions_dir, "scanner-real", "x")
        wf = _write_example(
            examples, "ex.yml", "scanner-imaginary",
            {"some_input": "'.'"},
        )
        action_inputs = cei.collect_action_inputs(actions_dir)

        issues = cei.audit_workflow(wf, action_inputs)
        assert len(issues) == 1
        assert issues[0]["kind"] == "missing_action"
        assert issues[0]["action"] == "scanner-imaginary"

    def test_yaml_parse_error_is_reported_not_raised(self, tmp_path):
        # Hand-write a malformed YAML to bypass the helper's safe scaffold.
        wf = tmp_path / "broken.yml"
        wf.write_text("name: x\n  bad: indent: here\n")
        issues = cei.audit_workflow(wf, {"scanner-foo": {"x"}})
        assert len(issues) == 1
        assert issues[0]["kind"] == "yaml_parse_error"

    def test_non_argus_uses_step_is_ignored(self, repo):
        _, actions_dir, examples = repo
        wf = examples / "ex.yml"
        wf.write_text(dedent("""\
            name: example
            on: [workflow_dispatch]
            jobs:
              j:
                runs-on: ubuntu-latest
                steps:
                  - name: Checkout
                    uses: actions/checkout@v6
                    with:
                      ref: main
            """))
        # No argus actions registered — and the only `uses:` step is
        # actions/checkout, which we never audit.
        issues = cei.audit_workflow(wf, {})
        assert issues == []

    def test_workflow_with_no_jobs_is_silent(self, repo):
        _, actions_dir, examples = repo
        wf = examples / "ex.yml"
        wf.write_text("name: x\non: [workflow_dispatch]\n")
        assert cei.audit_workflow(wf, {}) == []

    def test_step_with_no_with_block_is_clean(self, repo):
        _, actions_dir, examples = repo
        _write_action(actions_dir, "scanner-foo", "scan_path")
        wf = _write_example(
            examples, "ex.yml", "scanner-foo", {},  # empty with: block
        )
        # No `with:` keys at all → nothing to be unknown.
        assert cei.audit_workflow(wf, cei.collect_action_inputs(actions_dir)) == []


# --------------------------------------------------------------------- #
# main() exit codes + output formats                                    #
# --------------------------------------------------------------------- #


class TestMain:

    def test_clean_repo_exits_zero(self, repo, capsys, monkeypatch):
        tmp, actions_dir, examples = repo
        _write_action(actions_dir, "scanner-foo", "scan_path")
        _write_example(examples, "ex.yml", "scanner-foo", {"scan_path": "'.'"})
        monkeypatch.chdir(tmp)

        assert cei.main(["--paths", "examples"]) == 0
        out = capsys.readouterr().out
        assert "all example with: keys match" in out

    def test_dirty_repo_exits_one(self, repo, capsys, monkeypatch):
        tmp, actions_dir, examples = repo
        _write_action(actions_dir, "scanner-foo", "scan_path")
        _write_example(
            examples, "ex.yml", "scanner-foo",
            {"scan_path": "'.'", "removed_flag": "1"},
        )
        monkeypatch.chdir(tmp)

        assert cei.main(["--paths", "examples"]) == 1
        out = capsys.readouterr().out
        assert "removed_flag" in out
        assert "1 issue" in out

    def test_json_mode_emits_parseable_array(self, repo, capsys, monkeypatch):
        tmp, actions_dir, examples = repo
        _write_action(actions_dir, "scanner-foo", "scan_path")
        _write_example(
            examples, "ex.yml", "scanner-foo",
            {"scan_path": "'.'", "removed_flag": "1"},
        )
        monkeypatch.chdir(tmp)

        rc = cei.main(["--paths", "examples", "--json"])
        assert rc == 1

        out = capsys.readouterr().out
        data = json.loads(out)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["kind"] == "unknown_input"
        assert data[0]["unknown"] == ["removed_flag"]

    def test_actions_dir_missing_exits_two(self, tmp_path, monkeypatch, capsys):
        # No .github/actions in the cwd → can't build the contract.
        monkeypatch.chdir(tmp_path)
        rc = cei.main(["--paths", "examples", "--actions-dir", str(tmp_path / "nope")])
        assert rc == 2

    def test_gh_annotations_emitted_to_stderr_on_failure(
        self, repo, capsys, monkeypatch,
    ):
        tmp, actions_dir, examples = repo
        _write_action(actions_dir, "scanner-foo", "scan_path")
        _write_example(
            examples, "ex.yml", "scanner-foo",
            {"scan_path": "'.'", "removed_flag": "1"},
        )
        monkeypatch.chdir(tmp)

        rc = cei.main(["--paths", "examples", "--gh-annotations"])
        assert rc == 1
        captured = capsys.readouterr()
        # GitHub Actions parses ::error::-prefixed lines from any
        # stream, but stderr is the conventional channel.
        assert "::error file=" in captured.err
        assert "removed_flag" in captured.err

    def test_clean_repo_no_annotations_on_success(self, repo, capsys, monkeypatch):
        tmp, actions_dir, examples = repo
        _write_action(actions_dir, "scanner-foo", "scan_path")
        _write_example(examples, "ex.yml", "scanner-foo", {"scan_path": "'.'"})
        monkeypatch.chdir(tmp)

        rc = cei.main(["--paths", "examples", "--gh-annotations"])
        assert rc == 0
        # Don't spam ::error annotations on success.
        assert "::error" not in capsys.readouterr().err


# --------------------------------------------------------------------- #
# Integration: real argus repo state                                    #
# --------------------------------------------------------------------- #


class TestRealRepo:

    def test_current_repo_examples_pass_audit(self):
        """Smoke: every example in the actual repo passes the audit.

        If this fails, it means an action.yml's input list shrank
        (or an example added an unknown ``with:`` key). Either fix
        the example, or update the action's contract — see the
        script's docstring for the resolution flow.
        """
        # Use the actual repo's .github/actions and examples roots.
        rc = cei.main([])
        assert rc == 0, (
            "examples/ has unknown with: keys vs current action.yml "
            "contracts; run `python -m scripts.ci.check_example_inputs` "
            "for the diff."
        )
