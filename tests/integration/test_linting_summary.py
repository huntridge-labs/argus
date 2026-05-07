"""Integration tests for the linting-summary composite action.

These tests exercise the real `generate_summary.py` script that ships inside
`.github/actions/linting-summary/scripts/` — not a Python reproduction of
bash logic. The script owns the report-generation contract, so testing it
directly means the tests will catch regressions that the composite's
consumers would actually see.

Coverage goals:

- Discovery path: summaries are found, sorted, and stitched together.
- Status-table path: `scan_statuses` JSON renders a per-linter pass/fail
  table and surfaces failing linters.
- Silent-failure guard: a linter that reports `failure` but uploads no
  summary artifact is surfaced as failing in the status table rather than
  collapsing into a "no findings" verdict.
- Double-disclosure UX: a summary pre-wrapped in `<details>` is unwrapped so
  reviewers don't have to click twice to see findings.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Iterator

import pytest


# Dynamically load the generate_summary module from the composite action
# so tests stay co-located with the shipped script without needing to add
# the composite's scripts dir to the global pythonpath.
_SCRIPT_PATH = (
    Path(__file__).resolve().parents[2]
    / ".github/actions/linting-summary/scripts/generate_summary.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("linting_generate_summary", _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generate_summary = _load_module()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

YAML_SUMMARY = """\
#### YAML Lint

| Severity | Count |
|----------|-------|
| Info     | 3     |

**Total findings:** 3
"""

PYTHON_SUMMARY = """\
#### Python Lint

| Severity | Count |
|----------|-------|
| Info     | 1     |

**Total findings:** 1
"""

DOCKERFILE_SUMMARY_WRAPPED = """\
<details><summary>🐳 Dockerfile Lint</summary>

**Status:** ✅ Completed

| Info | Style | Warnings |
|:----:|:-----:|:--------:|
| 0    | 2     | 5        |

</details>
"""


@pytest.fixture
def summaries_dir(tmp_path: Path) -> Path:
    d = tmp_path / "linter-summaries"
    d.mkdir()
    return d


@pytest.fixture
def run_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Run tests with tmp_path as the working directory and GITHUB_OUTPUT set."""
    monkeypatch.chdir(tmp_path)
    github_output = tmp_path / "gh_output.env"
    github_output.touch()
    monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
    yield tmp_path


def _set_env(monkeypatch: pytest.MonkeyPatch, **env: str) -> None:
    defaults = {
        "SUMMARY_TITLE": "Code Quality & Linting Summary",
        "SHOW_METADATA": "false",
        "SHOW_STATS": "true",
        "SCAN_STATUSES_JSON": "",
        "HEAD_REF": "",
        "REF_NAME": "main",
        "RUN_NUMBER": "1",
        "SERVER_URL": "https://github.com",
        "REPOSITORY": "owner/repo",
        "RUN_ID": "123",
        "COMMIT_SHA": "abc1234567",
    }
    defaults.update(env)
    for key, value in defaults.items():
        monkeypatch.setenv(key, value)


def _read_outputs(path: Path) -> dict[str, str]:
    pairs = {}
    for line in path.read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            pairs[k] = v
    return pairs


# ---------------------------------------------------------------------------
# Pure-function unit coverage (no file system)
# ---------------------------------------------------------------------------


class TestParseScanStatuses:
    def test_blank_input_returns_empty_dict(self):
        assert generate_summary.parse_scan_statuses("") == {}
        assert generate_summary.parse_scan_statuses("   \n  ") == {}

    def test_valid_json_normalizes_values(self):
        raw = '{"yaml": "success", "python": "failure"}'
        assert generate_summary.parse_scan_statuses(raw) == {
            "yaml": "success",
            "python": "failure",
        }

    def test_empty_string_value_becomes_not_run(self):
        raw = '{"yaml": "", "python": "success"}'
        result = generate_summary.parse_scan_statuses(raw)
        assert result["yaml"] == "not-run"
        assert result["python"] == "success"

    def test_invalid_json_returns_empty_dict(self, capsys):
        result = generate_summary.parse_scan_statuses("not-json-at-all")
        assert result == {}
        captured = capsys.readouterr()
        assert "not valid JSON" in captured.err
        # Warning is namespaced to the linting-summary action so log readers
        # can tell which aggregator produced the message.
        assert "linting-summary" in captured.err

    def test_json_that_is_not_an_object_returns_empty(self, capsys):
        result = generate_summary.parse_scan_statuses('["yaml", "python"]')
        assert result == {}
        captured = capsys.readouterr()
        assert "must be a JSON object" in captured.err


class TestDeriveOverallStatus:
    def test_empty_statuses_are_unknown(self):
        assert generate_summary.derive_overall_status({}) == ("unknown", 0)

    def test_all_success_is_success(self):
        statuses = {"a": "success", "b": "success"}
        assert generate_summary.derive_overall_status(statuses) == ("success", 0)

    def test_skipped_counts_as_passing(self):
        statuses = {"a": "success", "b": "skipped", "c": "not-run"}
        assert generate_summary.derive_overall_status(statuses) == ("success", 0)

    def test_any_failure_is_failure(self):
        statuses = {"a": "success", "b": "failure"}
        assert generate_summary.derive_overall_status(statuses) == ("failure", 1)

    def test_cancelled_counts_as_failure(self):
        # Cancelled lint jobs can't be trusted; must block downstream consumers.
        statuses = {"a": "cancelled", "b": "success"}
        assert generate_summary.derive_overall_status(statuses) == ("failure", 1)


class TestNormalizeSummary:
    def test_plain_markdown_passes_through(self):
        src = "#### YAML Lint\n\nNo findings.\n"
        result = generate_summary.normalize_summary(src)
        assert "<details" not in result
        assert "YAML Lint" in result

    def test_adds_trailing_newline_to_plain_markdown(self):
        # Without a trailing newline, subsequent cats would glue linter
        # headings together.
        src = "#### YAML Lint\n\nNo findings."
        result = generate_summary.normalize_summary(src)
        assert result.endswith("\n")

    def test_strips_single_outer_details_wrapper(self):
        result = generate_summary.normalize_summary(DOCKERFILE_SUMMARY_WRAPPED)
        assert "<details>" not in result
        assert "</details>" not in result
        assert "#### 🐳 Dockerfile Lint" in result
        # Body is preserved.
        assert "Status:" in result and "Warnings" in result

    def test_leaves_nested_details_intact_when_outer_is_not_sole_wrapper(self):
        # Document contains a heading followed by a disclosure — the outer
        # regex doesn't match, so the whole thing should survive.
        src = "## Terraform Lint\n\n<details><summary>details</summary>body</details>\n"
        result = generate_summary.normalize_summary(src)
        assert "## Terraform Lint" in result
        assert "<details>" in result


# ---------------------------------------------------------------------------
# End-to-end tests: invoke the script entry point, read the rendered report
# ---------------------------------------------------------------------------


class TestGenerateSummaryEndToEnd:
    def test_discovery_only_combines_summaries_in_sorted_order(
        self, run_in, summaries_dir, monkeypatch
    ):
        (summaries_dir / "yaml.md").write_text(YAML_SUMMARY)
        (summaries_dir / "terraform.md").write_text("#### Terraform Lint\n\nNo findings.\n")
        (summaries_dir / "python.md").write_text(PYTHON_SUMMARY)

        _set_env(monkeypatch)
        output = run_in / "report.md"
        exit_code = generate_summary.main(
            ["generate_summary.py", str(output), "true"]
        )
        assert exit_code == 0

        content = output.read_text()
        # Alphabetical order: python < terraform < yaml
        assert (
            content.index("Python Lint")
            < content.index("Terraform Lint")
            < content.index("YAML Lint")
        )
        assert "**Linters Executed:** 3" in content
        assert "_Generated by [Argus]" in content

    def test_status_table_renders_when_scan_statuses_provided(
        self, run_in, summaries_dir, monkeypatch
    ):
        (summaries_dir / "yaml.md").write_text(YAML_SUMMARY)

        _set_env(
            monkeypatch,
            SCAN_STATUSES_JSON=json.dumps(
                {
                    "yaml": "success",
                    "python": "success",
                    "dockerfile": "failure",
                    "terraform": "skipped",
                }
            ),
        )
        output = run_in / "report.md"
        exit_code = generate_summary.main(
            ["generate_summary.py", str(output), "true"]
        )
        assert exit_code == 0

        content = output.read_text()
        assert "### Lint Status" in content
        assert "| `yaml` | ✅ PASS |" in content
        assert "| `dockerfile` | ❌ FAIL |" in content
        assert "| `terraform` | ⏭️ skipped |" in content
        # Failing linters are called out explicitly in the blockquote footer.
        assert "1 linter(s) failed" in content
        assert "`dockerfile`" in content

    def test_silent_failure_surfaces_when_summary_missing(
        self, run_in, summaries_dir, monkeypatch
    ):
        # Dockerfile linter reports "failure" but never uploaded a summary —
        # the pre-refactor bash rollup would have silently reported "no
        # linter summaries found." The status table must catch it as a real
        # failure rather than a benign empty state.
        _set_env(
            monkeypatch,
            SCAN_STATUSES_JSON=json.dumps({"dockerfile": "failure"}),
        )
        output = run_in / "report.md"
        exit_code = generate_summary.main(
            ["generate_summary.py", str(output), "true"]
        )
        assert exit_code == 0

        content = output.read_text()
        assert "| `dockerfile` | ❌ FAIL |" in content
        # No summary artifacts means the Linter Results section explicitly
        # warns that the status table is the source of truth.
        assert "_No linter summary artifacts were uploaded._" in content
        assert "status table above is the source of truth" in content

        # GitHub outputs reflect the failing verdict so the composite knows
        # to exit non-zero.
        outputs = _read_outputs(run_in / "gh_output.env")
        assert outputs["overall_status"] == "failure"
        assert outputs["failed_count"] == "1"

    def test_all_success_emits_success_overall_status(
        self, run_in, summaries_dir, monkeypatch
    ):
        (summaries_dir / "yaml.md").write_text(YAML_SUMMARY)
        _set_env(
            monkeypatch,
            SCAN_STATUSES_JSON=json.dumps(
                {"yaml": "success", "python": "success"}
            ),
        )
        output = run_in / "report.md"
        generate_summary.main(["generate_summary.py", str(output), "true"])

        outputs = _read_outputs(run_in / "gh_output.env")
        assert outputs["overall_status"] == "success"
        assert outputs["failed_count"] == "0"
        assert "**✅ All enabled linters completed successfully.**" in output.read_text()

    def test_all_failed_emits_failure_overall_status(
        self, run_in, summaries_dir, monkeypatch
    ):
        # Worst-case scenario: every wired linter failed. The status table
        # must list each one and the GitHub output must reflect the count.
        _set_env(
            monkeypatch,
            SCAN_STATUSES_JSON=json.dumps(
                {"yaml": "failure", "python": "failure", "dockerfile": "cancelled"}
            ),
        )
        output = run_in / "report.md"
        generate_summary.main(["generate_summary.py", str(output), "true"])

        content = output.read_text()
        outputs = _read_outputs(run_in / "gh_output.env")
        assert outputs["overall_status"] == "failure"
        assert outputs["failed_count"] == "3"
        assert "3 linter(s) failed" in content
        assert "| `dockerfile` | ⏹️ cancelled |" in content

    def test_mixed_pass_fail_skipped_renders_each_badge(
        self, run_in, summaries_dir, monkeypatch
    ):
        _set_env(
            monkeypatch,
            SCAN_STATUSES_JSON=json.dumps(
                {
                    "yaml": "success",
                    "python": "failure",
                    "javascript": "skipped",
                    "dockerfile": "cancelled",
                    "terraform": "",  # empty -> not-run
                }
            ),
        )
        output = run_in / "report.md"
        generate_summary.main(["generate_summary.py", str(output), "true"])

        content = output.read_text()
        assert "✅ PASS" in content
        assert "❌ FAIL" in content
        assert "⏭️ skipped" in content
        assert "⏹️ cancelled" in content
        assert "◻️ not run" in content

        outputs = _read_outputs(run_in / "gh_output.env")
        # Failure + cancelled = 2 blocking; skipped + not-run + success = passing.
        assert outputs["overall_status"] == "failure"
        assert outputs["failed_count"] == "2"

    def test_no_scan_statuses_emits_unknown_overall_status(
        self, run_in, summaries_dir, monkeypatch
    ):
        (summaries_dir / "yaml.md").write_text(YAML_SUMMARY)
        _set_env(monkeypatch)  # no SCAN_STATUSES_JSON
        output = run_in / "report.md"
        generate_summary.main(["generate_summary.py", str(output), "true"])

        outputs = _read_outputs(run_in / "gh_output.env")
        # When caller doesn't wire scan_statuses we cannot make a verdict.
        # The composite's optional fail step won't fire on "unknown", so the
        # caller's gating is preserved.
        assert outputs["overall_status"] == "unknown"
        content = output.read_text()
        assert "### Lint Status" not in content

    def test_invalid_scan_statuses_falls_back_to_discovery_only(
        self, run_in, summaries_dir, monkeypatch
    ):
        # A typo in the workflow caller's `with:` block must not crash the
        # report. We expect a warning + a degraded but valid output.
        (summaries_dir / "yaml.md").write_text(YAML_SUMMARY)
        _set_env(monkeypatch, SCAN_STATUSES_JSON="{not valid json")
        output = run_in / "report.md"
        exit_code = generate_summary.main(
            ["generate_summary.py", str(output), "true"]
        )
        assert exit_code == 0

        content = output.read_text()
        assert "### Lint Status" not in content
        assert "YAML Lint" in content
        outputs = _read_outputs(run_in / "gh_output.env")
        assert outputs["overall_status"] == "unknown"

    def test_double_details_unwrap_in_rendered_output(
        self, run_in, summaries_dir, monkeypatch
    ):
        # Dockerfile summary ships wrapped; simulate the previously-broken
        # double-disclosure UX by rendering it through the aggregator.
        (summaries_dir / "dockerfile.md").write_text(DOCKERFILE_SUMMARY_WRAPPED)
        _set_env(monkeypatch)
        output = run_in / "report.md"
        generate_summary.main(["generate_summary.py", str(output), "true"])

        content = output.read_text()
        # The outer <details> wrapper is replaced with a heading so reviewers
        # see the section title without clicking twice.
        assert "<details>" not in content
        assert "</details>" not in content
        assert "#### 🐳 Dockerfile Lint" in content

    def test_metadata_block_renders_when_enabled(
        self, run_in, summaries_dir, monkeypatch
    ):
        (summaries_dir / "yaml.md").write_text(YAML_SUMMARY)
        _set_env(
            monkeypatch,
            SHOW_METADATA="true",
            RUN_NUMBER="42",
            REPOSITORY="acme/lint",
            RUN_ID="9999",
            REF_NAME="main",
            COMMIT_SHA="deadbeef123456",
        )
        output = run_in / "report.md"
        generate_summary.main(["generate_summary.py", str(output), "true"])

        content = output.read_text()
        assert "**Workflow Run:** [42]" in content
        assert "**Branch:** `main`" in content
        assert "`deadbee`" in content  # short sha

    def test_show_stats_false_hides_executed_count(
        self, run_in, summaries_dir, monkeypatch
    ):
        (summaries_dir / "yaml.md").write_text(YAML_SUMMARY)
        _set_env(monkeypatch, SHOW_STATS="false")
        output = run_in / "report.md"
        generate_summary.main(["generate_summary.py", str(output), "true"])

        content = output.read_text()
        assert "**Linters Executed:**" not in content
        # The actual linter section still renders.
        assert "### Linter Results" in content
        assert "YAML Lint" in content

    def test_title_hidden_when_include_title_false(
        self, run_in, summaries_dir, monkeypatch
    ):
        # The composite calls the script twice — once with include_title for
        # the job summary, once without for the PR comment body. Verify the
        # toggle works.
        (summaries_dir / "yaml.md").write_text(YAML_SUMMARY)
        _set_env(monkeypatch, SUMMARY_TITLE="Custom Title")
        output = run_in / "report.md"
        generate_summary.main(["generate_summary.py", str(output), "false"])

        content = output.read_text()
        assert not content.lstrip().startswith("## Custom Title")
        assert "YAML Lint" in content

    def test_title_renders_with_h2_when_include_title_true(
        self, run_in, summaries_dir, monkeypatch
    ):
        (summaries_dir / "yaml.md").write_text(YAML_SUMMARY)
        _set_env(monkeypatch, SUMMARY_TITLE="Code Quality & Linting Summary")
        output = run_in / "report.md"
        generate_summary.main(["generate_summary.py", str(output), "true"])

        # The job-step-summary copy gets the title prefixed with `## `.
        assert output.read_text().lstrip().startswith("## Code Quality & Linting Summary")

    def test_empty_linter_summaries_without_statuses_shows_no_results(
        self, run_in, summaries_dir, monkeypatch
    ):
        _set_env(monkeypatch)  # empty summaries dir, no scan_statuses
        output = run_in / "report.md"
        generate_summary.main(["generate_summary.py", str(output), "true"])

        content = output.read_text()
        assert "_No linter summary artifacts were uploaded._" in content
        outputs = _read_outputs(run_in / "gh_output.env")
        # With no statuses AND no summaries we can't claim success OR failure.
        assert outputs["overall_status"] == "unknown"


class TestScriptInterface:
    def test_missing_args_returns_nonzero(self, monkeypatch, capsys):
        _set_env(monkeypatch)
        exit_code = generate_summary.main(["generate_summary.py"])
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "usage:" in captured.err


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
