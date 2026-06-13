"""Unit tests for argus.viewers.terminal.init_wizard (Phase 3).

UI-free: no Textual. Pins the detect → propose → write model the Console's
Init wizard wraps around argus.init's pure functions.
"""

from __future__ import annotations

import pytest

from argus.viewers.terminal.init_wizard import (
    CONFIG_FILENAME,
    DetectedCategory,
    InitPlan,
    build_plan,
    detected_categories,
    readiness_line,
    summary_line,
    write_config,
)


@pytest.fixture
def python_project(tmp_path):
    """A minimal project the detector recognises (Python + deps + CI)."""
    (tmp_path / "app.py").write_text("print('hi')\n")
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\n")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("on: push\n")
    return tmp_path


class TestDetectedCategories:
    def test_maps_keys_to_human_labels(self):
        cats = detected_categories({"python": ["app.py", "x.py"], "iac": ["main.tf"]})
        by_key = {c.key: c for c in cats}
        assert by_key["python"].label == "Python source files"
        assert by_key["python"].example == "app.py"
        assert by_key["python"].count == 2
        assert by_key["iac"].label == "Infrastructure as code"

    def test_unknown_key_falls_back_to_key(self):
        cats = detected_categories({"mystery": ["a"]})
        assert cats[0].label == "mystery"

    def test_empty_signals_yields_no_categories(self):
        assert detected_categories({}) == []


class TestBuildPlan:
    def test_detects_python_project(self, python_project):
        plan = build_plan(python_project)
        keys = {c.key for c in plan.categories}
        assert "python" in keys
        assert "dependencies" in keys
        assert "github-actions" in keys

    def test_proposes_expected_scanners(self, python_project):
        plan = build_plan(python_project)
        # gitleaks + opengrep always; bandit (python), osv (deps),
        # supply-chain (gh-actions) all proposed for this project.
        for scanner in ("gitleaks", "bandit", "osv", "opengrep", "supply-chain"):
            assert scanner in plan.proposed_scanners

    def test_yaml_is_generated_and_parseable(self, python_project):
        import yaml
        plan = build_plan(python_project)
        assert plan.yaml.strip()
        parsed = yaml.safe_load(plan.yaml)
        assert "scanners" in parsed

    def test_config_path_and_absence(self, python_project):
        plan = build_plan(python_project)
        assert plan.config_path == python_project / CONFIG_FILENAME
        assert plan.config_exists is False

    def test_config_exists_when_present(self, python_project):
        (python_project / CONFIG_FILENAME).write_text("version: '1.0'\n")
        plan = build_plan(python_project)
        assert plan.config_exists is True

    def test_no_detect_still_proposes_defaults(self, python_project):
        plan = build_plan(python_project, detect=False)
        assert plan.categories == []
        # Always-on scanners still proposed even with detection off.
        assert "gitleaks" in plan.proposed_scanners
        assert "opengrep" in plan.proposed_scanners

    def test_empty_dir_proposes_safe_defaults(self, tmp_path):
        plan = build_plan(tmp_path)
        assert "gitleaks" in plan.proposed_scanners
        assert "bandit" not in plan.proposed_scanners  # no python detected


class TestReadinessLine:
    def test_none_is_empty(self):
        assert readiness_line(None) == ""
        assert readiness_line({}) == ""

    def test_formats_buckets(self):
        line = readiness_line({"local": 2, "container": 1, "missing": 0})
        assert "2 ready locally" in line
        assert "1 via container" in line
        assert "0 missing" in line

    def test_missing_count_surfaced(self):
        assert "3 missing" in readiness_line({"local": 0, "container": 0, "missing": 3})


class TestSummaryLine:
    def test_with_categories(self, python_project):
        plan = build_plan(python_project)
        line = summary_line(plan)
        assert "detected" in line
        assert "scanners proposed" in line

    def test_no_signals(self):
        plan = InitPlan(root=None, categories=[], proposed_scanners=["gitleaks"])
        assert "no project signals detected" in summary_line(plan)


class TestWriteConfig:
    def test_writes_new_file(self, tmp_path):
        target = tmp_path / CONFIG_FILENAME
        written = write_config(target, "version: '1.0'\n")
        assert written == target
        assert target.read_text() == "version: '1.0'\n"

    def test_refuses_existing_without_force(self, tmp_path):
        target = tmp_path / CONFIG_FILENAME
        target.write_text("old\n")
        with pytest.raises(FileExistsError):
            write_config(target, "new\n")
        assert target.read_text() == "old\n"  # untouched

    def test_overwrites_with_force(self, tmp_path):
        target = tmp_path / CONFIG_FILENAME
        target.write_text("old\n")
        write_config(target, "new\n", force=True)
        assert target.read_text() == "new\n"


class TestDataclasses:
    def test_detected_category_is_frozen(self):
        cat = DetectedCategory(key="python", label="Python", example="a.py", count=1)
        with pytest.raises(Exception):
            cat.key = "go"  # type: ignore[misc]
