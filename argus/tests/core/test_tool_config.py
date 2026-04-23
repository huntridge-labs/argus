"""Unit tests for argus.core.tool_config — scanner config discovery."""

from __future__ import annotations

from pathlib import Path

from argus.core.tool_config import (
    ConfigCandidate,
    ConfigResolution,
    DISCOVERY_RULES,
    _has_toml_section,
    format_resolutions_for_display,
    resolve_config,
)


class TestResolveConfigExplicit:
    """Explicit config_file: in argus.yml should always win over discovery."""

    def test_explicit_beats_present_auto_file(self, tmp_path):
        (tmp_path / ".bandit").write_text("# autodiscoverable")
        res = resolve_config("bandit", str(tmp_path), explicit="/shared/bandit.yaml")
        assert res.source == "explicit"
        assert res.path == "/shared/bandit.yaml"

    def test_explicit_for_unknown_scanner(self, tmp_path):
        res = resolve_config("brand-new", str(tmp_path), explicit="cfg.yaml")
        assert res.source == "explicit"
        assert res.path == "cfg.yaml"


class TestResolveConfigDiscovery:
    """Auto-discovery walks the priority list and reports the first hit."""

    def test_bandit_picks_up_dot_bandit(self, tmp_path):
        (tmp_path / ".bandit").write_text("[bandit]\nskips = [\"B101\"]\n")
        res = resolve_config("bandit", str(tmp_path), explicit=None)
        assert res.source == "discovered"
        assert Path(res.path).name == ".bandit"

    def test_bandit_prefers_pyproject_with_tool_bandit(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            "[tool.bandit]\nskips = [\"B101\"]\n"
        )
        (tmp_path / ".bandit").write_text("# fallback, should not be picked")
        res = resolve_config("bandit", str(tmp_path), explicit=None)
        assert res.source == "discovered"
        assert Path(res.path).name == "pyproject.toml"

    def test_bandit_skips_pyproject_without_tool_section(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            "[build-system]\nrequires = [\"setuptools\"]\n"
        )
        (tmp_path / ".bandit").write_text("# real config")
        res = resolve_config("bandit", str(tmp_path), explicit=None)
        assert res.source == "discovered"
        assert Path(res.path).name == ".bandit"

    def test_checkov_yaml_preferred_over_yml(self, tmp_path):
        (tmp_path / ".checkov.yml").write_text("skip-check: [CKV_DOCKER_1]")
        (tmp_path / ".checkov.yaml").write_text("skip-check: [CKV_DOCKER_1]")
        res = resolve_config("checkov", str(tmp_path), explicit=None)
        assert res.source == "discovered"
        assert Path(res.path).name == ".checkov.yaml"

    def test_trivy_picks_up_trivy_yaml(self, tmp_path):
        (tmp_path / "trivy.yaml").write_text("severity: HIGH,CRITICAL\n")
        res = resolve_config("trivy-iac", str(tmp_path), explicit=None)
        assert res.source == "discovered"
        assert Path(res.path).name == "trivy.yaml"

    def test_osv_picks_up_osv_scanner_toml(self, tmp_path):
        (tmp_path / "osv-scanner.toml").write_text(
            "[[IgnoredVulns]]\nid = \"GHSA-1\"\n"
        )
        res = resolve_config("osv", str(tmp_path), explicit=None)
        assert res.source == "discovered"
        assert Path(res.path).name == "osv-scanner.toml"

    def test_opengrep_picks_up_semgrep_yml(self, tmp_path):
        (tmp_path / "semgrep.yml").write_text("rules: []\n")
        res = resolve_config("opengrep", str(tmp_path), explicit=None)
        assert res.source == "discovered"
        assert Path(res.path).name == "semgrep.yml"


class TestResolveConfigNone:
    """No hits should return a 'none' resolution with candidates tried."""

    def test_none_when_no_files_present(self, tmp_path):
        res = resolve_config("bandit", str(tmp_path), explicit=None)
        assert res.source == "none"
        assert res.path is None
        assert ".bandit" in res.candidates_tried

    def test_none_for_scanner_with_no_discovery_rules(self, tmp_path):
        res = resolve_config("gitleaks", str(tmp_path), explicit=None)
        assert res.source == "none"
        assert res.candidates_tried == []


class TestHasTomlSection:
    def test_finds_dotted_section(self, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text("[tool.bandit]\nskips = []\n")
        assert _has_toml_section(f, "tool.bandit") is True

    def test_missing_section(self, tmp_path):
        f = tmp_path / "pyproject.toml"
        f.write_text("[build-system]\nrequires = []\n")
        assert _has_toml_section(f, "tool.bandit") is False

    def test_invalid_toml_returns_false(self, tmp_path):
        f = tmp_path / "bad.toml"
        f.write_text("not = valid = toml = at = all")
        assert _has_toml_section(f, "tool.bandit") is False


class TestFormatting:
    def test_log_line_explicit(self):
        res = ConfigResolution(
            scanner="bandit", source="explicit", path=".bandit"
        )
        assert "from argus.yml" in res.log_line()

    def test_log_line_discovered(self):
        res = ConfigResolution(
            scanner="bandit", source="discovered", path=".bandit"
        )
        assert "auto-discovered" in res.log_line()

    def test_log_line_none_with_candidates(self):
        res = ConfigResolution(
            scanner="bandit", source="none",
            candidates_tried=[".bandit", "bandit.yaml"],
        )
        assert "looked for" in res.log_line()
        assert ".bandit" in res.log_line()

    def test_format_for_display_empty(self):
        assert format_resolutions_for_display([]) == "(no scanners selected)"

    def test_format_for_display_renders_lines(self):
        res = ConfigResolution(
            scanner="bandit", source="discovered", path=".bandit"
        )
        out = format_resolutions_for_display([res])
        assert "Scanner config resolution" in out
        assert "bandit" in out


class TestDiscoveryRulesShape:
    """Discovery rules stay consistent with the module docstring table."""

    def test_every_rule_has_filename(self):
        for scanner, candidates in DISCOVERY_RULES.items():
            assert candidates, f"{scanner} has no discovery candidates"
            for c in candidates:
                assert c.filename, f"{scanner} candidate missing filename"

    def test_required_section_only_on_toml_files(self):
        for scanner, candidates in DISCOVERY_RULES.items():
            for c in candidates:
                if c.required_section:
                    assert c.filename.endswith(".toml"), (
                        f"{scanner}: required_section only makes sense for "
                        f"TOML files, got {c.filename}"
                    )

    def test_scanners_covered(self):
        # Keep this list aligned with what the DISCOVERY_RULES docstring
        # promises. If you add a rule here, update that docstring too.
        expected = {"bandit", "trivy-iac", "checkov", "osv", "opengrep"}
        assert expected.issubset(set(DISCOVERY_RULES.keys()))
