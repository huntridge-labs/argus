"""Tests for supply chain scanner parse_results.py (SARIF parsing)."""

import importlib.util
import json
from pathlib import Path

import pytest

# Load module from file path
SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
PARSER_SCRIPT = SCRIPT_DIR / "parse_results.py"
FIXTURES_DIR = Path(__file__).resolve().parents[4] / "tests" / "fixtures" / "scanner-outputs" / "supply-chain"

spec = importlib.util.spec_from_file_location("parse_results", PARSER_SCRIPT)
parse_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parse_mod)


class TestFixtures:
    """Verify test fixtures exist and are valid."""

    def test_zizmor_findings_fixture_exists(self):
        assert (FIXTURES_DIR / "zizmor-results-with-findings.json").exists()

    def test_zizmor_clean_fixture_exists(self):
        assert (FIXTURES_DIR / "zizmor-results-clean.json").exists()

    def test_actionlint_findings_fixture_exists(self):
        assert (FIXTURES_DIR / "actionlint-results-with-findings.json").exists()

    def test_actionlint_clean_fixture_exists(self):
        assert (FIXTURES_DIR / "actionlint-results-clean.json").exists()

    def test_zizmor_findings_fixture_is_valid_sarif(self):
        data = json.loads((FIXTURES_DIR / "zizmor-results-with-findings.json").read_text())
        assert data.get("version") == "2.1.0"
        assert len(data["runs"][0]["results"]) > 0

    def test_zizmor_clean_fixture_is_valid_sarif(self):
        data = json.loads((FIXTURES_DIR / "zizmor-results-clean.json").read_text())
        assert data.get("version") == "2.1.0"
        assert len(data["runs"][0]["results"]) == 0


class TestValidateFile:
    """Test file validation helper."""

    def test_nonexistent_file(self):
        assert parse_mod.validate_file("/nonexistent/path.json") is False

    def test_empty_file(self, tmp_path):
        empty = tmp_path / "empty.json"
        empty.write_text("")
        assert parse_mod.validate_file(str(empty)) is False

    def test_valid_file(self, tmp_path):
        valid = tmp_path / "valid.json"
        valid.write_text("{}")
        assert parse_mod.validate_file(str(valid)) is True


class TestLoadJson:
    """Test JSON loading helper."""

    def test_valid_json(self, tmp_path):
        f = tmp_path / "data.json"
        f.write_text('{"key": "value"}')
        result = parse_mod.load_json(str(f))
        assert result == {"key": "value"}

    def test_invalid_json_exits(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not json {{{")
        with pytest.raises(SystemExit) as exc_info:
            parse_mod.load_json(str(f))
        assert exc_info.value.code == 1

    def test_nonexistent_file_returns_none(self):
        result = parse_mod.load_json("/nonexistent.json")
        assert result is None

    def test_permission_error_exits(self, tmp_path):
        f = tmp_path / "noperm.json"
        f.write_text('{"key": "value"}')
        f.chmod(0o000)
        try:
            with pytest.raises(SystemExit) as exc_info:
                parse_mod.load_json(str(f))
            assert exc_info.value.code == 1
        finally:
            f.chmod(0o644)


class TestScoreToSeverity:
    """Test security-severity score mapping."""

    def test_high_score(self):
        assert parse_mod._score_to_severity(9.0) == "HIGH"

    def test_medium_score(self):
        assert parse_mod._score_to_severity(5.0) == "MEDIUM"

    def test_low_score(self):
        assert parse_mod._score_to_severity(3.0) == "LOW"

    def test_info_score(self):
        assert parse_mod._score_to_severity(0.0) == "INFO"

    def test_boundary_high(self):
        assert parse_mod._score_to_severity(7.0) == "HIGH"

    def test_boundary_medium(self):
        assert parse_mod._score_to_severity(4.0) == "MEDIUM"

    def test_boundary_low(self):
        assert parse_mod._score_to_severity(0.1) == "LOW"


class TestBuildRuleIndex:
    """Test SARIF rule index builder."""

    def test_builds_index(self):
        sarif = {
            "runs": [{
                "tool": {"driver": {"rules": [
                    {"id": "rule-1", "helpUri": "https://example.com/rule-1"},
                    {"id": "rule-2", "helpUri": "https://example.com/rule-2"},
                ]}},
                "results": [],
            }]
        }
        index = parse_mod._build_rule_index(sarif)
        assert "rule-1" in index
        assert "rule-2" in index
        assert index["rule-1"]["helpUri"] == "https://example.com/rule-1"

    def test_empty_runs(self):
        assert parse_mod._build_rule_index({"runs": []}) == {}

    def test_no_runs(self):
        assert parse_mod._build_rule_index({}) == {}

    def test_no_rules(self):
        sarif = {"runs": [{"tool": {"driver": {}}, "results": []}]}
        assert parse_mod._build_rule_index(sarif) == {}


class TestResolveSeverity:
    """Test severity resolution from SARIF result + rule metadata."""

    def test_security_severity_score(self):
        result = {"level": "warning"}
        rule = {"properties": {"security-severity": "9.0"}}
        assert parse_mod._resolve_severity(result, rule) == "HIGH"

    def test_score_overrides_level(self):
        result = {"level": "note"}
        rule = {"properties": {"security-severity": "8.5"}}
        assert parse_mod._resolve_severity(result, rule) == "HIGH"

    def test_falls_back_to_level(self):
        result = {"level": "error"}
        rule = {}
        assert parse_mod._resolve_severity(result, rule) == "HIGH"

    def test_warning_level(self):
        result = {"level": "warning"}
        rule = {}
        assert parse_mod._resolve_severity(result, rule) == "MEDIUM"

    def test_note_level(self):
        result = {"level": "note"}
        rule = {}
        assert parse_mod._resolve_severity(result, rule) == "LOW"

    def test_falls_back_to_default_config(self):
        result = {}
        rule = {"defaultConfiguration": {"level": "error"}}
        assert parse_mod._resolve_severity(result, rule) == "HIGH"

    def test_no_metadata_defaults_low(self):
        assert parse_mod._resolve_severity({}, None) == "LOW"

    def test_invalid_score_falls_through(self):
        result = {"level": "warning"}
        rule = {"properties": {"security-severity": "not-a-number"}}
        assert parse_mod._resolve_severity(result, rule) == "MEDIUM"


class TestParseZizmorSarif:
    """Test zizmor SARIF parsing."""

    def test_with_findings(self):
        fixture = FIXTURES_DIR / "zizmor-results-with-findings.json"
        findings = parse_mod.parse_zizmor_sarif(str(fixture))
        assert len(findings) == 5

    def test_severity_mapping_from_scores(self):
        fixture = FIXTURES_DIR / "zizmor-results-with-findings.json"
        findings = parse_mod.parse_zizmor_sarif(str(fixture))
        severities = {f["rule"]: f["severity"] for f in findings}
        assert severities["template-injection"] == "HIGH"     # score 9.0
        assert severities["unpinned-uses"] == "MEDIUM"         # score 5.0
        assert severities["excessive-permissions"] == "MEDIUM"  # score 6.0
        assert severities["ref-confusion"] == "LOW"            # score 3.0
        assert severities["github-env"] == "INFO"              # score 0.0

    def test_finding_structure(self):
        fixture = FIXTURES_DIR / "zizmor-results-with-findings.json"
        findings = parse_mod.parse_zizmor_sarif(str(fixture))
        finding = findings[0]
        assert "rule" in finding
        assert "severity" in finding
        assert "description" in finding
        assert "file" in finding
        assert "line" in finding
        assert "source" in finding
        assert finding["source"] == "zizmor"

    def test_location_extraction(self):
        fixture = FIXTURES_DIR / "zizmor-results-with-findings.json"
        findings = parse_mod.parse_zizmor_sarif(str(fixture))
        injection = [f for f in findings if f["rule"] == "template-injection"][0]
        assert injection["file"] == ".github/workflows/pr-title.yml"
        assert injection["line"] == 23

    def test_clean_scan(self):
        fixture = FIXTURES_DIR / "zizmor-results-clean.json"
        findings = parse_mod.parse_zizmor_sarif(str(fixture))
        assert len(findings) == 0

    def test_nonexistent_file(self):
        findings = parse_mod.parse_zizmor_sarif("/nonexistent.json")
        assert len(findings) == 0

    def test_invalid_json_exits(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not json")
        with pytest.raises(SystemExit) as exc_info:
            parse_mod.parse_zizmor_sarif(str(f))
        assert exc_info.value.code == 1

    def test_non_sarif_json_exits(self, tmp_path):
        f = tmp_path / "array.json"
        f.write_text("[]")
        with pytest.raises(SystemExit) as exc_info:
            parse_mod.parse_zizmor_sarif(str(f))
        assert exc_info.value.code == 1

    def test_empty_runs(self, tmp_path):
        f = tmp_path / "empty_runs.json"
        f.write_text('{"version": "2.1.0", "runs": []}')
        findings = parse_mod.parse_zizmor_sarif(str(f))
        assert len(findings) == 0

    def test_no_results_key(self, tmp_path):
        sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"rules": []}}}]}
        f = tmp_path / "no_results.json"
        f.write_text(json.dumps(sarif))
        findings = parse_mod.parse_zizmor_sarif(str(f))
        assert len(findings) == 0

    def test_result_without_locations(self, tmp_path):
        sarif = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"rules": []}}, "results": [
                {"ruleId": "test", "level": "error", "message": {"text": "no location"}}
            ]}]
        }
        f = tmp_path / "no_loc.json"
        f.write_text(json.dumps(sarif))
        findings = parse_mod.parse_zizmor_sarif(str(f))
        assert len(findings) == 1
        assert findings[0]["file"] == ""
        assert findings[0]["line"] == 0

    def test_non_dict_results_skipped(self, tmp_path):
        sarif = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"rules": []}}, "results": ["not a dict", 42]}]
        }
        f = tmp_path / "bad_results.json"
        f.write_text(json.dumps(sarif))
        findings = parse_mod.parse_zizmor_sarif(str(f))
        assert len(findings) == 0

    def test_rule_help_uri_extracted(self):
        fixture = FIXTURES_DIR / "zizmor-results-with-findings.json"
        findings = parse_mod.parse_zizmor_sarif(str(fixture))
        injection = [f for f in findings if f["rule"] == "template-injection"][0]
        assert injection["url"] == "https://docs.zizmor.sh/audits/template-injection/"


class TestParseActionlintFindings:
    """Test actionlint output parsing."""

    def test_with_findings(self):
        fixture = FIXTURES_DIR / "actionlint-results-with-findings.json"
        findings = parse_mod.parse_actionlint_findings(str(fixture))
        assert len(findings) == 3

    def test_all_mapped_to_medium(self):
        fixture = FIXTURES_DIR / "actionlint-results-with-findings.json"
        findings = parse_mod.parse_actionlint_findings(str(fixture))
        for finding in findings:
            assert finding["severity"] == "MEDIUM"

    def test_source_is_actionlint(self):
        fixture = FIXTURES_DIR / "actionlint-results-with-findings.json"
        findings = parse_mod.parse_actionlint_findings(str(fixture))
        for finding in findings:
            assert finding["source"] == "actionlint"

    def test_finding_structure(self):
        fixture = FIXTURES_DIR / "actionlint-results-with-findings.json"
        findings = parse_mod.parse_actionlint_findings(str(fixture))
        finding = findings[0]
        assert finding["rule"] == "shellcheck"
        assert finding["file"] == ".github/workflows/ci.yml"
        assert finding["line"] == 18

    def test_clean_scan(self):
        fixture = FIXTURES_DIR / "actionlint-results-clean.json"
        findings = parse_mod.parse_actionlint_findings(str(fixture))
        assert len(findings) == 0

    def test_nonexistent_file(self):
        findings = parse_mod.parse_actionlint_findings("/nonexistent.json")
        assert len(findings) == 0

    def test_non_dict_items_skipped(self, tmp_path):
        data = ["string", 123]
        f = tmp_path / "mixed.json"
        f.write_text(json.dumps(data))
        findings = parse_mod.parse_actionlint_findings(str(f))
        assert len(findings) == 0


class TestGetAllFindings:
    """Test combined findings from both tools."""

    def test_zizmor_only(self):
        zizmor = FIXTURES_DIR / "zizmor-results-with-findings.json"
        findings = parse_mod.get_all_findings(str(zizmor))
        assert len(findings) == 5

    def test_combined(self):
        zizmor = FIXTURES_DIR / "zizmor-results-with-findings.json"
        actionlint = FIXTURES_DIR / "actionlint-results-with-findings.json"
        findings = parse_mod.get_all_findings(str(zizmor), str(actionlint))
        assert len(findings) == 8  # 5 zizmor + 3 actionlint

    def test_sorted_by_severity(self):
        zizmor = FIXTURES_DIR / "zizmor-results-with-findings.json"
        actionlint = FIXTURES_DIR / "actionlint-results-with-findings.json"
        findings = parse_mod.get_all_findings(str(zizmor), str(actionlint))
        severities = [f["severity"] for f in findings]
        first_high = severities.index("HIGH")
        first_medium = severities.index("MEDIUM")
        first_low = severities.index("LOW")
        first_info = severities.index("INFO")
        assert first_high < first_medium
        assert first_medium < first_low
        assert first_low < first_info

    def test_both_clean(self):
        zizmor = FIXTURES_DIR / "zizmor-results-clean.json"
        actionlint = FIXTURES_DIR / "actionlint-results-clean.json"
        findings = parse_mod.get_all_findings(str(zizmor), str(actionlint))
        assert len(findings) == 0

    def test_actionlint_none(self):
        zizmor = FIXTURES_DIR / "zizmor-results-with-findings.json"
        findings = parse_mod.get_all_findings(str(zizmor), None)
        assert len(findings) == 5


class TestGetCounts:
    """Test severity count aggregation."""

    def test_with_findings(self):
        zizmor = FIXTURES_DIR / "zizmor-results-with-findings.json"
        counts = parse_mod.get_counts(str(zizmor))
        assert counts["high"] == 1
        assert counts["medium"] == 2
        assert counts["low"] == 1
        assert counts["info"] == 1
        assert counts["total"] == 5

    def test_combined_counts(self):
        zizmor = FIXTURES_DIR / "zizmor-results-with-findings.json"
        actionlint = FIXTURES_DIR / "actionlint-results-with-findings.json"
        counts = parse_mod.get_counts(str(zizmor), str(actionlint))
        assert counts["high"] == 1
        assert counts["medium"] == 5  # 2 zizmor + 3 actionlint
        assert counts["low"] == 1
        assert counts["info"] == 1
        assert counts["total"] == 8

    def test_clean_scan(self):
        zizmor = FIXTURES_DIR / "zizmor-results-clean.json"
        counts = parse_mod.get_counts(str(zizmor))
        assert counts["high"] == 0
        assert counts["medium"] == 0
        assert counts["low"] == 0
        assert counts["info"] == 0
        assert counts["total"] == 0

    def test_nonexistent_file(self):
        counts = parse_mod.get_counts("/nonexistent.json")
        assert counts["total"] == 0

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.json"
        f.write_text("")
        counts = parse_mod.get_counts(str(f))
        assert counts["total"] == 0


class TestMainCLI:
    """Test CLI entry point."""

    def test_counts_command(self, capsys):
        fixture = FIXTURES_DIR / "zizmor-results-with-findings.json"
        import sys
        old_argv = sys.argv
        sys.argv = ["parse_results.py", "counts", str(fixture)]
        try:
            parse_mod.main()
        finally:
            sys.argv = old_argv
        captured = capsys.readouterr()
        parts = captured.out.strip().split()
        assert len(parts) == 4
        assert parts[0] == "1"  # high
        assert parts[1] == "2"  # medium
        assert parts[2] == "1"  # low
        assert parts[3] == "1"  # info

    def test_findings_command(self, capsys):
        fixture = FIXTURES_DIR / "zizmor-results-with-findings.json"
        import sys
        old_argv = sys.argv
        sys.argv = ["parse_results.py", "findings", str(fixture)]
        try:
            parse_mod.main()
        finally:
            sys.argv = old_argv
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) == 5

    def test_counts_with_actionlint(self, capsys):
        zizmor = FIXTURES_DIR / "zizmor-results-with-findings.json"
        actionlint = FIXTURES_DIR / "actionlint-results-with-findings.json"
        import sys
        old_argv = sys.argv
        sys.argv = ["parse_results.py", "counts", str(zizmor),
                     "--actionlint-file", str(actionlint)]
        try:
            parse_mod.main()
        finally:
            sys.argv = old_argv
        captured = capsys.readouterr()
        parts = captured.out.strip().split()
        assert parts[0] == "1"   # high
        assert parts[1] == "5"   # medium (2 + 3)
        assert parts[2] == "1"   # low
        assert parts[3] == "1"   # info
