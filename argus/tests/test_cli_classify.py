"""SCN configuration validation through the classify command."""

import json
from unittest.mock import Mock

import pytest
import yaml

from argus.cli import EXIT_ERROR, EXIT_SUCCESS, build_parser, cmd_classify
from argus.scn import diff


@pytest.fixture
def iac_analysis():
    return {
        "changes": [{
            "file": "main.tf",
            "resources": [{
                "type": "aws_instance",
                "name": "web",
                "operation": "modify",
                "attributes_changed": ["tags"],
                "diff": 'tags = { Name = "updated" }',
            }],
        }],
    }


@pytest.mark.parametrize("filename,content,error", [
    ("scn.yml", "thresholds:\n  bogus: true\nai:\n  provider: notreal\n",
     "version: required field missing"),
    ("scn.json", '{"version": "1.0"}', "rules: required field missing"),
    ("empty.yml", "", "version: required field missing"),
    ("list.json", "[]", "config: must be a mapping"),
    ("rules.yaml", 'version: "1.0"\nrules:\n  routine: []\n',
     "rules.routine: must have at least 1 rule"),
])
def test_invalid_config_rejected_before_diff(
    monkeypatch, tmp_path, capsys, filename, content, error,
):
    config = tmp_path / filename
    config.write_text(content, encoding="utf-8")
    analyze = Mock(return_value={"changes": []})
    monkeypatch.setattr(diff, "analyze_iac_changes", analyze)
    args = build_parser().parse_args(["classify", "--config", str(config)])

    assert cmd_classify(args) == EXIT_ERROR

    captured = capsys.readouterr()
    assert "Error: failed to load SCN config: Config validation failed:" in captured.err
    assert error in captured.err
    assert "No IaC changes detected" not in captured.out
    analyze.assert_not_called()


def test_invalid_config_does_not_classify_with_defaults(
    monkeypatch, tmp_path, capsys, iac_analysis,
):
    config = tmp_path / "scn.yml"
    config.write_text("thresholds:\n  bogus: true\nai:\n  provider: notreal\n")
    analyze = Mock(return_value=iac_analysis)
    monkeypatch.setattr(diff, "analyze_iac_changes", analyze)
    output = tmp_path / "report"
    args = build_parser().parse_args([
        "classify", "--config", str(config), "--format", "json",
        "--output-dir", str(output),
    ])

    assert cmd_classify(args) == EXIT_ERROR

    assert "rules: required field missing" in capsys.readouterr().err
    assert not (output / "scn-report.json").exists()
    analyze.assert_not_called()


@pytest.mark.parametrize("suffix", [".yml", ".json"])
def test_valid_config_applies_custom_rule(monkeypatch, tmp_path, iac_analysis, suffix):
    config = {
        "version": "1.0",
        "rules": {"routine": [{
            "attribute": "^tags$", "description": "Custom tag policy",
        }]},
    }
    path = tmp_path / ("scn" + suffix)
    content = json.dumps(config) if suffix == ".json" else yaml.safe_dump(config)
    path.write_text(content, encoding="utf-8")
    monkeypatch.setattr(diff, "analyze_iac_changes", Mock(return_value=iac_analysis))
    output = tmp_path / "report"
    args = build_parser().parse_args([
        "classify", "--config", str(path), "--format", "json",
        "--output-dir", str(output),
    ])

    assert cmd_classify(args) == EXIT_SUCCESS

    report = json.loads((output / "scn-report.json").read_text())
    assert report["categories"] == {"ROUTINE": 1}
    assert report["classifications"][0]["reasoning"] == "Custom tag policy"
    assert report["classifications"][0]["method"] == "rule-based"


@pytest.mark.parametrize("has_changes", [False, True])
def test_omitted_config_keeps_defaults(
    monkeypatch, tmp_path, capsys, iac_analysis, has_changes,
):
    analysis = iac_analysis if has_changes else {"changes": []}
    monkeypatch.setattr(diff, "analyze_iac_changes", Mock(return_value=analysis))
    args = build_parser().parse_args([
        "classify", "--format", "json", "--output-dir", str(tmp_path),
    ])

    assert cmd_classify(args) == EXIT_SUCCESS

    if has_changes:
        report = json.loads((tmp_path / "scn-report.json").read_text())
        assert report["categories"] == {"ROUTINE": 1}
        assert report["classifications"][0]["reasoning"] == "Tag changes"
    else:
        assert "No IaC changes detected" in capsys.readouterr().out


@pytest.mark.parametrize("content", [None, "rules: ["])
def test_unreadable_config_keeps_load_error(monkeypatch, tmp_path, capsys, content):
    path = tmp_path / "scn.yml"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    analyze = Mock(return_value={"changes": []})
    monkeypatch.setattr(diff, "analyze_iac_changes", analyze)
    args = build_parser().parse_args(["classify", "--config", str(path)])

    assert cmd_classify(args) == EXIT_ERROR

    assert "Error: failed to load SCN config:" in capsys.readouterr().err
    analyze.assert_not_called()
