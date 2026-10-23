"""``argus sbom inspect`` CLI wiring (#494)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus.cli import (
    EXIT_ERROR,
    EXIT_SUCCESS,
    _generate_bash_completion,
    _generate_zsh_completion,
    build_parser,
    cmd_sbom,
)

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "sbom"


def _run(*argv):
    args = build_parser().parse_args(["sbom", *argv])
    return cmd_sbom(args)


class TestSbomInspect:
    def test_terminal_output(self, capsys):
        assert _run("inspect", str(FIXTURES / "syft-amzn2023.spdx.json")) == EXIT_SUCCESS
        out = capsys.readouterr().out
        assert "Generator:  syft 1.54.1" in out
        assert "Matcher:    grype" in out

    def test_json_output(self, capsys):
        assert _run(
            "inspect", str(FIXTURES / "trivy-amzn2023.cdx.json"), "--format", "json",
        ) == EXIT_SUCCESS
        data = json.loads(capsys.readouterr().out)
        assert data["generator"]["name"] == "trivy"
        assert data["matcher"]["matchers"] == ["trivy"]
        assert data["os"]["source"] == "purl"

    def test_not_an_sbom(self, tmp_path, capsys):
        bad = tmp_path / "x.json"
        bad.write_text('{"hello": "world"}')
        assert _run("inspect", str(bad)) == EXIT_ERROR
        assert "Unrecognized SBOM format" in capsys.readouterr().err

    def test_missing_file(self, tmp_path, capsys):
        assert _run("inspect", str(tmp_path / "nope.json")) == EXIT_ERROR
        assert "not found" in capsys.readouterr().err

    def test_no_action_prints_usage(self, capsys):
        assert _run() == EXIT_ERROR
        assert "inspect" in capsys.readouterr().err

    def test_rejects_unknown_format(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["sbom", "inspect", "x", "--format", "xml"])


class TestCompletions:
    def test_zsh_knows_sbom_inspect(self):
        script = _generate_zsh_completion("bandit grype")
        assert "'sbom:" in script
        assert "inspect" in script

    def test_bash_knows_sbom_inspect(self):
        script = _generate_bash_completion("bandit grype")
        assert " sbom" in script
        assert "inspect" in script
