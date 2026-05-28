"""Tests for scripts/ci/affected_scanners — the diff→scanner mapping that
scopes container smoke tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from scripts.ci.affected_scanners import (
    CROSS_CUTTING,
    affected_scanners,
    changed_files,
    main,
)


class TestAffectedScanners:
    def test_no_scanner_files_changed_returns_empty(self):
        assert affected_scanners(["README.md", "docs/scanners.md"]) == []

    def test_single_scanner_module_maps_to_its_name(self):
        # bandit lives in argus/scanners/bandit.py and registers "bandit".
        assert affected_scanners(["argus/scanners/bandit.py"]) == ["bandit"]

    def test_renamed_module_resolves_via_registry_module(self):
        # trivy_iac.py registers the hyphenated "trivy-iac" — the mapping
        # must go through cls.__module__, not a naive filename transform.
        assert affected_scanners(["argus/scanners/trivy_iac.py"]) == ["trivy-iac"]

    def test_supply_chain_underscore_to_hyphen(self):
        assert affected_scanners(["argus/scanners/supply_chain.py"]) == ["supply-chain"]

    def test_multiple_scanners(self):
        out = affected_scanners([
            "argus/scanners/bandit.py",
            "argus/scanners/gitleaks.py",
        ])
        assert out == ["bandit", "gitleaks"]

    def test_cross_cutting_change_returns_ALL(self):
        for f in CROSS_CUTTING:
            assert affected_scanners([f]) == "ALL", f

    def test_cross_cutting_wins_over_specific(self):
        # An engine change alongside a scanner change still means ALL.
        assert affected_scanners([
            "argus/scanners/bandit.py",
            "argus/core/engine.py",
        ]) == "ALL"

    def test_unrelated_argus_file_is_not_a_scanner(self):
        # A change to a non-scanner argus module maps to nothing (and is
        # not cross-cutting).
        assert affected_scanners(["argus/reporters/terminal.py"]) == []


class TestChangedFiles:
    def test_parses_git_diff_output(self):
        with patch("scripts.ci.affected_scanners.subprocess.run") as run:
            run.return_value = MagicMock(
                stdout="argus/scanners/bandit.py\nREADME.md\n\n"
            )
            files = changed_files("origin/main")
        # Trailing/blank lines stripped; three-dot diff range used.
        assert files == ["argus/scanners/bandit.py", "README.md"]
        assert run.call_args[0][0] == [
            "git", "diff", "--name-only", "origin/main...HEAD",
        ]


class TestMain:
    def test_prints_ALL_for_cross_cutting(self, capsys):
        with patch(
            "scripts.ci.affected_scanners.changed_files",
            return_value=["argus/core/engine.py"],
        ):
            rc = main(["origin/main"])
        assert rc == 0
        assert capsys.readouterr().out.strip() == "ALL"

    def test_prints_scanner_names(self, capsys):
        with patch(
            "scripts.ci.affected_scanners.changed_files",
            return_value=["argus/scanners/bandit.py", "argus/scanners/gitleaks.py"],
        ):
            main([])  # default base ref
        out = capsys.readouterr().out.split()
        assert out == ["bandit", "gitleaks"]

    def test_prints_nothing_when_no_scanner_changed(self, capsys):
        with patch(
            "scripts.ci.affected_scanners.changed_files",
            return_value=["README.md"],
        ):
            main(["origin/main"])
        assert capsys.readouterr().out.strip() == ""
