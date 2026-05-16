"""Tests for argus.core.exclusions — path exclusion and ignore file handling."""

from pathlib import Path

import pytest

from argus.core.exclusions import (
    build_exclusion_set,
    filter_findings,
    is_excluded,
    _parse_ignore_file,
    _BUILTIN_EXCLUDES,
)
from argus.core.models import Finding, Severity


class TestBuildExclusionSet:
    """Tests for build_exclusion_set() combining all exclusion sources."""

    def test_includes_builtins(self):
        patterns = build_exclusion_set(scan_path="/nonexistent")
        for builtin in ["node_modules", ".git", "__pycache__", ".venv"]:
            assert builtin in patterns

    def test_adds_cli_excludes(self):
        patterns = build_exclusion_set(
            scan_path="/nonexistent",
            cli_excludes="mydir,other",
        )
        assert "mydir" in patterns
        assert "other" in patterns

    def test_adds_config_excludes(self):
        patterns = build_exclusion_set(
            scan_path="/nonexistent",
            config_excludes="vendor,third_party",
        )
        assert "vendor" in patterns
        assert "third_party" in patterns

    def test_combines_all_sources(self):
        patterns = build_exclusion_set(
            scan_path="/nonexistent",
            cli_excludes="cli_dir",
            config_excludes="config_dir",
        )
        assert "node_modules" in patterns  # builtin
        assert "cli_dir" in patterns
        assert "config_dir" in patterns

    def test_deduplicates(self):
        patterns = build_exclusion_set(
            scan_path="/nonexistent",
            cli_excludes="node_modules,.git",
        )
        assert patterns.count("node_modules") == 1
        assert patterns.count(".git") == 1

    def test_strips_whitespace(self):
        patterns = build_exclusion_set(
            scan_path="/nonexistent",
            cli_excludes="  foo , bar  ",
        )
        assert "foo" in patterns
        assert "bar" in patterns

    def test_ignores_empty_entries(self):
        patterns = build_exclusion_set(
            scan_path="/nonexistent",
            cli_excludes="foo,,bar,",
        )
        assert "" not in patterns

    def test_reads_gitignore(self, tmp_path):
        (tmp_path / ".gitignore").write_text("*.log\nsecrets/\n# comment\n\n")
        patterns = build_exclusion_set(scan_path=str(tmp_path))
        assert "*.log" in patterns
        assert "secrets" in patterns

    def test_reads_dockerignore(self, tmp_path):
        (tmp_path / ".dockerignore").write_text("Dockerfile\n.env\n")
        patterns = build_exclusion_set(scan_path=str(tmp_path))
        assert "Dockerfile" in patterns
        assert ".env" in patterns

    def test_reads_multiple_ignore_files(self, tmp_path):
        (tmp_path / ".gitignore").write_text("*.log\n")
        (tmp_path / ".dockerignore").write_text("*.tar\n")
        (tmp_path / ".semgrepignore").write_text("generated/\n")
        patterns = build_exclusion_set(scan_path=str(tmp_path))
        assert "*.log" in patterns
        assert "*.tar" in patterns
        assert "generated" in patterns

    def test_missing_ignore_files_no_error(self):
        patterns = build_exclusion_set(scan_path="/nonexistent/path")
        assert len(patterns) >= len(_BUILTIN_EXCLUDES)

    def test_use_defaults_false_drops_builtins(self):
        patterns = build_exclusion_set(
            scan_path="/nonexistent", cli_excludes="mine", use_defaults=False
        )
        assert "node_modules" not in patterns
        assert ".git" not in patterns
        assert patterns == ["mine"]

    def test_use_defaults_false_skips_ignore_files(self, tmp_path):
        (tmp_path / ".gitignore").write_text("*.log\n")
        patterns = build_exclusion_set(
            scan_path=str(tmp_path),
            cli_excludes="mine",
            use_defaults=False,
        )
        assert "*.log" not in patterns
        assert patterns == ["mine"]


class TestDoublestarGlob:
    """is_excluded must understand ``**`` the way users/git/semgrep do."""

    def test_doublestar_tests_dir_matches_nested(self):
        assert is_excluded("src/foo/tests/bar.py", ["**/tests/**"])

    def test_doublestar_matches_leading_segments(self):
        assert is_excluded("a/b/c/tests/x.py", ["**/tests/**"])

    def test_doublestar_respects_segment_boundary(self):
        # "tests" appearing mid-name is NOT a directory match — guard against
        # the naive "tests" substring false positive that fnmatch alone has.
        assert not is_excluded(
            "src/contests/run.py", ["**/tests/**"]
        )

    def test_doublestar_with_trailing_glob(self):
        assert is_excluded("generated/pb.py", ["generated/**"])
        assert is_excluded("generated/nested/pb.py", ["generated/**"])

    def test_star_does_not_cross_segment(self):
        # Single * must not consume path separators
        assert not is_excluded("src/a/b.py", ["src/*.py"])
        assert is_excluded("src/b.py", ["src/*.py"])

    def test_question_mark_single_char(self):
        assert is_excluded("a/b.py", ["a/?.py"])
        assert not is_excluded("a/bc.py", ["a/?.py"])

    def test_builtin_substring_still_matches(self):
        # Plain tokens like "node_modules" keep their substring semantics
        assert is_excluded(
            "proj/node_modules/pkg/index.js", ["node_modules"]
        )

    def test_windows_style_path_matches_posix_pattern(self):
        assert is_excluded(
            "src\\tests\\x.py", ["**/tests/**"]
        )


class TestParseIgnoreFile:
    """Tests for _parse_ignore_file() gitignore-style parsing."""

    def test_basic_patterns(self, tmp_path):
        f = tmp_path / ".gitignore"
        f.write_text("*.pyc\n__pycache__/\ndist\n")
        patterns = _parse_ignore_file(f)
        assert "*.pyc" in patterns
        assert "__pycache__" in patterns
        assert "dist" in patterns

    def test_skips_comments(self, tmp_path):
        f = tmp_path / ".gitignore"
        f.write_text("# Build output\ndist\n# Logs\n*.log\n")
        patterns = _parse_ignore_file(f)
        assert len(patterns) == 2
        assert "dist" in patterns
        assert "*.log" in patterns

    def test_skips_empty_lines(self, tmp_path):
        f = tmp_path / ".gitignore"
        f.write_text("\n\ndist\n\n*.log\n\n")
        patterns = _parse_ignore_file(f)
        assert len(patterns) == 2

    def test_skips_negation_patterns(self, tmp_path):
        f = tmp_path / ".gitignore"
        f.write_text("*.log\n!important.log\ndist\n")
        patterns = _parse_ignore_file(f)
        assert "*.log" in patterns
        assert "dist" in patterns
        assert len(patterns) == 2  # negation skipped

    def test_strips_trailing_slash(self, tmp_path):
        f = tmp_path / ".gitignore"
        f.write_text("node_modules/\nbuild/\n")
        patterns = _parse_ignore_file(f)
        assert "node_modules" in patterns
        assert "build" in patterns

    def test_handles_missing_file(self, tmp_path):
        f = tmp_path / "nonexistent"
        patterns = _parse_ignore_file(f)
        assert patterns == []

    def test_handles_binary_file(self, tmp_path):
        f = tmp_path / ".gitignore"
        f.write_bytes(b"\x00\x01\x02\xff")
        patterns = _parse_ignore_file(f)
        assert isinstance(patterns, list)


class TestIsExcluded:
    """Tests for is_excluded() pattern matching."""

    def test_substring_match(self):
        assert is_excluded("tests/test_main.py", ["tests"])
        assert is_excluded("src/vendor/lib.py", ["vendor"])

    def test_no_match(self):
        assert not is_excluded("src/main.py", ["tests"])
        assert not is_excluded("app/views.py", ["vendor"])

    def test_glob_match_extension(self):
        assert is_excluded("src/cache.pyc", ["*.pyc"])
        assert not is_excluded("src/main.py", ["*.pyc"])

    def test_glob_match_directory(self):
        assert is_excluded("node_modules/express/index.js", ["node_modules"])

    def test_glob_wildcard(self):
        assert is_excluded("src/foo.egg-info/PKG-INFO", ["*.egg-info"])

    def test_empty_patterns(self):
        assert not is_excluded("anything.py", [])

    def test_empty_path(self):
        assert not is_excluded("", ["tests"])

    def test_multiple_patterns_first_match_wins(self):
        assert is_excluded("vendor/lib.py", ["src", "vendor"])

    def test_nested_path_matches(self):
        assert is_excluded("deep/nested/__pycache__/module.pyc", ["__pycache__"])


class TestFilterFindings:
    """Tests for filter_findings() bulk filtering."""

    def _make_findings(self, locations):
        return [
            Finding(
                id=str(i), severity=Severity.LOW,
                title=f"finding-{i}", location=loc,
            )
            for i, loc in enumerate(locations)
        ]

    def test_filters_matching(self):
        findings = self._make_findings([
            "src/main.py",
            "tests/test_main.py",
            "src/utils.py",
        ])
        kept, excluded = filter_findings(findings, ["tests"])
        assert excluded == 1
        assert len(kept) == 2

    def test_no_patterns_keeps_all(self):
        findings = self._make_findings(["a.py", "b.py"])
        kept, excluded = filter_findings(findings, [])
        assert excluded == 0
        assert len(kept) == 2

    def test_all_excluded(self):
        findings = self._make_findings(["tests/a.py", "tests/b.py"])
        kept, excluded = filter_findings(findings, ["tests"])
        assert excluded == 2
        assert len(kept) == 0

    def test_finding_without_location_kept(self):
        findings = [
            Finding(id="1", severity=Severity.LOW, title="no loc", location=None),
            Finding(id="2", severity=Severity.LOW, title="has loc", location="tests/x.py"),
        ]
        kept, excluded = filter_findings(findings, ["tests"])
        assert excluded == 1
        assert len(kept) == 1
        assert kept[0].id == "1"

    def test_multiple_patterns(self):
        findings = self._make_findings([
            "src/main.py",
            "vendor/lib.py",
            "tests/test.py",
            "docs/readme.md",
        ])
        kept, excluded = filter_findings(findings, ["vendor", "tests"])
        assert excluded == 2
        assert len(kept) == 2

    def test_glob_pattern_filtering(self):
        findings = self._make_findings([
            "src/main.py",
            "src/cache.pyc",
            "lib/compiled.pyc",
        ])
        kept, excluded = filter_findings(findings, ["*.pyc"])
        assert excluded == 2
        assert len(kept) == 1
