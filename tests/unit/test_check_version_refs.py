"""Tests for scripts/check-version-refs.py.

Covers the core utility functions: _expand_braces, find_version_refs,
is_ref_covered, and the release-it-ignore marker behaviour.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

# Import the module from scripts/ via importlib since the filename has hyphens
_SCRIPT_PATH = Path(__file__).parent.parent.parent / "scripts" / "check-version-refs.py"
_spec = importlib.util.spec_from_file_location("check_version_refs", _SCRIPT_PATH)
check_version_refs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_version_refs)

_expand_braces = check_version_refs._expand_braces
find_version_refs = check_version_refs.find_version_refs
is_ref_covered = check_version_refs.is_ref_covered
IGNORE_MARKER = check_version_refs.IGNORE_MARKER


class TestExpandBraces:
    """Tests for _expand_braces() brace expansion."""

    def test_simple_brace_expansion(self):
        result = _expand_braces("*.{yml,yaml}")
        assert result == ["*.yml", "*.yaml"]

    def test_no_braces_returns_single_item(self):
        result = _expand_braces("*.md")
        assert result == ["*.md"]

    def test_brace_expansion_with_glob_prefix(self):
        result = _expand_braces("docs/**/*.{md,txt}")
        assert result == ["docs/**/*.md", "docs/**/*.txt"]

    def test_three_alternatives(self):
        result = _expand_braces("file.{a,b,c}")
        assert result == ["file.a", "file.b", "file.c"]

    def test_single_alternative_in_braces(self):
        result = _expand_braces("file.{txt}")
        assert result == ["file.txt"]

    def test_empty_string(self):
        result = _expand_braces("")
        assert result == [""]


class TestFindVersionRefs:
    """Tests for find_version_refs() scanning temp file trees."""

    def test_finds_action_ref(self, tmp_path):
        """Detects huntridge-labs/argus/.github/actions/<name>@<version> refs."""
        workflow = tmp_path / "workflow.yml"
        workflow.write_text(
            "uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.7.0\n"
        )
        refs = find_version_refs(tmp_path)
        assert len(refs) == 1
        assert "scanner-bandit@0.7.0" in refs[0]['text']
        assert refs[0]['file'] == "workflow.yml"

    def test_finds_workflow_ref(self, tmp_path):
        """Detects huntridge-labs/argus/.github/workflows/<name>.yml@<version> refs."""
        doc = tmp_path / "readme.md"
        doc.write_text(
            "uses: huntridge-labs/argus/.github/workflows/reusable-security.yml@0.7.0\n"
        )
        refs = find_version_refs(tmp_path)
        assert len(refs) == 1
        assert "reusable-security.yml@0.7.0" in refs[0]['text']

    def test_finds_schema_url_ref(self, tmp_path):
        """Detects raw.githubusercontent.com/huntridge-labs/argus/<version>/.github/ refs."""
        config = tmp_path / "config.json"
        config.write_text(
            '"$id": "https://raw.githubusercontent.com/huntridge-labs/argus/0.7.0/.github/schemas/foo.json"\n'
        )
        refs = find_version_refs(tmp_path)
        assert len(refs) == 1
        assert "raw.githubusercontent.com/huntridge-labs/argus/0.7.0/.github/" in refs[0]['text']

    def test_finds_hrl_ref_pattern(self, tmp_path):
        """Detects HRL_REF fallback patterns."""
        workflow = tmp_path / "deploy.yml"
        workflow.write_text(
            "HRL_REF: ${{ inputs.ref || '0.7.0' }}\n"
        )
        refs = find_version_refs(tmp_path)
        assert len(refs) == 1
        assert "HRL_REF:" in refs[0]['text']
        assert "'0.7.0'" in refs[0]['text']

    def test_skips_release_it_ignore_lines(self, tmp_path):
        """Lines containing the release-it-ignore marker are skipped entirely."""
        workflow = tmp_path / "example.yml"
        workflow.write_text(
            "uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.5.0  # release-it-ignore\n"
            "uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.7.0\n"
        )
        refs = find_version_refs(tmp_path)
        assert len(refs) == 1
        assert "0.7.0" in refs[0]['text']

    def test_skips_excluded_directories(self, tmp_path):
        """Files inside SKIP_DIRS (e.g. node_modules) are not scanned."""
        nm_dir = tmp_path / "node_modules"
        nm_dir.mkdir()
        (nm_dir / "dep.yml").write_text(
            "uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.7.0\n"
        )
        refs = find_version_refs(tmp_path)
        assert len(refs) == 0

    def test_skips_excluded_files(self, tmp_path):
        """Files in SKIP_FILES are not scanned."""
        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text(
            "uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.6.0\n"
        )
        refs = find_version_refs(tmp_path)
        assert len(refs) == 0

    def test_skips_non_text_extensions(self, tmp_path):
        """Binary or unknown-extension files are not scanned."""
        binary = tmp_path / "image.png"
        binary.write_text(
            "uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.7.0\n"
        )
        refs = find_version_refs(tmp_path)
        assert len(refs) == 0

    def test_multiple_refs_same_file(self, tmp_path):
        """Multiple version refs in a single file are all captured."""
        workflow = tmp_path / "multi.yml"
        workflow.write_text(
            "uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.7.0\n"
            "uses: huntridge-labs/argus/.github/actions/scanner-gitleaks@0.7.0\n"
        )
        refs = find_version_refs(tmp_path)
        assert len(refs) == 2

    def test_returns_empty_for_no_refs(self, tmp_path):
        """A file with no version references returns an empty list."""
        plain = tmp_path / "notes.md"
        plain.write_text("Nothing to see here.\n")
        refs = find_version_refs(tmp_path)
        assert refs == []


class TestIsRefCovered:
    """Tests for is_ref_covered() checking release-it rule coverage."""

    def test_covered_by_pattern_rule(self):
        """A ref matching a rule's pattern for the correct file is covered."""
        rules = [{
            'covered_files': {'workflow.yml'},
            'pattern': r'(huntridge-labs/argus/\.github/actions/[^@]+)@[^\s]+',
        }]
        assert is_ref_covered(
            'workflow.yml',
            'huntridge-labs/argus/.github/actions/scanner-bandit@0.7.0',
            'uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.7.0',
            rules,
        )

    def test_not_covered_wrong_file(self):
        """A ref in a file not listed in any rule is not covered."""
        rules = [{
            'covered_files': {'other.yml'},
            'pattern': r'(huntridge-labs/argus/\.github/actions/[^@]+)@[^\s]+',
        }]
        assert not is_ref_covered(
            'workflow.yml',
            'huntridge-labs/argus/.github/actions/scanner-bandit@0.7.0',
            'uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.7.0',
            rules,
        )

    def test_not_covered_pattern_mismatch(self):
        """A ref that does not match the rule's pattern is not covered."""
        rules = [{
            'covered_files': {'workflow.yml'},
            'pattern': r'DOES_NOT_MATCH',
        }]
        assert not is_ref_covered(
            'workflow.yml',
            'huntridge-labs/argus/.github/actions/scanner-bandit@0.7.0',
            'uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.7.0',
            rules,
        )

    def test_covered_by_no_pattern_rule(self):
        """A rule with pattern=None covers the whole file (e.g. version.yaml)."""
        rules = [{
            'covered_files': {'version.yaml'},
            'pattern': None,
        }]
        assert is_ref_covered(
            'version.yaml',
            'anything',
            'anything on a line',
            rules,
        )

    def test_covered_via_full_line_match(self):
        """Pattern matching against the full line (not just ref_text) works."""
        rules = [{
            'covered_files': {'schema.json'},
            'pattern': r'\$id.*raw\.githubusercontent\.com',
        }]
        assert is_ref_covered(
            'schema.json',
            'raw.githubusercontent.com/huntridge-labs/argus/0.7.0/.github/',
            '"$id": "https://raw.githubusercontent.com/huntridge-labs/argus/0.7.0/.github/schemas/foo.json"',
            rules,
        )

    def test_invalid_regex_pattern_skipped(self):
        """A rule with an invalid regex pattern is skipped without error."""
        rules = [{
            'covered_files': {'file.yml'},
            'pattern': r'[invalid',
        }]
        assert not is_ref_covered(
            'file.yml',
            'huntridge-labs/argus/.github/actions/scanner-bandit@0.7.0',
            'uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.7.0',
            rules,
        )

    def test_multiple_rules_first_match_wins(self):
        """When multiple rules exist, coverage is True if any rule matches."""
        rules = [
            {
                'covered_files': {'workflow.yml'},
                'pattern': r'DOES_NOT_MATCH',
            },
            {
                'covered_files': {'workflow.yml'},
                'pattern': r'huntridge-labs/argus',
            },
        ]
        assert is_ref_covered(
            'workflow.yml',
            'huntridge-labs/argus/.github/actions/scanner-bandit@0.7.0',
            'uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.7.0',
            rules,
        )

    def test_empty_rules_list(self):
        """An empty rules list means nothing is covered."""
        assert not is_ref_covered(
            'file.yml',
            'huntridge-labs/argus/.github/actions/scanner-bandit@0.7.0',
            'uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.7.0',
            [],
        )


class TestReleaseItIgnoreMarker:
    """Ensure the IGNORE_MARKER constant is the expected value."""

    def test_ignore_marker_value(self):
        assert IGNORE_MARKER == 'release-it-ignore'
