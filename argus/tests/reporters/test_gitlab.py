"""Tests for argus.reporters.gitlab — GitLabReporter."""

import json

import pytest

from argus.core.models import Finding, ScanResult, ScanSummary, Severity
from argus.reporters.gitlab import GitLabReporter


def _read(filepath):
    return json.loads(filepath.read_text())


class TestGitLabReporterFiles:
    """Output filename and on-disk shape."""

    def test_default_filename(self, tmp_output_dir):
        summary = ScanSummary(results=[])
        filepath = GitLabReporter().report(summary, tmp_output_dir)
        assert filepath.name == "gl-code-quality-report.json"
        assert filepath.exists()

    def test_override_filename(self, tmp_output_dir):
        summary = ScanSummary(results=[])
        filepath = GitLabReporter().report(
            summary,
            tmp_output_dir,
            config={"output_filename": "custom.json"},
        )
        assert filepath.name == "custom.json"

    def test_creates_output_dir_if_missing(self, tmp_path):
        nested = tmp_path / "nested" / "out"
        summary = ScanSummary(results=[])
        filepath = GitLabReporter().report(summary, nested)
        assert filepath.exists()

    def test_empty_summary_writes_empty_array(self, tmp_output_dir):
        summary = ScanSummary(results=[])
        filepath = GitLabReporter().report(summary, tmp_output_dir)
        data = _read(filepath)
        assert data == []


class TestGitLabReporterEntries:
    """Per-finding entry shape."""

    def test_single_finding_basic_fields(self, tmp_output_dir):
        finding = Finding(
            id="B102",
            severity=Severity.HIGH,
            title="exec used",
            description="dangerous call",
            location="app.py:25",
        )
        summary = ScanSummary(
            results=[ScanResult(scanner="bandit", findings=[finding])]
        )
        data = _read(GitLabReporter().report(summary, tmp_output_dir))

        assert len(data) == 1
        entry = data[0]
        assert entry["severity"] == "critical"
        assert entry["check_name"] == "bandit:B102"
        assert entry["location"]["path"] == "app.py"
        assert entry["location"]["lines"]["begin"] == 25
        assert "exec used" in entry["description"]
        assert "dangerous call" in entry["description"]

    def test_finding_without_description_uses_title_only(self, tmp_output_dir):
        finding = Finding(id="X", severity=Severity.LOW, title="just a title", location="a.py:1")
        summary = ScanSummary(results=[ScanResult(scanner="s", findings=[finding])])
        data = _read(GitLabReporter().report(summary, tmp_output_dir))
        assert data[0]["description"] == "just a title"

    def test_duplicate_title_and_description_not_concatenated(self, tmp_output_dir):
        """Many linter rules (yamllint, flake8) ship the same string for
        both title and description. The naive ``f"{title}: {description}"``
        produced doubled output like ``"line too long ...: line too long ..."``.
        See issue #168-G."""
        same = "line too long (117 > 80 characters) (line-length)"
        finding = Finding(
            id="line-length", severity=Severity.INFO,
            title=same, description=same, location="argus.yml:1",
        )
        summary = ScanSummary(results=[ScanResult(scanner="lint-yaml", findings=[finding])])
        data = _read(GitLabReporter().report(summary, tmp_output_dir))
        # Title-and-description-identical case → no concatenation.
        assert data[0]["description"] == same
        assert data[0]["description"].count(same) == 1

    def test_finding_without_location_uses_empty_path_and_zero_line(self, tmp_output_dir):
        finding = Finding(id="X", severity=Severity.HIGH, title="t")
        summary = ScanSummary(results=[ScanResult(scanner="s", findings=[finding])])
        data = _read(GitLabReporter().report(summary, tmp_output_dir))
        assert data[0]["location"]["path"] == ""
        assert data[0]["location"]["lines"]["begin"] == 0

    def test_path_only_location_extracts_path(self, tmp_output_dir):
        finding = Finding(id="X", severity=Severity.HIGH, title="t", location="src/app.py")
        summary = ScanSummary(results=[ScanResult(scanner="s", findings=[finding])])
        data = _read(GitLabReporter().report(summary, tmp_output_dir))
        assert data[0]["location"]["path"] == "src/app.py"
        assert data[0]["location"]["lines"]["begin"] == 0

    def test_categories_security_for_non_info(self, tmp_output_dir):
        finding = Finding(id="X", severity=Severity.HIGH, title="t", location="f.py:1")
        summary = ScanSummary(results=[ScanResult(scanner="s", findings=[finding])])
        data = _read(GitLabReporter().report(summary, tmp_output_dir))
        assert data[0]["categories"] == ["Security"]

    def test_categories_style_for_linter_info(self, tmp_output_dir):
        finding = Finding(id="X", severity=Severity.INFO, title="t", location="f.py:1")
        summary = ScanSummary(
            results=[ScanResult(scanner="lint-yaml", findings=[finding])]
        )
        data = _read(GitLabReporter().report(summary, tmp_output_dir))
        assert data[0]["categories"] == ["Style"]


class TestGitLabReporterSeverityMapping:
    """Argus -> Code Climate severity translation."""

    @pytest.mark.parametrize(
        "severity,expected",
        [
            (Severity.CRITICAL, "blocker"),
            (Severity.HIGH, "critical"),
            (Severity.MEDIUM, "major"),
            (Severity.LOW, "minor"),
            (Severity.INFO, "info"),
            (Severity.UNKNOWN, "info"),
        ],
    )
    def test_severity_mapping(self, severity, expected, tmp_output_dir):
        finding = Finding(id="X", severity=severity, title="t", location="f.py:1")
        summary = ScanSummary(results=[ScanResult(scanner="s", findings=[finding])])
        data = _read(GitLabReporter().report(summary, tmp_output_dir))
        assert data[0]["severity"] == expected


class TestGitLabReporterFingerprint:
    """Fingerprint stability and uniqueness guarantees."""

    def test_fingerprint_is_16_hex_chars(self, tmp_output_dir):
        finding = Finding(id="X", severity=Severity.HIGH, title="t", location="f.py:1")
        summary = ScanSummary(results=[ScanResult(scanner="s", findings=[finding])])
        data = _read(GitLabReporter().report(summary, tmp_output_dir))
        fp = data[0]["fingerprint"]
        assert len(fp) == 16
        int(fp, 16)  # must parse as hex

    def test_fingerprint_stable_across_runs(self, tmp_output_dir):
        finding = Finding(id="X", severity=Severity.HIGH, title="t", location="f.py:1")
        summary = ScanSummary(results=[ScanResult(scanner="s", findings=[finding])])
        a = _read(GitLabReporter().report(summary, tmp_output_dir))[0]["fingerprint"]
        b = _read(GitLabReporter().report(summary, tmp_output_dir))[0]["fingerprint"]
        assert a == b

    def test_fingerprint_changes_with_line_move(self, tmp_output_dir):
        f1 = Finding(id="X", severity=Severity.HIGH, title="t", location="f.py:1")
        f2 = Finding(id="X", severity=Severity.HIGH, title="t", location="f.py:99")
        summary = ScanSummary(
            results=[ScanResult(scanner="s", findings=[f1, f2])]
        )
        data = _read(GitLabReporter().report(summary, tmp_output_dir))
        assert data[0]["fingerprint"] != data[1]["fingerprint"]

    def test_fingerprint_distinct_per_scanner(self, tmp_output_dir):
        f = Finding(id="X", severity=Severity.HIGH, title="t", location="f.py:1")
        summary = ScanSummary(
            results=[
                ScanResult(scanner="a", findings=[f]),
                ScanResult(scanner="b", findings=[f]),
            ]
        )
        data = _read(GitLabReporter().report(summary, tmp_output_dir))
        assert data[0]["fingerprint"] != data[1]["fingerprint"]


class TestGitLabReporterRobustness:
    """Robustness against odd inputs."""

    def test_mixed_severities_all_emitted(self, tmp_output_dir):
        findings = [
            Finding(id="A", severity=Severity.CRITICAL, title="c", location="a.py:1"),
            Finding(id="B", severity=Severity.MEDIUM, title="m", location="b.py:2"),
            Finding(id="C", severity=Severity.LOW, title="l", location="c.py:3"),
        ]
        summary = ScanSummary(results=[ScanResult(scanner="s", findings=findings)])
        data = _read(GitLabReporter().report(summary, tmp_output_dir))
        assert len(data) == 3
        assert {e["severity"] for e in data} == {"blocker", "major", "minor"}

    def test_execution_failed_metadata_does_not_crash(self, tmp_output_dir):
        summary = ScanSummary(
            results=[
                ScanResult(
                    scanner="broken",
                    findings=[],
                    metadata={"execution_failed": True, "error": "tool crashed"},
                )
            ]
        )
        # No findings, no entries — but the reporter must run cleanly.
        data = _read(GitLabReporter().report(summary, tmp_output_dir))
        assert data == []

    def test_special_characters_survive_json_encoding(self, tmp_output_dir):
        finding = Finding(
            id="X",
            severity=Severity.HIGH,
            title="newline\nand <html> & \"quotes\"",
            location="f.py:1",
        )
        summary = ScanSummary(results=[ScanResult(scanner="s", findings=[finding])])
        data = _read(GitLabReporter().report(summary, tmp_output_dir))
        # JSON round-trip preserves the literal — no manual escaping
        # needed.
        assert "\n" in data[0]["description"]
        assert "<html>" in data[0]["description"]
        assert '"quotes"' in data[0]["description"]

    def test_unicode_path_preserved(self, tmp_output_dir):
        finding = Finding(
            id="X",
            severity=Severity.HIGH,
            title="t",
            location="src/héllo.py:1",
        )
        summary = ScanSummary(results=[ScanResult(scanner="s", findings=[finding])])
        data = _read(GitLabReporter().report(summary, tmp_output_dir))
        assert data[0]["location"]["path"] == "src/héllo.py"
