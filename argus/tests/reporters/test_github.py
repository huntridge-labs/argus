"""Tests for argus.reporters.github — GitHubReporter."""

import io

import pytest

from argus.core.models import Finding, ScanResult, ScanSummary, Severity
from argus.reporters.github import GitHubReporter


def _capture(summary: ScanSummary) -> str:
    """Run the reporter against an in-memory stream and return text."""
    buf = io.StringIO()
    GitHubReporter().report(summary, output_dir=None, stream=buf)
    return buf.getvalue()


class TestGitHubReporterEmptyAndShape:
    """Empty scans and basic line shape."""

    def test_empty_summary_produces_no_output(self):
        summary = ScanSummary(results=[])
        assert _capture(summary) == ""

    def test_empty_scanner_produces_no_output(self):
        summary = ScanSummary(
            results=[ScanResult(scanner="bandit", findings=[])]
        )
        assert _capture(summary) == ""

    def test_single_finding_with_location(self):
        finding = Finding(
            id="B102",
            severity=Severity.HIGH,
            title="exec used",
            location="app.py:25:7",
        )
        summary = ScanSummary(
            results=[ScanResult(scanner="bandit", findings=[finding])]
        )
        out = _capture(summary)
        assert "::error " in out
        assert "file=app.py" in out
        assert "line=25" in out
        assert "col=7" in out
        assert "[bandit][B102] exec used" in out

    def test_finding_without_line_drops_line_param(self):
        finding = Finding(
            id="X1",
            severity=Severity.MEDIUM,
            title="bare path",
            location="src/app.py",
        )
        summary = ScanSummary(
            results=[ScanResult(scanner="checker", findings=[finding])]
        )
        out = _capture(summary)
        assert "file=src/app.py" in out
        assert "line=" not in out
        assert "col=" not in out

    def test_finding_without_location_omits_file_param(self):
        finding = Finding(id="X1", severity=Severity.LOW, title="systemic issue")
        summary = ScanSummary(
            results=[ScanResult(scanner="checker", findings=[finding])]
        )
        out = _capture(summary).strip()
        assert out.startswith("::notice::")
        assert "file=" not in out


class TestGitHubReporterSeverityMapping:
    """Severity → annotation level."""

    @pytest.mark.parametrize(
        "severity,level",
        [
            (Severity.CRITICAL, "::error"),
            (Severity.HIGH, "::error"),
            (Severity.MEDIUM, "::warning"),
            (Severity.LOW, "::notice"),
            (Severity.INFO, "::notice"),
            (Severity.UNKNOWN, "::notice"),
        ],
    )
    def test_severity_to_level(self, severity, level):
        finding = Finding(id="ID", severity=severity, title="t", location="f.py:1")
        summary = ScanSummary(
            results=[ScanResult(scanner="s", findings=[finding])]
        )
        out = _capture(summary)
        assert level in out


class TestGitHubReporterMixedAndSpecial:
    """Mixed severities, special chars, multi-scanner output."""

    def test_mixed_severity_emits_one_line_per_finding(self):
        findings = [
            Finding(id="A", severity=Severity.CRITICAL, title="c", location="a.py:1"),
            Finding(id="B", severity=Severity.MEDIUM, title="m", location="b.py:2"),
            Finding(id="C", severity=Severity.LOW, title="l", location="c.py:3"),
        ]
        summary = ScanSummary(
            results=[ScanResult(scanner="multi", findings=findings)]
        )
        out = _capture(summary)
        lines = [ln for ln in out.splitlines() if ln]
        assert len(lines) == 3

    def test_multiple_scanners_each_contribute(self):
        summary = ScanSummary(
            results=[
                ScanResult(
                    scanner="bandit",
                    findings=[
                        Finding(id="B1", severity=Severity.HIGH, title="b", location="x.py:1")
                    ],
                ),
                ScanResult(
                    scanner="gitleaks",
                    findings=[
                        Finding(id="GL1", severity=Severity.CRITICAL, title="leak", location="y.py:5")
                    ],
                ),
            ]
        )
        out = _capture(summary)
        assert "[bandit][B1]" in out
        assert "[gitleaks][GL1]" in out

    def test_special_characters_in_title_are_escaped(self):
        finding = Finding(
            id="X",
            severity=Severity.HIGH,
            title="line1\nline2 with 50% margin",
            location="f.py:1",
        )
        summary = ScanSummary(
            results=[ScanResult(scanner="s", findings=[finding])]
        )
        out = _capture(summary)
        # Newline must be encoded so it doesn't terminate the command.
        assert "line1%0Aline2" in out
        # Percent sign must be escaped.
        assert "50%25 margin" in out
        # The decoded original must NOT appear as a raw newline mid-line.
        assert "line1\nline2" not in out

    def test_carriage_return_in_title_is_escaped(self):
        finding = Finding(
            id="X",
            severity=Severity.HIGH,
            title="hi\rthere",
            location="f.py:1",
        )
        summary = ScanSummary(
            results=[ScanResult(scanner="s", findings=[finding])]
        )
        out = _capture(summary)
        assert "hi%0Dthere" in out


class TestGitHubReporterRobustness:
    """Edge cases around metadata/location parsing."""

    def test_execution_failed_metadata_does_not_crash(self):
        # Engine sometimes flags a scanner as failed and returns no
        # findings; the reporter must not blow up.
        summary = ScanSummary(
            results=[
                ScanResult(
                    scanner="broken",
                    findings=[],
                    metadata={"execution_failed": True, "error": "boom"},
                )
            ]
        )
        # Should produce no output (no findings) and not raise.
        assert _capture(summary) == ""

    def test_windows_style_path_with_drive_letter(self):
        finding = Finding(
            id="W1",
            severity=Severity.HIGH,
            title="t",
            location="C:\\code\\app.py:42",
        )
        summary = ScanSummary(
            results=[ScanResult(scanner="s", findings=[finding])]
        )
        out = _capture(summary)
        # The drive prefix should survive — file= contains both the
        # drive letter and the path.
        assert "file=C:\\code\\app.py" in out
        assert "line=42" in out

    def test_report_accepts_output_dir_argument(self, tmp_path):
        # output_dir is part of the protocol but unused here. Make
        # sure passing it doesn't blow up.
        finding = Finding(id="X", severity=Severity.HIGH, title="t", location="f.py:1")
        summary = ScanSummary(
            results=[ScanResult(scanner="s", findings=[finding])]
        )
        # No exception, no file written. Default stream goes to
        # sys.stdout which pytest captures via capsys.
        GitHubReporter().report(summary, output_dir=tmp_path)

    def test_default_stream_is_stdout(self, capsys):
        finding = Finding(id="X", severity=Severity.HIGH, title="t", location="f.py:1")
        summary = ScanSummary(
            results=[ScanResult(scanner="s", findings=[finding])]
        )
        GitHubReporter().report(summary)
        captured = capsys.readouterr()
        assert "[s][X] t" in captured.out
