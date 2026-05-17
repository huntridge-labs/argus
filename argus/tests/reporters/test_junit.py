"""Tests for argus.reporters.junit — JUnitReporter."""

import xml.etree.ElementTree as ET

import pytest

from argus.core.models import Finding, ScanResult, ScanSummary, Severity
from argus.reporters.junit import JUnitReporter


def _parse(filepath):
    return ET.parse(str(filepath)).getroot()


class TestJUnitReporterFiles:
    """Output file shape."""

    def test_default_filename(self, tmp_output_dir):
        summary = ScanSummary(results=[])
        filepath = JUnitReporter().report(summary, tmp_output_dir)
        assert filepath.name == "argus-junit.xml"
        assert filepath.exists()

    def test_override_filename(self, tmp_output_dir):
        summary = ScanSummary(results=[])
        filepath = JUnitReporter().report(
            summary, tmp_output_dir, config={"output_filename": "junit.xml"}
        )
        assert filepath.name == "junit.xml"

    def test_creates_output_dir_if_missing(self, tmp_path):
        nested = tmp_path / "a" / "b"
        summary = ScanSummary(results=[])
        filepath = JUnitReporter().report(summary, nested)
        assert filepath.exists()

    def test_root_is_testsuites(self, tmp_output_dir):
        summary = ScanSummary(results=[])
        filepath = JUnitReporter().report(summary, tmp_output_dir)
        root = _parse(filepath)
        assert root.tag == "testsuites"

    def test_xml_declaration_present(self, tmp_output_dir):
        summary = ScanSummary(results=[])
        filepath = JUnitReporter().report(summary, tmp_output_dir)
        # ElementTree writes ``<?xml version='1.0' encoding='utf-8'?>``
        # when xml_declaration=True is set.
        text = filepath.read_text()
        assert text.startswith("<?xml")


class TestJUnitReporterEmptyAndClean:
    """Empty scans and clean scanners."""

    def test_empty_summary_has_zero_counts(self, tmp_output_dir):
        summary = ScanSummary(results=[])
        root = _parse(JUnitReporter().report(summary, tmp_output_dir))
        assert root.get("tests") == "0"
        assert root.get("failures") == "0"
        assert root.get("errors") == "0"

    def test_clean_scanner_emits_passing_testcase(self, tmp_output_dir):
        summary = ScanSummary(
            results=[ScanResult(scanner="bandit", findings=[])]
        )
        root = _parse(JUnitReporter().report(summary, tmp_output_dir))
        suite = root.find("testsuite")
        assert suite is not None
        assert suite.get("name") == "bandit"
        assert suite.get("tests") == "1"
        assert suite.get("failures") == "0"
        cases = suite.findall("testcase")
        assert len(cases) == 1
        # The clean testcase has no <failure> child.
        assert cases[0].find("failure") is None
        assert "clean" in cases[0].get("name")


class TestJUnitReporterFindings:
    """Finding-driven testcase shape."""

    def test_single_finding_creates_failing_testcase(self, tmp_output_dir):
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
        root = _parse(JUnitReporter().report(summary, tmp_output_dir))
        suite = root.find("testsuite")
        assert suite.get("name") == "bandit"
        assert suite.get("failures") == "1"
        case = suite.find("testcase")
        assert case.get("classname") == "bandit"
        assert case.get("name") == "app.py"
        failure = case.find("failure")
        assert failure is not None
        # ``type`` is the rule id (exception-class-shaped per JUnit
        # convention); severity rides on the message prefix so
        # dashboards that group on ``type`` get sensible buckets
        # (issue #168-G).
        assert failure.get("type") == "B102"
        assert "[HIGH]" in failure.get("message")
        assert "dangerous call" in failure.text

    def test_findings_grouped_by_file(self, tmp_output_dir):
        findings = [
            Finding(id="A", severity=Severity.HIGH, title="a", location="f1.py:1"),
            Finding(id="B", severity=Severity.HIGH, title="b", location="f1.py:5"),
            Finding(id="C", severity=Severity.HIGH, title="c", location="f2.py:1"),
        ]
        summary = ScanSummary(
            results=[ScanResult(scanner="bandit", findings=findings)]
        )
        root = _parse(JUnitReporter().report(summary, tmp_output_dir))
        suite = root.find("testsuite")
        assert suite.get("tests") == "2"  # 2 files = 2 testcases
        assert suite.get("failures") == "3"  # 3 findings = 3 failures
        cases = suite.findall("testcase")
        names = sorted(c.get("name") for c in cases)
        assert names == ["f1.py", "f2.py"]

    def test_finding_without_location_buckets_under_unknown(self, tmp_output_dir):
        finding = Finding(id="X", severity=Severity.HIGH, title="systemic")
        summary = ScanSummary(
            results=[ScanResult(scanner="s", findings=[finding])]
        )
        root = _parse(JUnitReporter().report(summary, tmp_output_dir))
        case = root.find("testsuite/testcase")
        assert case.get("name") == "<unknown>"
        assert case.find("failure") is not None

    def test_failure_type_is_rule_id_severity_in_message(self, tmp_output_dir):
        """JUnit consumers (Jenkins, GitLab MR widget, Azure DevOps)
        treat ``failure[type]`` as an exception-class grouping key and
        ignore prose values like ``"high"``. Use the rule id there and
        surface severity on the message prefix instead. Issue #168-G."""
        findings = [
            Finding(id="A", severity=Severity.CRITICAL, title="c", location="a.py:1"),
            Finding(id="B", severity=Severity.LOW, title="l", location="b.py:1"),
        ]
        summary = ScanSummary(results=[ScanResult(scanner="s", findings=findings)])
        root = _parse(JUnitReporter().report(summary, tmp_output_dir))
        failures = root.findall("testsuite/testcase/failure")
        types = sorted(f.get("type") for f in failures)
        messages = sorted(f.get("message") for f in failures)
        assert types == ["A", "B"]
        assert messages == ["[CRITICAL] c", "[LOW] l"]


class TestJUnitReporterCounts:
    """Aggregate counters at suite and root level."""

    def test_root_aggregates_per_suite_counts(self, tmp_output_dir):
        s1 = ScanResult(
            scanner="a",
            findings=[
                Finding(id="X", severity=Severity.HIGH, title="t", location="x.py:1")
            ],
        )
        s2 = ScanResult(scanner="b", findings=[])  # clean -> 1 test
        summary = ScanSummary(results=[s1, s2])
        root = _parse(JUnitReporter().report(summary, tmp_output_dir))
        assert root.get("tests") == "2"
        assert root.get("failures") == "1"
        assert root.get("errors") == "0"

    def test_mixed_severity_counts(self, tmp_output_dir):
        findings = [
            Finding(id="A", severity=Severity.CRITICAL, title="a", location="x.py:1"),
            Finding(id="B", severity=Severity.LOW, title="b", location="x.py:2"),
            Finding(id="C", severity=Severity.MEDIUM, title="c", location="y.py:1"),
        ]
        summary = ScanSummary(results=[ScanResult(scanner="s", findings=findings)])
        root = _parse(JUnitReporter().report(summary, tmp_output_dir))
        suite = root.find("testsuite")
        assert suite.get("failures") == "3"
        assert suite.get("tests") == "2"  # 2 distinct files


class TestJUnitReporterExecutionFailed:
    """Engine-level execution failures must surface as <error>."""

    def test_execution_failed_emits_error_testcase(self, tmp_output_dir):
        summary = ScanSummary(
            results=[
                ScanResult(
                    scanner="broken",
                    findings=[],
                    metadata={"execution_failed": True, "error": "tool crashed"},
                )
            ]
        )
        root = _parse(JUnitReporter().report(summary, tmp_output_dir))
        suite = root.find("testsuite")
        assert suite.get("errors") == "1"
        assert suite.get("failures") == "0"
        err = suite.find("testcase/error")
        assert err is not None
        assert err.get("type") == "execution_failed"
        assert "tool crashed" in err.get("message")

    def test_execution_failed_with_findings_combines(self, tmp_output_dir):
        # A scanner can both fail AND produce some partial findings.
        finding = Finding(id="X", severity=Severity.HIGH, title="t", location="a.py:1")
        summary = ScanSummary(
            results=[
                ScanResult(
                    scanner="partial",
                    findings=[finding],
                    metadata={"execution_failed": True, "error": "timeout"},
                )
            ]
        )
        root = _parse(JUnitReporter().report(summary, tmp_output_dir))
        suite = root.find("testsuite")
        assert suite.get("errors") == "1"
        assert suite.get("failures") == "1"


class TestJUnitReporterSpecialChars:
    """Escaping of XML-meaningful and unicode characters."""

    def test_special_chars_in_title_are_escaped(self, tmp_output_dir):
        finding = Finding(
            id="X",
            severity=Severity.HIGH,
            title="foo & bar <script>",
            location="f.py:1",
        )
        summary = ScanSummary(results=[ScanResult(scanner="s", findings=[finding])])
        filepath = JUnitReporter().report(summary, tmp_output_dir)
        # ElementTree escapes & and < automatically.
        raw = filepath.read_text()
        assert "&amp;" in raw
        assert "&lt;script&gt;" in raw
        # Round-trip parse must yield the original literal.
        root = _parse(filepath)
        msg = root.find("testsuite/testcase/failure").get("message")
        assert "foo & bar <script>" in msg

    def test_newline_in_description_preserved(self, tmp_output_dir):
        finding = Finding(
            id="X",
            severity=Severity.HIGH,
            title="t",
            description="line1\nline2",
            location="f.py:1",
        )
        summary = ScanSummary(results=[ScanResult(scanner="s", findings=[finding])])
        root = _parse(JUnitReporter().report(summary, tmp_output_dir))
        text = root.find("testsuite/testcase/failure").text
        assert "line1\nline2" in text

    def test_unicode_in_title(self, tmp_output_dir):
        finding = Finding(
            id="X",
            severity=Severity.HIGH,
            title="héllo wörld",
            location="f.py:1",
        )
        summary = ScanSummary(results=[ScanResult(scanner="s", findings=[finding])])
        root = _parse(JUnitReporter().report(summary, tmp_output_dir))
        msg = root.find("testsuite/testcase/failure").get("message")
        assert "héllo wörld" in msg
