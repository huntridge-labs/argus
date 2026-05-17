"""JUnit XML reporter.

Emits a JUnit-compatible XML document so generic CI test reporters
(GitLab CI ``junit`` artifact, Jenkins JUnit plugin, GitHub Actions
``test-reporter`` actions, CircleCI test summaries) can ingest
Argus findings as test failures.

Layout:
    <testsuites>
      <testsuite name="bandit" tests=N failures=F errors=0>
        <testcase classname="bandit" name="<location-or-finding-id>">
          <failure type="<severity>" message="<title>">
            <description>
          </failure>
        </testcase>
        ...
      </testsuite>
      <testsuite name="gitleaks" tests=1 failures=0 errors=0>
        <testcase classname="gitleaks" name="gitleaks: clean"/>
      </testsuite>
    </testsuites>

A scanner with no findings emits a single passing testcase named
``<scanner>: clean`` so the suite isn't empty (some consumers reject
empty suites).

Implementation note: stdlib ``xml.etree.ElementTree`` only — no
``lxml`` dependency.
"""

import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Optional

from argus.core.models import Finding, ScanResult, ScanSummary, Severity


_DEFAULT_OUTPUT_DIR = Path("./argus-results")
_DEFAULT_FILENAME = "argus-junit.xml"


class JUnitReporter:
    """Generate a JUnit XML report."""

    def report(
        self,
        summary: ScanSummary,
        output_dir: Optional[Path] = None,
        config: Optional[dict] = None,
    ) -> Path:
        """Write the JUnit XML file.

        Returns the path to the written file. ``config`` accepts
        ``output_filename`` to override the default ``argus-junit.xml``.
        """
        dest = Path(output_dir) if output_dir else _DEFAULT_OUTPUT_DIR
        dest.mkdir(parents=True, exist_ok=True)

        filename = (config or {}).get("output_filename", _DEFAULT_FILENAME)
        filepath = dest / filename

        root = self._build_root(summary)
        tree = ET.ElementTree(root)
        # ``xml_declaration=True`` so consumers that sniff the XML
        # prolog (Jenkins JUnit plugin, some old parsers) accept the
        # file as-is.
        tree.write(
            filepath,
            encoding="utf-8",
            xml_declaration=True,
        )
        return filepath

    def _build_root(self, summary: ScanSummary) -> ET.Element:
        suites_root = ET.Element("testsuites")

        total_tests = 0
        total_failures = 0
        total_errors = 0

        for result in summary.results:
            suite_elem, tests, failures, errors = self._build_suite(result)
            suites_root.append(suite_elem)
            total_tests += tests
            total_failures += failures
            total_errors += errors

        suites_root.set("tests", str(total_tests))
        suites_root.set("failures", str(total_failures))
        suites_root.set("errors", str(total_errors))
        suites_root.set("name", "argus")

        return suites_root

    def _build_suite(
        self, result: ScanResult
    ) -> tuple[ET.Element, int, int, int]:
        """Return ``(suite_elem, tests, failures, errors)`` for a scanner."""
        suite = ET.Element("testsuite", name=result.scanner)

        # Surface engine-level execution failures as test errors so
        # CI dashboards distinguish "scanner crashed" from "scanner
        # found a bug." ``execution_failed`` is the canonical flag
        # the engine sets on ScanResult.metadata.
        execution_failed = bool(result.metadata.get("execution_failed"))

        if not result.findings and not execution_failed:
            # Clean scanner — emit a passing testcase so the suite
            # isn't empty.
            ET.SubElement(
                suite,
                "testcase",
                classname=result.scanner,
                name=f"{result.scanner}: clean",
            )
            suite.set("tests", "1")
            suite.set("failures", "0")
            suite.set("errors", "0")
            return suite, 1, 0, 0

        # Group findings by file path so each <testcase> represents
        # one file. Findings without a parseable location go under
        # an ``<unknown>`` bucket.
        by_file: dict[str, list[Finding]] = defaultdict(list)
        for finding in result.findings:
            path = self._extract_path(finding.location) or "<unknown>"
            by_file[path].append(finding)

        tests = 0
        failures = 0
        for path, findings in by_file.items():
            case = ET.SubElement(
                suite,
                "testcase",
                classname=result.scanner,
                name=path,
            )
            tests += 1
            for finding in findings:
                self._append_failure(case, finding)
                failures += 1

        errors = 0
        if execution_failed:
            err_case = ET.SubElement(
                suite,
                "testcase",
                classname=result.scanner,
                name=f"{result.scanner}: execution",
            )
            err = ET.SubElement(
                err_case,
                "error",
                type="execution_failed",
                message=str(
                    result.metadata.get("error", "scanner execution failed")
                ),
            )
            err.text = str(result.metadata.get("error", "scanner execution failed"))
            tests += 1
            errors += 1

        suite.set("tests", str(tests))
        suite.set("failures", str(failures))
        suite.set("errors", str(errors))
        return suite, tests, failures, errors

    def _append_failure(self, case: ET.Element, finding: Finding) -> None:
        """Attach a <failure> element describing a single finding.

        The ``type`` attribute follows the JUnit convention of an
        exception-class-shaped identifier — most consumers (Jenkins,
        GitLab MR widget, Azure DevOps test results) treat it as a
        grouping key and ignore values that look like prose
        (``"high"``, ``"critical"``). Encode the rule identifier
        there instead and surface severity as a separate property,
        which test reporters group on by convention. See issue #168-G.
        """
        # ``type`` follows the exception-class convention — use the rule
        # ID so consumers can group failures by check. The severity is
        # tucked into the message prefix so dashboards that render
        # ``message`` see it without parsing extra elements; the body
        # below carries the full finding context.
        failure = ET.SubElement(
            case,
            "failure",
            type=finding.id or "finding",
            message=f"[{finding.severity.value.upper()}] {finding.title}",
        )
        body_lines = [f"{finding.id}: {finding.title}"]
        if finding.location:
            body_lines.append(f"Location: {finding.location}")
        if finding.severity:
            body_lines.append(f"Severity: {finding.severity.value}")
        if finding.cwe:
            body_lines.append(f"CWE: {finding.cwe}")
        if finding.cve:
            body_lines.append(f"CVE: {finding.cve}")
        if finding.description:
            body_lines.append("")
            body_lines.append(finding.description)
        # ElementTree handles XML escaping of the text content
        # automatically — no manual ``&amp;``/``&lt;`` substitution
        # needed.
        failure.text = "\n".join(body_lines)

    def _extract_path(self, location: Optional[str]) -> Optional[str]:
        """Strip trailing ``:line[:col]`` from a location string."""
        if not location:
            return None

        parts = location.split(":")
        if len(parts) == 1:
            return parts[0] or None

        cut = len(parts)
        for idx in range(len(parts) - 1, 0, -1):
            if parts[idx].isdigit():
                cut = idx
            else:
                break

        path = ":".join(parts[:cut]) or None
        return path
