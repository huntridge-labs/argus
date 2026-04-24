"""Unit tests for the four export writers in argus.browse.export.

Pure I/O tests — no Textual needed. Each writer is exercised against
a small hand-built finding set and the output is parsed back to confirm
the shape is correct (CSV header + row, JSON structure, Markdown table,
SARIF runs/results).
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

from argus.browse.export import (
    CSV_COLUMNS,
    WRITERS,
    available_formats,
    make_export_path,
    write_csv,
    write_json,
    write_markdown,
    write_sarif,
)
from argus.core.models import Finding, Severity


def _sample_findings() -> list[Finding]:
    """Two findings spanning two scanners and two SBOMs — enough to
    exercise per-scanner grouping (SARIF) and pipe-escaping (Markdown)."""
    return [
        Finding(
            id="CVE-2021-44228",
            severity=Severity.CRITICAL,
            title="log4j RCE | JNDI lookup",   # intentional pipe — exercises markdown escaping
            description="Remote code execution via JNDI message lookup.",
            location="log4j-core@2.14.1",
            cve="CVE-2021-44228",
            scanner="grype",
            metadata={
                "package": "log4j-core",
                "installed_version": "2.14.1",
                "fixed_version": "2.17.1",
                "sbom_source": "BVMS.spdx",
            },
        ),
        Finding(
            id="CVE-2023-12345",
            severity=Severity.HIGH,
            title="openssl CVE",
            description="Some TLS issue",
            location="openssl@1.1.1",
            cve="CVE-2023-12345",
            scanner="trivy",
            metadata={
                "package": "openssl",
                "installed_version": "1.1.1",
                "fixed_version": "1.1.2",
                "sbom_source": "VRM.spdx",
            },
        ),
    ]


class TestMakeExportPath:
    def test_contains_timestamp_and_scope(self, tmp_path):
        now = datetime(2026, 4, 24, 10, 30, 0)
        p = make_export_path(
            "csv", scope="critical", now=now, directory=tmp_path,
        )
        assert p.name == "argus-findings-20260424-103000-critical.csv"
        # Returned path is absolute (for copy-pasting from the toast)
        assert p.is_absolute()

    def test_default_directory_is_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        p = make_export_path("json")
        assert Path(p).parent.resolve() == tmp_path.resolve()


class TestCsvWriter:
    def test_header_matches_csv_columns_constant(self, tmp_path):
        path = write_csv(_sample_findings(), tmp_path / "out.csv")
        with open(path) as fh:
            header = next(csv.reader(fh))
        assert header == CSV_COLUMNS

    def test_row_for_each_finding(self, tmp_path):
        path = write_csv(_sample_findings(), tmp_path / "out.csv")
        with open(path) as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == 2
        assert rows[0]["id"] == "CVE-2021-44228"
        assert rows[0]["severity"] == "critical"
        assert rows[0]["fixed_version"] == "2.17.1"
        assert rows[0]["sbom_source"] == "BVMS.spdx"


class TestJsonWriter:
    def test_is_a_list_of_finding_dicts(self, tmp_path):
        path = write_json(_sample_findings(), tmp_path / "out.json")
        data = json.loads(path.read_text())
        assert isinstance(data, list)
        assert len(data) == 2
        # Matches the shape Finding.to_dict produces — the severity key
        # is already the string value, not the enum.
        assert data[0]["severity"] == "critical"
        assert data[0]["id"] == "CVE-2021-44228"
        assert data[0]["metadata"]["fixed_version"] == "2.17.1"


class TestMarkdownWriter:
    def test_contains_table_header(self, tmp_path):
        path = write_markdown(_sample_findings(), tmp_path / "out.md")
        text = path.read_text()
        assert "| Sev | ID | Scanner | Package | Fix | Location | SBOM | Title |" in text

    def test_pipes_in_titles_are_escaped(self, tmp_path):
        path = write_markdown(_sample_findings(), tmp_path / "out.md")
        text = path.read_text()
        # The "|" in "log4j RCE | JNDI lookup" must be backslash-escaped
        # so it doesn't break the table cell.
        assert "log4j RCE \\| JNDI lookup" in text

    def test_each_finding_has_its_severity_icon(self, tmp_path):
        path = write_markdown(_sample_findings(), tmp_path / "out.md")
        text = path.read_text()
        assert "🚨" in text   # CRITICAL
        assert "⚠️" in text   # HIGH


class TestSarifWriter:
    def test_valid_sarif_2_1_0_shape(self, tmp_path):
        path = write_sarif(_sample_findings(), tmp_path / "out.sarif")
        data = json.loads(path.read_text())
        assert data["version"] == "2.1.0"
        assert "runs" in data
        # Per-scanner run grouping — two findings, two scanners → two runs
        assert len(data["runs"]) == 2
        scanner_names = {r["tool"]["driver"]["name"] for r in data["runs"]}
        assert scanner_names == {"grype", "trivy"}

    def test_severity_maps_to_sarif_level(self, tmp_path):
        path = write_sarif(_sample_findings(), tmp_path / "out.sarif")
        data = json.loads(path.read_text())
        levels = []
        for run in data["runs"]:
            for res in run["results"]:
                levels.append(res["level"])
        # CRITICAL + HIGH both map to "error"
        assert levels.count("error") == 2

    def test_results_include_metadata_properties(self, tmp_path):
        path = write_sarif(_sample_findings(), tmp_path / "out.sarif")
        data = json.loads(path.read_text())
        grype_run = next(r for r in data["runs"] if r["tool"]["driver"]["name"] == "grype")
        props = grype_run["results"][0]["properties"]
        assert props["severity"] == "critical"
        assert props["cve"] == "CVE-2021-44228"
        assert props["fixedVersion"] == "2.17.1"
        assert props["sbomSource"] == "BVMS.spdx"


class TestDispatchTable:
    def test_writers_registered_for_every_advertised_format(self):
        formats = available_formats()
        for fmt in formats:
            assert fmt in WRITERS
            writer, ext = WRITERS[fmt]
            assert callable(writer)
            assert ext
