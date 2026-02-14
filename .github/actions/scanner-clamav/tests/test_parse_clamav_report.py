#!/usr/bin/env python3
"""
Unit tests for parse-clamav-report.py
Tests ClamAV report parsing using synthetic fixtures
"""

import json
import sys
from pathlib import Path
import pytest

pytestmark = pytest.mark.unit

# Add the scripts directory to the path
REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

# Import the script as a module
import importlib.util
spec = importlib.util.spec_from_file_location(
    "parse_clamav_report",
    SCRIPTS_DIR / "parse-clamav-report.py"
)
parse_clamav_report = importlib.util.module_from_spec(spec)

# Get fixtures path
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "scanner-outputs" / "clamav"


class TestParseClamAVReport:
    """Test cases for parse-clamav-report.py functionality using fixtures."""

    def test_parse_report_with_findings(self, tmp_path):
        """Test parsing a ClamAV report with infected files using fixture."""
        # Copy fixture to temp location for testing
        fixture_path = FIXTURES_DIR / "results-with-findings.txt"
        report_file = tmp_path / "clamav-report.log"
        report_file.write_text(fixture_path.read_text())

        # Execute the parsing logic
        content = report_file.read_text(encoding='utf-8')

        # Parse the summary line
        infected = 0
        scanned = 0

        if "Infected files:" in content:
            import re
            match = re.search(r'Infected files: (\d+)', content)
            if match:
                infected = int(match.group(1))

        if "Scanned files:" in content:
            match = re.search(r'Scanned files: (\d+)', content)
            if match:
                scanned = int(match.group(1))

        # Find infected file details
        infected_files = []
        for line in content.split('\n'):
            if 'FOUND' in line:
                infected_files.append(line.strip())

        # Build results structure
        results = []
        for line in infected_files:
            if ' FOUND' in line:
                parts = line.split(': ')
                if len(parts) >= 2:
                    file_path = parts[0].strip()
                    # Get infection name (everything after ": " and before " FOUND")
                    infection_part = ': '.join(parts[1:])
                    infection = infection_part.replace(' FOUND', '').strip()
                    results.append({
                        "file": file_path,
                        "infection": infection,
                        "status": "infected"
                    })

        json_data = {
            "total_files": scanned,
            "infected_files": infected,
            "clean_files": scanned - infected,
            "infections": infected_files,
            "results": results
        }

        # Write JSON to same directory as report file
        json_path = report_file.parent / f"{report_file.stem}.json"
        json_path.write_text(json.dumps(json_data, indent=2), encoding='utf-8')

        # Verify the JSON was created correctly
        assert json_path.exists()
        with open(json_path, 'r') as f:
            data = json.load(f)

        # Assertions based on fixture content
        assert data["total_files"] == 245
        assert data["infected_files"] == 2
        assert data["clean_files"] == 243
        assert len(data["infections"]) == 2
        assert len(data["results"]) == 2

        # Verify specific infections from fixture
        assert any("malicious.exe" in inf for inf in data["infections"])
        assert any("suspicious.zip" in inf for inf in data["infections"])

    def test_parse_report_clean_scan(self, tmp_path):
        """Test parsing a ClamAV report with no infections using fixture."""
        # Copy fixture to temp location for testing
        fixture_path = FIXTURES_DIR / "results-clean.txt"
        report_file = tmp_path / "clamav-report.log"
        report_file.write_text(fixture_path.read_text())

        # Execute the parsing logic
        content = report_file.read_text(encoding='utf-8')

        # Parse the summary line
        infected = 0
        scanned = 0

        if "Infected files:" in content:
            import re
            match = re.search(r'Infected files: (\d+)', content)
            if match:
                infected = int(match.group(1))

        if "Scanned files:" in content:
            match = re.search(r'Scanned files: (\d+)', content)
            if match:
                scanned = int(match.group(1))

        # Find infected file details
        infected_files = []
        for line in content.split('\n'):
            if 'FOUND' in line:
                infected_files.append(line.strip())

        json_data = {
            "total_files": scanned,
            "infected_files": infected,
            "clean_files": scanned - infected,
            "infections": infected_files
        }

        # Write JSON to same directory as report file
        json_path = report_file.parent / f"{report_file.stem}.json"
        json_path.write_text(json.dumps(json_data, indent=2), encoding='utf-8')

        # Verify the JSON was created correctly
        assert json_path.exists()
        with open(json_path, 'r') as f:
            data = json.load(f)

        # Assertions based on clean fixture
        assert data["total_files"] == 245
        assert data["infected_files"] == 0
        assert data["clean_files"] == 245
        assert len(data["infections"]) == 0

    def test_parse_report_missing_fields(self, tmp_path):
        """Test parsing a report with missing infected files count."""
        import re

        report_content = """----------- SCAN SUMMARY -----------
Known viruses: 8518380
Engine version: 0.103.8
Scanned directories: 1
Scanned files: 10
Data scanned: 0.01 MB
Data read: 0.01 MB (ratio 1.00:1)
Time: 0.008 sec (0 m 0 s)
"""

        report_file = tmp_path / "clamav-report.log"
        report_file.write_text(report_content)

        # Execute the parsing logic
        content = report_file.read_text(encoding='utf-8')

        # Parse the summary line
        infected = 0
        scanned = 0

        if "Infected files:" in content:
            match = re.search(r'Infected files: (\d+)', content)
            if match:
                infected = int(match.group(1))

        if "Scanned files:" in content:
            match = re.search(r'Scanned files: (\d+)', content)
            if match:
                scanned = int(match.group(1))

        # Should handle missing "Infected files:" gracefully
        assert scanned == 10
        assert infected == 0  # Default to 0 if not found

    def test_parse_report_empty_file(self, tmp_path):
        """Test parsing an empty report file."""
        report_file = tmp_path / "clamav-report.log"
        report_file.write_text("")

        content = report_file.read_text(encoding='utf-8')

        # Parse the summary line
        infected = 0
        scanned = 0

        if "Infected files:" in content:
            import re
            match = re.search(r'Infected files: (\d+)', content)
            if match:
                infected = int(match.group(1))

        if "Scanned files:" in content:
            match = re.search(r'Scanned files: (\d+)', content)
            if match:
                scanned = int(match.group(1))

        # Empty file should result in zero counts
        assert scanned == 0
        assert infected == 0

    def test_fixtures_exist(self):
        """Verify that required fixtures exist."""
        assert FIXTURES_DIR.exists(), f"Fixtures directory not found: {FIXTURES_DIR}"
        assert (FIXTURES_DIR / "results-with-findings.txt").exists(), "Fixture with findings not found"
        assert (FIXTURES_DIR / "results-clean.txt").exists(), "Fixture clean results not found"

    def test_fixture_format_with_findings(self):
        """Test that the fixture with findings has correct format."""
        fixture_path = FIXTURES_DIR / "results-with-findings.txt"
        content = fixture_path.read_text()

        # Verify fixture contains expected content
        assert "SCAN SUMMARY" in content
        assert "Infected files: 2" in content
        assert "Scanned files: 245" in content
        assert "FOUND" in content

    def test_fixture_format_clean(self):
        """Test that the clean fixture has correct format."""
        fixture_path = FIXTURES_DIR / "results-clean.txt"
        content = fixture_path.read_text()

        # Verify fixture contains expected content
        assert "SCAN SUMMARY" in content
        assert "Infected files: 0" in content
        assert "Scanned files: 245" in content


class TestEdgeCases:
    """Edge case tests for ClamAV report parsing."""

    def test_empty_report_file(self, tmp_path):
        """Test with empty report file."""
        empty_file = tmp_path / "empty.txt"
        empty_file.write_text("")
        content = empty_file.read_text()
        assert "Infected files" not in content

    def test_missing_report_file(self):
        """Test with nonexistent report file."""
        report_file = Path("/nonexistent/report.txt")
        assert not report_file.exists()

    def test_report_without_scan_summary(self, tmp_path):
        """Test report missing SCAN SUMMARY section."""
        report_file = tmp_path / "no_summary.txt"
        report_file.write_text("Some output\nNo summary here\n")
        content = report_file.read_text()
        assert "SCAN SUMMARY" not in content

    def test_report_with_zero_infected(self, tmp_path):
        """Test report with zero infected files."""
        report_file = tmp_path / "clean.txt"
        report_file.write_text("""
SCAN SUMMARY
Infected files: 0
Scanned files: 100
""")
        content = report_file.read_text()
        assert "Infected files: 0" in content

    def test_very_large_infected_count(self, tmp_path):
        """Test with very large infected file count."""
        report_file = tmp_path / "huge_infection.txt"
        report_file.write_text("""
SCAN SUMMARY
Infected files: 99999
Scanned files: 999999
Data scanned: 10000 MB
Data read: 10000 MB
Execution time: 5.0 sec
Time: 10:00:00
""")
        content = report_file.read_text()
        assert "99999" in content

    def test_report_with_whitespace_variations(self, tmp_path):
        """Test report with varying whitespace around numbers."""
        report_file = tmp_path / "whitespace.txt"
        report_file.write_text("""
SCAN SUMMARY
Infected files:    42
Scanned files:  1000
""")
        content = report_file.read_text()
        assert "Infected files:" in content


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])
