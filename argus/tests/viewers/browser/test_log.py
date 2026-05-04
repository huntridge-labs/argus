"""Tests for the /log viewer route + parsing/filter helpers.

Two layers of coverage:
- Pure-function tests for ``log_view.parse_log`` and
  ``log_view.filter_entries`` — no app, no fixtures.
- Route tests via FastAPI's TestClient covering the empty state, the
  level filter, the search filter, and the raw download endpoint.
"""

from __future__ import annotations

import json

import pytest

from argus.viewers.browser.log_view import (
    LogEntry,
    filter_entries,
    parse_log,
)

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient   # noqa: E402

from argus.viewers.browser.app import create_app   # noqa: E402


# ───────────────────────────────────────────────
# Fixtures shared across route + parser tests
# ───────────────────────────────────────────────

_SAMPLE_LOG = (
    "07:13:58 DEBUG    argus Full exclusion set: ['node_modules', '.git']\n"
    "07:13:58 INFO     argus Loaded 66 exclusion pattern(s) from .gitignore\n"
    "07:13:59 WARNING  argus Native pull failed for clamav/clamav:1.5\n"
    "       continuation line for the warning above\n"
    "07:13:59 ERROR    viewers.browser Could not connect to docker.sock\n"
    "07:13:59 INFO     argus Scanner 'gitleaks' finished in 11722ms: 0 finding(s)\n"
)


def _sample_payload() -> dict:
    return {
        "severity_threshold": None,
        "results": [
            {
                "scanner": "bandit",
                "findings": [],
                "raw_report": None,
                "sarif_report": None,
                "metadata": {},
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "total_count": 0,
            },
        ],
    }


def _write_scan(tmp_path, log_contents: str | None = _SAMPLE_LOG) -> str:
    """Drop a results JSON + optional argus.log into ``tmp_path``."""
    (tmp_path / "argus-results.json").write_text(json.dumps(_sample_payload()))
    if log_contents is not None:
        (tmp_path / "argus.log").write_text(log_contents)
    return str(tmp_path)


# ───────────────────────────────────────────────
# Pure-function tests
# ───────────────────────────────────────────────


class TestParseLog:
    def test_parses_each_header_line(self):
        entries = parse_log(_SAMPLE_LOG)
        # 5 header lines (the continuation belongs to the WARNING entry).
        assert len(entries) == 5

    def test_canonicalizes_warn_to_warning(self):
        entries = parse_log("07:00:00 WARN     argus short-warn form\n")
        assert len(entries) == 1
        assert entries[0].level == "WARNING"

    def test_attaches_continuation_to_previous_entry(self):
        entries = parse_log(_SAMPLE_LOG)
        warning = next(e for e in entries if e.level == "WARNING")
        assert "continuation line for the warning above" in warning.msg

    def test_continuation_before_first_header_is_dropped(self):
        text = "stray line before any header\n07:00:00 INFO     argus first\n"
        entries = parse_log(text)
        assert len(entries) == 1
        assert entries[0].logger == "argus"

    def test_line_no_points_at_header_line(self):
        entries = parse_log(_SAMPLE_LOG)
        # Lines are 1-based; the WARNING is the 3rd header line.
        warning = next(e for e in entries if e.level == "WARNING")
        assert warning.line_no == 3

    def test_empty_text_returns_empty_list(self):
        assert parse_log("") == []


class TestFilterEntries:
    def _make(self, level: str, msg: str = "msg") -> LogEntry:
        return LogEntry(line_no=1, time="07:00:00", level=level, logger="argus", msg=msg)

    def test_min_level_excludes_below(self):
        entries = [self._make("DEBUG"), self._make("INFO"), self._make("WARNING"), self._make("ERROR")]
        result = filter_entries(entries, min_level="WARNING")
        assert {e.level for e in result} == {"WARNING", "ERROR"}

    def test_min_level_unknown_value_returns_all(self):
        entries = [self._make("DEBUG"), self._make("INFO")]
        result = filter_entries(entries, min_level="bogus")
        assert len(result) == 2

    def test_min_level_accepts_lowercase(self):
        entries = [self._make("DEBUG"), self._make("WARNING")]
        result = filter_entries(entries, min_level="warning")
        assert {e.level for e in result} == {"WARNING"}

    def test_min_level_accepts_warn_short_form(self):
        entries = [self._make("INFO"), self._make("WARNING"), self._make("ERROR")]
        result = filter_entries(entries, min_level="warn")
        assert {e.level for e in result} == {"WARNING", "ERROR"}

    def test_query_substring_matches_msg(self):
        entries = [self._make("INFO", "scanner finished"), self._make("INFO", "loading config")]
        result = filter_entries(entries, query="scanner")
        assert len(result) == 1
        assert "scanner" in result[0].msg

    def test_query_substring_is_case_insensitive(self):
        entries = [self._make("ERROR", "Permission Denied")]
        result = filter_entries(entries, query="permission")
        assert len(result) == 1

    def test_query_matches_logger_or_level(self):
        entries = [self._make("DEBUG", "irrelevant")]
        # Logger field included in the haystack — searching the logger
        # name finds the entry even when the message doesn't match.
        result = filter_entries(entries, query="argus")
        assert len(result) == 1
        # Level field included too.
        assert filter_entries(entries, query="debug") == result

    def test_combined_level_and_query(self):
        entries = [
            self._make("DEBUG", "container exited"),
            self._make("WARNING", "container pull failed"),
            self._make("INFO", "scanner started"),
        ]
        result = filter_entries(entries, min_level="WARNING", query="container")
        assert len(result) == 1
        assert result[0].level == "WARNING"


# ───────────────────────────────────────────────
# Route tests
# ───────────────────────────────────────────────


class TestLogRoute:
    def test_empty_state_when_log_missing(self, tmp_path):
        _write_scan(tmp_path, log_contents=None)
        client = TestClient(create_app(root=str(tmp_path)))
        resp = client.get("/log")
        assert resp.status_code == 200
        assert "No log available" in resp.text

    def test_empty_state_when_no_scan_loaded(self, tmp_path):
        # Empty root → no scan → no log; graceful empty state, not 500.
        client = TestClient(create_app(root=str(tmp_path)))
        resp = client.get("/log")
        assert resp.status_code == 200
        assert "No log available" in resp.text

    def test_renders_all_entries_with_no_filters(self, tmp_path):
        _write_scan(tmp_path)
        client = TestClient(create_app(root=str(tmp_path)))
        resp = client.get("/log")
        assert resp.status_code == 200
        assert "Showing <strong>5</strong> of 5 entries" in resp.text
        # Spot-check a few signatures from the sample log.
        assert "Native pull failed" in resp.text
        assert "Scanner 'gitleaks' finished" in resp.text

    def test_level_filter_drops_lower_severity(self, tmp_path):
        _write_scan(tmp_path)
        client = TestClient(create_app(root=str(tmp_path)))
        resp = client.get("/log?level=warning")
        assert resp.status_code == 200
        # 1 WARNING + 1 ERROR remain; 2 INFO + 1 DEBUG drop out.
        assert "Showing <strong>2</strong> of 5 entries" in resp.text
        assert "(filtered)" in resp.text
        assert "Could not connect" in resp.text   # ERROR survives
        assert "Loaded 66 exclusion" not in resp.text   # INFO drops

    def test_search_filter_narrows_to_matching_messages(self, tmp_path):
        _write_scan(tmp_path)
        client = TestClient(create_app(root=str(tmp_path)))
        resp = client.get("/log?q=clamav")
        assert resp.status_code == 200
        assert "Showing <strong>1</strong> of 5 entries" in resp.text
        assert "clamav" in resp.text

    def test_combined_level_and_query(self, tmp_path):
        _write_scan(tmp_path)
        client = TestClient(create_app(root=str(tmp_path)))
        resp = client.get("/log?level=error&q=docker")
        assert resp.status_code == 200
        assert "Showing <strong>1</strong> of 5 entries" in resp.text
        assert "docker.sock" in resp.text

    def test_unrecognized_level_is_silently_ignored(self, tmp_path):
        _write_scan(tmp_path)
        client = TestClient(create_app(root=str(tmp_path)))
        # Crafted URL: bogus level should fall back to no level filter,
        # not 500.
        resp = client.get("/log?level=bogus")
        assert resp.status_code == 200
        assert "Showing <strong>5</strong> of 5 entries" in resp.text

    def test_nav_link_present_on_all_pages(self, tmp_path):
        _write_scan(tmp_path)
        client = TestClient(create_app(root=str(tmp_path)))
        for path in ("/", "/findings", "/log"):
            resp = client.get(path)
            assert resp.status_code == 200, path
            assert 'href="/log' in resp.text, path

    def test_nav_link_carries_scan_param_when_present(self, tmp_path):
        # Scan param threading is what keeps the URL bookmarkable across
        # nav clicks; without it the picker / dashboard / findings /
        # log all snap back to the launch root.
        run = tmp_path / "run-a"
        run.mkdir()
        _write_scan(run)
        client = TestClient(create_app(root=str(tmp_path)))
        resp = client.get(f"/?scan={run}")
        assert resp.status_code == 200
        assert "/log?scan=" in resp.text


class TestLogRawRoute:
    def test_returns_raw_log_with_text_plain(self, tmp_path):
        _write_scan(tmp_path)
        client = TestClient(create_app(root=str(tmp_path)))
        resp = client.get("/log/raw")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/plain")
        # Body matches the file we wrote, byte-for-byte.
        assert resp.text == _SAMPLE_LOG

    def test_404_when_log_missing(self, tmp_path):
        _write_scan(tmp_path, log_contents=None)
        client = TestClient(create_app(root=str(tmp_path)))
        resp = client.get("/log/raw")
        assert resp.status_code == 404

    def test_404_when_no_scan_loaded(self, tmp_path):
        client = TestClient(create_app(root=str(tmp_path)))
        resp = client.get("/log/raw")
        assert resp.status_code == 404

    def test_content_disposition_marks_attachment(self, tmp_path):
        # FileResponse with filename= adds a Content-Disposition header
        # so browsers save the file rather than rendering inline.
        _write_scan(tmp_path)
        client = TestClient(create_app(root=str(tmp_path)))
        resp = client.get("/log/raw")
        cd = resp.headers.get("content-disposition", "")
        assert "argus.log" in cd
