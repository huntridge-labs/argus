"""Unit tests for argus.viewers.terminal.results_picker (UI-free row formatting).

No Textual: the picker screen lives in app.py; this pins the pure
row-building + id-encoding the screen renders and decodes.
"""

from __future__ import annotations

from argus.viewers.terminal.results_picker import UP_ID, decode_id, picker_rows


def _entry(name, path, *, is_dir=False, is_results_file=False,
           has_results=False, finding_count=None):
    return {
        "name": name, "path": path, "is_dir": is_dir,
        "is_results_file": is_results_file, "has_results": has_results,
        "finding_count": finding_count,
    }


class TestPickerRows:
    def test_parent_row_added_when_included(self):
        rows = picker_rows([], include_parent=True)
        assert rows[0][0] == UP_ID

    def test_no_parent_row_at_root(self):
        rows = picker_rows([], include_parent=False)
        assert all(opt_id != UP_ID for opt_id, _ in rows)

    def test_results_file_is_a_load_row(self):
        rows = picker_rows(
            [_entry("argus-results.json", "/p/argus-results.json", is_results_file=True)],
            include_parent=False,
        )
        assert rows[0][0] == "load::/p/argus-results.json"

    def test_scan_dir_is_load_row_with_count(self):
        rows = picker_rows(
            [_entry("run-1", "/p/run-1", is_dir=True, has_results=True, finding_count=7)],
            include_parent=False,
        )
        opt_id, display = rows[0]
        assert opt_id == "load::/p/run-1"
        assert "7 findings" in display

    def test_scan_dir_without_count_says_scan(self):
        rows = picker_rows(
            [_entry("run", "/p/run", is_dir=True, has_results=True, finding_count=None)],
            include_parent=False,
        )
        assert "scan" in rows[0][1]

    def test_plain_dir_is_navigable(self):
        rows = picker_rows(
            [_entry("src", "/p/src", is_dir=True)], include_parent=False,
        )
        assert rows[0][0] == "dir::/p/src"

    def test_other_files_are_skipped(self):
        rows = picker_rows(
            [_entry("README.md", "/p/README.md")], include_parent=False,
        )
        assert rows == []

    def test_order_preserved_with_parent_first(self):
        entries = [
            _entry("src", "/p/src", is_dir=True),
            _entry("argus-results.json", "/p/argus-results.json", is_results_file=True),
        ]
        rows = picker_rows(entries, include_parent=True)
        assert [r[0] for r in rows] == [
            UP_ID, "dir::/p/src", "load::/p/argus-results.json",
        ]


class TestDecodeId:
    def test_up(self):
        assert decode_id(UP_ID) == ("up", None)

    def test_dir(self):
        assert decode_id("dir::/x/y") == ("dir", "/x/y")

    def test_load(self):
        assert decode_id("load::/x/y") == ("load", "/x/y")

    def test_none_for_empty(self):
        assert decode_id(None) == ("none", None)
        assert decode_id("") == ("none", None)

    def test_none_for_unrecognised(self):
        assert decode_id("__noop__") == ("none", None)

    def test_path_with_embedded_separator(self):
        # A path containing "::" still decodes (split on the first only).
        assert decode_id("load::/a::b/argus-results.json") == (
            "load", "/a::b/argus-results.json",
        )
