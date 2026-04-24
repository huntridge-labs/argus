"""Phase SD tests — picker navigation + scan-ready detection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient   # noqa: E402

from argus.serve.app import _list_directory, create_app   # noqa: E402


def _write_results(dir_path: Path, findings_count: int = 0) -> Path:
    """Drop a results file with N findings for the status-column peek."""
    results = [{
        "scanner": "grype",
        "findings": [
            {
                "id": f"CVE-{i}", "severity": "high", "title": "x",
                "description": "", "location": None, "cwe": None,
                "cve": None, "scanner": "grype", "metadata": {},
            }
            for i in range(findings_count)
        ],
        "raw_report": None, "sarif_report": None, "metadata": {},
        "critical_count": 0, "high_count": findings_count,
        "medium_count": 0, "low_count": 0,
        "total_count": findings_count,
    }]
    p = dir_path / "argus-results.json"
    p.write_text(json.dumps({
        "severity_threshold": None,
        "results": results,
    }))
    return p


class TestListDirectory:
    def test_filters_hidden_by_default(self, tmp_path):
        (tmp_path / "visible").mkdir()
        (tmp_path / ".git").mkdir()
        (tmp_path / "node_modules").mkdir()
        (tmp_path / ".env").write_text("")
        (tmp_path / "config.yml").write_text("")

        entries, err = _list_directory(tmp_path, show_hidden=False)
        names = {e["name"] for e in entries}
        assert names == {"visible", "config.yml"}
        assert err is None

    def test_show_hidden_reveals_everything(self, tmp_path):
        (tmp_path / "visible").mkdir()
        (tmp_path / ".git").mkdir()
        entries, _ = _list_directory(tmp_path, show_hidden=True)
        names = {e["name"] for e in entries}
        assert names == {"visible", ".git"}

    def test_directories_listed_before_files(self, tmp_path):
        (tmp_path / "a-file.txt").write_text("")
        (tmp_path / "b-dir").mkdir()
        entries, _ = _list_directory(tmp_path, show_hidden=False)
        # Directory `b-dir` comes before file `a-file.txt` despite
        # alphabetical order — directories-first is the UX contract
        # so the picker feels like a file browser.
        assert entries[0]["name"] == "b-dir"
        assert entries[1]["name"] == "a-file.txt"

    def test_has_results_flag_set_on_scan_dirs(self, tmp_path):
        scan_dir = tmp_path / "run-01"
        scan_dir.mkdir()
        _write_results(scan_dir, findings_count=3)

        (tmp_path / "empty-dir").mkdir()

        entries, _ = _list_directory(tmp_path, show_hidden=False)
        by_name = {e["name"]: e for e in entries}
        assert by_name["run-01"]["has_results"] is True
        assert by_name["run-01"]["finding_count"] == 3
        assert by_name["empty-dir"]["has_results"] is False

    def test_is_results_file_flag_for_direct_json(self, tmp_path):
        _write_results(tmp_path, findings_count=1)
        entries, _ = _list_directory(tmp_path, show_hidden=False)
        by_name = {e["name"]: e for e in entries}
        assert by_name["argus-results.json"]["is_results_file"] is True

    def test_malformed_results_doesnt_break_listing(self, tmp_path):
        # A broken JSON in a subdir used to 500 the whole picker row;
        # the finding_count peek is best-effort only.
        scan = tmp_path / "broken-scan"
        scan.mkdir()
        (scan / "argus-results.json").write_text("{not json")
        entries, _ = _list_directory(tmp_path, show_hidden=False)
        by_name = {e["name"]: e for e in entries}
        assert by_name["broken-scan"]["has_results"] is True
        # Count is None because the file didn't parse — but the row
        # still renders.
        assert by_name["broken-scan"]["finding_count"] is None

    def test_permission_error_yields_empty_entries_plus_error(self, tmp_path, monkeypatch):
        """iterdir() raising PermissionError should surface as a
        user-readable error rather than a 500."""
        def _boom(self):
            raise PermissionError("denied")
        monkeypatch.setattr(Path, "iterdir", _boom)
        entries, err = _list_directory(tmp_path, show_hidden=False)
        assert entries == []
        assert err is not None
        assert "Permission denied" in err


class TestPickerRoute:
    def test_picker_lists_subdirs(self, tmp_path):
        (tmp_path / "run-01").mkdir()
        (tmp_path / "run-02").mkdir()
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get(f"/picker?path={tmp_path}")
        assert resp.status_code == 200
        assert "run-01" in resp.text
        assert "run-02" in resp.text

    def test_picker_flags_scan_ready_dirs(self, tmp_path):
        scan = tmp_path / "run-01"
        scan.mkdir()
        _write_results(scan, findings_count=5)

        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get(f"/picker?path={tmp_path}")
        # "Load scan" affordance shown for scan-ready dirs
        assert "Load scan" in resp.text
        assert "5 findings" in resp.text

    def test_load_this_scan_button_when_current_dir_has_results(self, tmp_path):
        _write_results(tmp_path, findings_count=2)
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get(f"/picker?path={tmp_path}")
        assert "Load this scan" in resp.text

    def test_non_directory_path_shows_error_not_500(self, tmp_path):
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        # Point at a file, not a dir — route should render the error
        # placeholder rather than 500.
        results = _write_results(tmp_path, findings_count=1)
        resp = client.get(f"/picker?path={results}")
        assert resp.status_code == 200
        assert "is not a directory" in resp.text

    def test_missing_path_shows_error(self, tmp_path):
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get(f"/picker?path={tmp_path}/does-not-exist")
        assert resp.status_code == 200
        assert "is not a directory" in resp.text

    def test_parent_link_rendered_when_not_at_root(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get(f"/picker?path={sub}")
        # ".." row lets the user navigate up one level
        assert "parent directory" in resp.text

    def test_show_hidden_flag_surfaces_dotfiles(self, tmp_path):
        (tmp_path / ".hidden").mkdir()
        app = create_app(root=str(tmp_path))
        client = TestClient(app)

        resp = client.get(f"/picker?path={tmp_path}")
        assert ".hidden" not in resp.text

        resp = client.get(f"/picker?path={tmp_path}&show_hidden=1")
        assert ".hidden" in resp.text

    def test_switch_scan_nav_link_active(self, tmp_path):
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/picker")
        # Nav link for the picker is now live (not stubbed).
        assert 'aria-current="page"' in resp.text
        # ...and specifically on the Switch scan anchor.
        assert "Switch scan" in resp.text

    def test_breadcrumb_shows_filesystem_path_not_url_path(self, tmp_path):
        # Regression: base.html.j2 used to do ``{% set current = request.url.path %}``
        # which shadowed the route's ``current`` context var (the filesystem
        # path being browsed). Every picker view rendered the URL path
        # "/picker" in the breadcrumb and prefill, so the default Jump-to
        # form took users to a bad path and "Show hidden" built a broken
        # URL. Lock the correct behavior in.
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/picker")
        assert resp.status_code == 200
        # Breadcrumb + prefill must be the resolved launch root on disk,
        # never the HTTP path.
        assert str(tmp_path.resolve()) in resp.text
        assert f'value="{tmp_path.resolve()}"' in resp.text
        assert 'value="/picker"' not in resp.text
        # The "Show/Hide hidden" toggle link must carry the filesystem
        # path too, so clicking it doesn't strand the user.
        assert f"path={tmp_path.resolve()}".replace("/", "%2F") in resp.text or \
               f"path={tmp_path.resolve()}" in resp.text
