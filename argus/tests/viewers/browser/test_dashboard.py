"""Phase SB tests — executive-summary dashboard route.

Uses FastAPI's TestClient so we can exercise the full Jinja render
pipeline against in-memory app instances. The templates, CSS, and
static mount are all read from the packaged assets, so these tests
also guard against template/path drift.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient   # noqa: E402 — pytest importorskip above

from argus.viewers.browser.app import _resolve_scan, create_app   # noqa: E402


def _write_results(dir_path, payload):
    """Drop a valid argus-results.json inside ``dir_path``."""
    p = dir_path / "argus-results.json"
    p.write_text(json.dumps(payload))
    return p


def _sample_payload():
    """Minimal but structurally-valid results payload for rendering."""
    return {
        "severity_threshold": None,
        "results": [
            {
                "scanner": "grype",
                "findings": [
                    {
                        "id": "CVE-2021-44228",
                        "severity": "critical",
                        "title": "log4j RCE",
                        "description": "Remote code execution via JNDI",
                        "location": "log4j-core@2.14.1",
                        "cwe": None,
                        "cve": "CVE-2021-44228",
                        "scanner": "grype",
                        "metadata": {
                            "package": "log4j-core",
                            "installed_version": "2.14.1",
                            "fixed_version": "2.17.1",
                            "sbom_source": "BVMS.spdx",
                        },
                    },
                ],
                "raw_report": None,
                "sarif_report": None,
                "metadata": {},
                "critical_count": 1,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "total_count": 1,
            },
        ],
    }


class TestResolveScan:
    def test_file_path_used_as_is(self, tmp_path):
        f = _write_results(tmp_path, _sample_payload())
        result, err = _resolve_scan(str(f), launch_root=tmp_path)
        assert err is None
        assert result == f.resolve()

    def test_directory_path_finds_json_inside(self, tmp_path):
        _write_results(tmp_path, _sample_payload())
        result, err = _resolve_scan(str(tmp_path), launch_root=tmp_path)
        assert err is None
        assert result.name == "argus-results.json"

    def test_directory_without_results_file_gives_actionable_error(self, tmp_path):
        result, err = _resolve_scan(str(tmp_path), launch_root=tmp_path)
        assert result is None
        # Error message should name the expected filename AND the dir
        # so the user knows exactly what's missing.
        assert "argus-results.json" in err
        assert str(tmp_path) in err

    def test_missing_path_returns_friendly_error(self, tmp_path):
        result, err = _resolve_scan(str(tmp_path / "nope"), launch_root=tmp_path)
        assert result is None
        assert "does not exist" in err

    def test_fallback_to_launch_root_when_no_query_param(self, tmp_path):
        _write_results(tmp_path, _sample_payload())
        result, err = _resolve_scan(None, launch_root=tmp_path)
        assert err is None
        assert result.parent == tmp_path.resolve()

    def test_directory_with_latest_symlink_resolves(self, tmp_path):
        # Mirror argus scan's output convention: a timestamped run dir
        # plus a ``latest`` symlink pointing at it.
        run_dir = tmp_path / "2026-04-24T14-54-13Z"
        run_dir.mkdir()
        _write_results(run_dir, _sample_payload())
        (tmp_path / "latest").symlink_to(run_dir, target_is_directory=True)

        result, err = _resolve_scan(str(tmp_path), launch_root=tmp_path)
        assert err is None
        assert result is not None
        assert result.name == "argus-results.json"
        # The resolved path should walk through the symlink to the real run.
        assert result.parent.resolve() == run_dir.resolve()

    def test_directory_with_latest_subdir_resolves(self, tmp_path):
        # Same convention but ``latest`` is a real directory rather
        # than a symlink — happens on filesystems without symlink
        # support (some Windows setups) or after the symlink has
        # been materialized.
        latest = tmp_path / "latest"
        latest.mkdir()
        _write_results(latest, _sample_payload())

        result, err = _resolve_scan(str(tmp_path), launch_root=tmp_path)
        assert err is None
        assert result is not None
        assert result.parent.resolve() == latest.resolve()

    def test_parent_of_runs_nudges_to_picker(self, tmp_path):
        # Directory has timestamped run subdirs but no ``latest`` and
        # no top-level argus-results.json. We refuse to auto-pick but
        # point the user at the picker with a count.
        run_a = tmp_path / "2026-04-24T14-54-13Z"
        run_a.mkdir()
        _write_results(run_a, _sample_payload())
        run_b = tmp_path / "2026-04-23T10-00-00Z"
        run_b.mkdir()
        _write_results(run_b, _sample_payload())

        result, err = _resolve_scan(str(tmp_path), launch_root=tmp_path)
        assert result is None
        assert err is not None
        # Count is mentioned so the user knows they have multiple choices.
        assert "2" in err
        assert "picker" in err.lower()
        assert "argus-results.json" in err

    def test_direct_hit_beats_latest_fallback(self, tmp_path):
        # If the user drops an argus-results.json directly in a dir
        # that also happens to have a latest/ child, prefer the
        # direct hit. This keeps the simpler case fast and avoids
        # surprising precedence flips.
        direct = _write_results(tmp_path, _sample_payload())
        latest = tmp_path / "latest"
        latest.mkdir()
        _write_results(latest, _sample_payload())

        result, err = _resolve_scan(str(tmp_path), launch_root=tmp_path)
        assert err is None
        assert result == direct.resolve()


class TestDashboardRoute:
    def test_empty_state_when_root_has_no_results(self, tmp_path):
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        assert resp.status_code == 200
        assert "No scan loaded" in resp.text
        # Error message from _resolve_scan makes it into the placeholder
        assert "argus-results.json" in resp.text

    def test_renders_summary_when_root_has_results(self, tmp_path):
        _write_results(tmp_path, _sample_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        assert resp.status_code == 200
        # Dashboard content we expect from the fixture
        assert "Executive Summary" in resp.text
        assert "CVE-2021-44228" in resp.text
        assert "log4j-core" in resp.text
        assert "BVMS.spdx" in resp.text
        # Severity card label shows up
        assert "Critical" in resp.text
        # Scan crumb shows the resolved path
        assert "argus-results.json" in resp.text

    def test_renders_charts(self, tmp_path):
        # Phase B1: the dashboard renders inline SVG charts + count-up hooks.
        _write_results(tmp_path, _sample_payload())
        app = create_app(root=str(tmp_path))
        resp = TestClient(app).get("/")
        assert resp.status_code == 200
        assert 'class="charts"' in resp.text
        assert "chart-card" in resp.text
        assert "<svg" in resp.text                 # severity donut + scanner bars
        assert 'data-count="1"' in resp.text        # count-up hook on the total card
        assert "count-up.js" in resp.text

    def test_command_palette_wired(self, tmp_path):
        # Phase B0: the command palette (Cmd/Ctrl-K) is loaded on every page,
        # with the ⌘K hint affordance and data-cmd jump targets on the cards.
        _write_results(tmp_path, _sample_payload())
        app = create_app(root=str(tmp_path))
        resp = TestClient(app).get("/")
        assert resp.status_code == 200
        assert "command-palette.js" in resp.text
        assert "cmdk-hint" in resp.text and "data-cmdk-open" in resp.text
        assert 'data-cmd="Critical findings"' in resp.text

    def test_scan_query_param_overrides_launch_root_within_scope(self, tmp_path):
        # ``?scan=`` can point at any directory or file *inside* the
        # launch root. Launch at the parent; load a specific run below.
        run_a = tmp_path / "run-a"
        run_a.mkdir()
        _write_results(run_a, _sample_payload())

        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get(f"/?scan={run_a}")
        assert resp.status_code == 200
        assert "CVE-2021-44228" in resp.text

    def test_scan_query_param_outside_launch_root_rejected(self, tmp_path):
        # Defense-in-depth: even though the browser SOP blocks cross-site
        # readback, a path *outside* launch_root should still be refused.
        # Users who want to load scans elsewhere relaunch with a wider
        # --root rather than smuggling paths through ``?scan=``.
        empty = tmp_path / "empty"
        empty.mkdir()
        outside = tmp_path / "other" / "run-a"
        outside.mkdir(parents=True)
        _write_results(outside, _sample_payload())

        app = create_app(root=str(empty))
        client = TestClient(app)
        resp = client.get(f"/?scan={outside}")
        assert resp.status_code == 200
        # Error message tells the user what happened and how to widen.
        assert "outside the scan root" in resp.text
        assert "--root" in resp.text
        # And no finding leaks into the response.
        assert "CVE-2021-44228" not in resp.text

    def test_scan_query_param_for_sensitive_files_rejected(self, tmp_path):
        # The classic attack-vector test: /etc/passwd. The browser SOP
        # prevents an attacker from reading the response, but we reject
        # the path up front anyway so the server never opens it.
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/?scan=/etc/passwd")
        assert resp.status_code == 200
        assert "outside the scan root" in resp.text

    def test_malformed_results_json_shows_error_not_500(self, tmp_path):
        (tmp_path / "argus-results.json").write_text("not json {")
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        # Template renders the error placeholder rather than crashing.
        assert resp.status_code == 200
        assert "No scan loaded" in resp.text

    def test_csp_header_on_every_response(self, tmp_path):
        _write_results(tmp_path, _sample_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        for path in ("/", "/healthz"):
            resp = client.get(path)
            csp = resp.headers["Content-Security-Policy"]
            assert "default-src 'self'" in csp
            # Every style lives in static/argus.css; we deliberately
            # drop 'unsafe-inline' for style-src so any template edit
            # that re-inlines a style= fails loudly rather than quietly
            # loosening the policy.
            assert "'unsafe-inline'" not in csp
            assert "style-src 'self'" in csp
            assert "script-src 'self'" in csp
            assert resp.headers["X-Frame-Options"] == "DENY"
            # Scan paths and filter state travel through query params;
            # no-referrer stops them leaking if a user clicks out.
            assert resp.headers["Referrer-Policy"] == "no-referrer"

    def test_no_inline_styles_on_rendered_pages(self, tmp_path):
        # Regression guard: the CSP above bans inline styles. If a
        # template edit re-introduces one, the browser will block it
        # and the page will look wrong — better to fail a unit test.
        _write_results(tmp_path, _sample_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        for path in ("/", "/findings", "/picker"):
            resp = client.get(path)
            assert resp.status_code == 200, path
            assert 'style="' not in resp.text, (
                f"{path} contains an inline style= attribute — will be "
                "blocked by style-src 'self'. Move it into argus.css."
            )

    def test_static_css_served(self, tmp_path):
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/static/argus.css")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/css")
        # Presence of a known class from our stylesheet — catches
        # accidental path breakage between phases.
        assert ".sev-critical" in resp.text


class TestDashboardAccessibility:
    def test_no_scan_loaded_has_actionable_hint(self, tmp_path):
        """Empty state must tell the user what to do, not just 'no scan'."""
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        body = resp.text.lower()
        # Mention of both ways to point at a scan — dir or file.
        assert "results directory" in body or "results_json" in body or "argus-results.json" in body
