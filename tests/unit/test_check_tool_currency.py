"""Tests for ``scripts/ci/check_tool_currency.py``.

The checker exists because two pins went stale unnoticed for weeks while
Renovate's dashboard showed the updates as available. These lock the two
behaviours that made it useful on its first run:

1. It compares against the newest release we are *allowed* to adopt, not the
   newest release. Comparing against latest reports nothing actionable for a
   tool whose newest release is inside the cooling window, even when an older
   eligible release exists — that is how ``promptfoo 0.121.19`` was missed.
2. It reads the tag out of an image ref, not the digest. A greedy pattern runs
   past ``@sha256:`` to the last colon and captures 64 hex characters as the
   "version", which makes every pin look mismatched and every comparison
   meaningless.
"""

from __future__ import annotations

import datetime as dt
import io
import json
import urllib.error

import pytest

from scripts.ci import check_tool_currency as ctc

NOW = dt.datetime(2026, 8, 4, 12, 0, tzinfo=dt.timezone.utc)


def _release(tag: str, days_ago: int, *, prerelease: bool = False, draft: bool = False) -> dict:
    published = NOW - dt.timedelta(days=days_ago)
    return {
        "tag_name": tag,
        "published_at": published.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "prerelease": prerelease,
        "draft": draft,
    }


CONTAINERS_SNIPPET = '''
OFFICIAL_IMAGES: dict[str, str] = {
    "trivy": "aquasec/trivy:0.72.0@sha256:cffe3f5161a47a6823fbd23d985795b3ed72a4c806da4c4df16266c02accdd6f",
    "syft": "anchore/syft:v1.49.0@sha256:13b53ebabe3d215268c90cf8fb9b875f0183908245f376fd4b3a2cb69d21d484",
    "kics": "checkmarx/kics:latest@sha256:3e5a268eb8adda2e5a483c9359ddfc4cd520ab856a7076dc0b1d8784a37e2602",
}
SCANNER_IMAGE_ALIASES = {
    "opengrep": "semgrep",
    "osv": "osv-scanner",
}
CACHE_MOUNTS: dict[str, str] = {
    "trivy": "/root/.cache/trivy",
}
'''

DOCKERFILE_SNIPPET = """
ARG TRIVY_VERSION=0.72.0
ARG SYFT_VERSION=1.50.0
ARG TARGETARCH
"""


class TestParseImages:
    def test_captures_tag_not_digest(self):
        """The regression that made every comparison nonsense."""
        images = ctc.parse_images(CONTAINERS_SNIPPET)
        assert images["trivy"] == "0.72.0"
        assert images["syft"] == "v1.49.0"
        assert images["kics"] == "latest"
        for version in images.values():
            assert len(version) != 64, f"captured a digest as a version: {version}"

    def test_ignores_aliases_and_cache_paths(self):
        images = ctc.parse_images(CONTAINERS_SNIPPET)
        assert "opengrep" not in images
        assert "osv" not in images


class TestParseArgsVersions:
    def test_reads_arg_pins(self):
        args = ctc.parse_args_versions(DOCKERFILE_SNIPPET)
        assert args["TRIVY"] == "0.72.0"
        assert args["SYFT"] == "1.50.0"

    def test_ignores_non_version_args(self):
        assert "TARGETARCH" not in ctc.parse_args_versions(DOCKERFILE_SNIPPET)


class TestConsistency:
    def test_flags_disagreeing_pins(self):
        images = ctc.parse_images(CONTAINERS_SNIPPET)
        args = ctc.parse_args_versions(DOCKERFILE_SNIPPET)

        findings = ctc.check_consistency(images, args)

        assert [f.tool for f in findings] == ["syft"]
        assert "v1.49.0" in findings[0].detail and "1.50.0" in findings[0].detail

    def test_v_prefix_is_not_a_mismatch(self):
        findings = ctc.check_consistency({"trivy": "v0.72.0"}, {"TRIVY": "0.72.0"})
        assert findings == []

    def test_silent_when_a_side_is_absent(self):
        assert ctc.check_consistency({"trivy": "0.72.0"}, {}) == []


class TestNewestEligible:
    def test_skips_releases_inside_the_cooling_window(self):
        releases = [_release("0.122.0", 0), _release("0.121.19", 21)]

        assert ctc.newest_eligible(releases, 7, NOW) == ("0.121.19", 21)

    def test_boundary_day_counts_as_eligible(self):
        assert ctc.newest_eligible([_release("v1.50.0", 7)], 7, NOW) == ("v1.50.0", 7)

    def test_one_day_short_is_not_eligible(self):
        assert ctc.newest_eligible([_release("v1.50.0", 6)], 7, NOW) is None

    def test_ignores_prereleases_and_drafts(self):
        releases = [
            _release("2.0.0-rc1", 30, prerelease=True),
            _release("1.9.9", 40, draft=True),
            _release("1.9.8", 50),
        ]
        assert ctc.newest_eligible(releases, 7, NOW) == ("1.9.8", 50)

    def test_nothing_eligible_returns_none(self):
        assert ctc.newest_eligible([_release("1.0.0", 1)], 7, NOW) is None

    def test_tolerates_missing_publish_date(self):
        releases = [{"tag_name": "broken"}, _release("1.0.0", 30)]
        assert ctc.newest_eligible(releases, 7, NOW) == ("1.0.0", 30)


class TestCheckCurrency:
    def test_reports_only_adoptable_updates(self, monkeypatch):
        monkeypatch.setattr(
            ctc, "UPSTREAM_REPOS", {"promptfoo": "promptfoo/promptfoo"}
        )
        monkeypatch.setattr(
            ctc,
            "fetch_releases",
            lambda repo: [_release("0.122.0", 0), _release("0.121.19", 21)],
        )

        stale, unknown = ctc.check_currency({"promptfoo": "0.121.14"}, 7, NOW)

        assert unknown == []
        assert [f.tool for f in stale] == ["promptfoo"]
        assert "0.121.19" in stale[0].detail
        assert "0.122.0" not in stale[0].detail

    def test_current_pin_is_not_reported(self, monkeypatch):
        monkeypatch.setattr(ctc, "UPSTREAM_REPOS", {"syft": "anchore/syft"})
        monkeypatch.setattr(ctc, "fetch_releases", lambda repo: [_release("v1.50.0", 10)])

        stale, unknown = ctc.check_currency({"syft": "1.50.0"}, 7, NOW)

        assert stale == [] and unknown == []

    def test_network_failure_is_reported_not_raised(self, monkeypatch):
        def boom(repo):
            raise OSError("no route to host")

        monkeypatch.setattr(ctc, "UPSTREAM_REPOS", {"syft": "anchore/syft"})
        monkeypatch.setattr(ctc, "fetch_releases", boom)

        stale, unknown = ctc.check_currency({"syft": "v1.49.0"}, 7, NOW)

        assert stale == []
        assert [f.tool for f in unknown] == ["syft"]

    def test_unknown_detail_says_it_retried(self, monkeypatch):
        """The report must not imply a single failed poke was the whole effort."""

        def boom(repo):
            raise OSError("forbidden")

        monkeypatch.setattr(ctc, "UPSTREAM_REPOS", {"trivy": "aquasecurity/trivy"})
        monkeypatch.setattr(ctc, "fetch_releases", boom)

        _, unknown = ctc.check_currency({"trivy": "0.72.0"}, 7, NOW)

        assert "attempt(s)" in unknown[0].detail


def _http_error(code: int, *, retry_after: str | None = None) -> urllib.error.HTTPError:
    headers = {"Retry-After": retry_after} if retry_after is not None else {}
    return urllib.error.HTTPError(
        "https://api.github.com/x", code, "boom", headers, None  # type: ignore[arg-type]
    )


class TestFetchReleasesRetry:
    """#382 filed a report listing checkov and trivy as unchecked while both
    endpoints were healthy — a transient 403 was enough to give up. Retrying is
    what makes the "could not verify" bucket mean something.
    """

    def _patch_urlopen(self, monkeypatch, outcomes):
        """Serve ``outcomes`` in order; raise them if exceptions, return if not."""
        calls = []

        def fake_urlopen(request, timeout=None):
            outcome = outcomes[len(calls)]
            calls.append(request)
            if isinstance(outcome, Exception):
                raise outcome

            class _Response:
                def __enter__(self):
                    return io.BytesIO(json.dumps(outcome).encode())

                def __exit__(self, *exc):
                    return False

            return _Response()

        monkeypatch.setattr(ctc.urllib.request, "urlopen", fake_urlopen)
        monkeypatch.setattr(ctc, "_gh_token", lambda: None)
        return calls

    def test_retries_a_transient_403_then_succeeds(self, monkeypatch):
        releases = [_release("0.122.0", 21)]
        calls = self._patch_urlopen(monkeypatch, [_http_error(403), releases])
        slept: list[float] = []

        got = ctc.fetch_releases("aquasecurity/trivy", sleep=slept.append)

        assert got == releases
        assert len(calls) == 2
        assert slept == [ctc.BACKOFF_BASE_SECONDS**1]

    def test_retries_5xx_and_transport_errors(self, monkeypatch):
        releases = [_release("v1.0.0", 30)]
        calls = self._patch_urlopen(
            monkeypatch, [_http_error(503), urllib.error.URLError("reset"), releases]
        )

        got = ctc.fetch_releases("anchore/syft", sleep=lambda _: None)

        assert got == releases and len(calls) == 3

    def test_does_not_retry_a_404(self, monkeypatch):
        """A renamed repo is a config bug — surface it instead of burning quota."""
        calls = self._patch_urlopen(monkeypatch, [_http_error(404)])
        slept: list[float] = []

        with pytest.raises(urllib.error.HTTPError) as excinfo:
            ctc.fetch_releases("gone/away", sleep=slept.append)

        assert excinfo.value.code == 404
        assert len(calls) == 1 and slept == []

    def test_raises_the_last_error_once_attempts_run_out(self, monkeypatch):
        calls = self._patch_urlopen(monkeypatch, [_http_error(403)] * 3)

        with pytest.raises(urllib.error.HTTPError):
            ctc.fetch_releases("aquasecurity/trivy", attempts=3, sleep=lambda _: None)

        assert len(calls) == 3

    def test_token_is_resolved_once_not_per_attempt(self, monkeypatch):
        """_gh_token may shell out to `gh auth token`; keep it out of the loop."""
        self._patch_urlopen(monkeypatch, [_http_error(403), _http_error(403), []])
        token_calls: list[int] = []
        monkeypatch.setattr(ctc, "_gh_token", lambda: (token_calls.append(1), "tok")[1])

        ctc.fetch_releases("anchore/grype", sleep=lambda _: None)

        assert len(token_calls) == 1


class TestRetryDelay:
    def test_honours_retry_after(self):
        assert ctc._retry_delay(_http_error(403, retry_after="9"), 1) == 9.0

    def test_falls_back_to_exponential_backoff(self):
        assert ctc._retry_delay(_http_error(403), 1) == 2.0
        assert ctc._retry_delay(_http_error(403), 3) == 8.0

    def test_caps_the_wait(self):
        assert ctc._retry_delay(_http_error(403, retry_after="99999"), 1) == (
            ctc.MAX_BACKOFF_SECONDS
        )
        assert ctc._retry_delay(_http_error(403), 99) == ctc.MAX_BACKOFF_SECONDS

    def test_ignores_a_junk_retry_after(self):
        assert ctc._retry_delay(_http_error(403, retry_after="soon"), 1) == 2.0

    def test_tolerates_an_error_with_no_headers(self):
        assert ctc._retry_delay(OSError("reset"), 1) == 2.0


class TestExitCodes:
    def _write(self, tmp_path, containers: str, dockerfile: str) -> list[str]:
        (tmp_path / "containers.py").write_text(containers)
        (tmp_path / "Dockerfile").write_text(dockerfile)
        return [
            "--containers",
            str(tmp_path / "containers.py"),
            "--dockerfile",
            str(tmp_path / "Dockerfile"),
        ]

    def test_mismatch_fails_even_without_fail_on_stale(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ctc, "UPSTREAM_REPOS", {})
        argv = self._write(tmp_path, CONTAINERS_SNIPPET, DOCKERFILE_SNIPPET)

        assert ctc.main(argv + ["--consistency-only"]) == 1

    def test_clean_tree_passes(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ctc, "UPSTREAM_REPOS", {})
        argv = self._write(
            tmp_path,
            CONTAINERS_SNIPPET.replace("v1.49.0", "v1.50.0"),
            DOCKERFILE_SNIPPET,
        )

        assert ctc.main(argv + ["--consistency-only"]) == 0

    def test_stale_only_fails_when_asked(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ctc, "UPSTREAM_REPOS", {"trivy": "aquasecurity/trivy"})
        monkeypatch.setattr(ctc, "fetch_releases", lambda repo: [_release("0.73.0", 30)])
        argv = self._write(
            tmp_path,
            CONTAINERS_SNIPPET.replace("v1.49.0", "v1.50.0"),
            DOCKERFILE_SNIPPET,
        )

        assert ctc.main(argv) == 0
        assert ctc.main(argv + ["--fail-on-stale"]) == 1


class TestRender:
    def test_markdown_lists_each_category(self):
        report = ctc.Report(
            mismatches=[ctc.Finding("mismatch", "syft", "two pins disagree")],
            stale=[ctc.Finding("stale", "tflint", "v0.64.0 available")],
            unknown=[ctc.Finding("unknown", "zap", "query failed")],
        )

        out = ctc.render(report, "markdown", 7)

        assert "### Inconsistent pins (blocking)" in out
        assert "past the 7-day gate" in out
        assert "Could not verify" in out
        assert "syft" in out and "tflint" in out and "zap" in out

    def test_unverified_pins_are_not_presented_as_current(self):
        """An unknown-only report used to read like a pass under "Not checked"."""
        report = ctc.Report(unknown=[ctc.Finding("unknown", "checkov", "403")])

        out = ctc.render(report, "markdown", 7)

        assert "Nothing to do" not in out
        assert "not as up to date" in out

    def test_markdown_says_so_when_clean(self):
        out = ctc.render(ctc.Report(), "markdown", 7)
        assert "Nothing to do" in out
