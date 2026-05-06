"""Tests for argus.update_check.

Locks in the air-gap-friendly contract: the update check NEVER fails
loudly, NEVER hangs the scan, and ALWAYS honors the suppression hooks.
A new release notification is a UX nicety; the security tool's actual
job (scanning) must keep working under every degraded condition.
"""

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

import pytest

from argus import update_check


# ──────────────────────────────────────────────────────────────────
# Suppression hooks                                                #
# ──────────────────────────────────────────────────────────────────


def _ns(**flags) -> argparse.Namespace:
    base = {"no_update_check": False, "quiet": False}
    base.update(flags)
    return argparse.Namespace(**base)


class TestShouldCheck:

    def test_default_is_enabled(self, monkeypatch):
        monkeypatch.delenv("ARGUS_NO_UPDATE_CHECK", raising=False)
        monkeypatch.setattr(update_check, "_is_dev_install", lambda: False)
        assert update_check.should_check(_ns()) is True

    def test_env_var_disables(self, monkeypatch):
        monkeypatch.setenv("ARGUS_NO_UPDATE_CHECK", "1")
        monkeypatch.setattr(update_check, "_is_dev_install", lambda: False)
        assert update_check.should_check(_ns()) is False

    def test_no_update_check_flag_disables(self, monkeypatch):
        monkeypatch.delenv("ARGUS_NO_UPDATE_CHECK", raising=False)
        monkeypatch.setattr(update_check, "_is_dev_install", lambda: False)
        assert update_check.should_check(_ns(no_update_check=True)) is False

    def test_quiet_flag_disables(self, monkeypatch):
        monkeypatch.delenv("ARGUS_NO_UPDATE_CHECK", raising=False)
        monkeypatch.setattr(update_check, "_is_dev_install", lambda: False)
        assert update_check.should_check(_ns(quiet=True)) is False

    def test_dev_install_disables(self, monkeypatch):
        monkeypatch.delenv("ARGUS_NO_UPDATE_CHECK", raising=False)
        monkeypatch.setattr(update_check, "_is_dev_install", lambda: True)
        assert update_check.should_check(_ns()) is False

    def test_no_args_passed_is_still_handled(self, monkeypatch):
        monkeypatch.delenv("ARGUS_NO_UPDATE_CHECK", raising=False)
        monkeypatch.setattr(update_check, "_is_dev_install", lambda: False)
        # Some callers don't have an argparse Namespace — must not crash.
        assert update_check.should_check(None) is True


class TestIsDevInstall:

    @pytest.mark.parametrize("version", [
        "0.7.2.dev0",
        "0.7.2.dev0+g123abc",
        "0.7.2+dirty",
        "0.7.2rc1",
    ])
    def test_dev_markers_skip(self, monkeypatch, version):
        monkeypatch.setattr(update_check, "__version__", version)
        assert update_check._is_dev_install() is True

    @pytest.mark.parametrize("version", ["0.7.2", "1.0.0", "0.7.2.post1"])
    def test_release_versions_dont_skip(self, monkeypatch, version):
        monkeypatch.setattr(update_check, "__version__", version)
        assert update_check._is_dev_install() is False


# ──────────────────────────────────────────────────────────────────
# URL resolution                                                   #
# ──────────────────────────────────────────────────────────────────


class TestPyPIUrl:

    def test_default(self, monkeypatch):
        monkeypatch.delenv("ARGUS_UPDATE_CHECK_URL", raising=False)
        assert update_check._pypi_url() == update_check.DEFAULT_PYPI_URL

    def test_env_var_override(self, monkeypatch):
        monkeypatch.setenv(
            "ARGUS_UPDATE_CHECK_URL",
            "https://test.pypi.org/pypi/argus-security/json",
        )
        assert "test.pypi.org" in update_check._pypi_url()


# ──────────────────────────────────────────────────────────────────
# Fetch and cache                                                  #
# ──────────────────────────────────────────────────────────────────


class TestFetchLatestVersion:

    def test_returns_version_on_success(self):
        # Mock the json response from PyPI.
        class _Resp:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def read(self):
                return json.dumps({"info": {"version": "0.8.1"}}).encode()
        with patch("argus.update_check.urlopen", return_value=_Resp()):
            assert update_check.fetch_latest_version() == "0.8.1"

    def test_network_error_returns_none(self):
        with patch("argus.update_check.urlopen", side_effect=URLError("offline")):
            assert update_check.fetch_latest_version() is None

    def test_oserror_returns_none(self):
        with patch("argus.update_check.urlopen", side_effect=OSError("conn refused")):
            assert update_check.fetch_latest_version() is None

    def test_malformed_json_returns_none(self):
        class _Resp:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def read(self): return b"not json"
        with patch("argus.update_check.urlopen", return_value=_Resp()):
            assert update_check.fetch_latest_version() is None

    def test_missing_version_field_returns_none(self):
        class _Resp:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def read(self): return json.dumps({"info": {}}).encode()
        with patch("argus.update_check.urlopen", return_value=_Resp()):
            assert update_check.fetch_latest_version() is None


class TestCachedLatestVersion:

    def test_uses_fresh_cache(self, tmp_path, monkeypatch):
        cache_path = tmp_path / "argus" / "update-check.json"
        cache_path.parent.mkdir()
        cache_path.write_text(json.dumps({
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "latest_version": "0.9.0",
        }))
        monkeypatch.setattr(update_check, "_cache_path", lambda: cache_path)

        with patch("argus.update_check.fetch_latest_version") as mock_fetch:
            result = update_check.cached_latest_version()
            mock_fetch.assert_not_called()
        assert result == "0.9.0"

    def test_refetches_when_cache_stale(self, tmp_path, monkeypatch):
        cache_path = tmp_path / "argus" / "update-check.json"
        cache_path.parent.mkdir()
        cache_path.write_text(json.dumps({
            "checked_at": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
            "latest_version": "0.6.0",
        }))
        monkeypatch.setattr(update_check, "_cache_path", lambda: cache_path)

        with patch(
            "argus.update_check.fetch_latest_version",
            return_value="0.9.0",
        ):
            result = update_check.cached_latest_version()
        assert result == "0.9.0"

        # New value was written to cache.
        new_cache = json.loads(cache_path.read_text())
        assert new_cache["latest_version"] == "0.9.0"

    def test_no_cache_falls_through_to_fetch(self, tmp_path, monkeypatch):
        cache_path = tmp_path / "argus" / "update-check.json"
        monkeypatch.setattr(update_check, "_cache_path", lambda: cache_path)
        with patch(
            "argus.update_check.fetch_latest_version",
            return_value="0.9.0",
        ):
            result = update_check.cached_latest_version()
        assert result == "0.9.0"
        assert cache_path.is_file()

    def test_corrupt_cache_doesnt_crash(self, tmp_path, monkeypatch):
        cache_path = tmp_path / "argus" / "update-check.json"
        cache_path.parent.mkdir()
        cache_path.write_text("{not json")
        monkeypatch.setattr(update_check, "_cache_path", lambda: cache_path)
        with patch(
            "argus.update_check.fetch_latest_version",
            return_value="0.9.0",
        ):
            result = update_check.cached_latest_version()
        assert result == "0.9.0"


# ──────────────────────────────────────────────────────────────────
# Version comparison + notice formatting                           #
# ──────────────────────────────────────────────────────────────────


class TestIsNewer:

    def test_strictly_newer_returns_true(self):
        assert update_check.is_newer("0.7.2", "0.8.0") is True

    def test_same_version_returns_false(self):
        assert update_check.is_newer("0.7.2", "0.7.2") is False

    def test_older_returns_false(self):
        assert update_check.is_newer("0.8.0", "0.7.2") is False


class TestFormatNotice:

    def test_includes_both_versions(self):
        msg = update_check.format_notice("0.7.2", "0.8.1")
        assert "0.7.2" in msg
        assert "0.8.1" in msg

    def test_includes_pip_upgrade_command(self):
        msg = update_check.format_notice("0.7.2", "0.8.1")
        assert "pip install --upgrade argus-security" in msg

    def test_pip_style_notice_prefix(self):
        msg = update_check.format_notice("0.7.2", "0.8.1")
        assert "[notice]" in msg


# ──────────────────────────────────────────────────────────────────
# get_notice_if_outdated — the convenience entry point             #
# ──────────────────────────────────────────────────────────────────


class TestGetNoticeIfOutdated:

    def test_returns_notice_when_outdated(self, monkeypatch):
        monkeypatch.setattr(update_check, "__version__", "0.7.2")
        monkeypatch.setattr(update_check, "_is_dev_install", lambda: False)
        monkeypatch.setattr(
            update_check, "cached_latest_version", lambda: "0.9.0",
        )
        notice = update_check.get_notice_if_outdated()
        assert notice is not None
        assert "0.7.2" in notice and "0.9.0" in notice

    def test_returns_none_when_up_to_date(self, monkeypatch):
        monkeypatch.setattr(update_check, "__version__", "0.9.0")
        monkeypatch.setattr(update_check, "_is_dev_install", lambda: False)
        monkeypatch.setattr(
            update_check, "cached_latest_version", lambda: "0.9.0",
        )
        assert update_check.get_notice_if_outdated() is None

    def test_returns_none_on_dev_install(self, monkeypatch):
        monkeypatch.setattr(update_check, "_is_dev_install", lambda: True)
        # Should not even consult cache when dev install.
        with patch("argus.update_check.cached_latest_version") as mock:
            assert update_check.get_notice_if_outdated() is None
            mock.assert_not_called()

    def test_returns_none_when_fetch_fails(self, monkeypatch):
        monkeypatch.setattr(update_check, "_is_dev_install", lambda: False)
        monkeypatch.setattr(
            update_check, "cached_latest_version", lambda: None,
        )
        assert update_check.get_notice_if_outdated() is None


# ──────────────────────────────────────────────────────────────────
# Background check — daemon thread                                 #
# ──────────────────────────────────────────────────────────────────


class TestBackgroundCheck:

    def test_swallows_exceptions(self):
        # An unexpected exception inside the thread must not propagate
        # — air-gap friendly contract.
        check = update_check.BackgroundCheck()
        with patch(
            "argus.update_check.get_notice_if_outdated",
            side_effect=RuntimeError("unexpected"),
        ):
            check.start()
            assert check.notice(timeout=1.0) is None

    def test_returns_notice_when_set(self):
        check = update_check.BackgroundCheck()
        with patch(
            "argus.update_check.get_notice_if_outdated",
            return_value="my notice",
        ):
            check.start()
            assert check.notice(timeout=1.0) == "my notice"


class TestStartBackgroundCheck:

    def test_returns_none_when_suppressed(self, monkeypatch):
        monkeypatch.setenv("ARGUS_NO_UPDATE_CHECK", "1")
        assert update_check.start_background_check(_ns()) is None

    def test_returns_check_when_enabled(self, monkeypatch):
        monkeypatch.delenv("ARGUS_NO_UPDATE_CHECK", raising=False)
        monkeypatch.setattr(update_check, "_is_dev_install", lambda: False)
        with patch(
            "argus.update_check.get_notice_if_outdated", return_value=None,
        ):
            check = update_check.start_background_check(_ns())
            assert check is not None
            assert check.notice(timeout=1.0) is None
