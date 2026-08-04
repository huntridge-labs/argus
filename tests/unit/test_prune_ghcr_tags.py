"""Tests for ``scripts/ci/prune_ghcr_tags.py``.

Regression locks for two defects that broke the nightly GHCR Cleanup job:

1. A ``DELETE`` returning HTTP 404 aborted the entire sweep. Deleting a
   manifest-list parent cascades to dependent versions, so a version
   enumerated at the start of the run can already be gone by the time the
   loop reaches it — an outcome that is indistinguishable from success and
   must not raise.

2. Cosign artifacts are tagged ``sha256-<subject digest>``, which matches
   neither ``latest`` nor semver, so every signature and attestation older
   than ``--keep-days`` was pruned — including the ones proving the
   provenance of live releases. Pulling such a release then fails
   ``cosign verify``.
"""

from __future__ import annotations

import subprocess

import pytest

from scripts.ci import prune_ghcr_tags as prune


# --------------------------------------------------------------------- #
# Fixtures                                                              #
# --------------------------------------------------------------------- #

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def _version(
    version_id: int,
    tags: list[str],
    created: str = "2020-01-01T00:00:00Z",
    name: str = DIGEST_A,
) -> dict:
    """Build one entry shaped like the GHCR package-versions API."""
    return {
        "id": version_id,
        "name": name,
        "created_at": created,
        "metadata": {"container": {"tags": tags}},
    }


class _FakeProc:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# --------------------------------------------------------------------- #
# gh_delete — 404 tolerance                                             #
# --------------------------------------------------------------------- #


class TestGhDeleteTolerates404:
    def test_successful_delete_reports_true(self, monkeypatch):
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **k: _FakeProc(0)
        )
        assert prune.gh_delete("orgs/o/packages/container/p/versions/1") is True

    def test_404_is_treated_as_already_deleted(self, monkeypatch):
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **k: _FakeProc(
                1,
                stdout='{"message":"Package not found.","status":"404"}',
                stderr="gh: Package not found. (HTTP 404)",
            ),
        )
        assert prune.gh_delete("orgs/o/packages/container/p/versions/1") is False

    def test_other_errors_still_raise(self, monkeypatch):
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **k: _FakeProc(
                1, stderr="gh: Bad credentials (HTTP 401)"
            ),
        )
        with pytest.raises(RuntimeError, match="DELETE failed"):
            prune.gh_delete("orgs/o/packages/container/p/versions/1")

    def test_sweep_continues_past_a_404(self, monkeypatch):
        """The original bug: one 404 aborted every remaining deletion."""
        calls: list[str] = []

        def fake_run(cmd, *a, **k):
            path = cmd[-1]
            calls.append(path)
            if path.endswith("/2"):
                return _FakeProc(1, stderr="gh: Package not found. (HTTP 404)")
            return _FakeProc(0)

        monkeypatch.setattr(subprocess, "run", fake_run)
        monkeypatch.setattr(
            prune,
            "gh_json",
            lambda args: [
                _version(1, ["build-aaa"]),
                _version(2, ["build-bbb"]),
                _version(3, ["build-ccc"]),
            ],
        )

        deleted = prune.prune("org", "argus/cli", keep_days=14, dry_run=False)

        assert deleted == 3
        assert [c.rsplit("/", 1)[-1] for c in calls] == ["1", "2", "3"]


# --------------------------------------------------------------------- #
# cosign artifact protection                                            #
# --------------------------------------------------------------------- #


class TestCosignSubject:
    @pytest.mark.parametrize(
        "tag",
        [
            "sha256-" + "a" * 64,
            "sha256-" + "a" * 64 + ".sig",
            "sha256-" + "a" * 64 + ".att",
            "sha256-" + "a" * 64 + ".sbom",
        ],
    )
    def test_recognises_cosign_tag_forms(self, tag):
        assert prune.cosign_subject([tag]) == DIGEST_A

    @pytest.mark.parametrize(
        "tag", ["latest", "1.11.0", "build-abc123", "main-abc123", "pr-42"]
    )
    def test_ignores_ordinary_tags(self, tag):
        assert prune.cosign_subject([tag]) is None


class TestCosignArtifactsSurviveWithTheirSubject:
    def test_signature_for_released_image_is_kept(self, monkeypatch):
        """A release tag is kept forever, so its signature must be too."""
        deleted_paths: list[str] = []
        monkeypatch.setattr(
            prune,
            "gh_delete",
            lambda path: deleted_paths.append(path) or True,
        )
        monkeypatch.setattr(
            prune,
            "gh_json",
            lambda args: [
                # Released image — kept by the semver rule.
                _version(10, ["1.11.0"], name=DIGEST_A),
                # Its cosign signature, well past the cutoff.
                _version(
                    11,
                    ["sha256-" + "a" * 64],
                    created="2020-01-01T00:00:00Z",
                    name=DIGEST_B,
                ),
            ],
        )

        deleted = prune.prune("org", "argus/cli", keep_days=14, dry_run=False)

        assert deleted == 0
        assert deleted_paths == []

    def test_signature_for_pruned_image_is_deleted(self, monkeypatch):
        """Signatures of throwaway build tags should not accumulate."""
        deleted_ids: list[str] = []
        monkeypatch.setattr(
            prune,
            "gh_delete",
            lambda path: deleted_ids.append(path.rsplit("/", 1)[-1]) or True,
        )
        monkeypatch.setattr(
            prune,
            "gh_json",
            lambda args: [
                # Stale build tag — pruned.
                _version(20, ["build-abc123"], name=DIGEST_A),
                # Its signature — subject is going away, so this goes too.
                _version(21, ["sha256-" + "a" * 64], name=DIGEST_B),
            ],
        )

        deleted = prune.prune("org", "argus/cli", keep_days=14, dry_run=False)

        assert deleted == 2
        assert sorted(deleted_ids) == ["20", "21"]

    def test_signature_for_recent_image_is_kept(self, monkeypatch):
        """Subject inside the keep window counts as surviving."""
        monkeypatch.setattr(
            prune,
            "gh_delete",
            lambda path: pytest.fail(f"unexpected delete: {path}"),
        )
        recent = (
            __import__("datetime")
            .datetime.now(__import__("datetime").timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        monkeypatch.setattr(
            prune,
            "gh_json",
            lambda args: [
                _version(30, ["build-fresh"], created=recent, name=DIGEST_A),
                _version(31, ["sha256-" + "a" * 64], name=DIGEST_B),
            ],
        )

        assert prune.prune("org", "argus/cli", 14, dry_run=False) == 0


# --------------------------------------------------------------------- #
# existing keep rules still hold                                        #
# --------------------------------------------------------------------- #


class TestKeepRules:
    @pytest.mark.parametrize(
        "tags",
        [
            ["latest"],
            ["1.0.0"],
            ["1.0.0-rc.1"],
            ["1.0.0-beta.2"],
            [],  # untagged manifest-list child
        ],
    )
    def test_keepers(self, tags):
        assert prune.is_keeper(tags) is True

    @pytest.mark.parametrize(
        "tags", [["build-abc"], ["pr-7"], ["main-abc123"], ["test-thing"]]
    )
    def test_prunable(self, tags):
        assert prune.is_keeper(tags) is False

    def test_dry_run_deletes_nothing(self, monkeypatch):
        monkeypatch.setattr(
            prune,
            "gh_delete",
            lambda path: pytest.fail("dry run must not delete"),
        )
        monkeypatch.setattr(
            prune, "gh_json", lambda args: [_version(40, ["build-abc"])]
        )

        assert prune.prune("org", "argus/cli", 14, dry_run=True) == 1
