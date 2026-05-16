"""Unit tests for argus.core.image_verify.

The four verification paths under test:

  - argus-owned image + cosign passes → VERIFIED_COSIGN (scan proceeds)
  - argus-owned image + cosign fails  → FAILED_COSIGN (scan aborts)
  - third-party with @sha256 digest   → VERIFIED_DIGEST_PIN (scan proceeds)
  - third-party with tag only         → SKIPPED_TAG_PIN (scan proceeds with warning)

The ``cosign_runner`` injection point lets tests assert command
construction without needing the cosign binary on PATH.
"""

from __future__ import annotations

import logging
import subprocess

import pytest

from argus.core.image_verify import (
    ARGUS_CERT_IDENTITY_REGEXP,
    ARGUS_OIDC_ISSUER,
    VerifyResult,
    VerifyStatus,
    has_digest_pin,
    is_argus_owned,
    report_tag_pinned_summary,
    verify_image,
)


def _ok(stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=0, stdout=stdout, stderr=stderr,
    )


def _fail(returncode: int = 1, stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout="", stderr=stderr,
    )


class TestImageClassification:
    @pytest.mark.parametrize("image", [
        "ghcr.io/huntridge-labs/argus/scanner-bandit:0.7.0",
        "ghcr.io/huntridge-labs/argus/cli:latest",
        "ghcr.io/huntridge-labs/argus/scanner-opengrep:0.7.0",
    ])
    def test_argus_owned_recognized(self, image):
        assert is_argus_owned(image) is True

    @pytest.mark.parametrize("image", [
        "aquasec/trivy:0.70.0",
        "ghcr.io/google/osv-scanner:v2.3.6",
        "anchore/grype:v0.112.0",
    ])
    def test_third_party_not_argus_owned(self, image):
        assert is_argus_owned(image) is False

    def test_digest_pin_detected(self):
        assert has_digest_pin("aquasec/trivy@sha256:abc") is True
        assert has_digest_pin("repo:tag@sha256:def") is True

    def test_no_digest_pin_when_only_tag(self):
        assert has_digest_pin("aquasec/trivy:0.70.0") is False
        assert has_digest_pin("alpine:latest") is False


class TestVerifyImageArgusOwned:
    """Argus-owned images go through cosign verify."""

    def test_cosign_pass_returns_verified(self):
        captured: list = []

        def runner(cmd):
            captured.append(cmd)
            return _ok()

        result = verify_image(
            "ghcr.io/huntridge-labs/argus/scanner-bandit:0.7.0",
            cosign_runner=runner,
        )

        assert result.status == VerifyStatus.VERIFIED_COSIGN
        assert not result.is_fatal
        # Command construction: cosign verify with the right identity guards
        assert captured[0][0:3] == ["cosign", "verify",
                                     "ghcr.io/huntridge-labs/argus/scanner-bandit:0.7.0"]
        assert "--certificate-identity-regexp" in captured[0]
        assert ARGUS_CERT_IDENTITY_REGEXP in captured[0]
        assert "--certificate-oidc-issuer" in captured[0]
        assert ARGUS_OIDC_ISSUER in captured[0]

    def test_cosign_fail_returns_fatal_with_stderr(self):
        def runner(cmd):
            return _fail(stderr="error: no matching signatures found")

        result = verify_image(
            "ghcr.io/huntridge-labs/argus/scanner-bandit:0.7.0",
            cosign_runner=runner,
        )

        assert result.status == VerifyStatus.FAILED_COSIGN
        assert result.is_fatal
        # User must see the cosign error to diagnose
        assert "no matching signatures" in result.message

    def test_cosign_stderr_truncated_at_500(self):
        def runner(cmd):
            return _fail(stderr="x" * 5000)

        result = verify_image(
            "ghcr.io/huntridge-labs/argus/scanner-bandit:0.7.0",
            cosign_runner=runner,
        )

        # Bounded so we don't dump huge stack traces into logs
        assert "x" * 500 in result.message
        assert "x" * 501 not in result.message

    def test_missing_cosign_binary_returns_fatal_with_install_hint(self):
        def runner(cmd):
            raise FileNotFoundError(2, "No such file or directory: 'cosign'")

        result = verify_image(
            "ghcr.io/huntridge-labs/argus/scanner-bandit:0.7.0",
            cosign_runner=runner,
        )

        assert result.status == VerifyStatus.FAILED_COSIGN_BINARY_MISSING
        assert result.is_fatal
        # Helpful install hint surfaces in the error
        assert "cosign" in result.message
        assert ("install" in result.message.lower()
                or "sigstore" in result.message.lower())

    def test_digest_pinned_image_skips_cosign_and_returns_verified(self):
        """Argus-owned images pinned to ``tag@sha256:...`` are trusted
        via Docker's content-hash check at pull, same as third-party
        digest-pinned images. cosign becomes optional / additional —
        the engine doesn't fail when the binary is missing.
        """
        ran_cosign = False

        def runner(cmd):
            nonlocal ran_cosign
            ran_cosign = True
            return _ok()

        result = verify_image(
            "ghcr.io/huntridge-labs/argus/scanner-bandit:0.7.0"
            "@sha256:bb5a8b56bd9a1c65a7d6830a3be9b9a2c463fd32d45b5177edadeb2aafe68fd1",
            cosign_runner=runner,
        )

        assert result.status == VerifyStatus.VERIFIED_DIGEST_PIN
        assert not result.is_fatal
        # cosign was NOT invoked — digest pin alone is sufficient for
        # argus-owned images now that CUSTOM_IMAGES are digest-pinned.
        assert ran_cosign is False
        # The message should hint at cosign as additional verification
        # so users can opt into it explicitly.
        assert "cosign" in result.message.lower()

    def test_digest_pinned_image_passes_when_cosign_binary_missing(self):
        """Regression: dev laptop without cosign should NOT fail on
        argus-owned digest-pinned images. PR #161 missed this case;
        every argus-owned scanner was unrunnable on a fresh checkout
        until CUSTOM_IMAGES got digest pins."""
        def runner(cmd):
            raise FileNotFoundError(2, "No such file or directory: 'cosign'")

        result = verify_image(
            "ghcr.io/huntridge-labs/argus/scanner-bandit:0.7.0"
            "@sha256:bb5a8b56bd9a1c65a7d6830a3be9b9a2c463fd32d45b5177edadeb2aafe68fd1",
            cosign_runner=runner,
        )

        assert result.status == VerifyStatus.VERIFIED_DIGEST_PIN
        assert not result.is_fatal


class TestVerifyImageThirdParty:
    """Third-party images: digest pin = trust; tag-only = warn."""

    def test_digest_pin_no_cosign_call(self):
        called = False

        def runner(cmd):
            nonlocal called
            called = True
            return _ok()

        result = verify_image(
            "aquasec/trivy@sha256:abcdef123456",
            cosign_runner=runner,
        )

        assert result.status == VerifyStatus.VERIFIED_DIGEST_PIN
        assert not result.is_fatal
        # Cosign is NOT invoked for third-party images even with digest pin —
        # Docker enforces digest match at pull, no extra check needed.
        assert called is False

    def test_tag_only_pin_skipped_not_fatal(self):
        result = verify_image("aquasec/trivy:0.70.0", cosign_runner=lambda _: _ok())

        assert result.status == VerifyStatus.SKIPPED_TAG_PIN
        assert not result.is_fatal
        # Migration hint surfaces
        assert "@sha256" in result.message or "digest" in result.message


class TestVerifyImageDisabled:
    """When verification is disabled, every path returns SKIPPED_BY_CONFIG."""

    @pytest.mark.parametrize("image", [
        "ghcr.io/huntridge-labs/argus/scanner-bandit:0.7.0",
        "aquasec/trivy@sha256:abc",
        "aquasec/trivy:0.70.0",
        "",
    ])
    def test_disabled_returns_skipped_by_config(self, image):
        result = verify_image(image, verify_signatures=False)
        assert result.status == VerifyStatus.SKIPPED_BY_CONFIG
        assert not result.is_fatal


class TestTagPinnedSummary:
    def test_summary_logs_once_for_all_tag_pinned(self, caplog):
        results = [
            VerifyResult(VerifyStatus.SKIPPED_TAG_PIN, "aquasec/trivy:0.70.0", ""),
            VerifyResult(VerifyStatus.SKIPPED_TAG_PIN, "anchore/grype:v0.112.0", ""),
            VerifyResult(VerifyStatus.VERIFIED_COSIGN, "argus-img", ""),
        ]
        with caplog.at_level(logging.WARNING, logger="argus"):
            report_tag_pinned_summary(results)

        records = [r for r in caplog.records if r.levelno == logging.WARNING]
        # One warning, listing both tag-pinned images
        assert len(records) == 1
        assert "aquasec/trivy:0.70.0" in records[0].message
        assert "anchore/grype:v0.112.0" in records[0].message
        # Should NOT include the verified image
        assert "argus-img" not in records[0].message

    def test_no_warning_when_nothing_tag_pinned(self, caplog):
        results = [
            VerifyResult(VerifyStatus.VERIFIED_COSIGN, "img-a", ""),
            VerifyResult(VerifyStatus.VERIFIED_DIGEST_PIN, "img-b@sha256:x", ""),
        ]
        with caplog.at_level(logging.WARNING, logger="argus"):
            report_tag_pinned_summary(results)

        records = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert records == []

    def test_duplicate_images_collapsed(self, caplog):
        # Two scanners pointing at the same trivy image shouldn't be listed twice
        results = [
            VerifyResult(VerifyStatus.SKIPPED_TAG_PIN, "aquasec/trivy:0.70.0", ""),
            VerifyResult(VerifyStatus.SKIPPED_TAG_PIN, "aquasec/trivy:0.70.0", ""),
        ]
        with caplog.at_level(logging.WARNING, logger="argus"):
            report_tag_pinned_summary(results)

        msg = caplog.records[-1].message
        # Should mention the image exactly once
        assert msg.count("aquasec/trivy:0.70.0") == 1
        # And the count should reflect the dedup
        assert "1 third-party image" in msg
