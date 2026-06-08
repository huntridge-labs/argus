"""Tests for scanner-toolchain provenance (issue #240)."""

from argus.containers import CUSTOM_IMAGES
from argus.core.image_verify import VerifyResult, VerifyStatus
from argus.core.models import ScanSummary
from argus.core.toolchain import build_toolchain_provenance

# A real published argus image ref (tag@sha256) — its digest matches a pin.
GENUINE_ARGUS = CUSTOM_IMAGES["bandit"]
THIRD_PARTY = "aquasec/trivy:0.70.0@sha256:" + "a" * 64


def _vr(status, image):
    return VerifyResult(status=status, image=image, message="")


class TestBuildToolchainProvenance:
    def test_no_verify_results_returns_none(self):
        # An all-local-binary run pulls nothing — absence is informative,
        # never reported as "verified".
        assert build_toolchain_provenance([]) is None

    def test_genuine_argus_image_is_all_verified(self):
        prov = build_toolchain_provenance([
            _vr(VerifyStatus.VERIFIED_COSIGN, GENUINE_ARGUS),
            _vr(VerifyStatus.VERIFIED_DIGEST_PIN, THIRD_PARTY),
        ])
        assert prov["argus_images_all_verified"] is True
        assert prov["warnings"] == []
        argus_entry = next(e for e in prov["images"] if e["argus_owned"])
        assert argus_entry["digest_matches_published_pin"] is True
        assert argus_entry["digest"].startswith("sha256:")

    def test_rebuilt_argus_image_digest_mismatch_flagged(self):
        # argus-owned name, but a digest that matches no published pin —
        # the clone-and-rebuild tell.
        rebuilt = "ghcr.io/huntridge-labs/argus/scanner-bandit:1.3.1@sha256:" + "f" * 64
        prov = build_toolchain_provenance([
            _vr(VerifyStatus.VERIFIED_COSIGN, rebuilt),
        ])
        assert prov["argus_images_all_verified"] is False
        assert any("does not match any published release pin" in w
                   for w in prov["warnings"])

    def test_unverified_argus_image_flagged(self):
        prov = build_toolchain_provenance([
            _vr(VerifyStatus.FAILED_COSIGN, GENUINE_ARGUS),
        ])
        assert prov["argus_images_all_verified"] is False
        assert any("not signature/digest verified" in w
                   for w in prov["warnings"])

    def test_third_party_only_is_not_implied_verified(self):
        # No argus-owned image involved → don't claim toolchain verification.
        prov = build_toolchain_provenance([
            _vr(VerifyStatus.VERIFIED_DIGEST_PIN, THIRD_PARTY),
        ])
        assert prov["argus_images_all_verified"] is None
        assert prov["images"][0]["argus_owned"] is False
        assert "digest_matches_published_pin" not in prov["images"][0]

    def test_duplicate_image_deduplicated(self):
        prov = build_toolchain_provenance([
            _vr(VerifyStatus.VERIFIED_COSIGN, GENUINE_ARGUS),
            _vr(VerifyStatus.VERIFIED_COSIGN, GENUINE_ARGUS),
        ])
        assert len(prov["images"]) == 1


class TestScanSummaryToolchainSerialization:
    def test_toolchain_round_trips_through_to_dict(self):
        prov = build_toolchain_provenance([
            _vr(VerifyStatus.VERIFIED_COSIGN, GENUINE_ARGUS),
        ])
        summary = ScanSummary(results=[], toolchain=prov)
        out = summary.to_dict()
        assert out["toolchain"] == prov
        assert ScanSummary.from_dict(out).toolchain == prov

    def test_toolchain_absent_when_none(self):
        out = ScanSummary(results=[]).to_dict()
        assert "toolchain" not in out
