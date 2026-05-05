"""Tests for argus.reporters registry helpers — ``ensure_canonical_json``.

The helper guarantees ``argus-results.json`` is always emitted by the
source-scan flow, regardless of how the user configures
``reporting.formats``. That decouples the canonical scan artifact (the
audit manifest, both viewers, and ``argus report`` all consume it) from
user choice of additional human-readable reports.
"""

from __future__ import annotations

from argus.reporters import CANONICAL_FORMAT, ensure_canonical_json


class TestEnsureCanonicalJson:
    def test_appends_json_when_absent(self):
        assert ensure_canonical_json(["terminal"]) == ["terminal", "json"]

    def test_idempotent_when_json_already_present(self):
        # User explicitly listed json — don't double-write the file.
        assert ensure_canonical_json(["json"]) == ["json"]

    def test_preserves_user_order_when_json_already_present(self):
        # The user's preferred ordering of human reports stays intact.
        assert ensure_canonical_json(["json", "terminal", "sarif"]) == [
            "json", "terminal", "sarif",
        ]

    def test_appends_json_to_multi_format_list(self):
        # Common production case: user wants terminal + SARIF + audit JSON.
        assert ensure_canonical_json(["terminal", "sarif"]) == [
            "terminal", "sarif", "json",
        ]

    def test_handles_empty_input(self):
        # Edge case: a config with ``formats: []`` still produces the
        # canonical artifact. Without this, the viewers would silently
        # fail downstream.
        assert ensure_canonical_json([]) == ["json"]

    def test_does_not_mutate_input(self):
        # Defensive: the helper must not mutate the caller's list, since
        # the same list lives on the user's ArgusConfig.
        formats = ["terminal"]
        ensure_canonical_json(formats)
        assert formats == ["terminal"]

    def test_canonical_format_constant_is_json(self):
        # Sanity-check the constant name. If we ever rename the
        # canonical artifact, every consumer downstream needs to know.
        assert CANONICAL_FORMAT == "json"
