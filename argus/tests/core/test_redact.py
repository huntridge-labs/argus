"""Unit tests for argus.core.redact — the secret-redaction primitives.

The functions are intentionally small. The tests are small to match.
What we're really guarding against is a future contributor "improving"
the placeholder by encoding the original length or a prefix into it,
which would re-leak signal we're trying to scrub.
"""

from __future__ import annotations

from argus.core.redact import (
    REDACTED_PLACEHOLDER,
    is_redacted,
    redact_secret,
    redact_secret_in_message,
)


class TestRedactSecret:
    def test_returns_constant_placeholder_for_any_input(self):
        # Length, character set, prefix — none of it should leak
        # through. The placeholder is the same for every input.
        for value in (
            "ghp_1234567890abcdefghijklmnopqrstuvwxyz12",  # 40-char PAT
            "AKIAIOSFODNN7EXAMPLE",                          # 20-char AWS key
            "x",                                             # tiny
            "",                                              # empty
            None,                                            # missing
        ):
            assert redact_secret(value) == REDACTED_PLACEHOLDER

    def test_placeholder_does_not_encode_length(self):
        # If the placeholder grew with the secret, len(redact_secret(x))
        # would leak the original size. Assert the inverse — the
        # placeholder string is fixed-width regardless of input.
        short = redact_secret("a")
        long = redact_secret("a" * 1000)
        assert len(short) == len(long)


class TestRedactSecretInMessage:
    def test_replaces_each_occurrence_with_placeholder(self):
        # Bandit's "Possible hardcoded password: 'pw'" is the
        # canonical case — the secret appears verbatim in a
        # human-readable description string.
        msg = "Possible hardcoded password: 'hunter2'"
        assert (
            redact_secret_in_message(msg, "hunter2")
            == f"Possible hardcoded password: '{REDACTED_PLACEHOLDER}'"
        )

    def test_replaces_multiple_occurrences(self):
        msg = "secret=abc123; backup=abc123"
        out = redact_secret_in_message(msg, "abc123")
        assert "abc123" not in out
        assert out.count(REDACTED_PLACEHOLDER) == 2

    def test_empty_secret_returns_message_unchanged(self):
        # No secret to scrub for — pass through.
        assert redact_secret_in_message("nothing here", "") == "nothing here"
        assert redact_secret_in_message("nothing here", None) == "nothing here"

    def test_empty_message_returns_empty(self):
        assert redact_secret_in_message("", "secret") == ""

    def test_message_without_secret_unchanged(self):
        # Substring not present — message unchanged. No false-positive
        # masking; this helper only redacts what we know is leakable.
        assert redact_secret_in_message("hello world", "secret") == "hello world"


class TestIsRedacted:
    def test_recognizes_placeholder(self):
        assert is_redacted(REDACTED_PLACEHOLDER) is True

    def test_rejects_anything_else(self):
        assert is_redacted("") is False
        assert is_redacted("redacted") is False
        assert is_redacted("ghp_1234") is False
        assert is_redacted("[redacted]") is False
