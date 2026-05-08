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
    redact_finding_text,
    redact_high_risk_patterns,
    redact_secret,
    redact_secret_in_message,
)


class TestRedactSecret:
    def test_returns_constant_placeholder_for_any_input(self):
        # Length, character set, prefix — none of it should leak
        # through. The placeholder is the same for every input.
        for value in (
            "ghp_000000000000000000000000000000000000",  # 40-char PAT
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
        assert is_redacted("ghp_0000") is False
        assert is_redacted("[redacted]") is False


# --------------------------------------------------------------------- #
# Pattern-based second pass                                             #
# --------------------------------------------------------------------- #


class TestHighRiskPatterns:
    """Each known-vendor-prefix pattern matches its documented format
    and gets replaced with the redaction placeholder."""

    def test_github_pat_redacted(self):
        # ghp_ + 36 chars (the v2 GitHub PAT format).
        out = redact_high_risk_patterns(
            "leaked: ghp_000000000000000000000000000000000000 here",
        )
        assert "ghp_0000000000" not in out
        assert REDACTED_PLACEHOLDER in out

    def test_github_oauth_token_redacted(self):
        out = redact_high_risk_patterns(
            "gho_000000000000000000000000000000000000",
        )
        assert REDACTED_PLACEHOLDER in out

    def test_github_short_prefix_unchanged(self):
        # ghp_ followed by < 36 chars isn't a real GitHub token.
        out = redact_high_risk_patterns("ghp_short")
        assert out == "ghp_short"

    def test_aws_access_key_id_redacted(self):
        # AKIA + 16 alphanumeric upper.
        out = redact_high_risk_patterns(
            "user has AKIAIOSFODNN7EXAMPLE in env",
        )
        assert "AKIAIOSFODNN7EXAMPLE" not in out
        assert REDACTED_PLACEHOLDER in out

    def test_aws_sts_temp_credential_redacted(self):
        out = redact_high_risk_patterns("ASIAY34FZKBOKMUTVV7A")
        assert REDACTED_PLACEHOLDER in out

    def test_slack_bot_token_redacted(self):
        # All-zero body — convention for "obviously test data" that
        # most secret scanners (including GitHub's push-protection
        # detector) treat as a non-secret. No canonical Slack-docs
        # fixture exists.
        out = redact_high_risk_patterns(
            "Slack: xoxb-0000000000-0000000000-AAAAAAAAAAAA",
        )
        assert "xoxb-0" not in out
        assert REDACTED_PLACEHOLDER in out

    def test_gitlab_pat_redacted(self):
        out = redact_high_risk_patterns(
            "Found glpat-AbCdEfGhIjKlMnOpQrSt in config",
        )
        assert "glpat-AbCdEfGhIjKlMnOpQrSt" not in out

    def test_npm_token_redacted(self):
        # Fixed 36-char suffix.
        out = redact_high_risk_patterns(
            "npm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        assert REDACTED_PLACEHOLDER in out

    def test_google_api_key_redacted(self):
        # AIza + 35 chars (39 total). Exact length is part of the
        # documented format spec — the regex will not match shorter
        # or longer suffixes.
        suffix = "a" * 35
        out = redact_high_risk_patterns(f"key=AIza{suffix} found")
        assert f"AIza{suffix}" not in out
        assert REDACTED_PLACEHOLDER in out

    def test_stripe_live_key_redacted(self):
        # Build at runtime — even all-zero bodies trip GitHub's
        # Stripe-key push-protection scanner (pattern-only, no value
        # whitelist). Runtime concat keeps the test deterministic
        # without putting a literal token shape on disk.
        sample = "sk" + "_live_" + ("0" * 24)
        out = redact_high_risk_patterns(f"Stripe key {sample} detected")
        assert sample not in out
        assert REDACTED_PLACEHOLDER in out

    def test_stripe_test_key_NOT_redacted(self):
        # Test keys aren't sensitive in the same way; we deliberately
        # only match _live_ to avoid false positives on test data.
        # Runtime concat for the same push-protection reason as above.
        sample = "sk" + "_test_" + ("0" * 24)
        out = redact_high_risk_patterns(f"Stripe test {sample} here")
        assert "sk" + "_test_" in out

    def test_jwt_redacted(self):
        # Three-part base64url with eyJ prefix on first two parts.
        jwt = (
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        out = redact_high_risk_patterns(f"Bearer {jwt}")
        assert "eyJzdWIiOiIxMjM0NTY3ODkwIn0" not in out
        assert REDACTED_PLACEHOLDER in out

    def test_pem_private_key_header_redacted(self):
        out = redact_high_risk_patterns(
            "config has -----BEGIN RSA PRIVATE KEY----- in it",
        )
        assert "BEGIN RSA PRIVATE KEY" not in out

    def test_pem_ec_private_key_redacted(self):
        out = redact_high_risk_patterns("-----BEGIN EC PRIVATE KEY-----")
        assert REDACTED_PLACEHOLDER in out

    def test_clean_text_unchanged(self):
        # No false positives on benign content the scanners actually emit.
        for clean in [
            "Possible hardcoded password",
            "B102: rule violation found",
            "/path/to/some/file.py:42",
            "function name with 36 char identifier_aaaaaaaaaaaaaaaa",
            "package@1.2.3 has CVE-2024-12345",
            "rule_id: CWE-798",
            "github.com/owner/repo",
            "scan_path: '.'",
            "",
        ]:
            assert redact_high_risk_patterns(clean) == clean

    def test_none_returns_none(self):
        assert redact_high_risk_patterns(None) is None

    def test_multiple_secrets_in_one_string_all_redacted(self):
        # Defence-in-depth — finding a redacted GitHub token shouldn't
        # stop the pass from continuing through the rest of the text.
        # Test fixtures use the all-zero body convention (GitHub PAT,
        # Slack) and AWS's documented EXAMPLE fixture so the source
        # doesn't carry tokens that trip GitHub's secret-scanning
        # push protection.
        text = (
            "github=ghp_000000000000000000000000000000000000 "
            "aws=AKIAIOSFODNN7EXAMPLE "
            "slack=xoxb-EXAMPLE-EXAMPLE-EXAMPLE"
        )
        out = redact_high_risk_patterns(text)
        assert "ghp_0000" not in out
        assert "AKIAIOSF" not in out
        assert "xoxb-0" not in out
        # Three independent matches → three placeholders.
        assert out.count(REDACTED_PLACEHOLDER) == 3


class TestRedactFindingText:

    def test_clean_finding_unchanged(self):
        title, desc, meta = redact_finding_text(
            "Possible hardcoded password",
            "Found at /etc/config.yaml:42",
            {"rule": "B105", "line": 42},
        )
        assert title == "Possible hardcoded password"
        assert desc == "Found at /etc/config.yaml:42"
        assert meta == {"rule": "B105", "line": 42}

    def test_secret_in_title_redacted(self):
        title, _, _ = redact_finding_text(
            "Hardcoded GitHub PAT: ghp_000000000000000000000000000000000000",
            "",
            None,
        )
        assert "ghp_0000" not in title
        assert REDACTED_PLACEHOLDER in title

    def test_secret_in_description_redacted(self):
        _, desc, _ = redact_finding_text(
            "Some title",
            "Detected: AKIAIOSFODNN7EXAMPLE in env file",
            None,
        )
        assert "AKIAIOSFODNN7EXAMPLE" not in desc

    def test_secret_in_metadata_string_value_redacted(self):
        _, _, meta = redact_finding_text(
            "t", "d",
            {"raw_match": "ghp_000000000000000000000000000000000000"},
        )
        assert "ghp_0000" not in meta["raw_match"]

    def test_secret_in_nested_metadata_redacted(self):
        _, _, meta = redact_finding_text(
            "t", "d",
            {"context": {"deep": {"key": "AKIAIOSFODNN7EXAMPLE"}}},
        )
        assert "AKIA" not in meta["context"]["deep"]["key"]

    def test_secret_in_metadata_list_redacted(self):
        _, _, meta = redact_finding_text(
            "t", "d",
            {"matches": ["clean", "AKIAIOSFODNN7EXAMPLE"]},
        )
        assert meta["matches"][0] == "clean"
        assert "AKIA" not in meta["matches"][1]

    def test_metadata_non_string_values_preserved(self):
        # Numbers, booleans, None passed through unchanged.
        _, _, meta = redact_finding_text(
            "t", "d",
            {"line": 42, "is_test": True, "ratio": 1.5, "absent": None},
        )
        assert meta == {"line": 42, "is_test": True, "ratio": 1.5, "absent": None}

    def test_metadata_none_normalized_to_empty_dict(self):
        _, _, meta = redact_finding_text("t", "d", None)
        assert meta == {}

    def test_caller_metadata_dict_not_mutated(self):
        original = {"raw": "ghp_000000000000000000000000000000000000"}
        _, _, redacted = redact_finding_text("t", "d", original)
        assert original["raw"] == "ghp_000000000000000000000000000000000000"
        assert "ghp_0000" not in redacted["raw"]


class TestFindingAutoRedaction:
    """The constructor should run the second pass so a scanner that
    forgot to redact still doesn't leak secrets downstream."""

    def test_secret_in_title_redacted_at_construction(self):
        from argus.core.models import Finding, Severity
        f = Finding(
            id="X",
            severity=Severity.HIGH,
            title="Found ghp_000000000000000000000000000000000000 in code",
            description="",
        )
        assert "ghp_0000" not in f.title

    def test_secret_in_description_redacted_at_construction(self):
        from argus.core.models import Finding, Severity
        f = Finding(
            id="X",
            severity=Severity.HIGH,
            title="t",
            description="key=AKIAIOSFODNN7EXAMPLE",
        )
        assert "AKIA" not in f.description

    def test_secret_in_metadata_redacted_at_construction(self):
        from argus.core.models import Finding, Severity
        f = Finding(
            id="X",
            severity=Severity.HIGH,
            title="t",
            description="d",
            metadata={
                "snippet": "Authorization: Bearer ghp_000000000000000000000000000000000000",
            },
        )
        assert "ghp_0000" not in f.metadata["snippet"]

    def test_clean_finding_text_unchanged_at_construction(self):
        # Most findings have no secret patterns; they shouldn't be
        # measurably affected by the pass.
        from argus.core.models import Finding, Severity
        f = Finding(
            id="B102",
            severity=Severity.MEDIUM,
            title="Hardcoded password",
            description="user input is dangerous",
            location="src/app.py:42",
            metadata={"line": 42, "rule": "B102"},
        )
        assert f.title == "Hardcoded password"
        assert f.description == "user input is dangerous"
        assert f.metadata == {"line": 42, "rule": "B102"}

    def test_to_dict_output_carries_redaction_through(self):
        # Reporters and the MCP server consume Finding.to_dict() — the
        # serialization must preserve the post_init redaction.
        from argus.core.models import Finding, Severity
        f = Finding(
            id="X", severity=Severity.HIGH,
            title="ghp_000000000000000000000000000000000000",
            description="",
        )
        d = f.to_dict()
        assert "ghp_0000" not in d["title"]
