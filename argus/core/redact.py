"""Secret redaction primitives.

Argus's security commitment: a secret value detected by a scanner
**never** flows past the scanner's parser. Once a ``Finding`` is
constructed, every downstream consumer (terminal reporter, JSON
report, Markdown export, SARIF export, the MCP server's tool
responses, the AI assistant's context window) sees a redacted
placeholder, never the original value.

This module is the single source of truth for *how* we redact.
Scanner parsers import :func:`redact_secret` and stash a fingerprint
plus a length hint in ``Finding.metadata`` instead of the raw
match.

Why position-only (no masked preview):

A common pattern is ``ghp_***********…12`` — first 4 chars + last 2,
mask the middle. That preserves a "is this the same secret?" signal
for humans triaging at the file:line. We deliberately do **not** do
this:

- The first 4 chars often *are* the discriminator. ``ghp_``,
  ``gho_``, ``AKIA``, ``ASIA``, ``xoxb-``, ``glpat-`` etc.
  identify the secret type — but ``rule_id`` already carries
  that, much more reliably than a substring sniff.
- A masked-prefix preview is **enough entropy** for a brute-force
  attack on a short secret. Removing 32 chars from a 40-char PAT
  isn't a meaningful defence against an attacker with the masked
  preview.
- The location tuple (``file:line:col``) is already sufficient for
  a developer to find the right line and verify they're looking
  at the right secret.

So we redact to a **value-free** placeholder. Length is preserved
as metadata for the rare case where it's diagnostically useful
(e.g., distinguishing two rules that match different-length tokens
on the same line).
"""

from __future__ import annotations

import re
from typing import Any


REDACTED_PLACEHOLDER = "<redacted>"
"""The string that replaces a redacted secret value in any user-facing
output. Stable across versions — exports / log scrapers can grep for
it as a positive signal that redaction happened (vs. a missing field
which could mean "scanner didn't emit it")."""


def redact_secret(value: str | None) -> str:
    """Return the safe placeholder for a secret value.

    No matter the input — short, long, empty, ``None`` — the output
    contains zero characters from the original. Callers that want
    the length for downstream display should keep it as a separate
    integer field; encoding length into the placeholder string would
    leak it through `len(redact_secret(secret))`.
    """
    return REDACTED_PLACEHOLDER


def redact_secret_in_message(message: str, secret: str | None) -> str:
    """Replace any occurrence of ``secret`` in ``message`` with the placeholder.

    Used for scanner descriptions/titles that interpolate the matched
    value directly (bandit's ``"Possible hardcoded password: 'mypass'"``
    is the canonical example). When ``secret`` is empty / ``None`` the
    message is returned unchanged.

    Substring replacement only — we don't try to be clever about
    surrounding quotes or escapes. A scanner that puts a secret in a
    description without also exposing the raw value somewhere is rare;
    this helper is a belt-and-suspenders second pass.
    """
    if not message or not secret:
        return message
    return message.replace(secret, REDACTED_PLACEHOLDER)


def is_redacted(value: str) -> bool:
    """True if ``value`` is the redaction placeholder.

    Useful for tests asserting we didn't accidentally let a raw
    secret leak through.
    """
    return value == REDACTED_PLACEHOLDER


# --------------------------------------------------------------------- #
# Pattern-based second pass                                             #
# --------------------------------------------------------------------- #


# High-confidence secret patterns. The bar for inclusion is a *known
# vendor prefix* with documented entropy guarantees — generic
# high-entropy heuristics are deliberately excluded because their
# false-positive rate on legitimate finding bodies (rule IDs,
# descriptions, file paths) is too high.
#
# Each pattern is (regex, name). The regexes use word/byte boundaries
# so substring-overlap into surrounding text doesn't escape the match.
# Adding a new pattern: cite the issuer's documented format spec in a
# comment and add a passing + a non-matching test in
# ``test_redact.py::TestHighRiskPatterns``.
_HIGH_RISK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # GitHub Personal Access Tokens (and the variants for OAuth, server-
    # to-server, refresh, integration). Format documented at:
    #   https://github.blog/changelog/2021-03-31-authentication-token-format-updates-are-generally-available/
    (re.compile(r"\bgh[opusr]_[A-Za-z0-9]{36,}\b"), "github_token"),
    # AWS Access Key IDs — IAM user (AKIA), STS temp (ASIA), root (AIDA).
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
    (re.compile(r"\b(?:AKIA|ASIA|AIDA|AGPA|AIPA|ANPA|ANVA|AROA|APKA|ABIA|ACCA)[0-9A-Z]{16}\b"), "aws_access_key"),
    # Slack tokens — xoxb (bot), xoxp (user), xoxa (workspace), xoxr
    # (refresh), xoxs (legacy).
    # https://api.slack.com/authentication/token-types
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "slack_token"),
    # GitLab Personal Access Tokens.
    # https://docs.gitlab.com/ee/security/tokens/
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "gitlab_pat"),
    # npm publish tokens — fixed length, fixed prefix.
    # https://docs.npmjs.com/about-access-tokens
    (re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "npm_token"),
    # Google API keys — fixed prefix + fixed-length suffix.
    # https://cloud.google.com/docs/authentication/api-keys
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "google_api_key"),
    # Stripe live secret keys — distinctly NOT pattern-matching
    # ``sk_test_`` (test keys aren't sensitive in the same way).
    # https://docs.stripe.com/keys
    (re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b"), "stripe_live_key"),
    # JWTs — base64url(header).base64url(payload).base64url(signature).
    # The ``eyJ`` prefix is the base64-encoded ``{"`` opening of the
    # JSON header, which is invariant for any standard JWT.
    # We require non-empty parts on each segment to avoid matching
    # benign three-dot strings.
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "jwt"),
    # PEM private key headers. The body of the key may span multiple
    # lines; the header line alone is enough to redact in scanner
    # finding text (where keys are usually one-liners or pre-flattened).
    (re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"), "pem_private_key"),
]


def redact_high_risk_patterns(text: str | None) -> str | None:
    """Replace every known high-confidence secret pattern in *text*.

    Backstop pass for findings whose scanner forgot (or didn't know)
    to call :func:`redact_secret_in_message`. Inputs:
    ``None`` → ``None``; empty string → empty; matching text →
    placeholder substituted in place of each match.

    Patterns are conservative on purpose. Finding bodies often quote
    rule IDs, file paths, and configuration snippets that look like
    high-entropy strings; matching only documented-vendor-prefix
    formats keeps the false-positive rate near zero. The cost is that
    secrets without a recognizable prefix (raw passwords, custom
    tokens) still rely on the per-scanner first-pass redaction.

    Reference: ``argus/scanners/<name>.py`` parsers should still call
    :func:`redact_secret`/:func:`redact_secret_in_message` first;
    this is defence-in-depth, not a replacement.
    """
    if not text:
        return text
    out = text
    for pattern, _name in _HIGH_RISK_PATTERNS:
        out = pattern.sub(REDACTED_PLACEHOLDER, out)
    return out


def _redact_value(value: Any) -> Any:
    """Recursively redact strings inside arbitrary structures.

    Walks dicts and lists; redacts only ``str`` leaves. Other types
    (int, float, bool, None, custom objects) are returned unchanged
    — they can't carry a secret-pattern match.
    """
    if isinstance(value, str):
        return redact_high_risk_patterns(value)
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(v) for v in value)
    return value


def redact_finding_text(
    title: str,
    description: str,
    metadata: dict | None,
) -> tuple[str, str, dict]:
    """Apply the second-pass to the text-bearing fields of a Finding.

    Returns ``(title, description, metadata)`` with every known
    high-risk pattern replaced by :data:`REDACTED_PLACEHOLDER`.
    Designed for ``Finding.__post_init__`` to call once per
    construction so the redaction happens at the boundary, not at
    every reporter / MCP / export call site.

    Defensive copies the metadata dict so the caller's dict isn't
    mutated. Other fields on ``Finding`` (``id``, ``severity``,
    ``location``, ``cwe``, ``cve``, ``scanner``) are structural and
    don't carry free-form text — they aren't passed through here.
    """
    new_title = redact_high_risk_patterns(title) or ""
    new_desc = redact_high_risk_patterns(description) or ""
    new_meta = _redact_value(metadata or {})
    if not isinstance(new_meta, dict):
        # _redact_value preserves type; metadata should always be dict
        # but if a caller passed something unusual, normalize.
        new_meta = {}
    return new_title, new_desc, new_meta
