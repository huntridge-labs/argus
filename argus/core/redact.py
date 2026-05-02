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
