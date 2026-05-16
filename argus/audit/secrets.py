"""Secret masking for log messages.

Strips tokens, passwords, API keys, and other sensitive values from
any string before it reaches console or file output.
"""

import re

_MASK = "<REDACTED>"

# Patterns that look like secrets in log output.
# Each pattern uses a capturing group for the non-secret prefix so the
# replacement can preserve context (e.g. "token=" stays, value is masked).
_PATTERNS: list[tuple[re.Pattern, str]] = [
    # URL with embedded credentials  https://user:TOKEN@host
    (
        re.compile(r"(https?://[^:]+:)([^@]+)(@)"),
        rf"\1{_MASK}\3",
    ),
    # token=xxx / token: xxx
    (
        re.compile(r"(token[=:]\s*)[^\s]+", re.IGNORECASE),
        rf"\1{_MASK}",
    ),
    # password=xxx / password: xxx
    (
        re.compile(r"(password[=:]\s*)[^\s]+", re.IGNORECASE),
        rf"\1{_MASK}",
    ),
    # Bearer tokens
    (
        re.compile(r"(Bearer\s+)[^\s]+", re.IGNORECASE),
        rf"\1{_MASK}",
    ),
    # GitHub personal / OAuth / app tokens
    (
        re.compile(r"(ghp_|gho_|github_pat_)\w+"),
        _MASK,
    ),
    # AWS access key IDs
    (
        re.compile(r"AKIA[A-Z0-9]{16}"),
        _MASK,
    ),
    # OpenAI / Anthropic API keys (sk-...)
    (
        re.compile(r"sk-[a-zA-Z0-9]{20,}"),
        _MASK,
    ),
]


def mask_secrets(message: str) -> str:
    """Replace anything that looks like a secret with <REDACTED>."""
    for pattern, replacement in _PATTERNS:
        message = pattern.sub(replacement, message)
    return message


def mask_secrets_in_obj(obj):
    """Recursively apply ``mask_secrets`` to every string in ``obj``.

    Walks dicts, lists, and tuples; leaves non-string scalars and
    unknown types untouched. Returns a new structure (does NOT mutate
    the input) so the original objects remain available to callers
    that haven't fully migrated to the masked view.

    The defense-in-depth use case: callers serialize structured data
    (audit manifests, JSON log entries, anything else that could end
    up on disk) through this walker before writing. Even if a future
    contributor accidentally feeds a credential into a manifest field
    or a logger.info(..., real_secret) call, the pattern set in
    ``_PATTERNS`` catches the value before it reaches the filesystem.

    Dict keys are not masked — a key that is itself a secret is an
    extreme outlier in practice and key-masking would force every
    JSON consumer to re-derive the key set. Values cover the realistic
    leak surface.
    """
    if isinstance(obj, str):
        return mask_secrets(obj)
    if isinstance(obj, dict):
        return {k: mask_secrets_in_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_secrets_in_obj(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(mask_secrets_in_obj(v) for v in obj)
    # Scalars (int, float, bool, None) and unknown types pass through
    # unchanged; the caller's json.dumps(default=str) handles encoding.
    return obj
