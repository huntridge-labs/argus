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
