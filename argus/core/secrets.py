"""Resolve credential config values without embedding literals in argus.yml.

Argus configs are commonly checked into VCS. A literal
``registry_password: hunter2`` in that file is a baseline security
violation. This module provides a single resolver that supports two
field shapes for any credential field on any scanner:

    <field>_env: ENV_VAR_NAME       # preferred — name of an env var
    <field>: "literal-value"        # accepted but warned at config-load

Scanners (or any other config consumer) call
``resolve_secret(config, "registry_password")`` and get back the
plaintext string, or ``None`` if the credential is not configured
by any path. A CLI flag like ``--registry-password-stdin`` can
inject a value at the highest precedence via ``stdin_override``.

Deliberate non-goals:

  * ``${VAR}`` interpolation in arbitrary string fields. That is a
    separate feature on regular non-secret config keys; see ADR-024.
  * External secret backends (Vault, 1Password). The next likely
    extension is ``<field>_file: ./path/to/token``, which slots in
    without API change; backends would mirror the reporter
    plugin-entry-point pattern (ADR-023).

Stdlib-only. No external dependencies.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Mapping

logger = logging.getLogger("argus")

# Vendor-prefix patterns we recognize as "this looks like a literal
# secret." Subset of the patterns ``argus.core.redact`` uses; kept here
# as a leaf-level concern so config-load doesn't pull in the redact
# module. The point isn't to catch *every* literal secret — that's
# gitleaks's domain — but to flag the egregious case where a vendor-
# prefixed token gets pasted directly into argus.yml.
_LITERAL_LOOKS_LIKE_SECRET = re.compile(
    r"^("
    r"gh[opusr]_"            # GitHub PATs / OAuth / refresh tokens
    r"|AKIA|ASIA|AIDA"        # AWS access keys
    r"|xox[abprs]-"           # Slack tokens
    r"|glpat-"                # GitLab personal access tokens
    r"|sk_live_|rk_live_"     # Stripe live keys (test keys deliberately not matched)
    r"|AIza"                  # Google API keys
    r"|npm_"                  # npm publish tokens
    r")"
)

# POSIX shell identifier: leading letter or underscore, followed by
# letters, digits, or underscores. Shells accept any case; we follow.
_ENV_NAME_VALID = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def resolve_secret(
    config: Mapping[str, object],
    field: str,
    *,
    env: Mapping[str, str] | None = None,
    stdin_override: str | None = None,
) -> str | None:
    """Resolve a credential field to its plaintext value.

    Precedence (highest first):
      1. ``stdin_override`` — from a ``--*-password-stdin`` CLI flag.
      2. ``config[f"{field}_env"]`` — read ``os.environ[name]``.
      3. ``config[field]`` — literal value (back-compat; warned).

    Returns ``None`` if the credential is not configured.

    WARNING is logged when:
      - both ``<field>`` and ``<field>_env`` are present (uses _env);
      - ``<field>_env`` is set but the named env var is missing;
      - ``<field>`` is a literal that matches a known vendor secret prefix.
    """
    if stdin_override is not None:
        return stdin_override

    e = env if env is not None else os.environ
    env_field = f"{field}_env"
    has_env_ref = env_field in config
    has_literal = field in config

    if has_env_ref:
        if has_literal:
            logger.warning(
                "Both '%s' and '%s' set in config — using '%s' "
                "(env-var name reference takes precedence)",
                field, env_field, env_field,
            )
        name = config[env_field]
        if not isinstance(name, str):
            logger.warning(
                "'%s' must be a string env-var name, got %s — ignoring",
                env_field, type(name).__name__,
            )
            return None
        value = e.get(name)
        if value is None:
            logger.warning(
                "'%s' = %r points at an unset environment variable",
                env_field, name,
            )
        return value

    if has_literal:
        value = config[field]
        if not isinstance(value, str):
            return None
        if _LITERAL_LOOKS_LIKE_SECRET.match(value):
            logger.warning(
                "'%s' holds what looks like a literal vendor secret — "
                "prefer '%s' with an environment variable name",
                field, env_field,
            )
        return value

    return None


def validate_env_var_name(name: str) -> bool:
    """Return ``True`` if ``name`` is a valid POSIX shell identifier."""
    return isinstance(name, str) and bool(_ENV_NAME_VALID.match(name))


def looks_like_literal_secret(value: str) -> bool:
    """Return ``True`` if ``value`` matches a known vendor-secret prefix.

    Exposed for the schema validator so it can warn at config-load
    time, not at scan-time when the value would already have been
    used. Heuristic only — false positives are rare (vendor formats
    are documented and stable) but possible; false negatives are
    expected (basic-auth passwords, custom tokens have no prefix).
    """
    return isinstance(value, str) and bool(_LITERAL_LOOKS_LIKE_SECRET.match(value))
