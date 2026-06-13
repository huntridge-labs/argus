"""UI-free config editing for the Argus Console's Config screen (Phase 2).

Textual-free (imports only yaml + the config/schema layer) so it's
unit-testable in CI without the ``[terminal]`` extra. The Console's
``ConfigScreen`` renders the rows this module produces and previews the
diff before writing.

Editing is **comment-preserving**: rather than re-serialising the whole
file (which would clobber the user's comments and ordering — the open
decision in the roadmap), we make targeted in-place edits to the matched
``key: value`` line via indentation-aware path matching. The editable set
is bounded to toggle/enum settings (scanner enable + a handful of
section scalars) so every edit is a single, unambiguous line rewrite. The
result is validated by re-parsing + the existing schema checker before it
can be saved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import yaml


# Bounded enum settings (section, key) → allowed values, in cycle order.
# Mirrors the values ``argus/core/schema.py`` accepts.
_ENUMS: dict[tuple[str, str], list[str]] = {
    ("reporting", "severity_threshold"): ["none", "low", "medium", "high", "critical"],
    ("execution", "backend"): ["auto", "local", "docker"],
    ("execution", "pull_policy"): ["always", "if-not-present", "never"],
    ("view", "cve_source"): ["nvd", "cve_org", "github", "mitre"],
    ("view", "open_location"): ["ask", "local", "remote"],
}

# One-line help surfaced beside each setting (the "focused docs").
_DOCS: dict[str, str] = {
    "scanner": "Run this scanner on each scan.",
    "reporting.severity_threshold": "Fail the scan at or above this severity.",
    "execution.backend": "Run tools locally, in Docker, or auto-detect.",
    "execution.pull_policy": "When to pull scanner container images.",
    "view.cve_source": "Advisory site opened for CVE/GHSA links in the viewer.",
    "view.open_location": "Where file:line links open: ask, local editor, or git remote.",
}


@dataclass
class EditRow:
    """One editable setting in the Config screen."""

    key: str                       # stable id, e.g. "scanner:bandit" or "view.cve_source"
    label: str
    kind: str                      # "toggle" | "enum"
    value: str                     # current value, as text ("on"/"off" or the enum value)
    path: list[str] = field(default_factory=list)   # YAML key path to the value
    options: list[str] = field(default_factory=list)  # enum options (cycle order)
    doc: str = ""

    def next_value(self) -> str:
        """Return the value after this row's current one (toggle / cycle)."""
        if self.kind == "toggle":
            return "false" if self.value in ("on", "true", "True") else "true"
        opts = self.options or [self.value]
        try:
            idx = opts.index(self.value)
        except ValueError:
            return opts[0]
        return opts[(idx + 1) % len(opts)]


def editable_rows(text: str) -> list[EditRow]:
    """Parse ``text`` (an argus.yml) into the editable rows.

    Only settings actually present in the file are offered, so every row
    maps to a real line we can rewrite. Returns ``[]`` for unparsable
    input.
    """
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return []
    if not isinstance(data, dict):
        return []

    rows: list[EditRow] = []
    scanners = data.get("scanners")
    if isinstance(scanners, dict):
        for name in scanners:
            block = scanners[name]
            if not isinstance(block, dict) or "enabled" not in block:
                continue
            on = bool(block.get("enabled"))
            rows.append(EditRow(
                key=f"scanner:{name}", label=f"scanner · {name}", kind="toggle",
                value="on" if on else "off", path=["scanners", name, "enabled"],
                doc=_DOCS["scanner"],
            ))

    for (section, key), options in _ENUMS.items():
        block = data.get(section)
        if isinstance(block, dict) and key in block and block[key] is not None:
            rows.append(EditRow(
                key=f"{section}.{key}", label=f"{section} · {key}", kind="enum",
                value=str(block[key]), path=[section, key], options=options,
                doc=_DOCS.get(f"{section}.{key}", ""),
            ))
    return rows


def set_value(text: str, path: list[str], value: str) -> str | None:
    """Set the YAML scalar at ``path`` to ``value``, preserving formatting.

    Walks the file indentation-aware to find the exact ``key: value`` line
    at ``path`` and rewrites only its value, keeping the key, indentation,
    and any trailing inline comment. Returns ``None`` when the path isn't
    found as a simple scalar line (so callers don't write a no-op).

    Assumes the conventional 2-space indentation argus.yml uses; bounded to
    the editable settings, which are always plain scalars.
    """
    lines = text.splitlines(keepends=True)
    # Track, per line, the key path implied by indentation.
    stack: list[tuple[int, str]] = []  # (indent, key)
    for i, raw in enumerate(lines):
        stripped = raw.lstrip(" ")
        if not stripped.strip() or stripped.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(stripped)
        m = re.match(r"([A-Za-z0-9_.\-]+)\s*:(.*)$", stripped)
        if not m:
            continue
        key = m.group(1)
        # Pop deeper/sibling entries off the stack.
        while stack and stack[-1][0] >= indent:
            stack.pop()
        stack.append((indent, key))
        current_path = [k for _ind, k in stack]
        if current_path == path:
            after = m.group(2)
            comment = ""
            cm = re.search(r"(\s+#.*)$", after)
            if cm:
                comment = cm.group(1)
            newline = f"{' ' * indent}{key}: {value}{comment}"
            newline += "\n" if raw.endswith("\n") else ""
            if newline == raw:
                return None
            lines[i] = newline
            return "".join(lines)
    return None


def apply_row(text: str, row: EditRow) -> tuple[str, str] | None:
    """Apply ``row``'s next value to ``text``.

    Returns ``(new_text, new_value)`` or ``None`` if the edit was a no-op /
    the path vanished. The YAML scalar written is the literal next value
    (``true``/``false`` for toggles, the enum string otherwise).
    """
    new_value = row.next_value()
    new_text = set_value(text, row.path, new_value)
    if new_text is None:
        return None
    return new_text, new_value


def validate(text: str) -> str | None:
    """Return an error message if ``text`` isn't a valid argus.yml, else None.

    Parses the YAML and runs the existing schema checker so the Config
    screen can refuse to save a broken edit. Best-effort: if the schema
    module isn't importable for some reason, YAML-parse validity is the
    floor.
    """
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return f"Invalid YAML: {exc}"
    if not isinstance(data, dict):
        return "argus.yml must be a mapping at the top level."
    try:
        from argus.core.schema import validate_config
    except Exception:
        return None
    try:
        issues = validate_config(data)
    except Exception:
        return None
    errors = [str(i) for i in issues if getattr(i, "level", "") == "error"]
    return "; ".join(errors[:3]) if errors else None
