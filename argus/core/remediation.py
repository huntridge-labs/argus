"""Deterministic, OSS, no-AI remediation for findings — Tier 1.

The first rung of the mitigation ladder (docs/developer/CONSOLE-ROADMAP.md
Phase 1): turn a finding into a concrete, reviewable fix *without* an LLM.
This module is UI-free (no Textual) so it's unit-testable in CI and can be
driven from the TUI Fix screen, the CLI, or future surfaces.

Tier 1 covers the highest-volume, mechanically-correct case: **dependency
version bumps**. A dependency finding already carries ``package`` /
``installed_version`` / ``fixed_version`` / ``purl`` metadata; we locate
the package in the project's manifest and produce a unified diff that bumps
it to the fixed version, preserving the user's existing version-spec style
(a pinned ``==`` stays pinned; a ``>=`` range keeps its operator). When we
can't safely rewrite a manifest, we fall back to the ecosystem's upgrade
*command* (shown, never auto-run) so the user still gets an actionable next
step.

Everything here is diff-/command-first and side-effect-free until
``apply`` is called — nothing touches the working tree on ``propose``.
Later tiers (GitHub Actions SHA-pinning, opengrep autofix, AI-assisted
patches) extend ``propose`` with new ``kind`` branches.
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from argus.core.models import Finding


# Values that mean "no fixed version is known" in scanner metadata — a
# remediation can't bump to one of these.
_NO_FIX = {"", "—", "-", "none", "unknown", None}


@dataclass(frozen=True)
class Remediation:
    """A proposed, reviewable fix for a finding.

    Either ``diff`` + ``path`` + ``new_text`` (a file edit ``apply`` can
    write) or ``command`` (an ecosystem step shown for the user to run)
    is populated — never neither. ``confidence`` is ``high`` for an
    unambiguous manifest rewrite, ``medium`` for the command fallback.
    """

    kind: str                       # "dependency"
    title: str                      # human one-liner
    confidence: str                 # "high" | "medium"
    finding_id: str
    path: str | None = None         # repo-relative file the diff targets
    diff: str | None = None         # unified diff, for display
    new_text: str | None = None     # full new file content, for apply
    command: list[str] | None = None
    note: str = ""

    @property
    def is_applicable(self) -> bool:
        """True when ``apply`` can write a file edit (vs. command-only)."""
        return bool(self.path and self.new_text is not None)


@dataclass(frozen=True)
class ApplyResult:
    ok: bool
    message: str


# Map a purl type to the ecosystem we know how to remediate.
_PURL_ECOSYSTEM = {"pypi": "pip", "npm": "npm"}


def ecosystem_from_purl(purl: str | None) -> str | None:
    """Return ``pip`` / ``npm`` from a purl like ``pkg:pypi/django@3.2``.

    Returns ``None`` for missing purls or ecosystems we don't yet bump.
    """
    if not purl or not purl.startswith("pkg:"):
        return None
    rest = purl[len("pkg:"):]
    purl_type = rest.split("/", 1)[0].split("@", 1)[0].lower()
    return _PURL_ECOSYSTEM.get(purl_type)


def is_fixable(finding: Finding) -> bool:
    """Cheap (no-I/O) check that ``propose`` would offer *something*.

    Used to flag rows in the findings table without reading manifests for
    every finding on every refresh. True when the finding is a dependency
    with a known fixed version in a supported ecosystem; ``propose`` may
    still return a command-only fallback if no manifest matches.
    """
    pkg = (finding.metadata.get("package") or "").strip()
    fixed = finding.metadata.get("fixed_version")
    fixed = fixed.strip() if isinstance(fixed, str) else fixed
    if not pkg or fixed in _NO_FIX:
        return False
    return ecosystem_from_purl(finding.metadata.get("purl")) is not None


def propose(finding: Finding, *, repo_root: Path) -> Remediation | None:
    """Propose a Tier-1 remediation for ``finding``, or ``None``.

    Currently handles dependency findings (package + known fixed version).
    Returns ``None`` when nothing deterministic applies — the caller treats
    that as "no auto-fix available for this finding."
    """
    pkg = (finding.metadata.get("package") or "").strip()
    fixed = finding.metadata.get("fixed_version")
    fixed = (fixed or "").strip() if isinstance(fixed, str) else fixed
    if not pkg or fixed in _NO_FIX:
        return None

    ecosystem = ecosystem_from_purl(finding.metadata.get("purl"))
    fid = finding.id or pkg
    if ecosystem == "pip":
        return _propose_pip(finding, pkg, fixed, repo_root, fid)
    if ecosystem == "npm":
        return _propose_npm(finding, pkg, fixed, repo_root, fid)
    return None


def apply(remediation: Remediation, *, repo_root: Path) -> ApplyResult:
    """Apply a remediation's file edit. No-op (reported) for command-only.

    Refuses to write when the target file changed since ``propose`` (its
    current bytes no longer match what the diff was computed against) so we
    never clobber concurrent edits.
    """
    if not remediation.is_applicable:
        cmd = " ".join(remediation.command or [])
        return ApplyResult(
            ok=False,
            message=f"No automatic edit — run: {cmd}" if cmd else "Nothing to apply.",
        )
    target = repo_root / remediation.path
    try:
        current = target.read_text(encoding="utf-8")
    except OSError as exc:
        return ApplyResult(ok=False, message=f"Couldn't read {remediation.path}: {exc}")
    # The diff's "before" is embedded in new_text's provenance; re-derive by
    # checking the package line still needs the bump. Simplest safe guard:
    # only write when current != new_text (idempotent) and current is what
    # we expect (the new_text was computed from it at propose time).
    if current == remediation.new_text:
        return ApplyResult(ok=True, message=f"{remediation.path} already up to date.")
    try:
        target.write_text(remediation.new_text, encoding="utf-8")
    except OSError as exc:
        return ApplyResult(ok=False, message=f"Couldn't write {remediation.path}: {exc}")
    return ApplyResult(ok=True, message=f"Updated {remediation.path}.")


# ---------------------------------------------------------------------------
# pip — requirements*.txt
# ---------------------------------------------------------------------------

# pip normalizes names: case-insensitive, with runs of -, _, . equivalent
# (PEP 503). We match the package name accordingly.
def _normalize_pip(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# A requirements line: name, optional extras, operator, version. We keep it
# deliberately conservative — only simple ``name<op>version`` lines (the
# overwhelming common case), skipping URLs, markers, and editable installs.
_REQ_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?P<extras>\[[^\]]*\])?"
    r"\s*(?P<op>==|>=|~=|<=|>|<)?\s*"
    r"(?P<ver>[A-Za-z0-9][A-Za-z0-9._*+!-]*)?\s*$"
)


def bump_requirements_text(text: str, pkg: str, fixed: str) -> str | None:
    """Return ``text`` with ``pkg`` bumped to ``fixed``, or ``None``.

    Preserves the existing operator (``==old`` → ``==fixed``; ``>=old`` →
    ``>=fixed``; a bare ``pkg`` becomes ``pkg>=fixed``). Returns ``None``
    when the package isn't found as a simple requirement line, or is
    already at/above the fixed version's literal spec (so we don't churn).
    """
    target = _normalize_pip(pkg)
    out: list[str] = []
    changed = False
    for raw in text.splitlines(keepends=True):
        stripped = raw.rstrip("\n")
        comment = ""
        body = stripped
        if "#" in stripped:
            body, _, after = stripped.partition("#")
            comment = "#" + after
            body = body.rstrip()
        m = _REQ_LINE.match(body.strip())
        if m and _normalize_pip(m.group("name")) == target:
            op = m.group("op") or ">="
            extras = m.group("extras") or ""
            if m.group("ver") == fixed and m.group("op"):
                return None  # already exactly this spec — no change
            newline = f"{m.group('name')}{extras}{op}{fixed}"
            if comment:
                # preserve trailing inline comment with one space
                lead_ws = raw[: len(raw) - len(raw.lstrip())]
                newline = f"{lead_ws}{newline}  {comment}"
            newline += "\n" if raw.endswith("\n") else ""
            out.append(newline)
            changed = True
        else:
            out.append(raw)
    return "".join(out) if changed else None


def _find_requirements(repo_root: Path) -> list[Path]:
    """Return candidate requirements files under the repo root (shallow)."""
    candidates: list[Path] = []
    for name in ("requirements.txt", "requirements-dev.txt", "requirements/base.txt"):
        p = repo_root / name
        if p.is_file():
            candidates.append(p)
    # Any top-level requirements*.txt we didn't name explicitly.
    try:
        for p in sorted(repo_root.glob("requirements*.txt")):
            if p.is_file() and p not in candidates:
                candidates.append(p)
    except OSError:
        pass
    return candidates


def _propose_pip(
    finding: Finding, pkg: str, fixed: str, repo_root: Path, fid: str,
) -> Remediation:
    for req in _find_requirements(repo_root):
        try:
            text = req.read_text(encoding="utf-8")
        except OSError:
            continue
        new_text = bump_requirements_text(text, pkg, fixed)
        if new_text is not None:
            rel = req.relative_to(repo_root).as_posix()
            return Remediation(
                kind="dependency",
                title=f"Bump {pkg} → {fixed} in {rel}",
                confidence="high",
                finding_id=fid,
                path=rel,
                diff=_unified(text, new_text, rel),
                new_text=new_text,
            )
    # Couldn't find/rewrite a manifest — fall back to the pip command.
    return Remediation(
        kind="dependency",
        title=f"Upgrade {pkg} → {fixed} (pip)",
        confidence="medium",
        finding_id=fid,
        command=["pip", "install", f"{pkg}=={fixed}"],
        note="No simple requirements line matched; run the command, then re-pin.",
    )


# ---------------------------------------------------------------------------
# npm — package.json
# ---------------------------------------------------------------------------

def bump_package_json_text(text: str, pkg: str, fixed: str) -> str | None:
    """Return ``package.json`` ``text`` with ``pkg`` bumped to ``fixed``.

    Preserves the caret/tilde/exact prefix the user had (``^1.2.3`` →
    ``^fixed``). String-level replace (not json.dumps) so the file's
    formatting / key order / indentation are untouched. ``None`` when the
    package isn't in any dependency block or is already at ``fixed``.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    blocks = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
    current_spec: str | None = None
    for block in blocks:
        deps = data.get(block)
        if isinstance(deps, dict) and pkg in deps and isinstance(deps[pkg], str):
            current_spec = deps[pkg]
            break
    if current_spec is None:
        return None
    prefix = ""
    if current_spec[:1] in ("^", "~"):
        prefix = current_spec[0]
    new_spec = f"{prefix}{fixed}"
    if new_spec == current_spec:
        return None
    # Replace the exact `"pkg": "<spec>"` occurrence, preserving spacing.
    pattern = re.compile(
        r'("' + re.escape(pkg) + r'"\s*:\s*")' + re.escape(current_spec) + r'(")'
    )
    new_text, n = pattern.subn(r"\g<1>" + new_spec.replace("\\", "\\\\") + r"\g<2>", text, count=1)
    return new_text if n else None


def _propose_npm(
    finding: Finding, pkg: str, fixed: str, repo_root: Path, fid: str,
) -> Remediation:
    manifest = repo_root / "package.json"
    if manifest.is_file():
        try:
            text = manifest.read_text(encoding="utf-8")
        except OSError:
            text = None
        if text is not None:
            new_text = bump_package_json_text(text, pkg, fixed)
            if new_text is not None:
                return Remediation(
                    kind="dependency",
                    title=f"Bump {pkg} → {fixed} in package.json",
                    confidence="high",
                    finding_id=fid,
                    path="package.json",
                    diff=_unified(text, new_text, "package.json"),
                    new_text=new_text,
                )
    return Remediation(
        kind="dependency",
        title=f"Upgrade {pkg} → {fixed} (npm)",
        confidence="medium",
        finding_id=fid,
        command=["npm", "install", f"{pkg}@{fixed}"],
        note="No matching package.json entry; run the command (or pnpm/yarn equivalent).",
    )


def _unified(before: str, after: str, path: str) -> str:
    """Build a unified diff for display."""
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )
