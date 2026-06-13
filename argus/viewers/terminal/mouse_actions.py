"""Pure helpers for the mouse-driven actions wired into ``BrowseApp``.

Separated from ``app.py`` so the URL constructors + file-open logic
are unit-testable without spinning up Textual. The Textual side calls
into these as plain functions; nothing here touches the rendering
layer.

Public surface (callers in ``app.py``):
    cve_url(cve_id, source)              -> str | None
    advisory_url_for_id(id)              -> str | None  (auto-detect by prefix)
    package_url(location)                -> str | None  (PyPI / npm best-guess)
    parse_file_line(location)            -> (Path, int) | None
    git_blob_url(repo_root, rel_path, line, ref)  -> str | None
    open_in_browser(url)                 -> bool
    open_file_local(path, line, editor)  -> bool
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import webbrowser
from pathlib import Path


logger = logging.getLogger("argus.viewers.terminal.mouse_actions")


# ---------------------------------------------------------------------------
# CVE / GHSA / vendor advisory URL construction
# ---------------------------------------------------------------------------

CVE_SOURCES = ("nvd", "cve_org", "github", "mitre")
"""Allowed values for ``view.cve_source`` in argus.yml."""

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_GHSA_PATTERN = re.compile(r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$", re.IGNORECASE)


def cve_url(cve_id: str, source: str = "nvd") -> str | None:
    """Construct an authoritative-source URL for a CVE.

    ``source`` is one of ``CVE_SOURCES`` (validated by schema at
    config-load). Unknown sources fall back to NVD. Non-CVE IDs
    (e.g. GHSA-*, internal scanner IDs) return ``None`` — caller
    should route those through ``advisory_url_for_id``.
    """
    if not cve_id or not _CVE_PATTERN.match(cve_id):
        return None
    cid = cve_id.upper()
    if source == "cve_org":
        return f"https://www.cve.org/CVERecord?id={cid}"
    if source == "github":
        return f"https://github.com/advisories?query={cid}"
    if source == "mitre":
        return f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cid}"
    # default: nvd
    return f"https://nvd.nist.gov/vuln/detail/{cid}"


def advisory_url_for_id(advisory_id: str, cve_source: str = "nvd") -> str | None:
    """Pick the right vendor URL for any advisory-shaped ID.

    Routes by prefix:
      - ``CVE-*`` -> the configured CVE source (NVD / CVE.org / etc.)
      - ``GHSA-*`` -> GitHub Advisory Database
      - anything else -> ``None`` (no canonical source we can construct)
    """
    if not advisory_id:
        return None
    if _CVE_PATTERN.match(advisory_id):
        return cve_url(advisory_id, cve_source)
    if _GHSA_PATTERN.match(advisory_id):
        return f"https://github.com/advisories/{advisory_id.upper()}"
    return None


# ---------------------------------------------------------------------------
# Package registry URL construction
# ---------------------------------------------------------------------------

def package_url(location: str | None) -> str | None:
    """Guess a registry URL for a finding's ``location`` string.

    Argus scanners write the affected package as ``name@version``
    (e.g. ``flask@3.0.0``, ``express@4.17.1``,
    ``@octokit/rest@21.0.0``). We don't know the ecosystem from the
    location alone, so this is a best-effort PyPI-first guess with
    npm-scoped routing for ``@scope/pkg@version`` shapes. Returns
    ``None`` when the location doesn't parse as ``name@version``.
    """
    if not location or "@" not in location:
        return None
    # npm scoped packages start with ``@``; partition on the LAST ``@``
    # to keep the scope intact. Everything else: split on the first ``@``.
    if location.startswith("@"):
        name, _, version = location.rpartition("@")
    else:
        name, _, version = location.partition("@")
    name = name.strip()
    if not name or not version.strip():
        return None
    if name.startswith("@") or "/" in name:
        return f"https://www.npmjs.com/package/{name}"
    return f"https://pypi.org/project/{name}/"


# ---------------------------------------------------------------------------
# file:line parsing + open helpers
# ---------------------------------------------------------------------------

# Match common scanner location shapes:
#   src/app.py:42
#   src/app.py:42:13       (file:line:column — keep line only)
#   /abs/path/file.py      (no line)
_FILE_LINE_PATTERN = re.compile(r"^(.+?)(?::(\d+))?(?::\d+)?$")


def parse_file_line(location: str | None) -> tuple[Path, int | None] | None:
    """Parse a finding ``location`` into (path, line) or return None.

    A finding without a recognizable file path (e.g. ``flask@3.0.0``
    is a package@version, not a file) returns ``None``. Caller should
    fall through to ``package_url``.
    """
    if not location:
        return None
    # Package@version isn't a file ref — route it elsewhere.
    if "@" in location and ":" not in location:
        return None
    match = _FILE_LINE_PATTERN.match(location.strip())
    if not match:
        return None
    raw_path, raw_line = match.group(1), match.group(2)
    path = Path(raw_path)
    line = int(raw_line) if raw_line else None
    return path, line


def git_blob_url(
    repo_root: Path, rel_path: Path, line: int | None, ref: str,
) -> str | None:
    """Build a GitHub / GitLab blob URL from the local git remote.

    Reads ``git -C <repo_root> remote get-url origin`` and rewrites
    the SSH / HTTPS clone URL into a blob URL anchored at ``ref``
    (commit SHA, tag, or branch). Supports github.com, gitlab.com,
    and self-hosted instances using the same path layout.

    Returns ``None`` when:
      - the repo has no ``origin`` remote
      - the remote URL doesn't match a recognized provider shape
      - ``git`` isn't on PATH (e.g. air-gapped scan host)
    """
    if not shutil.which("git"):
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "remote", "get-url", "origin"],
            capture_output=True, text=True, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("git remote lookup failed: %s", exc)
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    remote = result.stdout.strip()
    base = _normalize_remote_to_https(remote)
    if not base:
        return None
    rel = rel_path.as_posix().lstrip("/")
    anchor = f"#L{line}" if line else ""
    # GitHub and GitLab both use /<owner>/<repo>/blob/<ref>/<path>.
    return f"{base}/blob/{ref}/{rel}{anchor}"


def _normalize_remote_to_https(remote_url: str) -> str | None:
    """Turn an SSH or HTTPS git remote into a public web base URL.

    ``git@github.com:owner/repo.git``      -> ``https://github.com/owner/repo``
    ``https://github.com/owner/repo.git``  -> ``https://github.com/owner/repo``
    ``https://gitlab.example.com/g/r``     -> ``https://gitlab.example.com/g/r``
    Anything that doesn't fit those shapes returns ``None``.
    """
    url = remote_url.strip()
    # SSH form: git@host:owner/repo[.git]
    if url.startswith("git@"):
        match = re.match(r"git@([^:]+):(.+)$", url)
        if not match:
            return None
        host, path = match.group(1), match.group(2)
        path = path.removesuffix(".git").rstrip("/")
        return f"https://{host}/{path}"
    # HTTPS form
    if url.startswith("https://") or url.startswith("http://"):
        return url.removesuffix(".git").rstrip("/")
    return None


def open_in_browser(url: str) -> bool:
    """Open a URL in the user's default browser. Returns success."""
    if not url:
        return False
    try:
        return webbrowser.open(url, new=2)
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("Failed to open browser for %s: %s", url, exc)
        return False


def open_file_local(
    path: Path, line: int | None = None, editor: str | None = None,
) -> bool:
    """Open ``path`` (optionally at ``line``) in a local editor.

    Resolution order for the editor command:
      1. Explicit ``editor`` argument (from ``view.editor`` config)
      2. ``$VISUAL`` environment variable
      3. ``$EDITOR`` environment variable
      4. ``code -g`` if VS Code is on PATH
      5. ``xdg-open`` / ``open`` for the OS-default app (no line support)

    The ``code -g <file>:<line>`` form is special-cased because it's the
    common ergonomic — most other editors take ``+<line> <file>``.
    """
    if not path.exists():
        logger.warning("Cannot open: file does not exist: %s", path)
        return False

    cmd = _build_editor_cmd(path, line, editor)
    if not cmd:
        return False

    try:
        subprocess.Popen(cmd)  # noqa: S603 — editor cmd is from trusted env
        return True
    except (OSError, ValueError) as exc:
        logger.warning("Failed to launch editor %s: %s", cmd[0], exc)
        return False


def _build_editor_cmd(
    path: Path, line: int | None, editor: str | None,
) -> list[str] | None:
    """Assemble the argv for an editor invocation."""
    candidates = []
    if editor:
        candidates.append(editor)
    candidates.append(os.environ.get("VISUAL", "").strip())
    candidates.append(os.environ.get("EDITOR", "").strip())

    for candidate in candidates:
        if not candidate:
            continue
        parts = candidate.split()
        bin_name = parts[0]
        if shutil.which(bin_name) is None:
            continue
        # ``code -g <file>:<line>`` is VS Code's documented goto-line form.
        if bin_name in ("code", "code-insiders") and line:
            return [*parts, "-g", f"{path}:{line}"]
        # vim / nvim / emacs / nano: ``+<line> <file>``
        if bin_name in ("vim", "nvim", "vi", "emacs", "nano") and line:
            return [*parts, f"+{line}", str(path)]
        # Fallback: just hand the file
        return [*parts, str(path)]

    # No EDITOR set — fall through to OS opener (no line support).
    for opener in ("xdg-open", "open"):
        if shutil.which(opener):
            return [opener, str(path)]
    return None


def find_repo_root(start: Path) -> Path | None:
    """Walk up from ``start`` looking for a ``.git`` directory."""
    for parent in (start, *start.parents):
        if (parent / ".git").exists():
            return parent
    return None


# Known container / CI mount points seen in the wild. When a scan
# captures no ``scan_context`` (older results, or scans built outside
# the engine), we fall back to stripping one of these from the front
# of any absolute path the scanner emitted. Order matters: more-
# specific prefixes (the GitHub Actions checkout default) come before
# generic Docker conventions so the right strip wins on a tie.
_HEURISTIC_PREFIXES: tuple[str, ...] = (
    "/github/workspace/",
    "/workspace/",
    "/builds/",
    "/code/",
    "/repo/",
    "/src/",
    "/app/",
)

# Parametric heuristics that don't fit a fixed-string strip. The
# ``rel`` named group MUST capture the repo-relative remainder so the
# caller can resolve it against the local checkout.
_HEURISTIC_PATTERNS: tuple[re.Pattern, ...] = (
    # GitHub Actions full path:  /home/runner/work/<repo>/<repo>/<rel>
    re.compile(r"^/home/runner/work/[^/]+/[^/]+/(?P<rel>.*)$"),
)


def candidate_relative_paths(path: Path, scan_context) -> list[Path]:
    """Yield plausible repo-relative interpretations of ``path``.

    Order:
      1. The ``scan_context``-driven strip (most accurate when the
         engine recorded the scan-time cwd / repo_root).
      2. Each ``_HEURISTIC_PREFIXES`` strip that matches.
      3. Each ``_HEURISTIC_PATTERNS`` match.
      4. The original path as last-resort fallback.

    Callers pick the first candidate whose ``<local_repo_root>/<rel>``
    exists on disk. For paths that are already relative, the only
    candidate is the path itself — the function still returns a list
    so callers can iterate uniformly.

    De-duped while preserving order so the same candidate doesn't
    appear twice when scan_context and heuristics produce the same
    relative path.
    """
    if not path.is_absolute():
        return [path]
    seen: set[str] = set()
    candidates: list[Path] = []

    def _add(p: Path) -> None:
        # Dedup on string form because Path objects compare by parts;
        # this keeps the order stable across runs (which matters for
        # tests) and avoids the "two equal Paths" trap on edge cases.
        key = p.as_posix()
        if key in seen:
            return
        seen.add(key)
        candidates.append(p)

    # 1. scan_context strip
    stripped = strip_scan_prefix(path, scan_context)
    if stripped != path and not stripped.is_absolute():
        _add(stripped)

    # 2. Fixed-prefix heuristics
    str_path = path.as_posix()
    for prefix in _HEURISTIC_PREFIXES:
        if str_path.startswith(prefix):
            remainder = str_path[len(prefix):]
            if remainder:
                _add(Path(remainder))

    # 3. Pattern heuristics
    for pattern in _HEURISTIC_PATTERNS:
        match = pattern.match(str_path)
        if match:
            remainder = match.group("rel")
            if remainder:
                _add(Path(remainder))

    # 4. Original path as last resort
    _add(path)
    return candidates


def verify_remote_url(url: str, timeout: float = 2.0) -> tuple[bool, str]:
    """HEAD-check ``url`` to see if it resolves on the remote.

    Returns ``(is_good, status_message)``:
      - ``(True, "HTTP 200")`` for 2xx / 3xx
      - ``(False, "HTTP 404")`` for 4xx / 5xx
      - ``(False, "network error: ...")`` on timeout or socket failure

    Used by the TUI before opening a remote URL so a dead link
    surfaces as a notification with the URL instead of a blank
    browser tab. Network access is required; the caller is expected
    to have it (this is the user's machine, not the scan host).

    The default 2-second timeout is short enough that a flaky DNS or
    rate-limited GitHub doesn't freeze the UI — preferring "fail
    open and let the user inspect" over "block forever waiting."
    """
    if not url:
        return False, "empty URL"
    # Defense in depth: callers construct URLs via the hardcoded https://
    # builders in this module (cve_url, advisory_url_for_id, …), but
    # ``url`` is still a plain str. Reject anything that isn't http(s) so
    # an unexpected caller can't turn this HEAD probe into a file://
    # disclosure gadget (bandit B310).
    if not url.lower().startswith(("http://", "https://")):
        return False, "unsupported URL scheme"
    import urllib.error
    import urllib.request
    try:
        req = urllib.request.Request(
            url, method="HEAD",
            headers={"User-Agent": "argus-view-terminal"},
        )
        # B310: scheme is enforced above; only http(s) reach this call.
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            status = getattr(resp, "status", None) or resp.getcode()
            if 200 <= status < 400:
                return True, f"HTTP {status}"
            return False, f"HTTP {status}"
    except urllib.error.HTTPError as exc:
        # urllib raises HTTPError on 4xx/5xx — we still want the code
        # surfaced to the user so they can tell "not found" from
        # "rate limited" without guessing.
        return False, f"HTTP {exc.code}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, f"network error: {exc}"


def git_file_status(repo_root: Path, rel_path: Path) -> str:
    """Best-effort working-tree status for a single file.

    Returns one of:
      - ``"clean"`` — file matches the index and HEAD
      - ``"modified"`` — uncommitted changes in the working tree
      - ``"untracked"`` — file isn't tracked by git
      - ``"unknown"`` — git isn't on PATH, or the command failed

    Used to warn before opening a remote URL: if the local file is
    dirty, the remote page won't reflect what the user is currently
    looking at, even when the URL itself resolves.
    """
    if not shutil.which("git"):
        return "unknown"
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "status", "--porcelain", "--", str(rel_path)],
            capture_output=True, text=True, timeout=2, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("git status lookup failed for %s: %s", rel_path, exc)
        return "unknown"
    if result.returncode != 0:
        return "unknown"
    output = result.stdout.strip()
    if not output:
        return "clean"
    # ``git status --porcelain`` prefixes untracked files with ``??``;
    # everything else (M, A, D, R, etc.) means the file has staged or
    # unstaged changes.
    if output.startswith("??"):
        return "untracked"
    return "modified"


def read_source_context(
    path: Path,
    line: int,
    *,
    before: int = 5,
    after: int = 5,
    max_file_size: int = 5 * 1024 * 1024,
    max_line_width: int = 120,
) -> list[tuple[int, str, bool]] | None:
    """Read a window of source lines around ``line`` for the detail pane.

    Returns ``[(line_number, text, is_flagged), ...]`` for lines in
    the closed range ``[line - before, line + after]``, clamped to
    the file bounds. ``is_flagged`` is True only for the originally
    requested line so the renderer can mark it.

    Returns ``None`` when:
      - ``path`` doesn't exist or isn't a regular file
      - the file is larger than ``max_file_size`` (5 MB default —
        guard against accidentally slurping a generated bundle into
        memory)
      - the file isn't decodable as text (we replace errors rather
        than fail, so this case is rare)
      - ``line`` is outside the file's line range

    Long lines are truncated to ``max_line_width`` characters with
    an ellipsis so the source block doesn't blow up the detail pane
    width on minified files / generated assets.
    """
    if line is None or line < 1:
        return None
    try:
        if not path.is_file():
            return None
        if path.stat().st_size > max_file_size:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("read_source_context failed for %s: %s", path, exc)
        return None
    lines = text.splitlines()
    if not lines or line > len(lines):
        return None
    start = max(1, line - before)
    end = min(len(lines), line + after)
    out: list[tuple[int, str, bool]] = []
    for n in range(start, end + 1):
        content = lines[n - 1]
        if len(content) > max_line_width:
            content = content[: max_line_width - 1].rstrip() + "…"
        out.append((n, content, n == line))
    return out


def strip_scan_prefix(path: Path, scan_context) -> Path:
    """Strip the scan-time cwd / repo_root prefix off an absolute path.

    Scans run inside containers / CI emit paths like
    ``/workspace/argus/preflight/issue_reporter.py``; the
    ``/workspace/argus/`` prefix is the scan-time mount point, which
    on the viewer's host is meaningless. ``scan_context.repo_root`` /
    ``scan_context.cwd`` (captured by the engine at scan time) tells
    us what to strip. Falls through to the original path when:

      - the path is already relative
      - scan_context is None (older results that predate the field)
      - neither recorded prefix matches the path

    Backwards-compatible with results files that predate the
    scan_context field — old payloads return the original path
    unchanged so the viewer's previous best-effort heuristics still
    apply. ``scan_context`` is typed loosely to avoid a runtime
    import from mouse_actions into argus.core.models; callers pass a
    ``ScanContext`` instance or ``None``.
    """
    if not path.is_absolute() or scan_context is None:
        return path
    candidates: list[str] = []
    repo_root = getattr(scan_context, "repo_root", "")
    cwd = getattr(scan_context, "cwd", "")
    if repo_root:
        candidates.append(repo_root)
    if cwd and cwd != repo_root:
        candidates.append(cwd)
    for prefix_str in candidates:
        prefix = Path(prefix_str)
        try:
            return path.relative_to(prefix)
        except ValueError:
            continue
    return path


def clamp_menu_offset(
    click_x: int,
    click_y: int,
    menu_w: int,
    menu_h: int,
    screen_w: int,
    screen_h: int,
) -> tuple[int, int]:
    """Position a context menu at the click, nudged to stay on screen.

    A right-click menu should open *where the cursor is*, not in the
    middle of the screen. The only adjustment is to slide the menu back
    inside the viewport when the click was near the right or bottom edge
    so the box never spills off — the chosen corner is the click point,
    clamped to ``[0, screen - menu]`` on each axis.

    Pure integer math (no Textual) so the placement is unit-testable.
    Degenerate inputs (menu at least as large as the screen) clamp to
    ``0`` on that axis rather than going negative.
    """
    max_x = max(0, screen_w - menu_w)
    max_y = max(0, screen_h - menu_h)
    x = min(max(click_x, 0), max_x)
    y = min(max(click_y, 0), max_y)
    return x, y
