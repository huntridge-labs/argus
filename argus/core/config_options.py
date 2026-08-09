"""Machine-readable description of every Argus config knob — the *config surface*.

Argus config is otherwise free-form passthrough: each scanner reads whatever keys
it wants from its ``config`` dict. That's flexible but opaque — a UI (the Console,
Argus Cloud) can't know that Checkov's rule-skip knob is ``skip_check`` while
Gitleaks' is a native ``.gitleaksignore``. This module makes those knobs explicit
and *versioned in the wheel*, so any consumer renders an accurate config editor
for the exact installed Argus version — no separate schema to keep in sync.

Two layers:

* **Common options** (:data:`BASE_OPTIONS`) apply to every scanner.
* **Per-scanner options** are declared on the scanner class as ``config_options``
  (a list of :class:`ConfigOption`), merged on top of the base. A scanner with no
  declaration still surfaces the base knobs, so a newly added scanner needs no
  change here.

:func:`config_surface` assembles everything (version + JSON schema + registry +
per-scanner options) into one dict — the single call an external consumer makes.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

#: How a knob is edited — drives the input widget a UI renders.
OPTION_KINDS = (
    "bool",
    "string",
    "path",
    "path_globs",  # comma-separated paths/globs (Argus ``exclude``)
    "rule_ids",  # comma-separated rule/check IDs (e.g. Checkov ``skip_check``)
    "severity",  # one of SEVERITY_LEVELS
    "enum",  # one of ``choices``
    "config_file",  # path to a tool-native config file
    "string_list",  # list of strings
    "port_list",  # list of "PORT/PROTO"
)

SEVERITY_LEVELS = ("critical", "high", "medium", "low", "none")


@dataclass(frozen=True)
class ConfigOption:
    """One configurable knob on a scanner (or the common base)."""

    key: str
    label: str
    kind: str = "string"
    help: str = ""
    #: True when setting this knob SUPPRESSES findings (rule/CVE/path ignore).
    #: A UI surfaces these as the "ignore this" controls.
    ignore: bool = False
    example: str | None = None
    choices: tuple[str, ...] | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return {k: v for k, v in d.items() if v not in (None, "", False) or k in ("key", "label", "kind")}


@dataclass(frozen=True)
class NativeIgnore:
    """A scanner's *native* suppression mechanism, when Argus has no direct knob.

    e.g. Trivy respects a ``.trivyignore`` file and ``# trivy:skip=<id>`` comments.
    A UI uses this to tell a user exactly how to ignore a finding at the source
    even when there's no ``argus.yml`` key for it.
    """

    file: str | None = None  # native ignore file, committed to the repo
    comment: str | None = None  # inline suppression comment
    help: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v}


# ── Common knobs on every scanner ────────────────────────────────────────────

BASE_OPTIONS: tuple[ConfigOption, ...] = (
    ConfigOption("enabled", "Enabled", "bool", "Run this scanner. Disabled scanners are skipped."),
    ConfigOption("path", "Path", "path", "Path to scan, relative to the repo root.", example="src"),
    ConfigOption(
        "severity_threshold",
        "Severity threshold",
        "severity",
        "Fail the scan at or above this severity (overrides the global threshold).",
        choices=SEVERITY_LEVELS,
    ),
    ConfigOption(
        "config_file",
        "Native config file",
        "config_file",
        "Path to the underlying tool's own config file.",
    ),
    ConfigOption(
        "exclude",
        "Exclude paths",
        "path_globs",
        "Comma-separated paths/globs to skip.",
        ignore=True,
        example="tests,docs,*.min.js",
    ),
)


# ── Curated per-scanner knobs (source of truth, versioned in the wheel) ───────
#
# Keyed by registry name. A scanner MAY instead declare ``config_options`` /
# ``native_ignore`` on its class (merged first, so it wins) — new scanners can
# own their metadata; the current set is curated centrally for one-file review.
# Only knobs the scanner's ``build_args``/``scan`` actually READS are listed, so
# the UI never offers a no-op key.

_SCANNER_EXTRAS: dict[str, tuple[ConfigOption, ...]] = {
    "bandit": (
        ConfigOption("check", "Only these tests", "rule_ids", "Run only these bandit test IDs.", example="B201,B301"),
        ConfigOption(
            "skip_check", "Skip tests", "rule_ids",
            "Bandit test IDs to ignore (e.g. B311).", ignore=True, example="B311,B404",
        ),
    ),
    "checkov": (
        ConfigOption("framework", "Framework", "string", "Limit to one framework.", example="terraform"),
        ConfigOption("check", "Only these checks", "rule_ids", "Run only these check IDs.", example="CKV_AWS_20"),
        ConfigOption(
            "skip_check", "Skip checks", "rule_ids",
            "Check IDs to ignore (e.g. CKV_AWS_1).", ignore=True, example="CKV_AWS_1,CKV_AWS_20",
        ),
    ),
    "opengrep": (
        ConfigOption("config", "Rules", "string", "Semgrep-compatible rules (path or registry).", example="p/ci"),
    ),
    "osv": (
        ConfigOption("lockfile", "Lockfile", "path", "Scan a specific lockfile."),
        ConfigOption("recursive", "Recursive", "bool", "Recurse into subdirectories for lockfiles."),
    ),
    "grype": (
        ConfigOption(
            "vex", "OpenVEX docs", "config_file",
            "OpenVEX document(s) — path or list — to drop not_affected / fixed "
            "findings via grype --vex.", ignore=True, example=".vex/argus.openvex.json",
        ),
    ),
    "trivy": (
        ConfigOption(
            "vex", "OpenVEX docs", "config_file",
            "OpenVEX document(s) — path or list — to drop not_affected / fixed "
            "findings via trivy --vex.", ignore=True, example=".vex/argus.openvex.json",
        ),
    ),
    "container": (
        ConfigOption("image_ref", "Image", "string", "Container image to scan.", example="myapp:latest"),
        ConfigOption("scanners", "Sub-scanners", "string", "Comma-separated.", example="trivy,grype,syft,exposure,services"),
        ConfigOption(
            "expose_ignore_ports", "Ignore ports", "port_list",
            "Exposed ports to suppress entirely.", ignore=True, example="22/tcp,3306/tcp",
        ),
        ConfigOption(
            "services_ignore", "Ignore services", "string_list",
            "Declared services to suppress (case-insensitive).", ignore=True, example="cron,rsyslog",
        ),
        ConfigOption("expose_warn_ports", "Warn ports", "port_list", "Override the WARN-list of exposed ports."),
        ConfigOption("services_warn", "Warn services", "string_list", "Override the WARN-list of services."),
        ConfigOption(
            "vex", "OpenVEX docs", "config_file",
            "OpenVEX document(s) — path or list — passed to trivy + grype to drop "
            "not_affected / fixed findings.", ignore=True, example=".vex/argus.openvex.json",
        ),
    ),
    "zap": (
        ConfigOption("target_url", "Target URL", "string", "URL of the running app to scan."),
        ConfigOption("scan_type", "Scan type", "enum", choices=("baseline", "full", "api")),
        ConfigOption("api_spec", "API spec", "string", "OpenAPI/Swagger spec URL or path (switches to API scan)."),
        ConfigOption(
            "rules_file", "Ignore rules", "config_file",
            "ZAP ignore-rules .tsv (suppress alert IDs).", ignore=True, example=".zap/rules.tsv",
        ),
    ),
    "supply-chain": (
        ConfigOption(
            "zizmor_config", "Zizmor config", "config_file",
            "zizmor config file with rule suppressions.", ignore=True, example=".zizmor.yml",
        ),
        ConfigOption("run_actionlint", "Run actionlint", "bool", "Also run actionlint."),
    ),
}

#: Native (source-file) suppression for scanners Argus doesn't expose a key for.
_NATIVE_IGNORE: dict[str, NativeIgnore] = {
    "bandit": NativeIgnore(file="pyproject.toml ([tool.bandit] skips)", comment="# nosec: B101", help="Bandit skips via native config or inline # nosec."),
    "gitleaks": NativeIgnore(file="gitleaks.toml (allowlist) / .gitleaksignore", comment="#gitleaks:allow"),
    "opengrep": NativeIgnore(comment="# nosem: <rule-id>"),
    "osv": NativeIgnore(file=".osv-scanner.toml (IgnoredVulns)", help="Ignore a CVE by id in the OSV config."),
    "checkov": NativeIgnore(comment="# checkov:skip=CKV_AWS_1:reason"),
    "trivy-iac": NativeIgnore(file=".trivyignore", comment="# trivy:skip=<AVD-id>"),
    "trivy": NativeIgnore(file=".trivyignore", help="Ignore CVE ids, one per line."),
    "grype": NativeIgnore(file=".grype.yaml (ignore rules)"),
    "container": NativeIgnore(file=".trivyignore / .grype.yaml", help="Image-layer CVEs use the underlying tools' ignore files."),
    "lint-yaml": NativeIgnore(file=".yamllint", comment="# yamllint disable-line rule:line-length"),
    "lint-python": NativeIgnore(file="ruff.toml / setup.cfg / .flake8", comment="# noqa: E501"),
}


def scanner_config_options(name: str, cls: type) -> list[ConfigOption]:
    """Full option list for a scanner: its own class-declared ``config_options``
    (highest priority) + the curated central extras + the common base, deduped by
    key (earliest wins)."""
    merged: list[ConfigOption] = []
    seen: set[str] = set()
    for source in (
        getattr(cls, "config_options", ()) or (),
        _SCANNER_EXTRAS.get(name, ()),
        BASE_OPTIONS,
    ):
        for opt in source:
            if opt.key not in seen:
                merged.append(opt)
                seen.add(opt.key)
    return merged


def scanner_native_ignore(name: str, cls: type) -> NativeIgnore | None:
    """The scanner's native (source-file) suppression mechanism, if any."""
    declared = getattr(cls, "native_ignore", None)
    if isinstance(declared, NativeIgnore):
        return declared
    return _NATIVE_IGNORE.get(name)


def _load_schema() -> dict[str, Any] | None:
    """The packaged ``argus-config.schema.json`` (repo root / wheel data), or None."""
    try:
        import argus

        schema_path = Path(argus.__file__).resolve().parent.parent / "argus-config.schema.json"
        if schema_path.is_file():
            return json.loads(schema_path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None


def config_surface(*, include_schema: bool = True) -> dict[str, Any]:
    """The complete, versioned config surface — the one call a UI makes.

    Returns Argus version, the config-format version, the JSON schema, the
    severity levels, and every scanner with its knobs (incl. how to ignore
    findings). Assembled from the live registry, so it always matches the
    installed Argus version.
    """
    from argus import __version__
    from argus.scanners import SCANNER_REGISTRY

    scanners: list[dict[str, Any]] = []
    for name, cls in sorted(SCANNER_REGISTRY.items()):
        options = scanner_config_options(name, cls)
        native = scanner_native_ignore(name, cls)
        scanners.append(
            {
                "name": name,
                "description": getattr(cls, "description", ""),
                "category": getattr(cls, "category", "other"),
                "languages": list(getattr(cls, "languages", []) or []),
                "supports_sbom": bool(getattr(cls, "supports_sbom", False)),
                "options": [o.to_dict() for o in options],
                "ignore_keys": [o.key for o in options if o.ignore],
                "native_ignore": native.to_dict() if native else None,
            }
        )

    surface: dict[str, Any] = {
        "argus_version": __version__,
        "config_version": "1.0",
        "severity_levels": list(SEVERITY_LEVELS),
        "scanners": scanners,
    }
    if include_schema:
        surface["schema"] = _load_schema()
    return surface
