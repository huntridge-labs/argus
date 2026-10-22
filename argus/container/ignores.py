"""Tool-native ignore files for the container scan.

An OpenVEX statement names a component PURL (``pkg:golang/stdlib@1.24.11``),
and neither trivy nor grype can scope one to a single file in the image, so a
statement written for one bundled binary hides the same CVE in every binary
built from that component. The tools' own ignore formats can scope a rule to
a path:

* trivy ``--ignorefile`` YAML: ``vulnerabilities: [{id, paths, statement}]``
  (paths have no leading slash, e.g. ``usr/local/bin/gitleaks``).
* grype ``-c`` config: ``ignore: [{vulnerability, reason, package: {name,
  location}}]`` (location has a leading slash).

``containers.trivy_ignore_file`` and ``containers.grype_config_file`` pass
those files through, mounted into the tool containers the same way VEX
documents are. Both tools also report what they dropped (trivy
``--show-suppressed`` -> ``ExperimentalModifiedFindings``, grype
``ignoredMatches``), which this module reads back so reports can list
ignored findings with their reason instead of making them vanish, and so CI
can catch a rule that matched nothing.

A configured file that does not exist is logged and skipped, the same as a
missing VEX document: findings stay visible.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable

from argus.core.models import Finding
from argus.scanners._vuln_parsers import parse_grype_match, parse_trivy_vuln

logger = logging.getLogger("argus.container")

TRIVY_IGNORE_KEY = "trivy_ignore_file"
GRYPE_CONFIG_KEY = "grype_config_file"

#: Where ignore files are mounted inside the trivy / grype containers. The
#: file keeps its basename because trivy picks the parser from the extension.
_MOUNT_DIR = "/argus-ignore"

#: ``ignore_source`` for a grype rule that is not in the configured file
#: (grype ships default rules of its own).
_GRYPE_BUILTIN = "grype (built-in rule)"
_OPENVEX = "openvex"


def _display(path: Path) -> str:
    """Path as shown in reports: relative to the working directory if inside it."""
    try:
        return str(path.relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def resolve_ignore_file(config: dict | None, key: str) -> Path | None:
    """Return the resolved file named by ``config[key]``, or None."""
    raw = (config or {}).get(key)
    if not raw:
        return None
    path = Path(str(raw)).expanduser()
    if not path.is_file():
        logger.warning("%s not found, skipping: %s", key, raw)
        return None
    return path.resolve()


def _file_args(
    config: dict | None, key: str, flag: str, use_container: bool,
) -> tuple[list[str], list[str]]:
    path = resolve_ignore_file(config, key)
    if path is None:
        return [], []
    if not use_container:
        return [], [flag, str(path)]
    target = f"{_MOUNT_DIR}/{path.name}"
    return ["-v", f"{path}:{target}:ro"], [flag, target]


def trivy_ignore_args(config: dict | None, use_container: bool) -> tuple[list[str], list[str]]:
    """``(docker mount args, --ignorefile flags)`` for ``containers.trivy_ignore_file``."""
    return _file_args(config, TRIVY_IGNORE_KEY, "--ignorefile", use_container)


def grype_config_args(config: dict | None, use_container: bool) -> tuple[list[str], list[str]]:
    """``(docker mount args, -c flags)`` for ``containers.grype_config_file``."""
    return _file_args(config, GRYPE_CONFIG_KEY, "-c", use_container)


def _load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _mark_ignored(finding: Finding, **fields: str) -> Finding:
    finding.metadata.update({"ignored": True, **fields})
    return finding


# --------------------------------------------------------------------- #
# trivy                                                                 #
# --------------------------------------------------------------------- #


def _trivy_source_names(config: dict | None) -> dict[str, str]:
    """Map the ``Source`` trivy reports (host or in-container path) to a display name."""
    from argus.core.vex import vex_container_mounts

    names: dict[str, str] = {}
    ignore = resolve_ignore_file(config, TRIVY_IGNORE_KEY)
    if ignore is not None:
        names[str(ignore)] = names[f"{_MOUNT_DIR}/{ignore.name}"] = _display(ignore)
    for host, container in vex_container_mounts(config):
        names[host] = names[container] = _display(Path(host))
    return names


def parse_trivy_suppressed(output_file: Path, config: dict | None) -> list[Finding]:
    """Findings trivy reported under ``ExperimentalModifiedFindings``.

    Requires ``--show-suppressed``. Only vulnerability entries are read; the
    container scan runs trivy's vulnerability scanner only.
    """
    data = _load_json(output_file)
    names = _trivy_source_names(config)
    ignored: list[Finding] = []
    for result in data.get("Results") or []:
        target = result.get("Target", "")
        for entry in result.get("ExperimentalModifiedFindings") or []:
            if entry.get("Type") != "vulnerability":
                continue
            source = entry.get("Source", "")
            finding = parse_trivy_vuln(entry.get("Finding") or {}, scanner_name="container")
            ignored.append(_mark_ignored(
                finding,
                ignore_status=entry.get("Status", ""),
                ignore_reason=entry.get("Statement", ""),
                ignore_source=names.get(source, source),
                ignore_path=target,
            ))
    return ignored


# --------------------------------------------------------------------- #
# grype                                                                 #
# --------------------------------------------------------------------- #


def _load_yaml(path: Path) -> dict:
    import yaml

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        logger.warning("Could not read ignore file %s: %s", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def _grype_rules(config: dict | None) -> tuple[Path | None, list[dict]]:
    path = resolve_ignore_file(config, GRYPE_CONFIG_KEY)
    if path is None:
        return None, []
    rules = _load_yaml(path).get("ignore") or []
    return path, [r for r in rules if isinstance(r, dict)]


def _grype_rule_key(rule: dict) -> tuple[str, ...]:
    """Fields we write in a grype rule, as grype echoes them back."""
    pkg = rule.get("package") or {}
    return (
        rule.get("vulnerability") or "",
        rule.get("reason") or "",
        pkg.get("name") or "",
        pkg.get("version") or "",
        pkg.get("location") or "",
    )


def _grype_reason(rule: dict) -> tuple[str, str]:
    """``(status, reason)`` for one applied grype rule."""
    status = rule.get("vex-status") or ""
    if status:
        justification = rule.get("vex-justification") or ""
        return status, f"VEX {status}: {justification}".rstrip(": ")
    return "ignored", rule.get("reason") or ""


def parse_grype_ignored(output_file: Path, config: dict | None) -> list[Finding]:
    """Findings grype moved to ``ignoredMatches``, with the rule that did it."""
    data = _load_json(output_file)
    path, rules = _grype_rules(config)
    ours = {_grype_rule_key(r) for r in rules}
    ignored: list[Finding] = []
    for match in data.get("ignoredMatches") or []:
        applied = [r for r in match.get("appliedIgnoreRules") or [] if isinstance(r, dict)]
        rule = next((r for r in applied if _grype_rule_key(r) in ours), applied[0] if applied else {})
        status, reason = _grype_reason(rule)
        if path is not None and _grype_rule_key(rule) in ours:
            source = _display(path)
        elif rule.get("vex-status"):
            source = _OPENVEX
        else:
            source = _GRYPE_BUILTIN
        locations = (match.get("artifact") or {}).get("locations") or [{}]
        finding = parse_grype_match(match, scanner_name="container")
        ignored.append(_mark_ignored(
            finding,
            ignore_status=status,
            ignore_reason=reason,
            ignore_source=source,
            ignore_path=locations[0].get("path", ""),
        ))
    return ignored


# --------------------------------------------------------------------- #
# Guard: rules that matched nothing                                     #
# --------------------------------------------------------------------- #


@dataclass(frozen=True)
class UnmatchedIgnoreRule:
    """An ignore rule no ignored finding came from."""

    tool: str
    vulnerability: str
    path: str
    source: str


def _trivy_rules(config: dict | None) -> tuple[Path | None, list[dict]]:
    """``[{id, paths}]`` from a YAML or plain-text trivy ignore file."""
    path = resolve_ignore_file(config, TRIVY_IGNORE_KEY)
    if path is None:
        return None, []
    if path.suffix in (".yaml", ".yml"):
        rules = _load_yaml(path).get("vulnerabilities") or []
        return path, [r for r in rules if isinstance(r, dict) and r.get("id")]
    lines = path.read_text(encoding="utf-8").splitlines()
    ids = [line.split()[0] for line in lines if line.strip() and not line.lstrip().startswith("#")]
    return path, [{"id": vuln_id} for vuln_id in ids]


def _trivy_rule_covers(rule: dict, finding: Finding) -> bool:
    paths = rule.get("paths") or []
    meta = finding.metadata
    return finding.id == rule["id"] and (
        not paths or any(fnmatch(meta.get("ignore_path", ""), p) for p in paths)
    )


def _grype_rule_covers(rule: dict, finding: Finding) -> bool:
    pkg = rule.get("package") or {}
    meta = finding.metadata
    checks = (
        (rule.get("vulnerability"), finding.id),
        (pkg.get("name"), meta.get("package", "")),
        (pkg.get("version"), meta.get("installed_version", "")),
    )
    if any(want and want != got for want, got in checks):
        return False
    location = pkg.get("location")
    return not location or fnmatch(meta.get("ignore_path", ""), location)


def unmatched_ignore_rules(
    ignored: list[Finding],
    config: dict | None,
    tools: Iterable[str] = ("trivy", "grype"),
) -> list[UnmatchedIgnoreRule]:
    """Rules in the configured ignore files that no ignored finding came from.

    A rule that matched nothing is either stale (the component was fixed and
    the rule should go) or wrong (a typo in the ID or path, so the finding it
    was meant for is still open). ``tools`` limits the check to sub-scanners
    that actually ran; a rule for a tool that did not run cannot be judged.
    """
    wanted = set(tools)
    checks = []
    if "trivy" in wanted:
        path, rules = _trivy_rules(config)
        checks += [("trivy", path, r, r["id"], ",".join(r.get("paths") or []),
                    _trivy_rule_covers) for r in rules]
    if "grype" in wanted:
        path, rules = _grype_rules(config)
        checks += [("grype", path, r, r.get("vulnerability") or "",
                    (r.get("package") or {}).get("location") or "",
                    _grype_rule_covers) for r in rules]

    misses: list[UnmatchedIgnoreRule] = []
    for tool, path, rule, vuln, where, covers in checks:
        source = _display(path)
        hit = any(
            f.metadata.get("tool") == tool
            and f.metadata.get("ignore_source") == source
            and covers(rule, f)
            for f in ignored
        )
        if not hit:
            misses.append(UnmatchedIgnoreRule(tool, vuln, where, source))
    return misses
