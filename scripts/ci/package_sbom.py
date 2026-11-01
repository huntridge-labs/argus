#!/usr/bin/env python3
"""Generate and collect the signed SBOM for the release job's wheel.

The image SBOMs (ADR-489) cover what ships in a container. This covers
what ships with ``pip install argus-security``: the runtime dependency
set from ``uv.lock``, with the dev group left out, so the SBOM lists
only what reaches a user (ADR-528).

``uv export --format cyclonedx1.5`` writes the inventory. On top of it:

- the root component gets the wheel's version, purl and sha256, so the
  SBOM names the file its attestation subject does;
- base dependencies get ``scope: required``; packages only an extra
  pulls in get ``scope: optional`` and an ``argus:extras`` property
  naming those extras, so a scanner can tell ``pip install argus-security``
  from ``pip install argus-security[all]``.

Two subcommands, one on each side of the ``actions/attest`` step:

``generate``  read the wheel, export the inventory, write
              ``sbom-argus-security-<version>.cdx.json``, and export
              ``PACKAGE_SBOM_PATH`` / ``PACKAGE_WHEEL`` to ``$GITHUB_ENV``.
``collect``   read the attest step's ``bundle-path`` from
              ``$ATTEST_STEPS``, check it signs the wheel with this SBOM,
              and copy it next to the SBOM as ``<sbom>.sigstore.json``.

Any problem exits 1, so the release job stops before PyPI publish.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from email.parser import Parser
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name, parse_wheel_filename

from scripts.ci.image_sboms import SbomError, check_bundle

ATTEST_STEP_ID = "attest-package"
EXPORT_BASE = [
    "uv", "export",
    "--format", "cyclonedx1.5",
    "--preview-features", "sbom-export",
    "--frozen",
    "--no-dev",
    "--no-header",
]


def sbom_name(version: str) -> str:
    return f"sbom-argus-security-{version}.cdx.json"


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wheel_metadata(wheel: Path) -> dict:
    """Name, version, extras and Requires-Dist names from the wheel itself."""
    name, version, _, _ = parse_wheel_filename(wheel.name)
    with zipfile.ZipFile(wheel) as zf:
        meta_path = next(n for n in zf.namelist() if n.endswith(".dist-info/METADATA"))
        meta = Parser().parsestr(zf.read(meta_path).decode("utf-8"))
    requires = {canonicalize_name(Requirement(r).name) for r in meta.get_all("Requires-Dist") or []}
    return {
        "name": str(name),
        "version": str(version),
        "extras": sorted(canonicalize_name(e) for e in meta.get_all("Provides-Extra") or []),
        # The ``all`` extra requires argus-security[...] itself; that's the root, not a component.
        "requires": sorted(requires - {name}),
    }


def export(extra_args: list[str]) -> dict:
    result = subprocess.run(
        [*EXPORT_BASE, *extra_args], capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        raise SbomError(f"uv export {' '.join(extra_args)} failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def component_names(bom: dict) -> set[str]:
    return {canonicalize_name(c["name"]) for c in bom.get("components", [])}


def extras_by_package(base: set[str], per_extra: dict[str, set[str]]) -> dict[str, list[str]]:
    """Map each package outside the base install to the extras that pull it in."""
    found: dict[str, list[str]] = {}
    for extra, names in sorted(per_extra.items()):
        for name in names - base:
            found.setdefault(name, []).append(extra)
    return found


def annotate(full: dict, meta: dict, wheel_sha: str, base: set[str], extras: dict) -> dict:
    """Stamp the wheel onto the root and scope every component."""
    root = {
        **full["metadata"]["component"],
        "version": meta["version"],
        "purl": f"pkg:pypi/{meta['name']}@{meta['version']}",
        "hashes": [{"alg": "SHA-256", "content": wheel_sha}],
    }
    components = []
    for comp in full["components"]:
        name = canonicalize_name(comp["name"])
        if name in base:
            components.append({**comp, "scope": "required"})
            continue
        prop = {"name": "argus:extras", "value": ",".join(extras.get(name, []))}
        components.append({**comp, "scope": "optional",
                           "properties": [*comp.get("properties", []), prop]})
    return {**full, "metadata": {**full["metadata"], "component": root}, "components": components}


def check_package_sbom(sbom: dict, meta: dict, wheel_sha: str) -> None:
    """The SBOM must name this wheel and list every dependency it declares."""
    root = sbom["metadata"]["component"]
    if root.get("name") != meta["name"] or root.get("version") != meta["version"]:
        raise SbomError(f"SBOM describes {root.get('name')}@{root.get('version')}, "
                        f"expected {meta['name']}@{meta['version']}")
    if root.get("hashes") != [{"alg": "SHA-256", "content": wheel_sha}]:
        raise SbomError("SBOM root hash is not the wheel's sha256")
    missing = sorted(set(meta["requires"]) - component_names(sbom))
    if missing:
        raise SbomError(f"wheel declares {', '.join(missing)} but uv.lock exports none of them; "
                        "is uv.lock stale?")
    unscoped = [c["name"] for c in sbom["components"] if c.get("scope") is None]
    if unscoped:
        raise SbomError(f"components without a scope: {', '.join(unscoped)}")


def export_env(lines: list[str]) -> None:
    github_env = os.environ.get("GITHUB_ENV")
    if github_env:
        with open(github_env, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")


def cmd_generate(args) -> int:
    wheel = Path(args.wheel)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    meta = wheel_metadata(wheel)
    wheel_sha = sha256_of(wheel)
    base = component_names(export([]))
    per_extra = {e: component_names(export(["--extra", e])) for e in meta["extras"]}
    sbom = annotate(export(["--all-extras"]), meta, wheel_sha, base,
                    extras_by_package(base, per_extra))
    check_package_sbom(sbom, meta, wheel_sha)
    path = out_dir / sbom_name(meta["version"])
    path.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
    export_env([f"PACKAGE_SBOM_PATH={path.resolve()}", f"PACKAGE_WHEEL={wheel.resolve()}"])
    optional = sum(c["scope"] == "optional" for c in sbom["components"])
    print(f"{path.name}: {wheel.name} sha256:{wheel_sha} "
          f"({len(sbom['components']) - optional} required, {optional} optional)")
    return 0


def cmd_collect(args) -> int:
    wheel = Path(args.wheel)
    sbom_path = Path(args.sbom)
    steps = json.loads(os.environ.get("ATTEST_STEPS") or "{}")
    bundle = ((steps.get(ATTEST_STEP_ID) or {}).get("outputs") or {}).get("bundle-path")
    if not bundle:
        raise SbomError(f"no attest step '{ATTEST_STEP_ID}' output for {sbom_path.name}")
    subject = {
        "step_id": ATTEST_STEP_ID,
        "subject_name": wheel.name,
        "subject_digest": f"sha256:{sha256_of(wheel)}",
        "sbom": sbom_path.name,
    }
    check_bundle(Path(bundle), subject, json.loads(sbom_path.read_text(encoding="utf-8")))
    target = sbom_path.with_name(f"{sbom_path.name}.sigstore.json")
    shutil.copyfile(bundle, target)
    print(f"{target.name}: signed {subject['subject_name']}@{subject['subject_digest']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate", help="Generate the SBOM for a built wheel")
    gen.add_argument("--out-dir", required=True, help="Directory for the SBOM file")
    collect = sub.add_parser("collect", help="Check and collect the attestation bundle")
    collect.add_argument("--sbom", required=True, help="Path written by generate")
    for p in (gen, collect):
        p.add_argument("--wheel", required=True, help="The built .whl file")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = cmd_generate if args.command == "generate" else cmd_collect
    try:
        return handler(args)
    except (SbomError, OSError, ValueError, KeyError, StopIteration) as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
