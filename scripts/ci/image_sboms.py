#!/usr/bin/env python3
"""Generate and collect the signed SBOMs for the release job's images.

The release job pushes every image as a multi-arch index
(linux/amd64 + linux/arm64). ``containerimage.digest`` from the build is
the INDEX digest, and an index has no filesystem of its own. So each
image gets three CycloneDX documents (ADR-489):

``<image>-linux-amd64`` / ``<image>-linux-arm64``
    A syft SBOM of that platform's image, scanned from the registry by
    the platform manifest digest. Syft records the digest it was given
    as ``metadata.component.version``, so the SBOM names the same digest
    its attestation subject does. Scanning the index digest with
    ``--platform`` would record the index digest in both platform SBOMs.

``<image>-index``
    A small BOM for the index itself, listing its platform manifests by
    digest. ``gh attestation verify oci://<image>:<tag>`` looks up the
    index digest, so this is what makes tag-based verification work.

Two subcommands, one on each side of the ``actions/attest`` steps:

``generate``  inspect each index, run the pinned syft image per
              platform, write the documents and ``image-sboms-<sha12>.json``
              (the subject list), and export ``SBOM_<KEY>_<VARIANT>_DIGEST``
              / ``_PATH`` to ``$GITHUB_ENV`` for the attest steps.
``collect``   read the attest steps' ``bundle-path`` outputs from
              ``$ATTEST_STEPS`` (``toJSON(steps)``), check every bundle
              signs the right subject and SBOM, and copy each one next to
              its SBOM as ``<sbom>.sigstore.json``.

Any problem exits 1, so the release job stops before release-it runs.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from argus.containers import OFFICIAL_IMAGES

PLATFORMS = ("linux/amd64", "linux/arm64")
INDEX_VARIANT = "index"
CYCLONEDX_PREDICATE = "https://cyclonedx.org/bom"
IN_TOTO_PAYLOAD = "application/vnd.in-toto+json"
ATTESTATION_MANIFEST = "attestation-manifest"
SYFT_AUTH_ENV = (
    "SYFT_REGISTRY_AUTH_AUTHORITY",
    "SYFT_REGISTRY_AUTH_USERNAME",
    "SYFT_REGISTRY_AUTH_PASSWORD",
)
SYFT_ATTEMPTS = 2
RETRY_DELAY_SECONDS = 10


class SbomError(Exception):
    """A generated or signed SBOM failed a check."""


def variant_of(platform: str) -> str:
    return platform.replace("/", "-")


def env_key(image: str, variant: str) -> str:
    return f"{image}_{variant}".upper().replace("-", "_")


def step_id(image: str, variant: str) -> str:
    return f"attest-{image}-{variant}"


def sbom_name(image: str, sha12: str, variant: str) -> str:
    return f"sbom-{image}-{sha12}-{variant}.cdx.json"


def manifest_name(sha12: str) -> str:
    return f"image-sboms-{sha12}.json"


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def fetch_index(ref: str) -> str:
    result = run(["docker", "buildx", "imagetools", "inspect", "--raw", ref])
    if result.returncode != 0:
        raise SbomError(f"cannot inspect {ref}: {result.stderr.strip()}")
    return result.stdout


def platform_digests(raw_index: str, index_digest: str, platforms=PLATFORMS) -> dict:
    """Map each wanted platform to its manifest digest in the raw index.

    Hashing the raw bytes proves they are the index the build pushed.
    BuildKit's provenance manifests (``unknown/unknown``) are skipped.
    """
    actual = "sha256:" + hashlib.sha256(raw_index.encode()).hexdigest()
    if actual != index_digest:
        raise SbomError(f"index bytes hash to {actual}, expected {index_digest}")
    found: dict[str, list[str]] = {p: [] for p in platforms}
    for entry in json.loads(raw_index).get("manifests", []):
        annotations = entry.get("annotations") or {}
        if annotations.get("vnd.docker.reference.type") == ATTESTATION_MANIFEST:
            continue
        plat = entry.get("platform") or {}
        key = f"{plat.get('os')}/{plat.get('architecture')}"
        if key in found:
            found[key].append(entry["digest"])
    for plat, digests in found.items():
        if len(digests) != 1:
            raise SbomError(f"{index_digest}: expected one {plat} manifest, found {len(digests)}")
    return {plat: digests[0] for plat, digests in found.items()}


def syft_command(subject: str, platform: str) -> list[str]:
    auth = [arg for name in SYFT_AUTH_ENV if os.environ.get(name) for arg in ("-e", name)]
    return [
        "docker", "run", "--rm",
        "-e", "SYFT_CHECK_FOR_APP_UPDATE=false",
        *auth,
        OFFICIAL_IMAGES["syft"],
        f"registry:{subject}",
        "--platform", platform,
        "-o", "cyclonedx-json",
        "-q",
    ]


def scan(subject: str, platform: str) -> str:
    """Run the pinned syft image against a pushed manifest; retry once.

    Returns syft's CycloneDX JSON exactly as it printed it.
    """
    error = ""
    for attempt in range(1, SYFT_ATTEMPTS + 1):
        result = run(syft_command(subject, platform))
        if result.returncode == 0:
            return result.stdout
        error = result.stderr.strip()
        if attempt < SYFT_ATTEMPTS:
            time.sleep(RETRY_DELAY_SECONDS)
    raise SbomError(f"syft failed for {subject} ({platform}): {error}")


def check_sbom(sbom: dict, name: str, digest: str) -> None:
    """The SBOM must be CycloneDX and describe exactly ``name@digest``."""
    component = (sbom.get("metadata") or {}).get("component") or {}
    if sbom.get("bomFormat") != "CycloneDX":
        raise SbomError(f"{name}@{digest}: not a CycloneDX document")
    if component.get("name") != name or component.get("version") != digest:
        recorded = f"{component.get('name')}@{component.get('version')}"
        raise SbomError(f"SBOM describes {recorded}, expected {name}@{digest}")
    if not sbom.get("components"):
        raise SbomError(f"{name}@{digest}: SBOM lists no components")


def index_bom(name: str, index_digest: str, platforms: dict, files: dict, now: datetime) -> dict:
    """CycloneDX BOM for the index: its platform manifests, by digest."""
    children = [
        {
            "bom-ref": plat,
            "type": "container",
            "name": name,
            "version": digest,
            "properties": [
                {"name": "oci:platform", "value": plat},
                {"name": "argus:sbom", "value": files[plat]},
            ],
        }
        for plat, digest in platforms.items()
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'{name}@{index_digest}')}",
        "version": 1,
        "metadata": {
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "argus image_sboms"}]},
            "component": {
                "bom-ref": INDEX_VARIANT,
                "type": "container",
                "name": name,
                "version": index_digest,
                "properties": [{"name": "oci:mediaType", "value": "image index"}],
            },
        },
        "components": children,
        "dependencies": [{"ref": INDEX_VARIANT, "dependsOn": list(platforms)}],
    }


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def generate_image(image: str, index_digest: str, args, now: datetime) -> list[dict]:
    name = f"{args.registry}/{image}"
    out_dir = Path(args.out_dir)
    raw = fetch_index(f"{name}@{index_digest}")
    platforms = platform_digests(raw, index_digest)
    files = {p: sbom_name(image, args.sha12, variant_of(p)) for p in platforms}
    subjects = []
    for plat, digest in platforms.items():
        raw_sbom = scan(f"{name}@{digest}", plat)
        check_sbom(json.loads(raw_sbom), name, digest)
        (out_dir / files[plat]).write_text(raw_sbom, encoding="utf-8")
        subjects.append(subject_entry(image, variant_of(plat), name, digest, files[plat], plat))
    index_file = sbom_name(image, args.sha12, INDEX_VARIANT)
    write_json(out_dir / index_file, index_bom(name, index_digest, platforms, files, now))
    subjects.append(subject_entry(image, INDEX_VARIANT, name, index_digest, index_file, None))
    return subjects


def subject_entry(image, variant, name, digest, sbom, platform) -> dict:
    return {
        "image": image,
        "variant": variant,
        "platform": platform,
        "subject_name": name,
        "subject_digest": digest,
        "sbom": sbom,
        "bundle": f"{sbom}.sigstore.json",
        "step_id": step_id(image, variant),
    }


def export_env(subjects: list[dict], out_dir: Path) -> list[str]:
    lines = []
    for s in subjects:
        key = env_key(s["image"], s["variant"])
        lines.append(f"SBOM_{key}_DIGEST={s['subject_digest']}")
        lines.append(f"SBOM_{key}_PATH={(out_dir / s['sbom']).resolve()}")
    github_env = os.environ.get("GITHUB_ENV")
    if github_env:
        with open(github_env, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    return lines


def parse_image_arg(value: str) -> tuple[str, str]:
    image, sep, digest = value.partition("@")
    if not sep or not image or not digest.startswith("sha256:"):
        raise argparse.ArgumentTypeError(f"expected <image>@sha256:<hex>, got {value!r}")
    return image, digest


def cmd_generate(args, now: datetime | None = None) -> int:
    now = now or datetime.now(UTC)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    subjects = [s for image, digest in args.image for s in generate_image(image, digest, args, now)]
    write_json(out_dir / manifest_name(args.sha12), {"sha12": args.sha12, "subjects": subjects})
    export_env(subjects, out_dir)
    for s in subjects:
        print(f"{s['sbom']}: {s['subject_name']}@{s['subject_digest']}")
    return 0


def read_statement(bundle_path: Path) -> dict:
    lines = [ln for ln in bundle_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if len(lines) != 1:
        raise SbomError(f"{bundle_path}: expected one bundle, found {len(lines)}")
    envelope = json.loads(lines[0]).get("dsseEnvelope") or {}
    if envelope.get("payloadType") != IN_TOTO_PAYLOAD:
        raise SbomError(f"{bundle_path}: not an in-toto DSSE bundle")
    return json.loads(base64.b64decode(envelope["payload"]))


def check_bundle(bundle_path: Path, subject: dict, sbom: dict) -> None:
    """The bundle must sign exactly this subject with this SBOM."""
    statement = read_statement(bundle_path)
    expected = [{
        "name": subject["subject_name"],
        "digest": {"sha256": subject["subject_digest"].removeprefix("sha256:")},
    }]
    if statement.get("subject") != expected:
        raise SbomError(f"{subject['step_id']}: bundle subject {statement.get('subject')}")
    if statement.get("predicateType") != CYCLONEDX_PREDICATE:
        raise SbomError(f"{subject['step_id']}: predicate type {statement.get('predicateType')}")
    if statement.get("predicate") != sbom:
        raise SbomError(f"{subject['step_id']}: signed predicate is not {subject['sbom']}")


def cmd_collect(args) -> int:
    out_dir = Path(args.out_dir)
    manifest = json.loads((out_dir / manifest_name(args.sha12)).read_text(encoding="utf-8"))
    steps = json.loads(os.environ.get("ATTEST_STEPS") or "{}")
    for subject in manifest["subjects"]:
        bundle = ((steps.get(subject["step_id"]) or {}).get("outputs") or {}).get("bundle-path")
        if not bundle:
            raise SbomError(f"no attest step '{subject['step_id']}' output for {subject['sbom']}")
        sbom = json.loads((out_dir / subject["sbom"]).read_text(encoding="utf-8"))
        check_bundle(Path(bundle), subject, sbom)
        shutil.copyfile(bundle, out_dir / subject["bundle"])
        print(f"{subject['bundle']}: signed {subject['subject_name']}@{subject['subject_digest']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate", help="Generate SBOMs for pushed images")
    gen.add_argument("--image", action="append", required=True, type=parse_image_arg,
                     help="<image>@<index digest>, repeatable")
    gen.add_argument("--registry", required=True, help="e.g. ghcr.io/huntridge-labs/argus")
    collect = sub.add_parser("collect", help="Check and collect attestation bundles")
    for p in (gen, collect):
        p.add_argument("--sha12", required=True, help="First 12 chars of the commit SHA")
        p.add_argument("--out-dir", required=True, help="Directory for the SBOM files")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = cmd_generate if args.command == "generate" else cmd_collect
    try:
        return handler(args)
    except (SbomError, OSError, ValueError, KeyError) as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
