"""Scan container images with trivy and grype, deduplicate findings."""

import json
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from argus.core.models import Finding, Severity
from argus.scanners.container import ContainerScanner

from .discovery import ContainerTarget

logger = logging.getLogger("argus.container")


def _registry_auth_env(config: dict | None) -> dict[str, str]:
    """Resolve registry credentials and map them to per-tool env vars.

    Reads ``registry_username`` / ``registry_password`` from ``config``
    via ``argus.core.secrets.resolve_secret`` (preferring the ``*_env``
    references over literals, with stdin overriding both). Returns the
    env-var names each sub-scanner natively reads for registry auth:
    ``TRIVY_USERNAME`` / ``TRIVY_PASSWORD`` for Trivy,
    ``GRYPE_REGISTRY_AUTH_USERNAME`` / ``GRYPE_REGISTRY_AUTH_PASSWORD``
    for Grype, ``SYFT_REGISTRY_AUTH_USERNAME`` /
    ``SYFT_REGISTRY_AUTH_PASSWORD`` for Syft.

    Returning the same value under multiple tool-specific names is
    deliberate: every ``docker run`` invocation forwards the full set,
    and each sub-scanner ignores names it doesn't recognize. That keeps
    the call sites identical and avoids per-tool branching on every
    cmd build.

    Returns an empty dict when no credentials are configured —
    callers treat that as "anonymous pull" and emit no ``-e`` flags.
    """
    if not config:
        return {}

    from argus.core.secrets import get_stdin_override, resolve_secret

    username = resolve_secret(config, "registry_username")
    password = resolve_secret(
        config, "registry_password",
        stdin_override=get_stdin_override("registry_password"),
    )

    env: dict[str, str] = {}
    if username:
        env["TRIVY_USERNAME"] = username
        env["GRYPE_REGISTRY_AUTH_USERNAME"] = username
        env["SYFT_REGISTRY_AUTH_USERNAME"] = username
    if password:
        env["TRIVY_PASSWORD"] = password
        env["GRYPE_REGISTRY_AUTH_PASSWORD"] = password
        env["SYFT_REGISTRY_AUTH_PASSWORD"] = password
    return env


def _docker_env_flags(env: dict[str, str]) -> list[str]:
    """Convert an env dict to ``-e VAR=value`` flags for ``docker run``.

    ``docker run`` doesn't auto-forward host env vars into the
    container; each one needs an explicit ``-e`` flag. We use the
    ``VAR=value`` inline form so the resolved value travels with the
    flag — name-only forwarding (``-e VAR``) would require the caller
    to also configure the host env var.
    """
    flags: list[str] = []
    for k, v in env.items():
        flags += ["-e", f"{k}={v}"]
    return flags


def _subprocess_env(auth_env: dict[str, str]) -> dict[str, str] | None:
    """Build the env dict for ``subprocess.run`` covering the local-binary path.

    Locally-installed Trivy / Grype / Syft read their credential env
    vars from the parent process's environment. When ``auth_env`` is
    non-empty we layer it on top of ``os.environ`` so the resolved
    credentials reach the subprocess even if the user hasn't exported
    the tool-specific names themselves. ``None`` lets ``subprocess.run``
    inherit the host environment unchanged — the historical behavior.
    """
    if not auth_env:
        return None
    return {**os.environ, **auth_env}

# Shared parser instance — reuses ContainerScanner's parsing logic
_parser = ContainerScanner()


@dataclass
class ContainerScanResult:
    """Results for a single container image scan.

    ``dockerfile`` and ``context`` capture the source the image was
    built from — empty strings for remote-pull entries, populated for
    local builds. Without these, downstream artifacts (argus-results.
    json, per-image markdown, SARIF, audit manifest) only carry the
    auto-derived tag like ``scanner-bandit:argus-scan``, which is
    meaningless to a security reviewer asking "which Dockerfile
    produced this finding?". Plumbing them through here lets every
    consumer surface a real source path alongside the image.
    """

    name: str
    image_ref: str
    digest: str = ""
    dockerfile: str = ""
    context: str = ""
    trivy_findings: list[Finding] = field(default_factory=list)
    grype_findings: list[Finding] = field(default_factory=list)
    exposure_findings: list[Finding] = field(default_factory=list)
    services_findings: list[Finding] = field(default_factory=list)
    combined_findings: list[Finding] = field(default_factory=list)
    build_success: bool = True
    scan_error: str = ""
    scanner_errors: dict[str, str] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return self._count_severity(Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return self._count_severity(Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return self._count_severity(Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return self._count_severity(Severity.LOW)

    @property
    def total_count(self) -> int:
        return len(self.combined_findings)

    @property
    def unique_count(self) -> int:
        """Count of unique CVEs in combined findings."""
        cves = {f.cve for f in self.combined_findings if f.cve}
        non_cve_count = sum(
            1 for f in self.combined_findings if not f.cve
        )
        return len(cves) + non_cve_count

    def _count_severity(self, severity: Severity) -> int:
        return sum(
            1 for f in self.combined_findings if f.severity == severity
        )


@dataclass
class ContainerScanSummary:
    """Aggregated results across all container images."""

    results: list[ContainerScanResult] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(r.critical_count for r in self.results)

    @property
    def high_count(self) -> int:
        return sum(r.high_count for r in self.results)

    @property
    def medium_count(self) -> int:
        return sum(r.medium_count for r in self.results)

    @property
    def low_count(self) -> int:
        return sum(r.low_count for r in self.results)

    @property
    def total_count(self) -> int:
        return sum(r.total_count for r in self.results)

    @property
    def unique_count(self) -> int:
        """Deduplicated CVE count across all images."""
        cves: set[str] = set()
        non_cve_count = 0
        for result in self.results:
            for finding in result.combined_findings:
                if finding.cve:
                    cves.add(finding.cve)
                else:
                    non_cve_count += 1
        return len(cves) + non_cve_count

    @property
    def container_count(self) -> int:
        return len(self.results)

    @property
    def build_failures(self) -> int:
        return sum(1 for r in self.results if not r.build_success)

    @property
    def scan_failures(self) -> int:
        return sum(1 for r in self.results if r.scanner_errors)


def scan_image(
    target: ContainerTarget,
    scanners: tuple[str, ...] = (
        "trivy", "grype", "exposure", "services",
    ),
    sbom: bool = True,
    raw_output_dir: Path | None = None,
    config: dict | None = None,
) -> ContainerScanResult:
    """Scan a single container image with the enabled sub-scanners.

    Sub-scanners:
      - ``trivy`` / ``grype`` — CVE scanning against the image's
        installed packages (deduplicated by CVE).
      - ``exposure`` — declared EXPOSE ports as INFO/MEDIUM findings
        (attack-surface visibility, no CVE component).
      - ``services`` — systemd / SysV units the image would launch
        on boot, INFO/MEDIUM by service name.

    For remote images (not built from a Dockerfile), trivy and grype
    scan directly from the registry without pulling the full image.
    This uses minimal disk — only the vulnerability DB and scan output.

    For locally-built images, scanners reference the local Docker daemon.
    Per-scanner errors are caught and recorded, not swallowed.

    ``raw_output_dir``: when supplied, the raw scanner output files
    (``trivy-results.json``, ``grype-results.json``, ``syft-sbom.json``,
    ``exposure-findings.json``, ``services-findings.json``) are copied
    into this directory before the temp dir is cleaned up. Lets users
    preserve full per-scanner artifacts for forensics, audit, or manual
    triage workflows alongside the canonical ``argus-results.json``.
    ``None`` (the default) means transient output — historic behavior.

    ``config``: forwarded to the ``exposure`` and ``services`` helpers
    so config knobs (``expose_warn_ports``, ``expose_ignore_ports``,
    ``services_warn``, ``services_ignore``) take effect. Ignored by
    trivy / grype / syft, which have no equivalent knobs at this layer.
    """
    import shutil as _shutil  # local import to avoid shadowing the
                              # module-level ``shutil`` reference used
                              # by ``shutil.which`` checks below.

    cfg = config or {}
    trivy_findings: list[Finding] = []
    grype_findings: list[Finding] = []
    exposure_findings: list[Finding] = []
    services_findings: list[Finding] = []
    scanner_errors: dict[str, str] = {}

    # Determine if the image is local (built by us) or remote
    is_local = target.dockerfile is not None

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        if "trivy" in scanners:
            try:
                trivy_findings = _run_trivy(
                    target.image_ref, tmp_path, local=is_local, config=cfg,
                )
            except RuntimeError as exc:
                logger.error("trivy scan failed for %s: %s", target.image_ref, exc)
                scanner_errors["trivy"] = str(exc)

        if "grype" in scanners:
            try:
                grype_findings = _run_grype(
                    target.image_ref, tmp_path, local=is_local, config=cfg,
                )
            except RuntimeError as exc:
                logger.error("grype scan failed for %s: %s", target.image_ref, exc)
                scanner_errors["grype"] = str(exc)

        if sbom and "syft" not in scanners:
            _run_syft(target.image_ref, tmp_path, local=is_local, config=cfg)

        # Attack-surface sub-scanners. They take an image ref + a
        # config dict, run locally (no DB pulls), and return
        # ``(findings, metadata)``. Metadata is dropped here — the
        # canonical ``argus-results.json`` already carries per-scanner
        # status, and these helpers don't error out: they just return
        # zero findings when there's nothing to report.
        if "exposure" in scanners:
            try:
                exposure_findings, _meta = _parser._scan_exposed_ports(
                    target.image_ref, cfg,
                )
            except Exception as exc:  # pylint: disable=broad-except
                logger.error(
                    "exposure scan failed for %s: %s",
                    target.image_ref, exc,
                )
                scanner_errors["exposure"] = str(exc)

        if "services" in scanners:
            try:
                services_findings, _meta = _parser._scan_services(
                    target.image_ref, cfg,
                )
            except Exception as exc:  # pylint: disable=broad-except
                logger.error(
                    "services scan failed for %s: %s",
                    target.image_ref, exc,
                )
                scanner_errors["services"] = str(exc)

        # Persist raw scanner artifacts (best-effort) before the
        # tempdir is wiped. We copy whatever files exist; missing
        # files (e.g. grype failed before writing) just don't get
        # copied — the structured ``scanner_errors`` already records
        # why. Errors during copy are non-fatal: the scan succeeded,
        # the canonical JSON is still emitted upstream.
        if raw_output_dir is not None:
            try:
                raw_output_dir.mkdir(parents=True, exist_ok=True)
                for fname in (
                    "trivy-results.json",
                    "grype-results.json",
                    "syft-sbom.json",
                ):
                    src = tmp_path / fname
                    if src.exists() and src.stat().st_size > 0:
                        _shutil.copy2(src, raw_output_dir / fname)
                # Exposure / services have no upstream JSON file —
                # write a structured snapshot of their findings so
                # forensic consumers see the same per-sub-scanner
                # layout as trivy / grype.
                for fname, found in (
                    ("exposure-findings.json", exposure_findings),
                    ("services-findings.json", services_findings),
                ):
                    if found:
                        (raw_output_dir / fname).write_text(
                            json.dumps(
                                [f.to_dict() for f in found],
                                indent=2,
                            )
                        )
            except OSError as exc:
                logger.warning(
                    "Failed to persist raw scanner outputs to %s: %s",
                    raw_output_dir, exc,
                )

    combined = deduplicate_findings(
        trivy_findings, grype_findings,
        extra=[*exposure_findings, *services_findings],
    )

    return ContainerScanResult(
        name=target.name,
        image_ref=target.image_ref,
        dockerfile=str(target.dockerfile) if target.dockerfile else "",
        context=str(target.context) if target.context else "",
        trivy_findings=trivy_findings,
        grype_findings=grype_findings,
        exposure_findings=exposure_findings,
        services_findings=services_findings,
        combined_findings=combined,
        scanner_errors=scanner_errors,
    )


def deduplicate_findings(
    trivy: list[Finding],
    grype: list[Finding],
    extra: list[Finding] | None = None,
) -> list[Finding]:
    """Merge and deduplicate findings from multiple scanners by CVE ID.

    Trivy findings take precedence when a CVE appears in both lists.
    Findings without CVE IDs are always included.

    ``extra`` is appended verbatim — used by attack-surface sub-scanners
    (exposure, services) whose finding identity is the port or service
    name, not a CVE, so CVE-based dedup doesn't apply.
    """
    combined: list[Finding] = []
    seen_cves: set[str] = set()

    # Trivy findings first (they take precedence)
    for finding in trivy:
        if finding.cve:
            if finding.cve in seen_cves:
                continue
            seen_cves.add(finding.cve)
        combined.append(finding)

    # Grype findings, skipping duplicates
    for finding in grype:
        if finding.cve:
            if finding.cve in seen_cves:
                continue
            seen_cves.add(finding.cve)
        combined.append(finding)

    if extra:
        combined.extend(extra)

    return combined


_DOCKER_SOCK = Path("/var/run/docker.sock")


def _container_vol_args(
    tmp_path: Path, cache_scanner: str, mount_docker_sock: bool = False,
) -> list[str]:
    """Build standard volume arguments for a container-mode sub-scanner.

    Includes: output dir, optional DB cache, optional docker.sock mount
    (needed when scanning locally-built images visible only to the host daemon).
    """
    from argus.containers import get_cache_mount

    args = ["-v", f"{tmp_path}:/output"]

    cache = get_cache_mount(cache_scanner)
    if cache:
        host_dir, container_dir = cache
        args.extend(["-v", f"{host_dir}:{container_dir}"])

    if mount_docker_sock and _DOCKER_SOCK.exists():
        args.extend(["-v", f"{_DOCKER_SOCK}:{_DOCKER_SOCK}:ro"])

    return args


def _validate_scanner_output(
    scanner_name: str,
    output_file: Path,
    result,
) -> None:
    """Raise RuntimeError when a sub-scanner's run looks unhealthy.

    Container sub-scanners (trivy, grype) all hand off via the same
    "subprocess writes JSON to a file path, we parse it" contract.
    They all have the same failure modes:

    1. subprocess exits non-zero — DB pull failed, image not
       resolvable, registry auth missing, etc. Anything that prints
       to stderr and bails before producing meaningful output.
    2. output file isn't there — scanner crashed mid-run.
    3. output file exists but is 0 bytes — common when a wrapper
       process (e.g. ``docker run --rm``) exits non-zero from a
       different stage than the scanner itself, leaving a stub
       file from the redirect.

    All three modes need to surface the scanner's own stderr (clipped
    for terminal sanity), use ERROR-level logging without dumping a
    Python traceback, and raise a single ``RuntimeError`` shape so
    the caller can record it under ``scanner_errors`` consistently.

    JSON parse failure is intentionally NOT validated here — every
    sub-scanner uses a different parser, so the per-runner caller
    owns that check (and translates exceptions into RuntimeError
    via the same shape).
    """
    stderr = result.stderr.strip()[:500] if result.stderr else ""
    stderr_label = stderr or "no stderr"

    if result.returncode != 0:
        logger.error(
            "%s exited non-zero (%d): %s",
            scanner_name, result.returncode, stderr_label,
        )
        raise RuntimeError(
            f"{scanner_name} scan failed (exit {result.returncode}): "
            f"{stderr or 'no output'}"
        )

    if not output_file.exists():
        logger.error(
            "%s produced no output file (exit %d): %s",
            scanner_name, result.returncode, stderr_label,
        )
        raise RuntimeError(
            f"{scanner_name} scan produced no output file "
            f"(exit {result.returncode}): {stderr or 'no output'}"
        )

    if output_file.stat().st_size == 0:
        logger.error(
            "%s produced 0-byte output (exit %d): %s",
            scanner_name, result.returncode, stderr_label,
        )
        raise RuntimeError(
            f"{scanner_name} scan produced empty output file "
            f"(exit {result.returncode}): {stderr or 'no output'}"
        )


def _run_trivy(
    image_ref: str, tmp_path: Path, local: bool = False,
    config: dict | None = None,
) -> list[Finding]:
    """Run trivy and parse results.

    Tries local binary first, falls back to Docker container image
    when trivy is not installed and a container runtime is available.
    When using containers, pre-warms the vulnerability DB in a separate
    step so the DB download progress doesn't corrupt scan output.
    When local=False, trivy scans directly from the registry without
    pulling the image — minimal disk usage.
    """
    import subprocess
    from argus.containers import get_cache_mount

    output_file = tmp_path / "trivy-results.json"
    use_container = False

    if shutil.which("trivy") is None:
        from argus import container_runtime
        from argus.containers import get_image

        image = get_image("trivy")
        if not image or not container_runtime.is_available():
            logger.warning("trivy not available (local or container) — skipping")
            return []
        if not container_runtime.pull_image(image):
            logger.error("Failed to pull trivy image: %s", image)
            return []
        use_container = True
        logger.info("Running trivy via container: %s", image)

    # Resolve registry credentials. Empty for locally-built images
    # (no registry pull needed) or when no creds are configured.
    auth_env = {} if local else _registry_auth_env(config)

    if use_container:
        from argus import container_runtime
        from argus.containers import get_image

        rt = container_runtime.runtime_cmd()
        image = get_image("trivy")

        # Mount docker.sock when scanning local images so trivy can
        # see images on the host daemon
        vol_args = _container_vol_args(tmp_path, "trivy", mount_docker_sock=local)

        # Pre-warm the DB so the download progress doesn't mix with scan output
        logger.info("Updating trivy vulnerability DB...")
        db_cmd = [rt, "run", "--rm"] + vol_args + [
            image, "image", "--download-db-only",
        ]
        db_result = subprocess.run(db_cmd, capture_output=True, text=True, timeout=300)
        if db_result.returncode != 0:
            logger.warning(
                "Trivy DB download failed (exit %d), scan may still work with cached DB",
                db_result.returncode,
            )

        # Run actual scan with --skip-db-update (DB already warm). Cred
        # flags go on the scan step only; DB download pulls from public
        # ghcr.io and doesn't need (or use) registry auth.
        cmd = [rt, "run", "--rm"] + _docker_env_flags(auth_env) + vol_args + [
            image,
            "image", "--format", "json",
            "--output", "/output/trivy-results.json",
            "--skip-db-update",
        ]
        if not local:
            cmd.extend(["--image-src", "remote"])
        cmd.append(image_ref)
    else:
        cmd = [
            "trivy", "image",
            "--format", "json",
            "--output", str(output_file),
        ]
        if not local:
            cmd.extend(["--image-src", "remote"])
        cmd.append(image_ref)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
            env=_subprocess_env(auth_env),
        )
    except subprocess.TimeoutExpired:
        logger.error("trivy timed out scanning %s", image_ref)
        return []
    except FileNotFoundError:
        logger.error("trivy binary not found")
        return []

    _validate_scanner_output("trivy", output_file, result)

    try:
        return _parser.parse_trivy_results(output_file)
    except json.JSONDecodeError as exc:
        logger.error("trivy output JSON parse error for %s: %s", image_ref, exc)
        raise RuntimeError(
            f"trivy output JSON parse error: {exc}"
        ) from exc
    except Exception as exc:
        # Non-decode parser errors (schema mismatch, missing keys) —
        # log without traceback and re-raise as RuntimeError so the
        # engine catches it as a structured scanner_errors entry.
        logger.error("trivy output parse error for %s: %s", image_ref, exc)
        raise RuntimeError(f"trivy output parse error: {exc}") from exc


def _run_grype(
    image_ref: str, tmp_path: Path, local: bool = False,
    config: dict | None = None,
) -> list[Finding]:
    """Run grype and parse results.

    Tries local binary first, falls back to Docker container image.
    When using containers, pre-warms the vulnerability DB so the
    download progress doesn't corrupt scan output.
    """
    import subprocess
    from argus.containers import get_cache_mount

    output_file = tmp_path / "grype-results.json"
    use_container = False

    if shutil.which("grype") is None:
        from argus import container_runtime
        from argus.containers import get_image

        image = get_image("grype")
        if not image or not container_runtime.is_available():
            logger.warning("grype not available (local or container) — skipping")
            return []
        if not container_runtime.pull_image(image):
            logger.error("Failed to pull grype image: %s", image)
            return []
        use_container = True
        logger.info("Running grype via container: %s", image)

    # Grype's CLI uses source-scheme prefixes (``docker:``, ``podman:``,
    # etc.). When we're scanning a locally-built image, force the
    # docker-daemon source by prepending ``docker:`` to the user's ref.
    # Two effects:
    #   (a) For "normal" refs like ``myapp:dev``, this reads as
    #       "use docker daemon, image ``myapp:dev``" — the desired path.
    #   (b) For refs that happen to collide with a scheme prefix
    #       (``docker:argus-scan`` etc.), the explicit prefix flips
    #       Grype's parser back to "scheme=docker, identifier=<the
    #       whole user ref>" — so the user's literal name is preserved
    #       and resolved against the local daemon, not mis-parsed as
    #       a scheme request.
    #
    # For remote (registry) scans we leave the ref untouched — that
    # path was working before, and forcing a local-daemon source for
    # an image that doesn't exist locally would itself break.
    grype_target = f"docker:{image_ref}" if local else image_ref

    # Resolve registry credentials. Empty for locally-built images
    # (no registry pull needed) or when no creds are configured.
    auth_env = {} if local else _registry_auth_env(config)

    if use_container:
        from argus import container_runtime
        from argus.containers import get_image

        rt = container_runtime.runtime_cmd()
        image = get_image("grype")

        # Mount docker.sock when scanning local images
        vol_args = _container_vol_args(tmp_path, "grype", mount_docker_sock=local)

        # Pre-warm the DB so download progress doesn't mix with scan output
        logger.info("Updating grype vulnerability DB...")
        db_cmd = [rt, "run", "--rm"] + vol_args + [image, "db", "update"]
        db_result = subprocess.run(db_cmd, capture_output=True, text=True, timeout=300)
        if db_result.returncode != 0:
            logger.warning(
                "Grype DB update failed (exit %d), scan may still work with cached DB",
                db_result.returncode,
            )

        # Cred flags on the scan step only — the DB update pulls from
        # public sources and ignores registry auth.
        cmd = [rt, "run", "--rm"] + _docker_env_flags(auth_env) + vol_args + [
            image, grype_target,
            "-o", "json",
            "--file", "/output/grype-results.json",
        ]
    else:
        cmd = [
            "grype", grype_target,
            "-o", "json",
            "--file", str(output_file),
        ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
            env=_subprocess_env(auth_env),
        )
    except subprocess.TimeoutExpired:
        logger.error("grype timed out scanning %s", image_ref)
        return []
    except FileNotFoundError:
        logger.error("grype binary not found")
        return []

    _validate_scanner_output("grype", output_file, result)

    try:
        return _parser.parse_grype_results(output_file)
    except json.JSONDecodeError as exc:
        # The user-reported regression: grype writes a 0-byte file
        # when its image-resolution / catalog step fails after the
        # output handle is created. Validation above catches that
        # branch first, but JSON-shape errors (truncated output,
        # malformed schema) still land here. Raise instead of
        # swallowing — the engine catches the RuntimeError and
        # records it under scanner_errors so the summary reflects
        # reality instead of silently dropping grype's contribution.
        logger.error("grype output JSON parse error for %s: %s", image_ref, exc)
        raise RuntimeError(
            f"grype output JSON parse error: {exc}"
        ) from exc
    except Exception as exc:
        logger.error("grype output parse error for %s: %s", image_ref, exc)
        raise RuntimeError(f"grype output parse error: {exc}") from exc


def _run_syft(
    image_ref: str, tmp_path: Path,
    local: bool = False, config: dict | None = None,
) -> None:
    """Run syft to generate an SBOM (best-effort).

    Tries local binary first, falls back to Docker container image.
    """
    import subprocess

    output_file = tmp_path / "syft-sbom.json"

    # Resolve registry credentials. Empty for locally-built images
    # (Syft reads them through docker.sock, no registry pull) or when
    # no creds are configured.
    auth_env = {} if local else _registry_auth_env(config)

    if shutil.which("syft") is None:
        from argus import container_runtime
        from argus.containers import get_image

        image = get_image("syft")
        if not image or not container_runtime.is_available():
            logger.debug("syft not available (local or container) — skipping SBOM")
            return
        if not container_runtime.pull_image(image):
            logger.debug("Failed to pull syft image — skipping SBOM")
            return

        logger.info("Running syft via container: %s", image)
        rt = container_runtime.runtime_cmd()
        # Syft needs docker.sock to read local images
        vol_args = _container_vol_args(tmp_path, "syft", mount_docker_sock=True)
        cmd = [rt, "run", "--rm"] + _docker_env_flags(auth_env) + vol_args + [
            image,
            image_ref,
            "-o", "cyclonedx-json",
            "--file", "/output/syft-sbom.json",
        ]
    else:
        cmd = [
            "syft", image_ref,
            "-o", "cyclonedx-json",
            "--file", str(output_file),
        ]

    try:
        subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
            env=_subprocess_env(auth_env),
        )
    except subprocess.TimeoutExpired:
        logger.warning("syft timed out generating SBOM for %s", image_ref)
    except FileNotFoundError:
        logger.debug("syft binary not found")
