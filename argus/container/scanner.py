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
from .resources import is_image_local

logger = logging.getLogger("argus.container")


def _normalize_image_ref(ref: str) -> str:
    """Return the ``host/path`` portion of an image ref, stripping tag + digest.

    Examples:
      ``registry1.dso.mil/org/repo@sha256:abc``    → ``registry1.dso.mil/org/repo``
      ``registry1.dso.mil/org/repo:1.2.3``          → ``registry1.dso.mil/org/repo``
      ``localhost:5000/org/repo:1.2.3@sha256:abc`` → ``localhost:5000/org/repo``

    Only the LAST path component's ``:`` and ``@`` are stripped, so a
    host that includes a port (``localhost:5000``) keeps its port —
    the colon in the first path component is part of the host, not a
    tag separator.
    """
    parts = ref.split("/")
    last = parts[-1]
    last = last.split("@", 1)[0]
    last = last.split(":", 1)[0]
    parts[-1] = last
    return "/".join(parts)


def _is_path_component_prefix(prefix: str, full: str) -> bool:
    """True iff ``prefix`` is a path-component prefix of ``full``.

    The boundary check rules out string-prefix false matches:
    ``registry1.dso.mil/ironbank/restricted`` matches
    ``registry1.dso.mil/ironbank/restricted/foo`` but NOT
    ``registry1.dso.mil/ironbank/restrictedX/foo``. Without this guard
    a typo in the more-specific key would silently match a sibling
    repo with similar name.
    """
    if not prefix:
        return False
    if full == prefix:
        return True
    return full.startswith(prefix + "/")


def _resolve_user_pass(
    config: dict,
    user_field: str = "registry_username",
    pass_field: str = "registry_password",
) -> tuple[str | None, str | None]:
    """Resolve a username/password field pair via the shared secrets resolver.

    Honors ``*_env`` env-var references, literal forms, and the
    ``--registry-password-stdin`` slot in precedence order — matching
    every other credential-bearing scanner in argus.

    The defaults (``registry_username`` / ``registry_password``) match
    the top-of-``containers``-block shortcut shape. Per-registry
    entries inside ``registry_auth`` use the prefix-less ``username``
    / ``password`` field names (the ``registry_`` prefix is implied
    by context); callers pass those as the optional field-name
    arguments.
    """
    from argus.core.secrets import get_stdin_override, resolve_secret

    username = resolve_secret(config, user_field)
    password = resolve_secret(
        config, pass_field,
        stdin_override=get_stdin_override("registry_password"),
    )
    return username, password


def _resolve_registry_auth(
    config: dict, image_ref: str,
) -> tuple[str | None, str | None]:
    """Resolve (username, password) for ``image_ref`` using the config.

    Matching order:

    1. Walk ``containers.registry_auth`` for keys that are
       path-component prefixes of the normalized ``image_ref``.
       The LONGEST matching key wins (most specific entry).
       ``registry1.dso.mil/ironbank/restricted`` beats
       ``registry1.dso.mil`` when both match.
    2. If no map entry matches, fall through to the top-level
       ``registry_username`` / ``registry_password`` fields — the
       legacy single-default shape, still supported as a shortcut
       for "use these creds for every image."
    3. If a map entry matches but its credentials resolve to
       ``None`` (typically because the referenced env var is
       unset), surface a WARNING naming the missing env var and
       return ``(None, None)``. We deliberately do NOT fall back
       to the bare-default in this case — silently broadening the
       auth surface against a repo the user explicitly marked as
       needing different creds is a privilege-misuse risk. Same
       rule k8s ``imagePullSecrets`` follows: if the configured
       secret doesn't resolve, the pull fails, it doesn't try
       other secrets.
    """
    auth_map = config.get("registry_auth") or {}
    normalized = _normalize_image_ref(image_ref)

    best_key: str | None = None
    for key in auth_map:
        if not isinstance(key, str):
            continue
        if _is_path_component_prefix(key, normalized):
            if best_key is None or len(key) > len(best_key):
                best_key = key

    if best_key is None:
        # No specific match → bare-default shortcut at top of containers block.
        return _resolve_user_pass(config)

    entry = auth_map[best_key]
    if not isinstance(entry, dict):
        logger.warning(
            "registry_auth[%r] is not a mapping; skipping (got %s)",
            best_key, type(entry).__name__,
        )
        return None, None

    username, password = _resolve_user_pass(
        entry, user_field="username", pass_field="password",
    )

    if (entry.get("username_env") or entry.get("username")) and not username:
        logger.warning(
            "registry_auth[%s]: username unresolved (check that %s is exported)",
            best_key, entry.get("username_env", "the configured env var"),
        )
    if (entry.get("password_env") or entry.get("password")) and not password:
        logger.warning(
            "registry_auth[%s]: password unresolved (check that %s is exported)",
            best_key, entry.get("password_env", "the configured env var"),
        )

    return username, password


def _registry_auth_env(
    config: dict | None, image_ref: str | None = None,
) -> dict[str, str]:
    """Resolve registry credentials and map them to per-tool env vars.

    Reads from one of two locations under ``config``:

    * ``registry_auth`` — a registry/path-prefix-keyed map of
      credential blocks (preferred for multi-registry setups). The
      best match for ``image_ref`` (longest path-component prefix)
      provides the credentials.
    * ``registry_username`` / ``registry_password`` at the top of
      the config — the legacy single-default shape, used when no
      map entry matches.

    The resolved values are mapped to the env-var names each
    sub-scanner natively reads for registry auth (``TRIVY_USERNAME`` /
    ``TRIVY_PASSWORD`` for Trivy,
    ``GRYPE_REGISTRY_AUTH_USERNAME`` / ``GRYPE_REGISTRY_AUTH_PASSWORD``
    for Grype, ``SYFT_REGISTRY_AUTH_USERNAME`` /
    ``SYFT_REGISTRY_AUTH_PASSWORD`` for Syft). Returning the same value
    under multiple tool-specific names is deliberate: every
    ``docker run`` invocation forwards the full set, and each
    sub-scanner ignores names it doesn't recognize. That keeps the
    call sites identical and avoids per-tool branching on every
    cmd build.

    ``image_ref=None`` skips the registry-map path entirely — used by
    helper-level unit tests that exercise the single-default shape
    without manufacturing an image ref.

    Returns an empty dict when no credentials are configured —
    callers treat that as "anonymous pull" and emit no ``-e`` flags.
    """
    if not config:
        return {}

    if image_ref is not None:
        username, password = _resolve_registry_auth(config, image_ref)
    else:
        username, password = _resolve_user_pass(config)

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


def _redact_cmd_for_log(cmd: list[str]) -> str:
    """Return a debug-friendly string of a ``docker run`` argv with
    credential values masked.

    Operates on the flat ``-e VAR=value`` pairs produced by
    ``_docker_env_flags``. Anything other than the credential env vars
    we recognize is passed through untouched so the user can still
    inspect mount paths, image refs, and scanner flags. We mask the
    value, not the variable name — debugging is impossible without
    being able to see which vars are present.
    """
    safe: list[str] = []
    skip_next = False
    creds = {
        "TRIVY_USERNAME", "TRIVY_PASSWORD",
        "GRYPE_REGISTRY_AUTH_USERNAME", "GRYPE_REGISTRY_AUTH_PASSWORD",
        "SYFT_REGISTRY_AUTH_USERNAME", "SYFT_REGISTRY_AUTH_PASSWORD",
    }
    for i, token in enumerate(cmd):
        if skip_next:
            skip_next = False
            continue
        if token == "-e" and i + 1 < len(cmd) and "=" in cmd[i + 1]:
            name, _, value = cmd[i + 1].partition("=")
            if name in creds:
                safe.append(f"-e {name}=***REDACTED***")
            else:
                safe.append(f"-e {name}={value}")
            skip_next = True
        else:
            safe.append(token)
    return " ".join(safe)


def _resolve_sub_scanner_image(image_ref: str, config: dict | None) -> str:
    """Apply ``execution.registry`` / ``execution.registry_map`` rewrites
    to a sub-scanner image reference (Trivy / Grype / Syft).

    The source-scan engine already routes through
    ``ArgusEngine._resolve_image`` for the same effect, but the
    container-scan path used to pull raw upstream refs regardless of
    config. This helper reads the synthetic keys
    ``_execution_registry`` / ``_execution_registry_map`` stashed by
    ``argus.cli._load_container_config`` and delegates to the shared
    pure-function resolver — same algorithm, same logging shape,
    same back-compat fallthrough.

    Returns the original ``image_ref`` unchanged when no mirror config
    is in play, so the no-mirror case sees zero behavior change.
    Issue #186.
    """
    if not image_ref or not config:
        return image_ref
    from argus.core.engine import resolve_image_ref

    return resolve_image_ref(
        image_ref,
        registry=config.get("_execution_registry"),
        registry_map=config.get("_execution_registry_map"),
    )


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

    # Determine if the image is local (built by us) or remote.
    #
    # An image counts as local — and so must be scanned via the
    # ``docker:`` daemon source rather than resolved against a registry —
    # in two cases:
    #   1. We built it from a Dockerfile this run (``target.dockerfile``).
    #   2. It was built or loaded by an earlier step and handed to us by
    #      ref. CI commonly builds a throwaway tag (``app:scan-<sha>``)
    #      then calls ``argus scan container --image app:scan-<sha>``.
    #      There's no Dockerfile on the target, but the image is sitting
    #      in the local daemon. Without this check ``is_local`` is False,
    #      grype/trivy fall through to the ``registry:`` source, and the
    #      never-pushed dev tag resolves to ``docker.io/library/...`` →
    #      ``UNAUTHORIZED: authentication required`` (issue #233).
    #
    # The daemon probe (``docker image inspect``) is skipped when we
    # already know we built the image, avoiding a redundant subprocess.
    built_here = target.dockerfile is not None
    is_local = built_here or is_image_local(target.image_ref)

    # Transparency breadcrumb: when a ref we did NOT build is found in the
    # local daemon, we scan that local copy and skip the registry pull
    # (and any configured registry auth). That's the intended fix for
    # never-pushed build tags (#233), but for a fully-qualified registry
    # ref it also means a *stale* local copy would be scanned instead of
    # the current registry manifest. Log it so operators can see which
    # source was used rather than silently diverging from the registry.
    if is_local and not built_here:
        logger.info(
            "Image %s found in the local Docker daemon; scanning the local "
            "copy via the docker-daemon source (not pulling from a registry)",
            target.image_ref,
        )

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

        image = _resolve_sub_scanner_image(get_image("trivy"), config)
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
    auth_env = {} if local else _registry_auth_env(config, image_ref)

    if use_container:
        from argus import container_runtime
        from argus.containers import get_image

        rt = container_runtime.runtime_cmd()
        image = _resolve_sub_scanner_image(get_image("trivy"), config)

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

    logger.debug("trivy invocation: %s", _redact_cmd_for_log(cmd))
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

        image = _resolve_sub_scanner_image(get_image("grype"), config)
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
    # Grype's CLI defaults to the local-daemon source even for refs
    # that obviously can't exist on the daemon (digest-pinned remote
    # images, registry-prefixed names). When running inside the
    # ``anchore/grype`` container we have no docker.sock and no
    # podman either, so the daemon path fails immediately and Grype
    # never falls back to the ``registry:`` source on its own.
    # Force the registry source explicitly for remote scans — that's
    # the source that consults ``GRYPE_REGISTRY_AUTH_*`` for auth.
    if local:
        grype_target = f"docker:{image_ref}"
    else:
        grype_target = f"registry:{image_ref}"

    # Resolve registry credentials. Empty for locally-built images
    # (no registry pull needed) or when no creds are configured.
    auth_env = {} if local else _registry_auth_env(config, image_ref)

    if use_container:
        from argus import container_runtime
        from argus.containers import get_image

        rt = container_runtime.runtime_cmd()
        image = _resolve_sub_scanner_image(get_image("grype"), config)

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

    logger.debug("grype invocation: %s", _redact_cmd_for_log(cmd))
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
    auth_env = {} if local else _registry_auth_env(config, image_ref)

    if shutil.which("syft") is None:
        from argus import container_runtime
        from argus.containers import get_image

        image = _resolve_sub_scanner_image(get_image("syft"), config)
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
