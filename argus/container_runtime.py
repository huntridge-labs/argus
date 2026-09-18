"""Shared container runtime helpers for Docker/Podman/nerdctl.

Provides pull, inspect, and runtime detection that can be used by
both the engine and individual scanners (DAST, container scanner)
without duplicating logic.
"""

import json
import logging
import os
import shutil
import subprocess
import time

logger = logging.getLogger("argus")

# ── On the ``# nosec B603`` markers below ───────────────────────────
#
# Every subprocess call in this module passes an argv *list* with
# ``shell=False`` (the default), so image refs and platform strings —
# the only caller-influenced values — are argv elements and can never
# be re-parsed as shell syntax. A ref like ``foo; rm -rf /`` is handed
# to the runtime as one opaque argument and rejected by it as an
# invalid reference.
#
# argv[0] is always ``runtime_cmd()``, which resolves to one of
# docker / podman / nerdctl found on PATH, or to ``ARGUS_CONTAINER_RUNTIME``
# when that names a binary ``shutil.which`` can find. That env var is
# operator-supplied configuration at the same trust level as PATH
# itself: anyone able to set it for the argus process could equally
# prepend a directory to PATH. It is not attacker-controlled input in
# any threat model where the rest of argus is meaningful.
#
# B603 is bandit's blanket "you called subprocess" warning and cannot
# distinguish these from a genuine injection sink, so each site is
# marked individually with this rationale as the reference.

# Cache runtime detection across calls within a process
_cached_runtime: str | None = None


def detect_runtime() -> str | None:
    """Detect the available container runtime.

    Checks: ARGUS_CONTAINER_RUNTIME env var → docker → podman → nerdctl.
    Returns None if no runtime is found.  Result is cached for the process.
    """
    global _cached_runtime
    if _cached_runtime is not None:
        return _cached_runtime if _cached_runtime else None

    override = os.environ.get("ARGUS_CONTAINER_RUNTIME")
    if override and shutil.which(override):
        _cached_runtime = override
        return override

    for rt in ("docker", "podman", "nerdctl"):
        if shutil.which(rt):
            _cached_runtime = rt
            return rt

    _cached_runtime = ""  # negative cache
    return None


def runtime_cmd() -> str:
    """Return the runtime command name, defaulting to 'docker'."""
    return detect_runtime() or "docker"


def is_available() -> bool:
    """Check if any container runtime is available."""
    return detect_runtime() is not None


# How long to wait on a registry manifest read. The call is reached
# after every failed pull, so a registry that accepts the connection and
# then never answers — proxy blackhole, stale DNS behind a firewall —
# would otherwise hang ``argus scan container`` forever. There is no
# job-level timeout to fall back on in local CLI use.
_MANIFEST_TIMEOUT = 60


def _platform_blocks(data: object) -> list[dict]:
    """Yield the platform dicts in a manifest payload, whatever its shape.

    Three shapes are in play, because the runtimes disagree:

    - Docker ``manifest inspect --verbose`` — a list (multi-arch) or a
      single object (single-arch) of entries carrying ``Descriptor.platform``.
    - Podman ``manifest inspect`` — an OCI image index: a single object
      with a ``manifests`` array whose entries carry ``platform`` directly.
      Podman also rejects ``--verbose``, which is handled by the caller.
    - A bare OCI descriptor list, which some registries' tooling emits.
    """
    entries = data if isinstance(data, list) else [data]
    blocks: list[dict] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        nested = entry.get("manifests")
        if isinstance(nested, list):
            for sub_entry in nested:
                if isinstance(sub_entry, dict):
                    plat = sub_entry.get("platform")
                    if isinstance(plat, dict):
                        blocks.append(plat)
            continue
        descriptor = entry.get("Descriptor")
        plat = (
            descriptor.get("platform")
            if isinstance(descriptor, dict)
            else entry.get("platform")
        )
        if isinstance(plat, dict):
            blocks.append(plat)
    return blocks


def detect_image_platforms(image: str) -> list[str]:
    """Return the platforms ``image`` publishes, e.g. ``["linux/arm64"]``.

    Reads the registry manifest with ``<runtime> manifest inspect``,
    which reports a platform block for both single-arch images (one
    entry) and multi-arch manifest lists (one entry per architecture).
    Docker needs ``--verbose`` to emit the block and Podman rejects that
    flag entirely, so the flag is tried first and dropped on failure;
    :func:`_platform_blocks` then accepts either payload shape.
    Attestation entries — the ``unknown/unknown`` platform buildx
    attaches for provenance/SBOM — are filtered out; they are not
    pullable and would otherwise be picked as a retry candidate.

    Returns an empty list when the manifest cannot be read (no runtime,
    private registry without credentials, manifest command unsupported —
    nerdctl has no ``manifest inspect`` subcommand at all). Callers treat
    that as "no information", not as "no platforms"; pin
    ``containers.platform`` explicitly for those cases.
    """
    rt = runtime_cmd()
    name = os.path.basename(rt).lower()

    # nerdctl has no `manifest inspect` at all, so there is nothing to
    # ask. Returning early keeps a guaranteed-failing subprocess off the
    # pull-failure path, which ADR-038 is explicit about keeping cheap.
    if "nerdctl" in name:
        logger.debug(
            "%s has no 'manifest inspect' — no platform information for %s; "
            "set containers.platform to scan a foreign architecture",
            name, image,
        )
        return []

    # Docker needs --verbose to emit a platform block; Podman rejects the
    # flag outright. Branch on the runtime rather than probing twice, so
    # the common path costs exactly one call. An unrecognised runtime
    # (ARGUS_CONTAINER_RUNTIME can name anything on PATH) gets the Docker
    # form first and one retry without the flag.
    attempts = [[rt, "manifest", "inspect", image]]
    if "podman" not in name:
        attempts.insert(0, [rt, "manifest", "inspect", "--verbose", image])
        if "docker" in name:
            attempts.pop()  # docker: --verbose only, no second guess

    stdout = ""
    for argv in attempts:
        try:
            result = subprocess.run(  # nosec B603 — argv list, no shell; see module header
                argv, capture_output=True, text=True,
                timeout=_MANIFEST_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            logger.debug(
                "Timed out after %ds reading the manifest for %s",
                _MANIFEST_TIMEOUT, image,
            )
            return []
        except OSError as exc:
            logger.debug("Could not run %s: %s", " ".join(argv[:3]), exc)
            return []
        if result.returncode == 0:
            stdout = result.stdout
            break
        logger.debug(
            "Could not read manifest for %s via %s: %s",
            image, " ".join(argv[1:-1]), result.stderr.strip()[:200],
        )
    else:
        return []

    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        logger.debug("Could not parse manifest output for %s", image)
        return []

    platforms: list[str] = []
    for plat in _platform_blocks(data):
        os_name = plat.get("os")
        arch = plat.get("architecture")
        if not os_name or not arch:
            continue
        if os_name == "unknown" or arch == "unknown":
            continue  # buildx attestation entry, not a pullable image
        variant = plat.get("variant")
        candidate = (
            f"{os_name}/{arch}/{variant}" if variant else f"{os_name}/{arch}"
        )
        if candidate not in platforms:
            platforms.append(candidate)
    return platforms


def _os_arch(platform: str) -> str:
    """Reduce ``os/arch[/variant]`` to ``os/arch``.

    Registries routinely publish ``linux/arm64/v8`` where a host reports
    plain ``linux/arm64``, so any equality test between a requested and a
    published platform has to ignore the variant suffix or it silently
    never matches.
    """
    return "/".join(platform.split("/")[:2])


def _local_image_os_arch(image: str) -> str | None:
    """Return the ``os/arch`` of the locally cached ``image``, or None."""
    rt = runtime_cmd()
    try:
        result = subprocess.run(  # nosec B603 — argv list, no shell; see module header
            [rt, "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", image],
            capture_output=True, text=True, timeout=_MANIFEST_TIMEOUT,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def pull_image(
    image: str, policy: str = "if-not-present", platform: str | None = None,
) -> bool:
    """Pull a container image respecting the given pull policy.

    Args:
        image: full image reference (e.g. 'aquasec/trivy:0.69.3')
        policy: 'always', 'if-not-present', or 'never'
        platform: explicit ``os/arch[/variant]`` to pull. When set, it is
            used verbatim and no fallback is attempted — the caller has
            stated which variant it wants.

    Returns True if the image is available after this call.

    When ``platform`` is not given and the native pull fails, the
    image's published platforms are read from the registry manifest and
    the pull is retried against one of them. Scanners read image layers
    rather than execute them, so an image built for a foreign
    architecture is perfectly scannable from this host — the pull just
    has to name the architecture explicitly, because the daemon
    otherwise resolves the manifest against its own. This replaces an
    unconditional ``--platform linux/amd64`` retry, which could only
    ever rescue amd64 images and burned a second pull attempt on every
    unrelated failure (bad tag, auth, network).
    """
    rt = runtime_cmd()
    inspect_cmd = [rt, "image", "inspect", image]

    if policy == "never":
        result = subprocess.run(inspect_cmd, capture_output=True)  # nosec B603
        if result.returncode != 0:
            logger.warning("Image '%s' not found locally and pull_policy=never", image)
        return result.returncode == 0

    if policy == "if-not-present":
        result = subprocess.run(inspect_cmd, capture_output=True)  # nosec B603
        if result.returncode == 0:
            # A cache hit only counts when it is a cache hit on the
            # *requested* architecture. An earlier step may well have
            # pulled the host-native variant of this same ref, and
            # returning it here would hand the caller an image of the
            # wrong architecture while the docstring promises the
            # platform is used verbatim — the exposure and services
            # sub-scanners would then report EXPOSE ports and systemd
            # units read from a variant nobody asked about.
            cached = _local_image_os_arch(image) if platform else None
            if platform and cached and _os_arch(platform) != cached:
                logger.info(
                    "Image '%s' is cached as %s but %s was requested — "
                    "pulling the requested platform",
                    image, cached, platform,
                )
            else:
                logger.debug("Image '%s' found locally — skipping pull", image)
                return True
        else:
            logger.debug("Image '%s' not found locally — pulling", image)

    def _pull(plat: str | None) -> tuple[int, str, int]:
        cmd = [rt, "pull"] + (["--platform", plat] if plat else []) + [image]
        at = time.monotonic()
        proc = subprocess.run(cmd, capture_output=True, text=True)  # nosec B603
        return proc.returncode, proc.stderr, int((time.monotonic() - at) * 1000)

    if platform:
        logger.info(
            "Pulling container image: %s (platform %s)", image, platform,
        )
        rc, stderr, elapsed = _pull(platform)
        if rc == 0:
            logger.info("Pulled %s (%s) in %dms", image, platform, elapsed)
        else:
            logger.error(
                "Failed to pull %s for platform %s after %dms: %s",
                image, platform, elapsed, stderr.strip()[:300],
            )
        return rc == 0

    logger.info("Pulling container image: %s (this may take a moment)", image)
    rc, stderr, elapsed = _pull(None)

    if rc != 0:
        candidates = [
            p for p in detect_image_platforms(image)
            if p.startswith("linux/")
        ]
        if candidates:
            # Prefer this host's own architecture when the image does
            # publish it (the native pull may have failed for an
            # unrelated, transient reason); otherwise take the first
            # published platform — for a single-arch image that is the
            # only one there is.
            # Compare on ``os/arch`` only: ``_native_platform`` never
            # emits a variant, so an exact membership test missed every
            # image published as ``linux/arm64/v8`` and fell through to
            # ``candidates[0]`` — usually amd64, the opposite of what
            # "prefer this host's own architecture" means.
            native = _native_platform()
            chosen = next(
                (c for c in candidates if _os_arch(c) == native),
                candidates[0],
            )
            logger.info(
                "Native pull failed for %s (%dms); image publishes %s — "
                "retrying with --platform %s",
                image, elapsed, ", ".join(candidates), chosen,
            )
            rc, stderr, elapsed = _pull(chosen)
        else:
            logger.debug(
                "Native pull failed for %s and no platform information is "
                "available from the registry — not retrying",
                image,
            )

    if rc == 0:
        logger.info("Pulled %s in %dms", image, elapsed)
    else:
        logger.error(
            "Failed to pull %s after %dms: %s",
            image, elapsed, stderr.strip()[:300],
        )
    return rc == 0


def _native_platform() -> str:
    """Return this host's ``linux/<arch>`` platform string.

    Container images are Linux images regardless of the host OS — a
    Docker Desktop daemon on macOS or Windows still runs a Linux VM —
    so the OS component is always ``linux`` and only the architecture
    is read from the host.
    """
    import platform as _platform

    machine = _platform.machine().lower()
    arch = {
        "x86_64": "amd64", "amd64": "amd64",
        "aarch64": "arm64", "arm64": "arm64",
    }.get(machine, machine)
    return f"linux/{arch}"


def run_container(
    image: str,
    args: list[str],
    volumes: dict[str, str] | None = None,
    network: str | None = None,
    entrypoint: str | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess:
    """Run a container with the detected runtime.

    Args:
        image: container image to run
        args: command args passed to the container
        volumes: host_path → container_path mappings
        network: Docker network name to attach to
        entrypoint: override the container entrypoint
        timeout: subprocess timeout in seconds

    Returns the CompletedProcess result.
    """
    rt = runtime_cmd()
    cmd = [rt, "run", "--rm"]

    if network:
        cmd.extend(["--network", network])

    for host_path, container_path in (volumes or {}).items():
        cmd.extend(["-v", f"{host_path}:{container_path}"])

    if entrypoint:
        cmd.extend(["--entrypoint", entrypoint])

    cmd.append(image)
    cmd.extend(args)

    return subprocess.run(  # nosec B603 — argv list, no shell; see module header
        cmd, capture_output=True, text=True, timeout=timeout,
    )
