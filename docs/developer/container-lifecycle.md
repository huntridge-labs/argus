# Container Image Build & Release Lifecycle

How Argus container images are built, tested, and published. This document explains the relationship between `containers.py`, the build workflow, and the release process.

## Image References

All container image references live in `argus/containers.py`:

```python
# Official images — published by tool authors, we just pin versions
OFFICIAL_IMAGES = {
    "trivy": "aquasec/trivy:0.69.3",
    "gitleaks": "zricethezav/gitleaks:v8.30.1",
    ...
}

# Custom images — built from docker/ directory, published to GHCR on release.
# Each entry pins the release version AND the immutable sha256 digest captured
# at build time. release-it's after:bump hook overwrites both halves atomically.
CUSTOM_IMAGES = {
    "bandit": "ghcr.io/huntridge-labs/argus/scanner-bandit:1.9.1@sha256:bb5a...",
    "semgrep": "ghcr.io/huntridge-labs/argus/scanner-opengrep:1.9.1@sha256:2e7d...",
    "supply-chain": "ghcr.io/huntridge-labs/argus/scanner-supply-chain:1.9.1@sha256:7a0b...",
    "cli": "ghcr.io/huntridge-labs/argus/cli:1.9.1@sha256:52cc...",
}
```

**Official images** exist on Docker Hub/GHCR and are pulled directly. Versions and `@sha256:` digests tracked by Renovate.

**Custom images** are built from `docker/Dockerfile.*` in this repo. The `:VERSION` tag bumps on release; the `@sha256:` digest is captured by the release pipeline at build time and pinned by the release-it `after:bump` hook (see `scripts/release_it/inject_image_digests.py`). The pair gives content-addressable identity even if the tag is later moved.

## PR Testing (build-containers.yml)

During PR CI, custom images don't exist on GHCR. The build workflow handles this:

```
Build step (per image):
  docker build -t ghcr.io/huntridge-labs/argus/scanner-bandit:$COMMIT_SHA \
    -f docker/Dockerfile.bandit .
  docker save | gzip → upload as artifact

Test step (single job, loads all images):
  download all image artifacts
  docker load each tarball
  docker tag scanner-bandit:$COMMIT_SHA → scanner-bandit:1.0.0  ← bridges the gap
  python -m argus scan (finds 1.0.0 locally via pull_policy: if-not-present)
```

The **retag step** is critical — it makes locally-built images match what `containers.py` expects. The engine's `if-not-present` pull policy finds them locally and skips the GHCR pull.

### What gets tested where

| Workflow | What it tests | Custom images available? |
|----------|--------------|------------------------|
| `build-containers.yml` → "Test Argus CLI" | Full `argus scan` with all scanners | Yes (loaded + retagged locally) |
| `build-containers.yml` → "Scan scanner-*" | Grype/Trivy scan of the image itself | Yes (loaded from artifact) |
| `test-actions.yml` → scanner jobs | Composite action wrappers | No — falls back to local tools or public images |
| `test-unit.yml` | Unit tests (mocked, no Docker) | N/A |

The `test-actions` workflow runs on a separate runner without the locally-built images. Scanners with public Docker Hub images (gitleaks, osv, checkov, trivy, grype, clamav, zap) work. Scanners with custom GHCR images (bandit, opengrep, supply-chain) attempt Docker pull → fail → fall back to local tool if available → otherwise skip with a log warning.

This is expected behavior during PR testing. After release, the images exist on GHCR and all paths work.

## Release Process

The release pipeline is build-once-promote-everywhere. A single `release` job in `.github/workflows/release.yml` owns the whole lifecycle:

1. **Build** — buildx pushes 4 multi-arch images (cli + 3 scanners) to GHCR under a throwaway `build-<sha>-<run>` tag. Each image's `sha256:` digest is captured into `$GITHUB_ENV` as `ARGUS_DIGEST_<NAME>`.
2. **Bump** — `release-it` regex-bumper updates the version in `containers.py` (and other refs); the `after:bump` hook (`scripts/release_it/inject_image_digests.py`) consumes the `ARGUS_DIGEST_*` env vars and writes `<version>@sha256:<digest>` into each Argus-owned image line. release-it then commits + tags + pushes.
3. **Promote** — `docker buildx imagetools create` adds `:<VERSION>` and `:latest` as manifest aliases on the already-pushed digests. No rebuild.
4. **Sign** — `cosign sign --yes <image>@<digest>` signs each image by digest (not tag), so the signature stays valid if the tag is later moved.
5. **Publish** — wheel is built from the freshly-bumped tree (now pointing at signed, promoted images) and published to PyPI via OIDC trusted publishing.

Order matters: containers must be promoted and signed **before** the wheel lands on PyPI so a user running `pip install argus-security==<VERSION>` never gets a wheel that references unsigned or non-existent images.

If the build fails, release-it never runs and nothing public happens. If release-it decides no commits warrant a release, the build images become orphan `build-<sha>` tags that age out via the nightly `.github/workflows/ghcr-prune.yml` workflow (semver tags and `latest` are kept forever; everything else expires after 14 days).

## Version Management

| What | Managed by | Config |
|------|-----------|--------|
| Official image tags + digests | Renovate | `.github/renovate.json` docker regex manager (`pinDigests: true`) |
| Custom image tags | release-it regex bumper | `.release-it.json` |
| Custom image `@sha256:` digests | release pipeline + `after:bump` hook | `scripts/release_it/inject_image_digests.py` |
| Dockerfile tool versions | Renovate | `.github/renovate.json` ARG pattern manager |
| `containers.py` aliases | Manual | `_ALIASES` dict (e.g., opengrep → semgrep) |

The regex-bumper pattern for `argus/containers.py` matches `[^"@]+` (everything up to `@` or `"`) so it only touches the version segment, leaving the `@sha256:...` tail for the hook to rewrite.

## Adding a New Custom Image

1. Create `docker/Dockerfile.{name}`
2. Add to `CUSTOM_IMAGES` in `containers.py` (with placeholder `@sha256:` — the next release fills it in)
3. Add to `_ALIASES` if the scanner name differs from the image key
4. Add a build matrix entry in `build-containers.yml` (PR CI)
5. Add retag line in the "Load and retag images" step of `build-containers.yml`
6. Add an entry to the `IMAGES` array in the "Build and push containers" step of `release.yml`
7. Add a cosign-sign line in the "Sign images by digest" step of `release.yml`
8. Add the GHCR package name to the prune list in `.github/workflows/ghcr-prune.yml`

The `inject_image_digests.py` hook needs no change — it discovers `ARGUS_DIGEST_*` env vars by prefix and matches them against image short-names in `containers.py`.
