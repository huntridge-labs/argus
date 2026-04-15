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

# Custom images — built from docker/ directory, published to GHCR on release
CUSTOM_IMAGES = {
    "bandit": "ghcr.io/huntridge-labs/argus/scanner-bandit:1.0.0",
    "semgrep": "ghcr.io/huntridge-labs/argus/scanner-opengrep:1.0.0",
    "supply-chain": "ghcr.io/huntridge-labs/argus/scanner-supply-chain:1.0.0",
    "cli": "ghcr.io/huntridge-labs/argus/cli:1.0.0",
}
```

**Official images** exist on Docker Hub/GHCR and are pulled directly. Versions tracked by Renovate.

**Custom images** are built from `docker/Dockerfile.*` in this repo. The `1.0.0` tag is a placeholder — it gets bumped to the actual release version by `release-it` during the release process.

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

When `release-it` runs:

1. **Version bump**: `release-it` regex bumper updates `containers.py` tags from `1.0.0` → `0.8.0` (the release version)
2. **CI builds**: `build-containers.yml` builds images tagged with the new version
3. **GHCR push**: Images pushed to `ghcr.io/huntridge-labs/argus/scanner-bandit:0.8.0`
4. **CLI release**: `argus` package references `scanner-bandit:0.8.0` in `containers.py`
5. **User install**: `pip install argus-security` gets a CLI that references images that exist on GHCR

The chicken-and-egg resolves because the release process does both atomically — the version in `containers.py` and the GHCR tag are always in sync after release.

## Version Management

| What | Managed by | Config |
|------|-----------|--------|
| Official image tags | Renovate | `renovate.yaml` docker regex manager |
| Custom image tags | release-it | `.release-it.json` regex bumper |
| Dockerfile tool versions | Renovate | `renovate.yaml` ARG pattern manager |
| `containers.py` aliases | Manual | `_ALIASES` dict (e.g., opengrep → semgrep) |

Renovate's `pinDigests: true` setting will automatically add `@sha256:...` digests when it bumps image tags, providing immutable references on top of version tags.

## Adding a New Custom Image

1. Create `docker/Dockerfile.{name}`
2. Add to `CUSTOM_IMAGES` in `containers.py`
3. Add to `_ALIASES` if the scanner name differs from the image key
4. Add build matrix entry in `build-containers.yml`
5. Add retag line in the "Load and retag images" step
6. Add to `.release-it.json` regex bumper if version should be bumped on release
