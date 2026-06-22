<div align=center>

# Container Scanning from Configuration

Scan multiple container images using a configuration file instead of defining individual workflow jobs.
</div>

## Overview

The config-driven matrix scanner allows you to:

- Define multiple containers in a single configuration file
- Scan from public or private registries with authentication
- Use environment variable expansion for dynamic values
- Run multiple scanners against each container
- Generate comprehensive security reports

## Configuration File

Container configurations can be written in YAML, JSON, or JavaScript.

### Schema Location

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/huntridge-labs/argus/1.6.0/.github/actions/parse-container-config/schemas/container-config.schema.json
```

### Basic Structure

```yaml
containers:
    # Simple string required for use with dependabot
  - image: ghcr.io/myorg/myapp:latest@sha256:abc123...
    registry:
      host: ghcr.io
      username: ${GITHUB_TRIGGERING_ACTOR}
      auth_secret: GITHUB_TOKEN
    scanners:
      - trivy-container
      - grype
    fail_on_severity: high
    # Upload results to GitHub Security tab
    enable_code_security: false
```

## Registry Configuration

### Registry Authentication

The `registry` object consolidates all registry-related configuration:

```yaml
registry:
  host: ghcr.io                          # Registry hostname
  username: ${GITHUB_TRIGGERING_ACTOR}   # Username (supports env vars)
  auth_secret: GITHUB_TOKEN              # Name of GitHub secret with auth token
```

### Registry Patterns

**GitHub Container Registry:**

```yaml
registry:
  host: ghcr.io
  username: ${GITHUB_TRIGGERING_ACTOR}
  auth_secret: GITHUB_TOKEN
```

**Docker Hub:**

```yaml
registry:
  host: docker.io
  username: myuser
  auth_secret: DOCKERHUB_TOKEN
```

**AWS ECR:**

```yaml
registry:
  host: 123456789.dkr.ecr.us-east-1.amazonaws.com
  username: AWS
  auth_secret: ECR_TOKEN
```

**Azure Container Registry:**

```yaml
registry:
  host: myregistry.azurecr.io
  username: ${ACR_USERNAME}
  auth_secret: ACR_PASSWORD
```

**No Authentication (public registries):**

```yaml
image: nginx:latest
```

## Image Configuration

### Structured Format

Provides fine-grained control:

```yaml
image:
  repository: myorg      # Optional repository/namespace
  name: myapp           # Required: image name
  tag: v1.2.3          # Optional: defaults to 'latest'
  digest: sha256:abc...  # Optional: digest pinning
```

**Resulting reference:** `myorg/myapp:v1.2.3`

### String Format

Simple inline reference:

```yaml
image: "nginx:latest"
image: "myorg/myapp:v1.2.3"
image: "nginx:latest@sha256:abc..."
```

### Digest Pinning

Pin to exact image content:

```yaml
# Structured format
image:
  name: nginx
  tag: latest
  digest: sha256:abc123...

# String format
image: "nginx:latest@sha256:abc123..."
```

## Discover mode (multi-image monorepos)

If your repo has multiple `Dockerfile`s scattered across services or
component directories and you don't want to maintain a hand-written
`containers.images` list, enable auto-discovery:

```yaml
containers:
  discover: true
  search_paths:
    - "services"
    - "tools"
  scanners:
    - trivy
    - grype
    - syft
```

argus walks each path, treats every `Dockerfile*` it finds as a
build-then-scan target, builds the image locally (no registry push),
and runs the configured sub-scanners against the built artifact.
Cleanup defaults to `true` — the temporary image is removed once the
scan completes.

You can mix discovery with an explicit list — discovered Dockerfiles
augment the `containers.images` entries rather than replacing them:

```yaml
containers:
  images:
    - image: ghcr.io/myorg/external-runtime:1.4.0   # explicit pull
  discover: true
  search_paths:
    - "services"                                     # in-tree builds
```

This is the SDK-driven replacement for the `scan_mode: discover` input
the `scanner-container` composite action carried in 0.6.x. Use the
[`parse-container-config`](../README.md#composite-actions) action to
emit a GitHub Actions matrix from the `containers.images` list when
you want one job per image.

## Environment Variables

Use `${VAR_NAME}` syntax for dynamic values:

```yaml
registry:
  username: ${GITHUB_TRIGGERING_ACTOR}
  host: ${CUSTOM_REGISTRY_HOST}
image:
  repository: ${ORG_NAME}
  tag: ${IMAGE_TAG}
```

**Available in GitHub Actions:**
- `GITHUB_TRIGGERING_ACTOR` - User who triggered the workflow
- `GITHUB_REPOSITORY_OWNER` - Repository owner
- `GITHUB_REF_NAME` - Branch or tag name
- Any custom environment variables

## Complete Examples

### Multiple Containers with Different Registries

```yaml
# container-config.yml
containers:
  - name: frontend
    registry:
      host: ghcr.io
      username: ${GITHUB_TRIGGERING_ACTOR}
      auth_secret: GITHUB_TOKEN
    image:
      repository: myorg
      name: frontend
      tag: ${GITHUB_REF_NAME}
    scanners:
      - trivy-container
      - grype

  - name: backend
    registry:
      host: docker.io
      username: dockeruser
      auth_secret: DOCKERHUB_TOKEN
    image:
      name: myorg/backend
      tag: latest
    scanners:
      - trivy-container
      - sbom

  - name: nginx
    # Public image, no authentication
    image: nginx:alpine
    scanners:
      - trivy-container
```

### JSON Format

```json
{
  "containers": [
    {
      "name": "api",
      "registry": {
        "host": "ghcr.io",
        "username": "${GITHUB_TRIGGERING_ACTOR}",
        "auth_secret": "GITHUB_TOKEN"
      },
      "image": {
        "repository": "myorg",
        "name": "api",
        "tag": "v2.1.0",
        "digest": "sha256:abc123..."
      },
      "scanners": ["trivy-container", "grype", "sbom"]
    }
  ]
}
```

### JavaScript Format

```javascript
module.exports = {
  containers: [
    {
      name: 'webapp',
      registry: {
        host: 'ghcr.io',
        username: process.env.GITHUB_TRIGGERING_ACTOR,
        auth_secret: 'GITHUB_TOKEN'
      },
      image: {
        repository: 'myorg',
        name: 'webapp',
        tag: process.env.GITHUB_REF_NAME || 'latest'
      },
      scanners: ['trivy-container', 'grype']
    }
  ]
};
```

## Workflow Usage

### Basic Integration

```yaml
name: Container Security Scan

on:
  push:
    paths:
      - 'container-config.yml'
  workflow_dispatch:

jobs:
  scan:
    uses: huntridge-labs/argus/.github/workflows/container-scan-from-config.yml@1.6.0
    with:
      config_file: container-config.yml
      enable_code_security: true
      fail_on_severity: high
    secrets: inherit
```

### Advanced Configuration

```yaml
jobs:
  scan:
    uses: huntridge-labs/argus/.github/workflows/container-scan-from-config.yml@1.6.0
    with:
      config_file: .github/security/containers.yml
      enable_code_security: true
      post_pr_comment: true
      fail_on_severity: critical
    secrets: inherit  # Required for registry authentication
```

## Matrix Execution

The workflow generates a matrix from your configuration:

1. Parser validates configuration against JSON schema
2. Generates matrix with one job per container
3. Each job:
   - Authenticates to registry (if configured)
   - Pulls the specified image
   - Runs configured scanners sequentially
   - Uploads results to GitHub Security tab

**Example matrix output:**

```json
{
  "container": [
    {
      "name": "frontend",
      "image_ref": "ghcr.io/myorg/frontend:main",
      "registry_username": "user",
      "registry_auth_secret": "GITHUB_TOKEN",
      "scanners": "trivy-container,grype"
    },
    {
      "name": "backend",
      "image_ref": "docker.io/myorg/backend:latest",
      "registry_username": "dockeruser",
      "registry_auth_secret": "DOCKERHUB_TOKEN",
      "scanners": "trivy-container,sbom"
    }
  ]
}
```

## Automated Updates with Dependabot

### Limitation

Dependabot only supports simple string format for image references:

```yaml
# ✅ Works with Dependabot
containers:
  - name: nginx
    image: "nginx:1.25.0"

# ❌ Does NOT work with Dependabot
containers:
  - name: nginx
    image:
      name: nginx
      tag: 1.25.0
```

### Example Dependabot Configuration

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: docker
    directory: "/"
    schedule:
      interval: weekly
    open-pull-requests-limit: 10
```

**What Dependabot detects:**
- String format: `image: "nginx:1.25.0"`
- Digest pinning: `image: "nginx:latest@sha256:abc..."`

**What Dependabot cannot detect:**
- Structured object format
- Images split across multiple properties
- Environment variable references

See [dependabot.example.yml](../examples/dependabot.example.yml) for a complete example.

## Result provenance: the scanned content digest

Every container scan records the **content digest** of the image it actually
inspected, not just the tag it was asked to scan. This matters because a tag
is mutable: a "clean" scan of `app:scan-<sha>` proves nothing about what later
ships if different content can be published under the same tag.

Argus resolves the digest best-effort from the local daemon:

- **Pulled / pushed images** → the registry `RepoDigest`
  (`repo@sha256:…`), which a deploy-time check can compare against the
  registry manifest.
- **Locally-built, never-pushed images** → the image **config ID**
  (`sha256:…`). These have no `RepoDigest` until pushed, but the config ID is
  a stable content hash of the build.

The digest is surfaced two ways:

- **Per-image markdown** shows a `**Digest:**` line under the image.
- **Each finding** carries `image_digest` (and `image_ref`) in its
  `metadata`, so it travels into `argus-results.json` and SARIF.

This closes the scan-vs-deploy substitution gap **when you trust the runner**:
a deploy gate (or admission controller) that compares the *deployed* image's
digest against the digest Argus recorded will reject anything that was swapped
after the scan. An unknown digest (docker unavailable, inspect failed) is
non-fatal — it's simply left unrecorded.

> **Scope.** This does not defend against a *hostile* runner — an attacker who
> controls the environment Argus runs in controls its output. And note that a
> ref-only image already present in the local daemon is scanned from that local
> copy (see [#233](https://github.com/huntridge-labs/argus/pull/234)); the
> recorded digest is exactly what makes that choice auditable. A signed
> `cosign attest` of findings bound to the digest is tracked as a follow-up.

## Troubleshooting

### Authentication Failures

**Problem:** `Error: unauthorized: authentication required`

**Solution:** Verify:
- Registry host is correct
- Secret name matches workflow secrets
- Secret contains valid token with read permissions
- `secrets: inherit` is included in workflow

### Invalid Configuration

**Problem:** Parser fails with validation error

**Solution:**
- Validate against JSON schema
- Check YAML syntax (indentation, quotes)
- Verify required fields are present
- Test with simplified config first

### Image Not Found

**Problem:** `Error: image not found`

**Solution:**
- Verify image reference is correct
- Check registry hostname
- Ensure image exists and is accessible
- Test `docker pull` manually with same credentials

## Best Practices

1. **Use digest pinning** for production images to ensure immutability
2. **Store registry credentials** in GitHub secrets, never in config files
3. **Use environment variables** for dynamic values like branch names
4. **Validate config files** in CI before running scans
5. **Start with public images** when testing, then add authentication
6. **Use string format** if you need Dependabot support
7. **Group related images** in same config file for easier management
