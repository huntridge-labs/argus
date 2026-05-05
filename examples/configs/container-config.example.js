// Export container registry configuration
// This file can be used for dynamic config generation with environment-specific values

// RECOMMENDED: PIN EVERY IMAGE TO AN IMMUTABLE DIGEST.
// Tag-only references like ``alpine:3.23.2`` are mutable — the same
// name can publish different bytes over time, which makes CVE
// attribution drift and scan results unreproducible.
// ``@sha256:...`` references are byte-level immutable: the scanner
// reads exactly what you pinned, every run, forever.
//
// Format (1) below is the most ergonomic — simple-string + digest
// pin in one line, Dependabot-updatable.

// DEPENDABOT MAINTENANCE:
// For automated image updates with Dependabot, use simple string format for 'image' field.
// Dependabot can update: image: "alpine:3.23.2@sha256:865b..."
// Dependabot CANNOT update structured format: image: { name: "alpine", tag: "3.23.2" }
// See examples/dependabot.example.yml for configuration.

module.exports = {
  containers: [
    // PREFERRED: simple string with digest pin. Reproducible AND
    // Dependabot-updatable in one line.
    {
      name: "alpine-pinned-string",
      image: "alpine:3.23.2@sha256:865b95f46d98cf867a156fe4a135ad3fe50d2056aa3f25ed31662dff6da4eb62",
      scanners: ["trivy", "grype", "syft"],
      allow_failure: true,
      fail_on_severity: "medium",
    },

    // ALSO PREFERRED: structured form when you need registry/auth
    // separation. Same digest-pinned posture; Dependabot can't
    // auto-update — Renovate or manual updates only.
    {
      name: "alpine-pinned-structured",
      registry: {
        host: "docker.io",
      },
      image: {
        repository: "library",
        name: "alpine",
        tag: "3.23.2",
        digest: "sha256:865b95f46d98cf867a156fe4a135ad3fe50d2056aa3f25ed31662dff6da4eb62",
      },
      scanners: ["trivy", "grype"],
      allow_failure: true,
      fail_on_severity: "high",
    },

    // ACCEPTABLE FALLBACK: tag-only string. Easier to read but
    // mutable — CVE attribution drifts every time the registry
    // republishes the tag. Use only for ad-hoc scans or in
    // environments where digest discovery isn't yet wired up.
    {
      name: "busybox-latest",
      image: "busybox:latest",
      scanners: ["trivy", "grype", "syft"],
      allow_failure: true,
      fail_on_severity: "medium",
    },

    // Private registry example — auth secrets resolved by the
    // calling workflow, not stored here.
    {
      name: "ghcr-runner",
      registry: {
        host: "ghcr.io",
        username: process.env.GITHUB_TRIGGERING_ACTOR,
        auth_secret: "GITHUB_TOKEN",
      },
      image: {
        repository: "actions",
        name: "actions-runner",
        tag: "latest",
      },
      scanners: ["trivy"],
      allow_failure: false,
      fail_on_severity: "none",
    },
  ],
};
