// Export container registry configuration
// This file can be used for dynamic config generation with environment-specific values

// DEPENDABOT MAINTENANCE:
// For automated image updates with Dependabot, use simple string format for 'image' field.
// Dependabot can update: image: "alpine:3.23.2@sha256:abc123..."
// Dependabot CANNOT update structured format: image: { name: "alpine", tag: "3.23.2" }
// See examples/dependabot.example.yml for configuration.

module.exports = {
  containers: [
    {
      name: "busybox-latest",
      image: "busybox:latest",
      scanners: ["trivy", "grype", "syft"],
      allow_failure: true,
      fail_on_severity: "medium",
    },
    {
      name: "alpine-pinned",
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
    // Minimal image with pinned digest example
    // {
    //   name: "alpine-app-pinned",
    //   registry: {
    //     host: "docker.io",
    //   },
    //   image: {
    //     repository: "library",
    //     name: "alpine",
    //     tag: "3.18",
    //     digest: "sha256:ACTUAL_ALPINE_DIGEST_HERE",
    //   },
    //   scanners: ["trivy", "grype"],
    //   allow_failure: true,
    //   fail_on_severity: "critical",
    // },
  ],
};
