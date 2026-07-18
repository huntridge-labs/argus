# Reference Argus plugin image.
#
# Argus runs this under the plugin sandbox (docs/plugin-sandbox.md):
#   --network none --read-only --cap-drop ALL --security-opt no-new-privileges
#   --user 65534:65534  -v <target>:/scan:ro
# so the plugin must: read only from /scan, write findings JSON to stdout, and
# need no network, no writable disk (a tmpfs is provided at /tmp), and no root.
#
# Production plugins should pin the base image by digest (FROM python@sha256:...);
# left as a tag here for example readability.
FROM python:3.14-alpine

COPY plugin.py /plugin.py

# Run as the non-root "nobody" user. Matches the sandbox's runtime
# --user 65534:65534 and satisfies dockerfile.security.missing-user-entrypoint
# (defense-in-depth: the image itself never defaults to root).
USER 65534:65534

# Emits an argus.plugin.v1 findings document on stdout.
ENTRYPOINT ["python3", "/plugin.py"]
