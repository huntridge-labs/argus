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

# Emits an argus.plugin.v1 findings document on stdout.
ENTRYPOINT ["python3", "/plugin.py"]
