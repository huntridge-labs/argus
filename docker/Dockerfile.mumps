# =============================================================================
# Argus MUMPS / M language SAST scanner
# Multi-stage build: tree-sitter-mumps grammar compiled in builder, clean runtime
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Compile the tree-sitter-mumps shared library
# ---------------------------------------------------------------------------
FROM alpine:3.24.0@sha256:a2d49ea686c2adfe3c992e47dc3b5e7fa6e6b5055609400dc2acaeb241c829f4 AS grammar-builder

# Pinned to MITRE Public Release 23-4084 (janus-llm/tree-sitter-mumps).
# Update in lockstep with .ai/architecture.yaml.
ARG TREE_SITTER_MUMPS_SHA=345f3fb29a6a281a9e28d244e901732bc68c51fc

RUN apk add --no-cache git build-base

WORKDIR /build
# ``-Wno-error=implicit-function-declaration`` is load-bearing: Alpine
# ships gcc 14+, which promotes the warning to an error by default.
# tree-sitter-mumps' scanner.c calls ``isspace`` without including
# ``<ctype.h>``; rather than patch the vendored grammar source, we
# downgrade the diagnostic for the build.
RUN git clone https://github.com/janus-llm/tree-sitter-mumps.git . && \
    git checkout "${TREE_SITTER_MUMPS_SHA}" && \
    mkdir -p /opt/grammars && \
    gcc -O2 -shared -fPIC -I src \
        -Wno-error=implicit-function-declaration \
        -o /opt/grammars/mumps.so src/parser.c src/scanner.c

# ---------------------------------------------------------------------------
# Stage 2: Runtime image
# ---------------------------------------------------------------------------
FROM python:3.15.0b2-alpine@sha256:7b994e30eec677e35f9b57882dda3da2077dfb3936908f320397c5442e2654bb

LABEL org.opencontainers.image.source="https://github.com/huntridge-labs/argus"
LABEL org.opencontainers.image.description="Argus MUMPS / M language SAST scanner"
LABEL org.opencontainers.image.licenses="AGPL-3.0"

ARG TREE_SITTER_VERSION=0.25.2

# libstdc++ for the dlopened grammar .so. apk upgrade picks up OS CVEs.
RUN apk upgrade --no-cache && \
    apk add --no-cache libstdc++

# Python deps: py-tree-sitter (MumpsParser supports both the pre-0.22
# Language(path, name) API and the >=0.22 Language(<pointer>) + Parser(lang)
# API, so this floats with the [mumps] extra — #248), plus the minimum Argus core needs
# to import and run a scan. ``--virtual .ts-build-deps`` lets us drop
# gcc / python-dev after the install layer so the runtime image stays
# small (the grammar is already compiled in the previous stage).
RUN apk add --no-cache --virtual .ts-build-deps gcc musl-dev python3-dev && \
    pip install --no-cache-dir \
        "tree-sitter==${TREE_SITTER_VERSION}" \
        "PyYAML>=6.0.2" \
        "packaging>=21" && \
    apk del .ts-build-deps

RUN adduser -D -u 1000 argus

# Pre-built grammar from the builder stage; ARGUS_MUMPS_GRAMMAR points the
# scanner at it without further configuration.
COPY --from=grammar-builder /opt/grammars/mumps.so /opt/argus/grammars/mumps.so
ENV ARGUS_MUMPS_GRAMMAR=/opt/argus/grammars/mumps.so

# Argus from this branch's source — same layout as Dockerfile.cli.
COPY argus/ /opt/argus/argus/
COPY argus.example.yml /opt/argus/
ENV PYTHONPATH=/opt/argus

# Expose an ``argus`` command on PATH. The engine's container runner sets
# ``--entrypoint argus`` (matching every other scanner, whose
# container_entrypoint is a real binary on PATH). This image runs Argus
# from source via ``python -m argus``, so a tiny shim makes ``argus``
# resolve for both the engine and a manual
# ``docker run <image> scan mumps ...``.
RUN printf '#!/bin/sh\nexec python -m argus "$@"\n' > /usr/local/bin/argus \
    && chmod +x /usr/local/bin/argus

USER argus
WORKDIR /workspace
# ENTRYPOINT is the ``argus`` shim. The full "scan mumps --path ...
# --output-dir ... --format json" args come from MumpsScanner.build_args
# via the engine's container template (engine strips argv[0], the
# build_args "argus" sentinel, before append). A manual
# ``docker run <image> scan mumps --path /workspace`` works the same way.
ENTRYPOINT ["argus"]
