# =============================================================================
# Argus MUMPS / M language SAST scanner
# Multi-stage build: tree-sitter-mumps grammar compiled in builder, clean runtime
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Compile the tree-sitter-mumps shared library
# ---------------------------------------------------------------------------
FROM alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11 AS grammar-builder

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
FROM python:3.14.5-alpine@sha256:5a824eb82cc75361f98611f3cfc5091ea33f10a6ccea4d4ebdabbc523b9a1614

LABEL org.opencontainers.image.source="https://github.com/huntridge-labs/argus"
LABEL org.opencontainers.image.description="Argus MUMPS / M language SAST scanner"
LABEL org.opencontainers.image.licenses="AGPL-3.0"

ARG TREE_SITTER_VERSION=0.21.3

# libstdc++ for the dlopened grammar .so. apk upgrade picks up OS CVEs.
RUN apk upgrade --no-cache && \
    apk add --no-cache libstdc++

# Python deps: py-tree-sitter v0.21 (we use the Language(path, name)
# constructor that v0.22 dropped), plus the minimum Argus core needs
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

# Pre-built grammar from the builder stage; ARGUS_M_GRAMMAR points the
# scanner at it without further configuration.
COPY --from=grammar-builder /opt/grammars/mumps.so /opt/argus/grammars/mumps.so
ENV ARGUS_M_GRAMMAR=/opt/argus/grammars/mumps.so

# Argus from this branch's source — same layout as Dockerfile.cli.
COPY argus/ /opt/argus/argus/
COPY argus.example.yml /opt/argus/
ENV PYTHONPATH=/opt/argus

USER argus
WORKDIR /workspace
# ENTRYPOINT is just the argus invocation prefix. The full "scan m
# --path ... --output-dir ... --format json" args come from
# MScanner.build_args via the engine's container template (engine
# strips argv[0], the build_args "argus" sentinel, before append).
ENTRYPOINT ["python", "-m", "argus"]
