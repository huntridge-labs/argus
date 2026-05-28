#!/usr/bin/env bash
# Build the MUMPS tree-sitter grammar for local execution of `argus scan m`.
#
# The grammar (janus-llm/tree-sitter-mumps, Apache-2.0, MITRE PR 23-4084)
# is not on PyPI, so users who want to run the M scanner without the
# scanner-m container image need to compile it once. This script does
# the minimum: clones the pinned source, compiles the shared library
# with gcc, drops it where the scanner module looks for it.
#
# Output: $HOME/.cache/argus/grammars/mumps.so
#
# Override with ARGUS_M_GRAMMAR_OUT to write somewhere else.
set -euo pipefail

# Pinned to MITRE Public Release 23-4084. Update in lockstep with
# docker/Dockerfile.m and .ai/architecture.yaml.
TREE_SITTER_MUMPS_SHA="${TREE_SITTER_MUMPS_SHA:-345f3fb29a6a281a9e28d244e901732bc68c51fc}"
TREE_SITTER_MUMPS_REPO="${TREE_SITTER_MUMPS_REPO:-https://github.com/janus-llm/tree-sitter-mumps.git}"

OUT_PATH="${ARGUS_M_GRAMMAR_OUT:-${HOME}/.cache/argus/grammars/mumps.so}"
OUT_DIR="$(dirname "${OUT_PATH}")"

if ! command -v gcc >/dev/null 2>&1; then
  echo "error: gcc is required to build the MUMPS grammar. Install build tools and retry." >&2
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is required to fetch the grammar source." >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

echo "Cloning ${TREE_SITTER_MUMPS_REPO} at ${TREE_SITTER_MUMPS_SHA}"
git clone --quiet "${TREE_SITTER_MUMPS_REPO}" "${WORK_DIR}/src-tree"
( cd "${WORK_DIR}/src-tree" && git checkout --quiet "${TREE_SITTER_MUMPS_SHA}" )

echo "Compiling shared library to ${OUT_PATH}"
( cd "${WORK_DIR}/src-tree" && \
  gcc -O2 -shared -fPIC -I src -o "${OUT_PATH}" src/parser.c src/scanner.c )

echo "MUMPS grammar installed at ${OUT_PATH}"
echo ""
echo "Verify with: python -c \"import os; print(os.path.exists('${OUT_PATH}'))\""
echo "The scanner picks this up automatically; no further configuration needed."
