#!/usr/bin/env bash
# Run ``argus scan --list`` with retry-on-transient-SIGSEGV and print
# the listing on success.
#
# Why this exists
# ===============
#
# GitHub-hosted Python 3.13.13 runners hit a transient SIGSEGV in this
# specific subprocess pattern: the immediately-after-install smoke
# call ``argus scan --list`` segfaults inside ~600ms about 1 in 4
# runs. The same code path:
#
#   * works on every local invocation (macOS Python 3.13.13)
#   * works on linux/aarch64 + linux/amd64 in python:3.13.13-slim
#     Docker containers
#   * has no Python traceback — bash exits 139 with no further output
#   * ALWAYS resolves on retry
#
# We don't have a root cause yet (it's almost certainly inside the
# CPython runtime itself, not argus), so the pragmatic gate is a
# bounded retry. Real registration bugs fail every retry; the
# transient flake is suppressed.
#
# Usage
# =====
#
#   scripts/ci/argus_smoke.sh                       # default: argus scan --list, 3 attempts
#   scripts/ci/argus_smoke.sh --max-attempts 5      # increase retry budget
#   scripts/ci/argus_smoke.sh --min-scanners 18     # also assert >= N scanners listed
#
# Output: prints the ``argus scan --list`` output to stdout on
# success, captured from whichever attempt succeeded. Exits 0 on
# success, 1 on failure (with the last attempt's output for
# debugging).

set -euo pipefail

MAX_ATTEMPTS=3
MIN_SCANNERS=15

while [[ $# -gt 0 ]]; do
    case "$1" in
        --max-attempts) MAX_ATTEMPTS="$2"; shift 2 ;;
        --min-scanners) MIN_SCANNERS="$2"; shift 2 ;;
        --help|-h)
            grep -E '^# (Why|Usage|Output|  )' "$0" | sed 's/^# //'
            exit 0
            ;;
        *) echo "Unknown arg: $1" >&2; exit 2 ;;
    esac
done

last_output=""
for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
    # Capture stdout+stderr so a SIGSEGV-killed run still leaves
    # something for the failure-mode dump below. ``|| true`` keeps
    # the loop going on non-zero exits without ``set -e`` aborting.
    last_output=$(argus scan --list 2>&1 || true)
    scanners=$(printf '%s\n' "$last_output" | grep -cE '^\s+[a-z]' || true)

    if [[ "$scanners" -ge "$MIN_SCANNERS" ]]; then
        # Caller wants the listing for downstream grep checks
        # (``Verify wheel installation`` greps each scanner by name).
        printf '%s\n' "$last_output"
        echo "[argus_smoke] attempt $attempt: listed $scanners scanner(s)" >&2
        exit 0
    fi

    echo "[argus_smoke] attempt $attempt: only $scanners scanner(s) listed (likely transient SIGSEGV) — retrying" >&2
done

echo "::error::argus scan --list failed to enumerate >= $MIN_SCANNERS scanners after $MAX_ATTEMPTS attempts" >&2
echo "Last output:" >&2
printf '%s\n' "$last_output" >&2
exit 1
