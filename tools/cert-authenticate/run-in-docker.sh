#!/usr/bin/env bash
# run-in-docker.sh — build + run `tools/cert-authenticate` against
# go-algorand v5.0.0-stable inside a Linux container.
#
# Issue #470 §2. go-algorand's `crypto` package links a vendored
# libsodium fork via cgo, so any Go program importing `agreement`
# needs `make libsodium` to have run in the go-algorand checkout first
# (see CLAUDE.md and .github/workflows/algokey-e2e.yml). On Linux CI you
# can do that in place; on a Windows dev box you cannot — the checkout's
# shell scripts are CRLF and autotools refuses them — so this script
# always works from a fresh `git clone` of the sibling checkout made
# INSIDE the container, which normalizes line endings and leaves the
# pinned checkout untouched.
#
# The clone, the Go module cache and the built libsodium all live in
# named Docker volumes, so the expensive first run (~3-5 min) is paid
# once; later runs are seconds.
#
# Usage:
#   run-in-docker.sh --input <go-verify-input.json> \
#                    [--out <report.json>] [--require-rust-votes N]
#                    [--rebuild]
#
# Exit codes are the helper's own: 0 clean, 1 usage/IO, 2 a certificate
# failed to authenticate under go-algorand (or too few Rust votes).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
GO_ALGORAND_DIR="${GO_ALGORAND_DIR:-$(cd "$REPO_ROOT/../go-algorand" 2>/dev/null && pwd || true)}"

GO_ALGORAND_PIN="v5.0.0-stable"
BUILDER_IMAGE="${BUILDER_IMAGE:-golang:1.25-bookworm}"
SRC_VOLUME="${SRC_VOLUME:-algod-rust-goalgo-src}"
MOD_VOLUME="${MOD_VOLUME:-algod-rust-gomod}"
CACHE_VOLUME="${CACHE_VOLUME:-algod-rust-gocache}"

INPUT=""
OUT=""
REQUIRE_RUST_VOTES=0
REBUILD=0

usage() {
    sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --input)               INPUT="$2"; shift 2 ;;
        --out)                 OUT="$2"; shift 2 ;;
        --require-rust-votes)  REQUIRE_RUST_VOTES="$2"; shift 2 ;;
        --rebuild)             REBUILD=1; shift ;;
        -h|--help)             usage; exit 0 ;;
        *) echo "unknown arg: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [ -z "$INPUT" ]; then
    echo "error: --input is required" >&2
    usage >&2
    exit 1
fi
if [ ! -s "$INPUT" ]; then
    echo "error: --input file '$INPUT' is missing or empty" >&2
    echo "       produce it with:" >&2
    echo "         algo-cert-crossverify --export-go-input <path> …" >&2
    exit 1
fi
if [ -z "$GO_ALGORAND_DIR" ] || [ ! -d "$GO_ALGORAND_DIR/.git" ]; then
    echo "error: no go-algorand git checkout found next to the repo." >&2
    echo "       expected \$REPO_ROOT/../go-algorand, or set GO_ALGORAND_DIR." >&2
    exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is required to build the go-algorand helper" >&2
    exit 1
fi

# Git Bash rewrites both sides of a `docker run -v` argument; emit
# Windows-style host paths and set MSYS_NO_PATHCONV for the container
# side (same helper as ops/mixed-cluster/scripts/start.sh).
host_path() {
    if [ -n "${MSYSTEM:-}" ]; then
        (cd "$1" 2>/dev/null && pwd -W) || echo "$1"
    else
        echo "$1"
    fi
}

WORKDIR="$(mktemp -d -t cert-authenticate.XXXXXX)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

cp "$INPUT" "$WORKDIR/input.json"
cp "$HERE/main.go" "$WORKDIR/main.go"

echo "==> cert-authenticate: running go-algorand $GO_ALGORAND_PIN verifier in $BUILDER_IMAGE"

set +e
MSYS_NO_PATHCONV=1 docker run --rm \
    -e REBUILD="$REBUILD" \
    -e GO_ALGORAND_PIN="$GO_ALGORAND_PIN" \
    -e REQUIRE_RUST_VOTES="$REQUIRE_RUST_VOTES" \
    -v "$(host_path "$GO_ALGORAND_DIR"):/src:ro" \
    -v "$(host_path "$WORKDIR"):/io" \
    -v "$SRC_VOLUME:/work" \
    -v "$MOD_VOLUME:/go/pkg/mod" \
    -v "$CACHE_VOLUME:/root/.cache/go-build" \
    "$BUILDER_IMAGE" bash -c '
set -euo pipefail
CLONE=/work/go-algorand
if [ "$REBUILD" = "1" ]; then rm -rf "$CLONE"; fi
if [ ! -x "$CLONE/crypto/libs/linux/amd64/lib/libsodium.a" ] \
        && [ ! -f "$CLONE/crypto/libs/linux/amd64/lib/libsodium.a" ]; then
    echo "    (first run) preparing a clean go-algorand clone + libsodium"
    apt-get update -qq
    apt-get install -y -qq autoconf automake libtool build-essential git >/dev/null
    git config --global --add safe.directory /src
    rm -rf "$CLONE"
    # A clone made inside the container checks out LF regardless of how
    # the host checkout is stored, which autotools requires.
    git clone --shared --no-checkout /src "$CLONE"
    git -C "$CLONE" checkout -q "$GO_ALGORAND_PIN"
    make -C "$CLONE" libsodium
fi
ACTUAL_PIN="$(git -C "$CLONE" describe --tags --exact-match 2>/dev/null || echo unknown)"
if [ "$ACTUAL_PIN" != "$GO_ALGORAND_PIN" ]; then
    echo "error: cached clone is at $ACTUAL_PIN, expected $GO_ALGORAND_PIN;" >&2
    echo "       re-run with --rebuild" >&2
    exit 1
fi
# Stage our main.go INSIDE the go-algorand module so it builds against the
# pinned dependency graph with no go.sum of our own to keep in sync. The
# directory name is obviously ours, and it lives in a throwaway clone.
STAGE="$CLONE/tools/algod_rust_cert_authenticate"
mkdir -p "$STAGE"
cp /io/main.go "$STAGE/main.go"
cd "$CLONE"
go build -o /tmp/cert-authenticate ./tools/algod_rust_cert_authenticate
rm -rf "$STAGE"
/tmp/cert-authenticate \
    --input /io/input.json \
    --out /io/report.json \
    --require-rust-votes "$REQUIRE_RUST_VOTES"
'
rc=$?
set -e

if [ -n "$OUT" ] && [ -f "$WORKDIR/report.json" ]; then
    mkdir -p "$(dirname "$OUT")"
    cp "$WORKDIR/report.json" "$OUT"
    echo "    report: $OUT"
fi

exit "$rc"
