#!/usr/bin/env bash
# run-in-docker.sh — build + run `tools/required-field-decode-oracle`
# against go-algorand v4.7.4-stable inside a Linux container.
#
# Issue #618. go-algorand's `crypto` package links a vendored libsodium
# fork via cgo, so any Go program importing `data/transactions` (which
# pulls in `crypto`) needs `make libsodium` to have run in the
# go-algorand checkout first (see CLAUDE.md). On Linux CI you can do
# that in place; on a Windows dev box you cannot — the checkout's shell
# scripts are CRLF and autotools refuses them — so this script always
# works from a fresh `git clone` of the sibling checkout made INSIDE
# the container, which normalizes line endings and leaves the pinned
# checkout untouched. Mirrors tools/cert-authenticate/run-in-docker.sh.
#
# The clone, the Go module cache and the built libsodium all live in
# named Docker volumes, so the expensive first run (~3-5 min) is paid
# once; later runs are seconds.
#
# Usage: run-in-docker.sh [--rebuild]
#
# Exit codes are the tool's own: 0 every case matches go-algorand's
# real decoder, 2 a mismatch was found, 1 usage/IO error.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
GO_ALGORAND_DIR="${GO_ALGORAND_DIR:-$(cd "$REPO_ROOT/../go-algorand" 2>/dev/null && pwd || true)}"

GO_ALGORAND_PIN="v4.7.4-stable"
BUILDER_IMAGE="${BUILDER_IMAGE:-golang:1.25-bookworm}"
SRC_VOLUME="${SRC_VOLUME:-algod-rust-goalgo-src}"
MOD_VOLUME="${MOD_VOLUME:-algod-rust-gomod}"
CACHE_VOLUME="${CACHE_VOLUME:-algod-rust-gocache}"

REBUILD=0

usage() {
    sed -n '2,23p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --rebuild) REBUILD=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown arg: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [ -z "$GO_ALGORAND_DIR" ] || [ ! -d "$GO_ALGORAND_DIR/.git" ]; then
    echo "error: no go-algorand git checkout found next to the repo." >&2
    echo "       expected \$REPO_ROOT/../go-algorand, or set GO_ALGORAND_DIR." >&2
    exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is required to build the go-algorand oracle" >&2
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

WORKDIR="$(mktemp -d -t required-field-decode-oracle.XXXXXX)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

cp "$HERE/main.go" "$WORKDIR/main.go"

echo "==> required-field-decode-oracle: running go-algorand $GO_ALGORAND_PIN decoder oracle in $BUILDER_IMAGE"

set +e
MSYS_NO_PATHCONV=1 docker run --rm \
    -e REBUILD="$REBUILD" \
    -e GO_ALGORAND_PIN="$GO_ALGORAND_PIN" \
    -v "$(host_path "$GO_ALGORAND_DIR"):/src:ro" \
    -v "$(host_path "$WORKDIR"):/io" \
    -v "$SRC_VOLUME:/work" \
    -v "$MOD_VOLUME:/go/pkg/mod" \
    -v "$CACHE_VOLUME:/root/.cache/go-build" \
    "$BUILDER_IMAGE" bash -c '
set -euo pipefail
CLONE=/work/go-algorand
if [ "$REBUILD" = "1" ]; then rm -rf "$CLONE"; fi
if [ ! -f "$CLONE/crypto/libs/linux/amd64/lib/libsodium.a" ]; then
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
STAGE="$CLONE/tools/algod_rust_required_field_decode_oracle"
mkdir -p "$STAGE"
cp /io/main.go "$STAGE/main.go"
cd "$CLONE"
go build -o /tmp/required-field-decode-oracle ./tools/algod_rust_required_field_decode_oracle
rm -rf "$STAGE"
/tmp/required-field-decode-oracle
'
rc=$?
set -e

exit "$rc"
