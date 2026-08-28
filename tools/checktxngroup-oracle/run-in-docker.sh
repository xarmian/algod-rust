#!/usr/bin/env bash
# run-in-docker.sh — build + run `tools/checktxngroup-oracle`
# against go-algorand v5.0.0-stable inside a Linux container.
#
# Issue #617. Mirrors tools/required-field-decode-oracle/run-in-docker.sh:
# a Go program importing `data/transactions` pulls in `crypto` (cgo,
# vendored libsodium), so it's built inside a fresh in-container clone of
# the pinned go-algorand checkout (normalizes CRLF, leaves the host
# checkout untouched) with `make libsodium` run once and cached in a
# named Docker volume.
#
# Usage: run-in-docker.sh [--rebuild]
#
# Exit codes are the tool's own: 0 every case matches go-algorand's real
# CheckTxnGroup, 2 a mismatch was found, 1 usage/IO error.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
GO_ALGORAND_DIR="${GO_ALGORAND_DIR:-$(cd "$REPO_ROOT/../go-algorand" 2>/dev/null && pwd || true)}"

GO_ALGORAND_PIN="v5.0.0-stable"
BUILDER_IMAGE="${BUILDER_IMAGE:-golang:1.25-bookworm}"
SRC_VOLUME="${SRC_VOLUME:-algod-rust-goalgo-src}"
MOD_VOLUME="${MOD_VOLUME:-algod-rust-gomod}"
CACHE_VOLUME="${CACHE_VOLUME:-algod-rust-gocache}"

REBUILD=0

usage() {
    sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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

host_path() {
    if [ -n "${MSYSTEM:-}" ]; then
        (cd "$1" 2>/dev/null && pwd -W) || echo "$1"
    else
        echo "$1"
    fi
}

WORKDIR="$(mktemp -d -t checktxngroup-oracle.XXXXXX)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

cp "$HERE/main.go" "$WORKDIR/main.go"

echo "==> checktxngroup-oracle: running go-algorand $GO_ALGORAND_PIN CheckTxnGroup oracle in $BUILDER_IMAGE"

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
STAGE="$CLONE/tools/algod_rust_checktxngroup_oracle"
mkdir -p "$STAGE"
cp /io/main.go "$STAGE/main.go"
cd "$CLONE"
go build -o /tmp/checktxngroup-oracle ./tools/algod_rust_checktxngroup_oracle
rm -rf "$STAGE"
/tmp/checktxngroup-oracle
'
rc=$?
set -e

exit "$rc"
