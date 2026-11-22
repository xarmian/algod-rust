#!/usr/bin/env bash

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# run-in-docker.sh — regenerate the go-algorand v5.1.1-stable oracle for the
# post-quantum (Falcon-1024) signature failure texts (issue #2438).
#
# `oracle_test.go` is staged into `ledger/simulation/` of a clean in-container
# clone of the pinned go-algorand checkout (cgo + vendored libsodium, built
# once and cached in a named Docker volume, like
# tools/checktxngroup-oracle/run-in-docker.sh) and run with `go test`. It
# writes one JSON object per case, which this script copies to
# crates/core/algo-validate/tests/fixtures/pq_failure_texts.jsonl.
#
# Usage: run-in-docker.sh [--rebuild]

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
GO_ALGORAND_DIR="${GO_ALGORAND_DIR:-$(cd "$REPO_ROOT/../go-algorand" 2>/dev/null && pwd || true)}"
FIXTURE="$REPO_ROOT/crates/core/algo-validate/tests/fixtures/pq_failure_texts.jsonl"

GO_ALGORAND_PIN="v5.1.1-stable"
BUILDER_IMAGE="${BUILDER_IMAGE:-golang:1.27-bookworm}"
SRC_VOLUME="${SRC_VOLUME:-algod-rust-goalgo-src}"
MOD_VOLUME="${MOD_VOLUME:-algod-rust-gomod}"
CACHE_VOLUME="${CACHE_VOLUME:-algod-rust-gocache}"

REBUILD=0
while [ $# -gt 0 ]; do
    case "$1" in
        --rebuild) REBUILD=1; shift ;;
        -h|--help) sed -n '7,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
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

WORKDIR="$(mktemp -d -t pq-failure-text-oracle.XXXXXX)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

cp "$HERE/oracle_test.go" "$WORKDIR/oracle_test.go"

echo "==> pq-failure-text-oracle: go-algorand $GO_ALGORAND_PIN in $BUILDER_IMAGE"

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
    git config --global --add safe.directory '"'"'*'"'"'
    rm -rf "$CLONE"
    git clone --shared --no-checkout /src "$CLONE"
    git -C "$CLONE" checkout -q "$GO_ALGORAND_PIN"
    make -C "$CLONE" libsodium
fi
git config --global --add safe.directory '"'"'*'"'"'
ACTUAL_PIN="$(git -C "$CLONE" describe --tags --exact-match 2>/dev/null || echo unknown)"
if [ "$ACTUAL_PIN" != "$GO_ALGORAND_PIN" ]; then
    echo "error: cached clone is at $ACTUAL_PIN, expected $GO_ALGORAND_PIN;" >&2
    echo "       re-run with --rebuild" >&2
    exit 1
fi
STAGED="$CLONE/ledger/simulation/zz_algod_rust_pq_failure_text_oracle_test.go"
cp /io/oracle_test.go "$STAGED"
trap "rm -f $STAGED" EXIT
cd "$CLONE"
ORACLE_OUT=/io/out.jsonl go test -count=1 -run "^TestAlgodRustPQFailureTextOracle$" ./ledger/simulation/
'

mkdir -p "$(dirname "$FIXTURE")"
cp "$WORKDIR/out.jsonl" "$FIXTURE"
echo "==> wrote $(wc -l <"$FIXTURE") cases to $FIXTURE"
