#!/usr/bin/env bash

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# upgradeprop-nonutf8.sh — issue #2400 opt-in live case (follow-up of #2397).
#
# go accepts a block whose `upgradeprop` is ANY byte string of at most
# MaxVersionStringLen bytes (data/bookkeeping/block.go applyUpgradeVote), and
# then carries it as `nextproto` in every header until the vote deadline
# `nextbefore`, where the failed proposal is cleared. go's msgp string reader
# (ReadStringBytes) does not validate UTF-8, so a non-UTF-8 proposal is valid
# on go; algod-rust before #2397 rejected it at decode and forked off.
#
# The case:
#   1. a FRESH genesis (CLAUDE.md, issue #1590) with the future protocol's
#      UpgradeVoteRounds shortened to 20 by a go-generated consensus.json
#      (upgradeprop-inject/consensus.json, installed on all 4 nodes through
#      start.sh's PHASE6_CONSENSUS_OVERRIDE), so the vote deadline is reached
#      in about a minute;
#   2. go-node-1 runs a test-only go-algorand v5.0.5-stable build
#      (upgradeprop-inject/: Dockerfile + inject.patch) whose proposer, for
#      rounds [FROM, UNTIL), proposes the non-UTF-8 bytes INJECT_HEX.
#      go-node-2/3 stay stock, rust-node-4 is the image under test;
#   3. upgradeprop_check.py waits for the proposal block and the deadline +
#      MARGIN rounds, then fetches every round from every node and asserts:
#      nobody stalled, block hash AND raw block msgpack identical on all four
#      nodes, upgradeprop/nextproto/nextbefore byte-exact, cleared at the
#      deadline. It also reports which window blocks the Rust node proposed.
#
# TDD: RUST_IMAGE=<an algod-rust image built before 2bc2701b (#2397)> must
# FAIL (rust-node-4 stalls at the proposal round); the default (this tree's
# algod-rust-phase6:local) must PASS.
#
# Usage:
#   bash ops/mixed-cluster/scripts/upgradeprop-nonutf8.sh
#   PHASE6_HOST_PORT_BASE=5000 RUST_IMAGE=algod-rust-phase6:pre2397 bash ...
#   make consensus-cluster-upgradeprop
#
# Env:
#   INJECT_HEX    proposed bytes, hex     (7068617365362dfffe2dc328 =
#                 "phase6-" ff fe "-" c3 28: two invalid UTF-8 sequences)
#   INJECT_FROM   first round the injector proposes it          (10)
#   INJECT_UNTIL  first round it no longer does                 (FROM+12; must
#                 stay below FROM+20 so exactly one proposal cycle happens)
#   MARGIN        rounds checked past the vote deadline         (10)
#   RUST_IMAGE    rust-node-4 image (no rebuild); unset = build this tree
#   GO_IMAGE      injector image (default algod-upgradeprop-inject:local,
#                 built from upgradeprop-inject/ when missing)
#   TIMEOUT       wall-clock cap of the wait, seconds           (600)
#   KEEP_CLUSTER=1  leave the cluster up
#   OUT_DIR       artifact directory
#
# Exit 0 only if every check passed.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ports.sh
source "$HERE/ports.sh"  # PHASE6_HOST_PORT_BASE -> PHASE6_*_PORT (issue #1956)
ROOT="$(cd "$HERE/.." && pwd)"
INJECT_DIR="$ROOT/upgradeprop-inject"

INJECT_HEX="${INJECT_HEX:-7068617365362dfffe2dc328}"
INJECT_FROM="${INJECT_FROM:-10}"
INJECT_UNTIL="${INJECT_UNTIL:-$(( INJECT_FROM + 12 ))}"
MARGIN="${MARGIN:-10}"
TIMEOUT="${TIMEOUT:-600}"
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"
GO_IMAGE="${GO_IMAGE:-algod-upgradeprop-inject:local}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$ROOT/upgradeprop-run-$RUN_ID}"
mkdir -p "$OUT_DIR"

host_path() {  # native path for the Windows python3 under Git Bash
    if [ -n "${MSYSTEM:-}" ]; then
        (cd "$1" 2>/dev/null && pwd -W) || echo "$1"
    else
        echo "$1"
    fi
}

# The vote window comes from the committed override, not a second constant.
VOTE_ROUNDS="$(python3 -c "import json,sys;print(json.load(sys.stdin)['future']['UpgradeVoteRounds'])" \
    < "$INJECT_DIR/consensus.json" | tr -d '\r')"
if [ "$INJECT_UNTIL" -ge $(( INJECT_FROM + VOTE_ROUNDS )) ]; then
    echo "error: INJECT_UNTIL ($INJECT_UNTIL) must be < INJECT_FROM + UpgradeVoteRounds ($INJECT_FROM + $VOTE_ROUNDS)" >&2
    exit 2
fi

if ! docker image inspect "$GO_IMAGE" >/dev/null 2>&1; then
    echo "==> building the injector image $GO_IMAGE (go-algorand v5.0.5-stable + inject.patch)"
    docker build -t "$GO_IMAGE" "$INJECT_DIR" > "$OUT_DIR/build-injector.log" 2>&1 || {
        echo "injector build failed; see $OUT_DIR/build-injector.log" >&2
        exit 1
    }
fi

teardown() {
    if [ "$KEEP_CLUSTER" = "1" ]; then
        echo "==> KEEP_CLUSTER=1, leaving the cluster up"
        return
    fi
    # --purge: netroot/ now holds the shortened-vote-window consensus.json,
    # which must not leak into a later REUSE_NETROOT=1 run
    echo "==> tearing the cluster down (and purging netroot/)"
    (cd "$ROOT" && bash "$HERE/stop.sh" --purge >/dev/null 2>&1) || true
}

# Both compose files for every compose call start.sh / stop.sh make.
export COMPOSE_PATH_SEPARATOR=":"
export COMPOSE_FILE="docker-compose.yml:docker-compose.upgradeprop.yml"
export PHASE6_UPGRADEPROP_GO_IMAGE="$GO_IMAGE"
export PHASE6_UPGRADEPROP_HEX="$INJECT_HEX"
export PHASE6_UPGRADEPROP_FROM="$INJECT_FROM"
export PHASE6_UPGRADEPROP_UNTIL="$INJECT_UNTIL"
export PHASE6_CONSENSUS_OVERRIDE="$INJECT_DIR/consensus.json"
if [ -n "${RUST_IMAGE:-}" ]; then
    # never `up --build` here: it would retag this tree's build as RUST_IMAGE
    export PHASE6_RUST_IMAGE="$RUST_IMAGE" PHASE6_SKIP_BUILD=1
fi

# Fresh genesis (CLAUDE.md "Mixed-cluster soaks must start from a fresh genesis").
echo "==> purging any previous cluster + netroot"
bash "$HERE/stop.sh" --purge > "$OUT_DIR/stop-purge.log" 2>&1 || true
trap teardown EXIT

echo "==> starting the mixed cluster (go-node-1 = injector, rust-node-4 = ${RUST_IMAGE:-this tree})"
bash "$HERE/start.sh" > "$OUT_DIR/start.log" 2>&1 || {
    echo "start.sh failed; see $OUT_DIR/start.log" >&2
    exit 1
}
docker inspect --format '{{.Config.Image}} {{.Image}}' phase6-go-node-1 phase6-rust-node-4 \
    | tee "$OUT_DIR/images.txt"

RUST_ADDR="$(python3 -c "
import json, sys
g = json.load(sys.stdin)
print(next(a['addr'] for a in g['alloc'] if a.get('comment') == 'Wallet4'))
" < "$ROOT/netroot/genesis.json" | tr -d '\r')"
echo "==> rust-node-4 account $RUST_ADDR; injecting upgradeprop $INJECT_HEX for rounds [$INJECT_FROM, $INJECT_UNTIL), vote window $VOTE_ROUNDS"

rc=0
python3 "$HERE/upgradeprop_check.py" run \
    --inject-hex "$INJECT_HEX" \
    --inject-until "$INJECT_UNTIL" \
    --vote-rounds "$VOTE_ROUNDS" \
    --margin "$MARGIN" \
    --timeout "$TIMEOUT" \
    --rust-address "$RUST_ADDR" \
    --out "$(host_path "$OUT_DIR")/upgradeprop-summary.json" || rc=$?

for c in phase6-go-node-1 phase6-go-node-2 phase6-go-node-3 phase6-rust-node-4; do
    docker logs "$c" > "$OUT_DIR/$c.log" 2>&1 || true
done
if grep -q "upgradeprop-inject: proposing" "$OUT_DIR/phase6-go-node-1.log"; then
    echo "    [INFO] injector-active: go-node-1 logged 'upgradeprop-inject: proposing'"
fi
# pre-#2397 algod-rust: "rmp_decode: read_string: invalid utf-8" on every
# proposal / block carrying the bytes
utf8_errors="$(grep -c 'invalid utf-8' "$OUT_DIR/phase6-rust-node-4.log" || true)"
if [ "${utf8_errors:-0}" != "0" ]; then
    echo "    [FAIL] rust-decodes: rust-node-4 logged $utf8_errors 'invalid utf-8' decode error(s)" >&2
    rc=1
else
    echo "    [PASS] rust-decodes: no 'invalid utf-8' decode error in rust-node-4's log"
fi
if grep -Eq 'panicked at|^thread .* panicked' "$OUT_DIR/phase6-rust-node-4.log"; then
    echo "    [FAIL] rust-no-panic: rust-node-4 log contains a panic" >&2
    rc=1
fi

echo "==> artifacts in $OUT_DIR"
if [ "$rc" = "0" ]; then
    echo "==> PASS: every node accepted the non-UTF-8 upgradeprop with identical blocks"
else
    echo "==> FAIL (exit $rc)"
fi
exit "$rc"
