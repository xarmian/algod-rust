#!/usr/bin/env bash

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# consensus-round-trip.sh — issue #589 acceptance gate.
#
# Brings up the 4-node P2P-mode cluster (3 go-algorand P2P nodes + 1
# algod-rust `P2pOnly` participant, all four holding ONLINE stake — see
# ../template.json), waits for it to advance ROUNDS rounds, and asserts:
#
#   (a) all four nodes advance in lockstep (max-min <= LAG_TOLERANCE);
#   (b) the Rust node's REST /v2/status last-round progresses by at
#       least ROUNDS (i.e. it is not merely alive but actually chaining
#       blocks it validated over the /algorand-ws/2.2.0 stream / DHT
#       gossipsub P2P transport, not WS-gossip — there is no WS listener
#       in this harness at all);
#   (c) no Go node logs an agreement-level rejection of a peer's message
#       over the whole run.
#
# This is the P2P-transport analogue of
# `ops/mixed-cluster/scripts/participation-smoke.sh` (issue #469) — same
# assertions, same stake split (30/30/30/10), different transport.
#
# TDD note (issue #589's own instruction): before the stake-provisioned
# rust-node-4 service + P2P bootstrap wiring existed, this assertion
# failed for the right reason — rust-node-4 never started at all (no
# `docker-compose.yml` service), so `wait_all_rest` timed out with
# "unreachable" on port 5004. With a service that had zero stake (or a
# `--peers`-only / non-P2P config), it would instead fail at (b): the
# node's round would stay pinned near genesis because it never receives
# proposals/votes over the `/algorand-ws/2.2.0` stream go-algorand
# actually uses for that traffic in P2P mode.
#
# Usage:
#   bash ops/mixed-cluster-p2p/scripts/consensus-round-trip.sh
#
# Env:
#   ROUNDS           rounds to advance before asserting     (default 30)
#   ROUND_TIMEOUT    seconds to wait for those rounds        (default 900)
#   LAG_TOLERANCE    max round spread across the 4 nodes     (default 5)
#   KEEP_CLUSTER=1   leave the cluster running on exit (for debugging)
#   SKIP_START=1     assume the cluster is already up

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ROUNDS="${ROUNDS:-30}"
ROUND_TIMEOUT="${ROUND_TIMEOUT:-900}"
LAG_TOLERANCE="${LAG_TOLERANCE:-5}"
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"
SKIP_START="${SKIP_START:-0}"
ALGOD_TOKEN="${ALGOD_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"

# name|container|host REST port.
NODES=(
    "go-node-1|p2pinterop-go-node-1|5001"
    "go-node-2|p2pinterop-go-node-2|5002"
    "go-node-3|p2pinterop-go-node-3|5003"
    "rust-node-4|p2pinterop-rust-node-4|5004"
)
GO_CONTAINERS=(p2pinterop-go-node-1 p2pinterop-go-node-2 p2pinterop-go-node-3)
RUST_CONTAINER=p2pinterop-rust-node-4

# WARN-level agreement rejections from ../go-algorand/agreement/trace.go
# (same pattern ops/mixed-cluster/scripts/participation-smoke.sh matches).
REJECTION_PATTERN='malformed proposal for|malformed vote for|rejected block for|bundle malformed for'

teardown() {
    local rc=$?
    if [ "$KEEP_CLUSTER" = "1" ]; then
        echo ""
        echo "KEEP_CLUSTER=1 — leaving the cluster up. Tear down with:"
        echo "    $HERE/stop.sh"
    else
        echo ""
        echo "==> tearing down"
        "$HERE/stop.sh" >/dev/null 2>&1 || true
    fi
    exit "$rc"
}

# ---------------------------------------------------------------- helpers

node_round() {
    local port="$1" body
    body="$(curl -sf -H "X-Algo-API-Token: $ALGOD_TOKEN" \
        "http://127.0.0.1:$port/v2/status" 2>/dev/null || true)"
    if [ -z "$body" ]; then
        echo "unreachable"
        return
    fi
    python3 -c "
import json, sys
try:
    print(json.loads(sys.argv[1]).get('last-round', 'unknown'))
except Exception:
    print('parse-error')
" "$body" | tr -d '\r'
}

wait_all_rest() {
    local deadline=$(( $(date +%s) + 300 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local all_up=1
        for row in "${NODES[@]}"; do
            local port="${row##*|}"
            local r
            r="$(node_round "$port")"
            [[ "$r" =~ ^[0-9]+$ ]] || all_up=0
        done
        if [ "$all_up" = "1" ]; then
            return 0
        fi
        sleep 3
    done
    echo "FAIL: not all four nodes served /v2/status within 300s" >&2
    for row in "${NODES[@]}"; do
        local name="${row%%|*}" port="${row##*|}"
        echo "    $name (port $port): $(node_round "$port")" >&2
    done
    return 1
}

round_line() {
    local out=""
    for row in "${NODES[@]}"; do
        local name="${row%%|*}" port="${row##*|}"
        out+="$name=$(node_round "$port") "
    done
    echo "$out"
}

# ------------------------------------------------------------------- main

echo "==> P2P mixed-cluster consensus round-trip test (issue #589)"
echo "    rounds=$ROUNDS timeout=${ROUND_TIMEOUT}s lag_tolerance=$LAG_TOLERANCE"

trap teardown EXIT INT TERM

if [ "$SKIP_START" != "1" ]; then
    "$HERE/start.sh"
else
    echo "==> SKIP_START=1 — using the running cluster"
fi

echo "==> waiting for all four REST endpoints"
wait_all_rest

RUST_STATUS="$(curl -sf -H "X-Algo-API-Token: $ALGOD_TOKEN" \
    http://127.0.0.1:5004/v2/status 2>/dev/null || true)"
if [ -z "$RUST_STATUS" ]; then
    echo "FAIL: rust-node-4 /v2/status is empty" >&2
    exit 1
fi

declare -A BASE
for row in "${NODES[@]}"; do
    name="${row%%|*}"; port="${row##*|}"
    BASE[$name]="$(node_round "$port")"
done
BASE_RUST="${BASE[rust-node-4]}"
BASE_MAX=-1
for name in "${!BASE[@]}"; do
    r="${BASE[$name]}"
    if [ "$r" -gt "$BASE_MAX" ]; then BASE_MAX="$r"; fi
done
echo "==> baseline: $(round_line)"

TARGET=$(( BASE_MAX + ROUNDS ))
echo "==> waiting for every node to reach round >= $TARGET"

DEADLINE=$(( $(date +%s) + ROUND_TIMEOUT ))
START_TS="$(date +%s)"
REACHED=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    all_there=1
    for row in "${NODES[@]}"; do
        port="${row##*|}"
        r="$(node_round "$port")"
        if ! [[ "$r" =~ ^[0-9]+$ ]] || [ "$r" -lt "$TARGET" ]; then
            all_there=0
        fi
    done
    if [ "$all_there" = "1" ]; then
        REACHED=1
        break
    fi
    sleep 5
done
ELAPSED=$(( $(date +%s) - START_TS ))

echo "==> final:    $(round_line)"
echo "==> elapsed:  ${ELAPSED}s"

if [ "$REACHED" != "1" ]; then
    echo "FAIL: not every node reached round $TARGET within ${ROUND_TIMEOUT}s" >&2
    exit 1
fi

# ── (a) lockstep ──────────────────────────────────────────────────────
MIN=-1; MAX=-1
declare -A FINAL
for row in "${NODES[@]}"; do
    name="${row%%|*}"; port="${row##*|}"
    r="$(node_round "$port")"
    if ! [[ "$r" =~ ^[0-9]+$ ]]; then
        echo "FAIL: $name round is '$r' at the end of the run" >&2
        exit 1
    fi
    FINAL[$name]="$r"
    if [ "$MAX" -lt 0 ] || [ "$r" -gt "$MAX" ]; then MAX="$r"; fi
    if [ "$MIN" -lt 0 ] || [ "$r" -lt "$MIN" ]; then MIN="$r"; fi
done
SPREAD=$(( MAX - MIN ))
echo "==> round spread across 4 nodes: $SPREAD (tolerance $LAG_TOLERANCE)"
if [ "$SPREAD" -gt "$LAG_TOLERANCE" ]; then
    echo "FAIL: nodes are not in lockstep (spread $SPREAD > $LAG_TOLERANCE)" >&2
    exit 1
fi

# ── (b) the Rust node itself progressed ───────────────────────────────
RUST_FINAL="${FINAL[rust-node-4]}"
RUST_DELTA=$(( RUST_FINAL - BASE_RUST ))
echo "==> rust-node-4 advanced $RUST_DELTA rounds (${BASE_RUST} -> ${RUST_FINAL})"
if [ "$RUST_DELTA" -lt "$ROUNDS" ]; then
    echo "FAIL: rust-node-4 only advanced $RUST_DELTA rounds, wanted >= $ROUNDS" >&2
    exit 1
fi

# ── (c) no Go-side agreement rejections ───────────────────────────────
echo "==> scanning Go node logs for agreement rejections"
REJECTIONS=0
for c in "${GO_CONTAINERS[@]}"; do
    hits="$(docker logs "$c" 2>&1 | grep -E "$REJECTION_PATTERN" || true)"
    n="$(printf '%s' "$hits" | grep -c . || true)"
    echo "    $c: $n"
    if [ "$n" -gt 0 ]; then
        REJECTIONS=$(( REJECTIONS + n ))
        printf '%s\n' "$hits" | head -10 >&2
    fi
done
if [ "$REJECTIONS" -gt 0 ]; then
    echo "FAIL: $REJECTIONS agreement-level rejection(s) in Go node logs" >&2
    exit 1
fi

# ── informational: Rust-side participation evidence ───────────────────
# Same evidence ops/mixed-cluster/scripts/participation-smoke.sh reports
# (not asserted — see that script's comment on why a 10%-stake proposer
# share is only ~expected, not guaranteed, over a short window).
RUST_ACCOUNT="$(docker logs "$RUST_CONTAINER" 2>&1 \
    | sed -e 's/\x1b\[[0-9;]*m//g' \
    | grep 'imported go-algorand participation key ' \
    | grep -o 'account=[A-Z2-7]\{58\}' | head -1 | cut -d= -f2 || true)"
echo "==> rust-node-4 account: ${RUST_ACCOUNT:-<unknown>}"
if [ -n "$RUST_ACCOUNT" ]; then
    VOTES="$(docker logs "${GO_CONTAINERS[0]}" 2>&1 \
        | grep -c "\"Sender\":\"$RUST_ACCOUNT\"" || true)"
    echo "    votes accepted by ${GO_CONTAINERS[0]}: $VOTES"
    if [ "$VOTES" -eq 0 ]; then
        echo "    WARNING: no Rust votes accepted by Go — the node is following," >&2
        echo "             not participating. Check its participation keys / P2P stream." >&2
    fi
    PROPOSED="$(python3 -c "
import json, sys, urllib.request
tok, acct, lo, hi = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
def blk(r):
    req = urllib.request.Request(
        'http://127.0.0.1:5001/v2/blocks/{}?format=json'.format(r),
        headers={'X-Algo-API-Token': tok})
    return json.loads(urllib.request.urlopen(req, timeout=15).read())
n = 0
for r in range(max(lo, 1), hi + 1):
    try:
        if blk(r).get('block', {}).get('prp') == acct:
            n += 1
    except Exception:
        pass
print(n)
" "$ALGOD_TOKEN" "$RUST_ACCOUNT" "$BASE_MAX" "$MAX" | tr -d '\r')"
    echo "    blocks proposed in rounds $BASE_MAX..$MAX: $PROPOSED (expected ~10% of the window)"
fi

echo ""
echo "PASS: 4-node P2P-mode cluster advanced $ROUNDS rounds in lockstep,"
echo "      rust-node-4 (P2pOnly, /algorand-ws/2.2.0 + gossipsub) made"
echo "      REST-visible progress, and no Go node logged an agreement-level"
echo "      rejection."
