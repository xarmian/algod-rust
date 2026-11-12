#!/usr/bin/env bash

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Transaction-gossip check on an isolated-participation-node topology (issue
# #2280): start the cluster with PHASE6_TOPOLOGY (rust-relay: go-node-3's only
# peer is rust-node-4; go-relay: the control, its only peer is go-node-1), wait
# until every node has passed WARMUP_ROUNDS, run tx_gossip.py with the
# topology's sources, record the per-node rounds, and tear the cluster down.
#
# Usage:
#   PHASE6_TOPOLOGY=rust-relay [PHASE6_HOST_PORT_BASE=5000] [PHASE6_SKIP_BUILD=1] \
#     OUT_DIR=./out ops/mixed-cluster/scripts/tx-gossip-topology.sh
#
# Env: WARMUP_ROUNDS (default 12), WARMUP_TIMEOUT_S (default 300),
# TX_GOSSIP_COUNT / TX_GOSSIP_WITHIN_S (tx_gossip.py), KEEP_CLUSTER=1 (no
# teardown). Exit 0 when tx_gossip.py passed.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ports.sh
source "$HERE/ports.sh"

TOPOLOGY="${PHASE6_TOPOLOGY:-rust-relay}"
OUT_DIR="${OUT_DIR:-$HERE/../out-$TOPOLOGY}"
WARMUP_ROUNDS="${WARMUP_ROUNDS:-12}"
WARMUP_TIMEOUT_S="${WARMUP_TIMEOUT_S:-300}"
ALGOD_TOKEN="${ALGOD_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
mkdir -p "$OUT_DIR"

PORTS_FREE_TIMEOUT_S="${PORTS_FREE_TIMEOUT_S:-60}"
NODE_PORTS=("$PHASE6_GO1_PORT" "$PHASE6_GO2_PORT" "$PHASE6_GO3_PORT" "$PHASE6_RUST_PORT")

# Stop the cluster (and purge netroot/) and wait until its host ports are free:
# `docker compose down` returns when the containers are removed, but on a CI
# runner the published ports can stay bound for a moment, which made the next
# repetition's start.sh refuse to start (issue #2280 follow-up).
teardown() {
    "$HERE/stop.sh" --purge > "$OUT_DIR/stop.log" 2>&1 || true
    # belt and braces: a container compose lost track of still holds its ports
    docker rm -f phase6-go-node-1 phase6-go-node-2 phase6-go-node-3 phase6-rust-node-4         >> "$OUT_DIR/stop.log" 2>&1 || true
    if ! phase6_wait_ports_free "$PORTS_FREE_TIMEOUT_S" "${NODE_PORTS[@]}"; then
        { docker ps -a; ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null; } > "$OUT_DIR/ports-diag.txt" 2>&1 || true
        return 1
    fi
}

cleanup() {
    if [ "${KEEP_CLUSTER:-0}" != "1" ]; then
        for n in go-node-1 go-node-2 go-node-3 rust-node-4; do
            docker logs "phase6-$n" > "$OUT_DIR/$n.log" 2>&1 || true
        done
        teardown || true
    fi
}
trap cleanup EXIT

export PHASE6_TOPOLOGY="$TOPOLOGY"
if ! teardown; then
    echo "error: a previous cluster's host ports are still bound; not starting" >&2
    exit 1
fi
"$HERE/start.sh" > "$OUT_DIR/start.log" 2>&1 || { tail -30 "$OUT_DIR/start.log"; exit 1; }

round_of() {
    curl -sf -m 5 -H "X-Algo-API-Token: $ALGOD_TOKEN" "http://127.0.0.1:$1/v2/status" 2>/dev/null \
        | python3 -c "import json,sys; print(json.load(sys.stdin).get('last-round', 0))" 2>/dev/null | tr -d '\r' || echo 0
}

# Every node past WARMUP_ROUNDS (also used again before a retry); 1 on timeout.
wait_for_rounds() {
    local deadline r1 r2 r3 r4
    echo "==> waiting for every node to pass round $WARMUP_ROUNDS (topology $TOPOLOGY)"
    deadline=$(( $(date +%s) + WARMUP_TIMEOUT_S ))
    while :; do
        r1="$(round_of "$PHASE6_GO1_PORT")"; r2="$(round_of "$PHASE6_GO2_PORT")"
        r3="$(round_of "$PHASE6_GO3_PORT")"; r4="$(round_of "$PHASE6_RUST_PORT")"
        echo "    rounds go1=$r1 go2=$r2 go3=$r3 rust4=$r4"
        if [ "${r1:-0}" -ge "$WARMUP_ROUNDS" ] && [ "${r2:-0}" -ge "$WARMUP_ROUNDS" ] \
            && [ "${r3:-0}" -ge "$WARMUP_ROUNDS" ] && [ "${r4:-0}" -ge "$WARMUP_ROUNDS" ]; then
            return 0
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            echo "error: not every node reached round $WARMUP_ROUNDS within ${WARMUP_TIMEOUT_S}s" >&2
            printf '{"topology":"%s","pass":false,"error":"warmup timeout","rounds":{"go-node-1":%s,"go-node-2":%s,"go-node-3":%s,"rust-node-4":%s}}\n' \
                "$TOPOLOGY" "${r1:-0}" "${r2:-0}" "${r3:-0}" "${r4:-0}" > "$OUT_DIR/tx-gossip.json"
            return 1
        fi
        sleep 5
    done
}

wait_for_rounds || exit 1

# The check itself. A SETUP error (tx-gossip.json carries an `error`: kmd or
# the funder account not ready, e.g. a node container restarting) says nothing
# about gossip and is retried once the nodes are back; a VERDICT (a pair that
# failed) is final. TX_GOSSIP_ATTEMPTS (default 2) bounds the tries.
TX_GOSSIP_ATTEMPTS="${TX_GOSSIP_ATTEMPTS:-2}"
rc=0
attempt=1
while :; do
    rc=0
    python3 "$HERE/tx_gossip.py" --out "$OUT_DIR/tx-gossip.json" --topology "$TOPOLOGY" \
        --count "${TX_GOSSIP_COUNT:-12}" --within-s "${TX_GOSSIP_WITHIN_S:-6}" \
        > "$OUT_DIR/tx-gossip.log" 2>&1 || rc=$?
    cat "$OUT_DIR/tx-gossip.log"
    [ "$rc" = 0 ] && break
    if [ "$attempt" -lt "$TX_GOSSIP_ATTEMPTS" ] \
        && python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("error") else 1)' \
            "$OUT_DIR/tx-gossip.json" 2>/dev/null; then
        echo "==> tx_gossip.py hit a setup error (attempt $attempt of $TX_GOSSIP_ATTEMPTS); waiting for the nodes and retrying"
        attempt=$((attempt + 1))
        wait_for_rounds || break
        continue
    fi
    break
done

# The topology is checked from the Go nodes' own connection logs, not assumed
# from the configuration: go-node-3 must have dialed only its planned relay,
# accepted nothing, and nobody may have dialed it.
for n in go-node-1 go-node-2 go-node-3 rust-node-4; do
    docker logs "phase6-$n" > "$OUT_DIR/$n.log" 2>&1 || true
done
python3 "$HERE/topology.py" verify "$TOPOLOGY" "$OUT_DIR" | tee "$OUT_DIR/topology-check.log" || rc=1
exit "$rc"
