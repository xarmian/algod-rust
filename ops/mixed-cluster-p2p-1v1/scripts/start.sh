#!/usr/bin/env bash

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Start the 1 go-algorand + 1 algod-rust 50/50-stake P2P harness (issue
# #1580, fourth investigation round). See ../docker-compose.yml's header
# for the full rationale; this script is a straightforward reduction of
# ops/mixed-cluster-p2p/scripts/start.sh's steps 1/2/3/6 (there is no
# chain-bootstrap step since there is only one go node to begin with).
#
# Usage:
#   ops/mixed-cluster-p2p-1v1/scripts/start.sh
#   ops/mixed-cluster-p2p-1v1/scripts/status.sh
#   ops/mixed-cluster-p2p-1v1/scripts/stop.sh

set -euo pipefail

export MSYS_NO_PATHCONV=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

NETROOT="$ROOT/netroot"
TEMPLATE="$ROOT/template.json"
ALGOD_IMG="${ALGOD_IMG:-algorand/algod:5.0.2-stable}"
NUM_ROUNDS="${NUM_ROUNDS:-30000}"
ALGOD_TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

host_path() {
    if [ -n "${MSYSTEM:-}" ]; then
        (cd "$1" 2>/dev/null && pwd -W) || echo "$1"
    else
        echo "$1"
    fi
}

RUST_DATA_DIR="$NETROOT/rust-node-2-data"

echo "==> P2P 1-1 interop harness start (1 go-algorand node + 1 rust node, 50/50 stake)"
echo "    netroot:  $NETROOT"

# -- 1. Bootstrap the netgoal tree if missing ------------------------------
if [ ! -f "$NETROOT/network.json" ] || [ ! -d "$NETROOT/Node1" ] || [ ! -d "$NETROOT/Node2Rust" ]; then
    echo "==> generating netroot/ via goal network create"
    if [ -d "$NETROOT" ]; then
        MSYS_NO_PATHCONV=1 docker run --rm \
            -v "$(host_path "$NETROOT"):/netroot" \
            --entrypoint sh \
            "$ALGOD_IMG" \
            -c 'rm -rf /netroot/* /netroot/.[!.]* 2>/dev/null || true' || true
    fi
    mkdir -p "$NETROOT"

    RENDERED="$ROOT/.template.rendered.json"
    sed "s/NUM_ROUNDS/${NUM_ROUNDS}/" "$TEMPLATE" > "$RENDERED"

    MSYS_NO_PATHCONV=1 docker run --rm \
        -v "$(host_path "$NETROOT"):/netroot" \
        -v "$(host_path "$ROOT")/.template.rendered.json:/template.json:ro" \
        --entrypoint goal \
        "$ALGOD_IMG" \
        network create -n p2pinterop1v1 -r /netroot -t /template.json

    rm -f "$RENDERED"

    MSYS_NO_PATHCONV=1 docker run --rm \
        -v "$(host_path "$NETROOT"):/netroot" \
        --entrypoint sh \
        "$ALGOD_IMG" \
        -c 'chmod -R a+rwX /netroot'
else
    echo "==> reusing existing netroot/ (run stop.sh --purge to reset)"
fi

# -- 2. Patch go-node-1's config.json for plain P2P mode -------------------
patch_p2p_config() {
    local node_dir="$1" p2p_port="$2" net_address="$3"
    local node_host_path
    node_host_path="$(host_path "$NETROOT/$node_dir")"
    for kv in \
        "EnableP2P=true" \
        "NetAddress=${net_address}:${p2p_port}" \
        "IncomingConnectionsLimit=100" \
        "EndpointAddress=0.0.0.0:8080" \
        "DNSBootstrapID=" \
        "EnableDHTProviders=true"
    do
        MSYS_NO_PATHCONV=1 docker run --rm \
            -v "$node_host_path:/algod/data" \
            --entrypoint algocfg \
            "$ALGOD_IMG" \
            -d /algod/data set -p "${kv%%=*}" -v "${kv#*=}" >/dev/null
    done
    echo "    configured $node_dir for plain P2P on ${net_address}:$p2p_port (EnableP2P=true, no WS-gossip listener)"
}
patch_p2p_config Node1 4161 172.29.0.11

# -- 3. Start go-node-1 ------------------------------------------------------
cd "$ROOT"
echo "==> docker compose up -d go-node-1"
docker compose up -d go-node-1

wait_for_rest() {
    local host_port="$1" name="$2"
    echo "==> waiting for $name to answer /v2/status"
    for _ in $(seq 1 60); do
        if curl -sf -H "X-Algo-API-Token: $ALGOD_TOKEN" "http://127.0.0.1:${host_port}/v2/status" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    echo "error: $name never answered /v2/status — check 'docker compose logs $name'" >&2
    exit 1
}
wait_for_rest 5101 go-node-1

scrape_peer_id() {
    local service="$1"
    local peer_id=""
    for _ in $(seq 1 60); do
        peer_id="$(docker compose logs "$service" 2>/dev/null \
            | grep -o 'P2P host created: peer ID [A-Za-z0-9]*' \
            | head -1 \
            | awk '{print $NF}')"
        if [ -n "$peer_id" ]; then
            echo "$peer_id"
            return 0
        fi
        sleep 2
    done
    echo "error: never observed the 'P2P host created' log line for $service — check 'docker compose logs $service'" >&2
    exit 1
}

echo "==> waiting for go-node-1 P2P host creation log line"
PEER_ID_1="$(scrape_peer_id go-node-1)"
MULTIADDR_1_HOST="/ip4/127.0.0.1/tcp/5261/p2p/$PEER_ID_1"
# See ops/mixed-cluster-p2p/scripts/start.sh's comment on why algod-rust's
# libp2p host needs the /ip4/ form (no .with_dns() on its Swarm), not the
# /dns4/ form go-algorand's own nodes use with each other.
MULTIADDR_1_INTERNAL_IP="/ip4/172.29.0.11/tcp/4161/p2p/$PEER_ID_1"
echo "$MULTIADDR_1_HOST" > "$NETROOT/.p2p-multiaddr-1"
echo "==> go-node-1 P2P multiaddr (host-dialable): $MULTIADDR_1_HOST"

# -- 4. Start rust-node-2 ----------------------------------------------------
if [ -f "$NETROOT/genesis.json" ]; then
    GENESIS_SRC="$NETROOT/genesis.json"
elif [ -f "$NETROOT/Node1/genesis.json" ]; then
    GENESIS_SRC="$NETROOT/Node1/genesis.json"
else
    echo "error: no genesis.json found after goal network create" >&2
    exit 1
fi
GENESIS_ID="$(python3 -c "
import json, sys
g = json.loads(sys.argv[1])
print('{}-{}'.format(g.get('network', 'p2pinterop1v1'), g.get('id', 'v1')))
" "$(cat "$GENESIS_SRC")" | tr -d '\r')"
echo "==> genesis id: $GENESIS_ID"

PARTKEY_DIR="$NETROOT/Node2Rust/$GENESIS_ID"
if ! ls "$PARTKEY_DIR"/*.partkey >/dev/null 2>&1; then
    echo "error: no .partkey under $PARTKEY_DIR" >&2
    echo "       Wallet2 must be Online in template.json; re-run stop.sh --purge && start.sh" >&2
    exit 1
fi
echo "==> rust partkey dir: $PARTKEY_DIR ($(ls "$PARTKEY_DIR"/*.partkey | wc -l | tr -d ' ') key(s))"

echo "==> reading genesis hash from go-node-1 (port 5101)"
GENESIS_HASH=""
for _ in $(seq 1 60); do
    PARAMS="$(curl -sf -H "X-Algo-API-Token: $ALGOD_TOKEN" \
        http://127.0.0.1:5101/v2/transactions/params 2>/dev/null || true)"
    if [ -n "$PARAMS" ]; then
        GENESIS_HASH="$(python3 -c "
import base64, json, sys
print(base64.b64decode(json.loads(sys.argv[1])['genesis-hash']).hex())
" "$PARAMS" | tr -d '\r')"
        [ -n "$GENESIS_HASH" ] && break
    fi
    sleep 2
done
if [ -z "$GENESIS_HASH" ]; then
    echo "error: could not read the genesis hash from go-node-1 (port 5101)" >&2
    exit 1
fi
echo "==> genesis hash: $GENESIS_HASH"

mkdir -p "$RUST_DATA_DIR"
printf '%s' "$ALGOD_TOKEN" > "$RUST_DATA_DIR/algod.token"
printf '%s' "$ALGOD_TOKEN" > "$RUST_DATA_DIR/algod.admin.token"

export P2PINTEROP1V1_GENESIS_ID="$GENESIS_ID"
export P2PINTEROP1V1_GENESIS_HASH="$GENESIS_HASH"
export P2PINTEROP1V1_GO1_MULTIADDR="$MULTIADDR_1_INTERNAL_IP"

cat > "$NETROOT/.p2pinterop1v1-env" <<EOF
P2PINTEROP1V1_GENESIS_ID=$GENESIS_ID
P2PINTEROP1V1_GENESIS_HASH=$GENESIS_HASH
P2PINTEROP1V1_GO1_MULTIADDR=$MULTIADDR_1_INTERNAL_IP
EOF

if [ "${P2PINTEROP1V1_SKIP_BUILD:-0}" = "1" ]; then
    echo "==> docker compose up -d rust-node-2 (P2PINTEROP1V1_SKIP_BUILD=1, using algod-rust-p2pinterop1v1:local)"
    docker compose up -d rust-node-2
else
    echo "==> docker compose up -d --build rust-node-2"
    docker compose up -d --build rust-node-2
fi

echo ""
echo "cluster started: 1 go-algorand P2P node + 1 algod-rust P2pOnly participant (50/50 stake)."
echo "peek at rounds with:"
echo "    $HERE/status.sh"
echo "tear down with:"
echo "    $HERE/stop.sh"
