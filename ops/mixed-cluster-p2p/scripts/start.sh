#!/usr/bin/env bash

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Start the 4-node P2P interop + consensus harness (issues #543, #560, #589).
#
# Steps:
#   1. If netroot/ is missing, bootstrap a 3-relay + 1-participant netgoal
#      network (see ../template.json: Wallet1-3 = 30 online stake each on
#      the Go relays, Wallet4 = 10 online stake for the Rust node).
#   2. Overlay each Go node's config.json so it runs plain P2P (no
#      WS-gossip): EnableP2P=true, NetAddress=0.0.0.0:<port>,
#      IncomingConnectionsLimit set non-zero (p2p.go forces listenAddr=""
#      when this is 0), EndpointAddress=0.0.0.0:8080, DNSBootstrapID="",
#      EnableDHTProviders=true (config/localTemplate.go: "enables the DHT
#      for peer discovery and capabilities advertisement" — defaults to
#      false; without it, `network/p2pNetwork.go` never attaches a kad DHT
#      node at all, and any DHT query against the node comes back empty
#      instantly rather than actually reaching out over the network — this
#      was issue #560's first real finding).
#   3. Start go-node-1 with no PEER_ADDRESS (bootstrap origin), scrape its
#      PeerID from the "P2P host created: peer ID %s addrs %s" log line
#      go-algorand emits unconditionally at P2P host creation
#      (network/p2pNetwork.go), then start go-node-2 with PEER_ADDRESS set
#      to go-node-1's *internal* docker-network multiaddr — the only
#      address go-node-2 is ever directly told — then likewise chain
#      go-node-3 off go-node-2. This chain topology (1 -> 2 -> 3, no node
#      told about a non-adjacent peer) means any address the Rust test
#      discovers beyond one hop can only have come from real Kademlia DHT
#      routing.
#   4. Print/persist each Go node's *host*-dialable multiaddr (via the
#      docker-compose host port mappings) to netroot/.p2p-multiaddr-N.
#   5. Read go-node-1's genesis hash off its REST API, locate Wallet4's
#      `.partkey` under netroot/Node4Rust/<genesis-id>/, and start
#      rust-node-4 in P2pOnly mode (`--enable-p2p`,
#      `--p2p-bootstrap-peers=<go-node-1's internal multiaddr>`) — issue
#      #589's stake-provisioned Rust participant.
#
# Consume the go-only result directly (without the Rust node):
#   ALGOD_RUST_P2P_GO_MULTIADDR="$(cat netroot/.p2p-multiaddr-1)" \
#   ALGOD_RUST_P2P_GO_MULTIADDR_3="$(cat netroot/.p2p-multiaddr-3)" \
#     cargo test --package algod-rust --test p2p_go_algorand_interop -- --ignored --nocapture

set -euo pipefail

# MSYS/Git-Bash mangles any argument or environment-variable value that
# looks like a POSIX absolute path (e.g. PEER_ADDRESS=/dns4/go-node-1/...,
# passed to `docker compose up` below) into a Windows path before it ever
# reaches docker — exporting this for the whole script (not just the
# individual `docker run` invocations below, which already opted in
# per-call) covers the `docker compose up -d go-node-2/3` calls too, whose
# PEER_ADDRESS env vars hit exactly this mangling (found while
# reproducing issue #564 on Windows).
export MSYS_NO_PATHCONV=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

NETROOT="$ROOT/netroot"
TEMPLATE="$ROOT/template.json"
ALGOD_IMG="algorand/algod:5.0.0-stable"
NUM_ROUNDS="${NUM_ROUNDS:-30000}"
ALGOD_TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

# Same MSYS/Git-Bash path-mangling workaround as
# ops/mixed-cluster/scripts/start.sh.
host_path() {
    if [ -n "${MSYSTEM:-}" ]; then
        (cd "$1" 2>/dev/null && pwd -W) || echo "$1"
    else
        echo "$1"
    fi
}

RUST_DATA_DIR="$NETROOT/rust-node-4-data"

echo "==> P2P interop harness start (3 go-algorand nodes, chain-bootstrapped, + 1 rust participant)"
echo "    netroot:  $NETROOT"

# -- 1. Bootstrap the netgoal tree if missing ------------------------------
if [ ! -f "$NETROOT/network.json" ] || [ ! -d "$NETROOT/Node1" ] || [ ! -d "$NETROOT/Node4Rust" ]; then
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
        network create -n p2pinterop -r /netroot -t /template.json

    rm -f "$RENDERED"
else
    echo "==> reusing existing netroot/ (run stop.sh to reset)"
fi

# -- 2. Patch each node's config.json for plain P2P mode ------------------
#
# NetAddress is bound to each node's *static* docker-network IP (see the
# `networks.p2pinterop` ipv4_address pins in ../docker-compose.yml), not
# 0.0.0.0 — issue #566's root cause: go-algorand's own
# `network/p2p.addressFilter` (`network/p2p/p2p.go`) strips every
# candidate advertised address whenever NetAddress binds the *unspecified*
# address (`manet.IsIPUnspecified` — true for 0.0.0.0/::, false for a
# specific address including a private one), which left every node with
# zero addresses to announce and silently broke DHT provider-record
# propagation between all three nodes (`go-libp2p-kad-dht@v0.38.0`'s
# `PutProviderAddrs`: "no known addresses for self, cannot put provider").
# Binding to the specific static IP keeps `needAddressFilter` false so the
# real, routable-within-this-network address is advertised instead.
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
patch_p2p_config Node1 4161 172.28.0.11
patch_p2p_config Node2 4162 172.28.0.12
patch_p2p_config Node3 4163 172.28.0.13

# -- 3. Start go-node-1 (bootstrap origin, no PEER_ADDRESS) ----------------
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
wait_for_rest 5001 go-node-1

# network/p2pNetwork.go: log.Infof("P2P host created: peer ID %s addrs %s", ...)
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
    echo "       (confirm EnableP2P actually took effect: docker compose exec $service cat /algod/data/config.json)" >&2
    exit 1
}

echo "==> waiting for go-node-1 P2P host creation log line"
PEER_ID_1="$(scrape_peer_id go-node-1)"
MULTIADDR_1_HOST="/ip4/127.0.0.1/tcp/5161/p2p/$PEER_ID_1"
MULTIADDR_1_INTERNAL="/dns4/go-node-1/tcp/4161/p2p/$PEER_ID_1"
# go-node-1's static docker-network IP (see its `networks.p2pinterop`
# comment in ../docker-compose.yml), NOT the /dns4/ form above: algod-rust's
# libp2p host (`algo_p2p::host::P2pHost::new`) builds its Swarm with
# `.with_tcp(...)` only, no `.with_dns()` — a /dns4/ bootstrap multiaddr
# therefore never resolves and the dial silently never establishes a
# connection (no error surfaces either; `P2pTransport`'s swarm event loop
# has no handler for `SwarmEvent::OutgoingConnectionError`, so the failure
# is invisible short of watching `connected_peers` stay 0 forever). This
# was found live while building this harness (issue #589) — go-node-2/3
# above still use the /dns4/ form because go-algorand's own P2P stack does
# support DNS resolution.
MULTIADDR_1_INTERNAL_IP="/ip4/172.28.0.11/tcp/4161/p2p/$PEER_ID_1"
echo "$MULTIADDR_1_HOST" > "$NETROOT/.p2p-multiaddr-1"
echo "==> go-node-1 P2P multiaddr (host-dialable): $MULTIADDR_1_HOST"

# -- 4. Start go-node-2, bootstrapped ONLY off go-node-1 -------------------
echo "==> docker compose up -d go-node-2 (PEER_ADDRESS=$MULTIADDR_1_INTERNAL)"
GO_NODE_2_PEER_ADDRESS="$MULTIADDR_1_INTERNAL" docker compose up -d go-node-2
wait_for_rest 5002 go-node-2

echo "==> waiting for go-node-2 P2P host creation log line"
PEER_ID_2="$(scrape_peer_id go-node-2)"
MULTIADDR_2_HOST="/ip4/127.0.0.1/tcp/5162/p2p/$PEER_ID_2"
MULTIADDR_2_INTERNAL="/dns4/go-node-2/tcp/4162/p2p/$PEER_ID_2"
echo "$MULTIADDR_2_HOST" > "$NETROOT/.p2p-multiaddr-2"
echo "==> go-node-2 P2P multiaddr (host-dialable): $MULTIADDR_2_HOST"

# -- 5. Start go-node-3, bootstrapped ONLY off go-node-2 -------------------
# go-node-3 is never told go-node-1's address — it can only learn about
# go-node-1 (and vice versa) via Kademlia DHT routing through go-node-2.
echo "==> docker compose up -d go-node-3 (PEER_ADDRESS=$MULTIADDR_2_INTERNAL)"
GO_NODE_3_PEER_ADDRESS="$MULTIADDR_2_INTERNAL" docker compose up -d go-node-3
wait_for_rest 5003 go-node-3

echo "==> waiting for go-node-3 P2P host creation log line"
PEER_ID_3="$(scrape_peer_id go-node-3)"
MULTIADDR_3_HOST="/ip4/127.0.0.1/tcp/5163/p2p/$PEER_ID_3"
echo "$MULTIADDR_3_HOST" > "$NETROOT/.p2p-multiaddr-3"
echo "==> go-node-3 P2P multiaddr (host-dialable): $MULTIADDR_3_HOST"

echo "==> all three go-algorand P2P nodes started; chain topology: 1 <- 2 <- 3"
echo "    (written to $NETROOT/.p2p-multiaddr-1, -2, -3)"

# -- 6. Start rust-node-4 (issue #589) --------------------------------------
#
# The genesis-id `goal network create` actually picked (needed both to
# locate Wallet4's .partkey and as --genesis-id).
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
print('{}-{}'.format(g.get('network', 'p2pinterop'), g.get('id', 'v1')))
" "$(cat "$GENESIS_SRC")" | tr -d '\r')"
echo "==> genesis id: $GENESIS_ID"

PARTKEY_DIR="$NETROOT/Node4Rust/$GENESIS_ID"
if ! ls "$PARTKEY_DIR"/*.partkey >/dev/null 2>&1; then
    echo "error: no .partkey under $PARTKEY_DIR" >&2
    echo "       Wallet4 must be Online in template.json; re-run stop.sh --purge && start.sh" >&2
    exit 1
fi
echo "==> rust partkey dir: $PARTKEY_DIR ($(ls "$PARTKEY_DIR"/*.partkey | wc -l | tr -d ' ') key(s))"

# go-node-1's genesis hash — a digest over the canonical-msgpack Genesis
# struct, so shell cannot derive it; read it off go-node-1's own REST once
# healthy, same as ops/mixed-cluster/scripts/start.sh does.
echo "==> reading genesis hash from go-node-1 (port 5001)"
GENESIS_HASH=""
for _ in $(seq 1 60); do
    PARAMS="$(curl -sf -H "X-Algo-API-Token: $ALGOD_TOKEN" \
        http://127.0.0.1:5001/v2/transactions/params 2>/dev/null || true)"
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
    echo "error: could not read the genesis hash from go-node-1 (port 5001)" >&2
    echo "       check: docker compose logs go-node-1" >&2
    exit 1
fi
echo "==> genesis hash: $GENESIS_HASH"

# Seed the Rust node's writable data dir with the harness's well-known
# token so one curl header works against all four REST endpoints, mirroring
# ops/mixed-cluster/scripts/start.sh's own step 4.
mkdir -p "$RUST_DATA_DIR"
printf '%s' "$ALGOD_TOKEN" > "$RUST_DATA_DIR/algod.token"
printf '%s' "$ALGOD_TOKEN" > "$RUST_DATA_DIR/algod.admin.token"

export P2PINTEROP_GENESIS_ID="$GENESIS_ID"
export P2PINTEROP_GENESIS_HASH="$GENESIS_HASH"
export P2PINTEROP_GO1_MULTIADDR="$MULTIADDR_1_INTERNAL_IP"

cat > "$NETROOT/.p2pinterop-env" <<EOF
P2PINTEROP_GENESIS_ID=$GENESIS_ID
P2PINTEROP_GENESIS_HASH=$GENESIS_HASH
P2PINTEROP_GO1_MULTIADDR=$MULTIADDR_1_INTERNAL_IP
EOF

# P2PINTEROP_SKIP_BUILD=1 reuses whatever `algod-rust-p2pinterop:local`
# already exists instead of rebuilding it (mirrors
# ops/mixed-cluster/scripts/start.sh's PHASE6_SKIP_BUILD).
if [ "${P2PINTEROP_SKIP_BUILD:-0}" = "1" ]; then
    echo "==> docker compose up -d rust-node-4 (P2PINTEROP_SKIP_BUILD=1, using algod-rust-p2pinterop:local)"
    docker compose up -d rust-node-4
else
    echo "==> docker compose up -d --build rust-node-4"
    docker compose up -d --build rust-node-4
fi

echo ""
echo "cluster started: 3 go-algorand P2P nodes + 1 algod-rust P2pOnly participant."
echo "peek at rounds with:"
echo "    $HERE/status.sh"
echo "tear down with:"
echo "    $HERE/stop.sh"
