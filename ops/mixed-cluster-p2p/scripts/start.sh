#!/usr/bin/env bash
# Start the single-node go-algorand P2P interop harness (issue #543).
#
# Steps:
#   1. If netroot/ is missing, bootstrap a 1-node netgoal network
#      (see ../template.json).
#   2. Overlay Node1's config.json so it runs plain P2P (no WS-gossip):
#      EnableP2P=true, NetAddress=0.0.0.0:4161 (config/localTemplate.go's
#      IsP2PListenServer requires NetAddress != "" even in this mode —
#      see #543's investigation notes), IncomingConnectionsLimit set
#      non-zero (p2p.go forces listenAddr="" when this is 0),
#      EndpointAddress=0.0.0.0:8080, DNSBootstrapID="".
#   3. Start the container and wait for its REST API to answer.
#   4. Scrape the "P2P host created: peer ID %s addrs %s" log line
#      go-algorand emits unconditionally at P2P host creation
#      (network/p2pNetwork.go) to recover its PeerID, and print the
#      host-dialable multiaddr
#      (/ip4/127.0.0.1/tcp/5161/p2p/<peerid> — see docker-compose.yml's
#      5161:4161 port mapping) on stdout and into
#      netroot/.p2p-multiaddr.
#
# Consume the result:
#   ALGOD_RUST_P2P_GO_MULTIADDR="$(cat netroot/.p2p-multiaddr)" \
#     cargo test --test p2p_go_algorand_interop -p algod-rust

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

NETROOT="$ROOT/netroot"
TEMPLATE="$ROOT/template.json"
ALGOD_IMG="algorand/algod:4.7.0-stable"
NUM_ROUNDS="${NUM_ROUNDS:-30000}"
ALGOD_TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
MULTIADDR_FILE="$NETROOT/.p2p-multiaddr"

# Same MSYS/Git-Bash path-mangling workaround as
# ops/mixed-cluster/scripts/start.sh.
host_path() {
    if [ -n "${MSYSTEM:-}" ]; then
        (cd "$1" 2>/dev/null && pwd -W) || echo "$1"
    else
        echo "$1"
    fi
}

echo "==> P2P interop harness start"
echo "    netroot:  $NETROOT"

# -- 1. Bootstrap the netgoal tree if missing ------------------------------
if [ ! -f "$NETROOT/network.json" ] || [ ! -d "$NETROOT/Node1" ]; then
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

# -- 2. Patch config.json for plain P2P mode -------------------------------
NODE_HOST_PATH="$(host_path "$NETROOT/Node1")"
for kv in \
    "EnableP2P=true" \
    "NetAddress=0.0.0.0:4161" \
    "IncomingConnectionsLimit=100" \
    "EndpointAddress=0.0.0.0:8080" \
    "DNSBootstrapID="
do
    MSYS_NO_PATHCONV=1 docker run --rm \
        -v "$NODE_HOST_PATH:/algod/data" \
        --entrypoint algocfg \
        "$ALGOD_IMG" \
        -d /algod/data set -p "${kv%%=*}" -v "${kv#*=}" >/dev/null
done
echo "    configured Node1 for plain P2P (EnableP2P=true, no WS-gossip listener)"

# -- 3. Start and wait for REST -------------------------------------------
cd "$ROOT"
echo "==> docker compose up -d go-node-1"
docker compose up -d go-node-1

echo "==> waiting for go-node-1 to answer /v2/status"
for _ in $(seq 1 60); do
    if curl -sf -H "X-Algo-API-Token: $ALGOD_TOKEN" http://127.0.0.1:5001/v2/status >/dev/null 2>&1; then
        break
    fi
    sleep 2
done
if ! curl -sf -H "X-Algo-API-Token: $ALGOD_TOKEN" http://127.0.0.1:5001/v2/status >/dev/null 2>&1; then
    echo "error: go-node-1 never answered /v2/status — check 'docker compose logs go-node-1'" >&2
    exit 1
fi

# -- 4. Recover the PeerID from the log line -------------------------------
# network/p2pNetwork.go: log.Infof("P2P host created: peer ID %s addrs %s", ...)
echo "==> waiting for P2P host creation log line"
PEER_ID=""
for _ in $(seq 1 60); do
    PEER_ID="$(docker compose logs go-node-1 2>/dev/null \
        | grep -o 'P2P host created: peer ID [A-Za-z0-9]*' \
        | head -1 \
        | awk '{print $NF}')"
    if [ -n "$PEER_ID" ]; then
        break
    fi
    sleep 2
done
if [ -z "$PEER_ID" ]; then
    echo "error: never observed the 'P2P host created' log line — check 'docker compose logs go-node-1'" >&2
    echo "       (confirm EnableP2P actually took effect: docker compose exec go-node-1 cat /algod/data/config.json)" >&2
    exit 1
fi

MULTIADDR="/ip4/127.0.0.1/tcp/5161/p2p/$PEER_ID"
echo "$MULTIADDR" > "$MULTIADDR_FILE"
echo "==> go-node-1 P2P multiaddr: $MULTIADDR"
echo "    (written to $MULTIADDR_FILE)"
