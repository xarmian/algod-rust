#!/usr/bin/env bash
# Start the PLAN-32 / TASK-86 4-node mixed-cluster consensus harness.
#
# Steps:
#   1. If netroot/ is missing, bootstrap a 4-node netgoal network
#      (3 proposing Go nodes + 1 non-participating slot for the Rust peer).
#   2. Overlay each node's config.json with container-friendly listen
#      addresses (NetAddress=0.0.0.0:4161, EndpointAddress=0.0.0.0:8080,
#      DNSBootstrapID="" so no fallback to public DNS).
#   3. Extract the genesis-id the network actually got from goal; the
#      Rust node needs it at `--genesis-id`.
#   4. docker compose up -d --build.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

NETROOT="$ROOT/netroot"
TEMPLATE="$ROOT/template.json"
ALGOD_IMG="algorand/algod:4.5.1-stable"
NUM_ROUNDS="${NUM_ROUNDS:-30000}"
GENESIS_ID_FILE="$NETROOT/.phase6-genesis-id"

echo "==> phase6 mixed-cluster start"
echo "    netroot:  $NETROOT"
echo "    template: $TEMPLATE"

# -- 1. Bootstrap the netgoal tree if missing ------------------------------
#
# A complete bootstrap leaves BOTH `network.json` AND every expected
# Node<N>/ subdirectory. If `network.json` exists but one of the node
# dirs is missing, that means a previous bootstrap was interrupted;
# treat it as "needs regeneration" so we don't proceed with a
# half-built tree.
NEEDS_BOOTSTRAP=0
if [ ! -f "$NETROOT/network.json" ]; then
    NEEDS_BOOTSTRAP=1
else
    for node in Node1 Node2 Node3 Node4Rust; do
        if [ ! -d "$NETROOT/$node" ]; then
            echo "==> detected half-built netroot/ (missing $node) — rebuilding"
            NEEDS_BOOTSTRAP=1
            break
        fi
    done
fi

if [ "$NEEDS_BOOTSTRAP" = "1" ]; then
    echo "==> generating netroot/ via goal network create"
    # Clean any stale partial state. goal network create writes files
    # owned by uid 1001 (the `algorand` user inside the container); if
    # a previous aborted run left such files on the host, `rm -rf` from
    # the host won't succeed. Do the purge from inside a container.
    if [ -d "$NETROOT" ]; then
        docker run --rm \
            -v "$NETROOT:/netroot" \
            --entrypoint sh \
            "$ALGOD_IMG" \
            -c 'rm -rf /netroot/* /netroot/.[!.]* 2>/dev/null || true' || true
    fi
    mkdir -p "$NETROOT"

    # goal network create requires a template with NUM_ROUNDS substituted.
    RENDERED="$(mktemp -t phase6-template.XXXXXX.json)"
    sed "s/NUM_ROUNDS/${NUM_ROUNDS}/" "$TEMPLATE" > "$RENDERED"

    # Run goal network create inside the algod image. It writes every Node's
    # data dir + a shared genesis.json into /netroot.
    docker run --rm \
        -v "$NETROOT:/netroot" \
        -v "$RENDERED:/template.json:ro" \
        --entrypoint goal \
        "$ALGOD_IMG" \
        network create -n phase6net -r /netroot -t /template.json

    rm -f "$RENDERED"
else
    echo "==> reusing existing netroot/ (run stop.sh to reset)"
fi

# -- 2. Overlay per-node config so the container networking works ----------
#
# goal network create hard-codes NetAddress = 127.0.0.1:<port> which isn't
# reachable from sibling containers. Rewrite each Node's config.json to
# bind to 0.0.0.0 on predictable ports, and blank out DNSBootstrapID so
# the nodes don't try to reach mainnet/testnet relays from the private net.
for node in Node1 Node2 Node3 Node4Rust; do
    if [ ! -d "$NETROOT/$node" ]; then
        echo "error: $NETROOT/$node missing after bootstrap — rerun with stop.sh --purge and try again" >&2
        exit 1
    fi
    # Use algocfg from the image to avoid hand-rolling JSON diffs.
    docker run --rm \
        -v "$NETROOT/$node:/algod/data" \
        --entrypoint algocfg \
        "$ALGOD_IMG" \
        -d /algod/data set -p NetAddress -v "0.0.0.0:4161" >/dev/null
    docker run --rm \
        -v "$NETROOT/$node:/algod/data" \
        --entrypoint algocfg \
        "$ALGOD_IMG" \
        -d /algod/data set -p EndpointAddress -v "0.0.0.0:8080" >/dev/null
    docker run --rm \
        -v "$NETROOT/$node:/algod/data" \
        --entrypoint algocfg \
        "$ALGOD_IMG" \
        -d /algod/data set -p DNSBootstrapID -v "" >/dev/null
    echo "    configured $node"
done

# -- 3. Capture the genesis-id goal picked (needed by the Rust node) --------
# goal network create embeds an ID in the genesis.json; the Rust node must
# match it exactly or it rejects incoming messages.
if [ -f "$NETROOT/genesis.json" ]; then
    SRC="$NETROOT/genesis.json"
elif [ -f "$NETROOT/Node1/genesis.json" ]; then
    SRC="$NETROOT/Node1/genesis.json"
else
    echo "error: no genesis.json found after goal network create" >&2
    exit 1
fi
GENESIS_ID="$(python3 -c "
import json
with open('$SRC') as f:
    g = json.load(f)
net = g.get('network', 'phase6net')
id_ = g.get('id', 'v1')
print(f'{net}-{id_}')
")"
echo "$GENESIS_ID" > "$GENESIS_ID_FILE"
echo "==> genesis id: $GENESIS_ID"

# -- 4. Build + start the compose stack -------------------------------------
cd "$ROOT"
export PHASE6_GENESIS_ID="$GENESIS_ID"
echo "==> docker compose up -d --build"
docker compose up -d --build

echo ""
echo "cluster started. peek at rounds with:"
echo "    $HERE/status.sh"
echo "tear down with:"
echo "    $HERE/stop.sh"
