#!/usr/bin/env bash
# Issue #496 (Phase 7) — start the 6-node 3 Go + 3 Rust mixed-cluster
# harness (50/50 stake split, all six wallets ONLINE).
#
# Adapted from ../../mixed-cluster/scripts/start.sh for six nodes instead
# of four; see that file's comments for the long-form rationale behind
# each step (netroot bootstrap, config overlay, genesis-id/hash capture,
# per-node data-dir seeding). This copy generalizes every "Node4Rust" /
# "rust-node-4" singular reference into a loop over three Rust nodes.
#
# Steps:
#   1. Bootstrap netroot/ via `goal network create` if missing.
#   2. Overlay each node's config.json for container networking.
#   3. Capture the genesis-id goal picked.
#   4. Start the 3 Go nodes, read the genesis hash off go-node-1.
#   5. Seed each Rust node's writable data dir, then
#      docker compose up -d (--build unless PHASE7_SKIP_BUILD=1).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

NETROOT="$ROOT/netroot"
TEMPLATE="$ROOT/template.json"
ALGOD_IMG="algorand/algod:5.0.0-stable"
NUM_ROUNDS="${NUM_ROUNDS:-30000}"
GENESIS_ID_FILE="$NETROOT/.phase7-genesis-id"
ENV_FILE="$NETROOT/.phase7-env"
ALGOD_TOKEN="${ALGOD_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"

GO_NODES=(Node1 Node2 Node3)
RUST_NODES=(Node4Rust Node5Rust Node6Rust)
ALL_NODES=("${GO_NODES[@]}" "${RUST_NODES[@]}")
# service-name -> Node<N> dir, in the order docker-compose.yml declares them.
declare -A RUST_SERVICE_FOR_NODE=(
    [Node4Rust]=rust-node-4
    [Node5Rust]=rust-node-5
    [Node6Rust]=rust-node-6
)

# See ../../mixed-cluster/scripts/start.sh — Git Bash / MSYS mangles both
# sides of a `docker run -v` argument.
host_path() {
    if [ -n "${MSYSTEM:-}" ]; then
        (cd "$1" 2>/dev/null && pwd -W) || echo "$1"
    else
        echo "$1"
    fi
}

echo "==> phase7 mixed-cluster start (3 Go + 3 Rust, 50/50 stake)"
echo "    netroot:  $NETROOT"
echo "    template: $TEMPLATE"

# -- 1. Bootstrap the netgoal tree if missing ------------------------------
NEEDS_BOOTSTRAP=0
if [ ! -f "$NETROOT/network.json" ]; then
    NEEDS_BOOTSTRAP=1
else
    for node in "${ALL_NODES[@]}"; do
        if [ ! -d "$NETROOT/$node" ]; then
            echo "==> detected half-built netroot/ (missing $node) — rebuilding"
            NEEDS_BOOTSTRAP=1
            break
        fi
    done
fi

if [ "$NEEDS_BOOTSTRAP" = "1" ]; then
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
        network create -n phase7net -r /netroot -t /template.json

    rm -f "$RENDERED"
else
    echo "==> reusing existing netroot/ (run stop.sh to reset)"
fi

# -- 2. Overlay per-node config so the container networking works ----------
for node in "${ALL_NODES[@]}"; do
    if [ ! -d "$NETROOT/$node" ]; then
        echo "error: $NETROOT/$node missing after bootstrap — rerun with stop.sh --purge and try again" >&2
        exit 1
    fi
    case " ${RUST_NODES[*]} " in
        *" $node "*) NET_ADDRESS="" ;;
        *)           NET_ADDRESS="0.0.0.0:4161" ;;
    esac
    NODE_HOST_PATH="$(host_path "$NETROOT/$node")"
    for kv in "NetAddress=$NET_ADDRESS" "EndpointAddress=0.0.0.0:8080" "DNSBootstrapID="; do
        MSYS_NO_PATHCONV=1 docker run --rm \
            -v "$NODE_HOST_PATH:/algod/data" \
            --entrypoint algocfg \
            "$ALGOD_IMG" \
            -d /algod/data set -p "${kv%%=*}" -v "${kv#*=}" >/dev/null
    done
    echo "    configured $node"
done

# -- 3. Capture the genesis-id goal picked ----------------------------------
if [ -f "$NETROOT/genesis.json" ]; then
    SRC="$NETROOT/genesis.json"
elif [ -f "$NETROOT/Node1/genesis.json" ]; then
    SRC="$NETROOT/Node1/genesis.json"
else
    echo "error: no genesis.json found after goal network create" >&2
    exit 1
fi
GENESIS_ID="$(python3 -c "
import json, sys
g = json.loads(sys.argv[1])
print('{}-{}'.format(g.get('network', 'phase7net'), g.get('id', 'v1')))
" "$(cat "$SRC")" | tr -d '\r')"
echo "$GENESIS_ID" > "$GENESIS_ID_FILE"
echo "==> genesis id: $GENESIS_ID"

for node in "${RUST_NODES[@]}"; do
    PARTKEY_DIR="$NETROOT/$node/$GENESIS_ID"
    if ! ls "$PARTKEY_DIR"/*.partkey >/dev/null 2>&1; then
        echo "error: no .partkey under $PARTKEY_DIR" >&2
        echo "       the matching wallet must be Online in template.json; re-run stop.sh --purge && start.sh" >&2
        exit 1
    fi
    echo "==> $node partkey dir: $PARTKEY_DIR ($(ls "$PARTKEY_DIR"/*.partkey | wc -l | tr -d ' ') key(s))"
done

# -- 4. Seed each Rust node's writable data dir -----------------------------
for node in "${RUST_NODES[@]}"; do
    svc="${RUST_SERVICE_FOR_NODE[$node]}"
    RUST_DATA_DIR="$NETROOT/${svc}-data"
    mkdir -p "$RUST_DATA_DIR"
    printf '%s' "$ALGOD_TOKEN" > "$RUST_DATA_DIR/algod.token"
    printf '%s' "$ALGOD_TOKEN" > "$RUST_DATA_DIR/algod.admin.token"
done

# -- 5. Start the Go nodes, then the Rust nodes -----------------------------
cd "$ROOT"
export PHASE7_GENESIS_ID="$GENESIS_ID"

echo "==> docker compose up -d go-node-1 go-node-2 go-node-3"
docker compose up -d go-node-1 go-node-2 go-node-3

echo "==> waiting for go-node-1 to answer /v2/status"
GENESIS_HASH=""
for _ in $(seq 1 60); do
    PARAMS="$(curl -sf -H "X-Algo-API-Token: $ALGOD_TOKEN" \
        http://127.0.0.1:4101/v2/transactions/params 2>/dev/null || true)"
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
    echo "error: could not read the genesis hash from go-node-1 (port 4101)" >&2
    echo "       check: docker logs phase7-go-node-1" >&2
    exit 1
fi
export PHASE7_GENESIS_HASH="$GENESIS_HASH"
echo "==> genesis hash: $GENESIS_HASH"

cat > "$ENV_FILE" <<EOF
PHASE7_GENESIS_ID=$GENESIS_ID
PHASE7_GENESIS_HASH=$GENESIS_HASH
EOF

if [ "${PHASE7_SKIP_BUILD:-0}" = "1" ]; then
    echo "==> docker compose up -d rust-node-4 rust-node-5 rust-node-6 (PHASE7_SKIP_BUILD=1, using algod-rust-phase7:local)"
    docker compose up -d rust-node-4 rust-node-5 rust-node-6
else
    echo "==> docker compose up -d --build rust-node-4 rust-node-5 rust-node-6"
    docker compose up -d --build rust-node-4 rust-node-5 rust-node-6
fi

echo ""
echo "cluster started. peek at rounds with:"
echo "    $HERE/status.sh"
echo "tear down with:"
echo "    $HERE/stop.sh"
