#!/usr/bin/env bash
# Start the 4-node mixed-cluster consensus harness (3 Go + 1 Rust, all
# four ONLINE participants — issue #469).
#
# Steps:
#   1. If netroot/ is missing, bootstrap a 4-node netgoal network
#      (3 Go relays holding 30% of stake each + Node4Rust holding 10%,
#      whose `.partkey` the Rust node imports).
#   2. Overlay each node's config.json with container-friendly listen
#      addresses (NetAddress=0.0.0.0:4161 on the Go relays, "" on
#      Node4Rust, EndpointAddress=0.0.0.0:8080, DNSBootstrapID="" so no
#      fallback to public DNS), and seed the Rust node's writable
#      --data-dir with the harness API token.
#   3. Extract the genesis-id the network actually got from goal; the
#      Rust node needs it at `--genesis-id` and to locate its partkey
#      directory (`netroot/Node4Rust/<genesis-id>/`).
#   4. Start the 3 Go nodes, wait for go-node-1 to be healthy, and read
#      the genesis HASH off its REST API — it is a digest over the
#      canonical-msgpack Genesis struct, so there is no way to derive it
#      in shell. The Rust node needs it to validate blocks.
#   5. docker compose up -d --build rust-node-4.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

NETROOT="$ROOT/netroot"
TEMPLATE="$ROOT/template.json"
ALGOD_IMG="algorand/algod:4.5.1-stable"
NUM_ROUNDS="${NUM_ROUNDS:-30000}"
GENESIS_ID_FILE="$NETROOT/.phase6-genesis-id"
ENV_FILE="$NETROOT/.phase6-env"
ALGOD_TOKEN="${ALGOD_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
# Host-side writable data dir the Rust node mounts at /data. `participate
# --data-dir` writes algod.token / algod.admin.token / algod.net there;
# the netroot bind mount itself is read-only.
RUST_DATA_DIR="$NETROOT/rust-node-4-data"

# Git Bash / MSYS rewrites both sides of a `docker run -v` argument: the
# container path `/netroot` becomes `C:/Program Files/Git/netroot` and the
# host path stays an unusable `/c/...`. Emit a Windows-style host path and
# let callers set MSYS_NO_PATHCONV=1 for the container side. Same helper
# as docker/scripts/stress-bootstrap.sh.
host_path() {
    if [ -n "${MSYSTEM:-}" ]; then
        (cd "$1" 2>/dev/null && pwd -W) || echo "$1"
    else
        echo "$1"
    fi
}

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
        MSYS_NO_PATHCONV=1 docker run --rm \
            -v "$(host_path "$NETROOT"):/netroot" \
            --entrypoint sh \
            "$ALGOD_IMG" \
            -c 'rm -rf /netroot/* /netroot/.[!.]* 2>/dev/null || true' || true
    fi
    mkdir -p "$NETROOT"

    # goal network create requires a template with NUM_ROUNDS substituted.
    # Render next to the template (rather than into $TMPDIR) so the file
    # lives on a path docker can bind-mount on every platform.
    RENDERED="$ROOT/.template.rendered.json"
    sed "s/NUM_ROUNDS/${NUM_ROUNDS}/" "$TEMPLATE" > "$RENDERED"

    # Run goal network create inside the algod image. It writes every Node's
    # data dir + a shared genesis.json into /netroot.
    MSYS_NO_PATHCONV=1 docker run --rm \
        -v "$(host_path "$NETROOT"):/netroot" \
        -v "$(host_path "$ROOT")/.template.rendered.json:/template.json:ro" \
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
    # Node4Rust's data dir is never handed to an algod container — the
    # Rust node only reads its genesis + `.partkey` out of it — but keep
    # NetAddress honest: it dials out and accepts no inbound peers.
    if [ "$node" = "Node4Rust" ]; then
        NET_ADDRESS=""
    else
        NET_ADDRESS="0.0.0.0:4161"
    fi
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
# Pass the file *contents* rather than its path: under Git Bash the
# `python3` on PATH is a native Windows build that cannot open an MSYS
# `/c/...` path. `tr -d '\r'` because that interpreter writes CRLF, and a
# stray CR would be interpolated straight into --genesis-id.
GENESIS_ID="$(python3 -c "
import json, sys
g = json.loads(sys.argv[1])
print('{}-{}'.format(g.get('network', 'phase6net'), g.get('id', 'v1')))
" "$(cat "$SRC")" | tr -d '\r')"
echo "$GENESIS_ID" > "$GENESIS_ID_FILE"
echo "==> genesis id: $GENESIS_ID"

# The Rust node imports its participation key from the genesis
# subdirectory `goal network create` wrote it into — the same place Go's
# `loadParticipationKeys` looks. Fail early with a clear message rather
# than letting the node boot with zero keys and silently never propose.
PARTKEY_DIR="$NETROOT/Node4Rust/$GENESIS_ID"
if ! ls "$PARTKEY_DIR"/*.partkey >/dev/null 2>&1; then
    echo "error: no .partkey under $PARTKEY_DIR" >&2
    echo "       Wallet4 must be Online in template.json; re-run stop.sh --purge && start.sh" >&2
    exit 1
fi
echo "==> rust partkey dir: $PARTKEY_DIR ($(ls "$PARTKEY_DIR"/*.partkey | wc -l | tr -d ' ') key(s))"

# -- 4. Seed the Rust node's writable data dir -----------------------------
# `participate --data-dir` is where the REST server reads/writes
# algod.token. Seeding it with the same well-known token the Go nodes use
# lets one curl header work against all four endpoints.
mkdir -p "$RUST_DATA_DIR"
printf '%s' "$ALGOD_TOKEN" > "$RUST_DATA_DIR/algod.token"
printf '%s' "$ALGOD_TOKEN" > "$RUST_DATA_DIR/algod.admin.token"

# -- 5. Start the Go nodes, then the Rust node -----------------------------
cd "$ROOT"
export PHASE6_GENESIS_ID="$GENESIS_ID"

echo "==> docker compose up -d go-node-1 go-node-2 go-node-3"
docker compose up -d go-node-1 go-node-2 go-node-3

echo "==> waiting for go-node-1 to answer /v2/status"
GENESIS_HASH=""
for _ in $(seq 1 60); do
    PARAMS="$(curl -sf -H "X-Algo-API-Token: $ALGOD_TOKEN" \
        http://127.0.0.1:4001/v2/transactions/params 2>/dev/null || true)"
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
    echo "error: could not read the genesis hash from go-node-1 (port 4001)" >&2
    echo "       check: docker logs phase6-go-node-1" >&2
    exit 1
fi
export PHASE6_GENESIS_HASH="$GENESIS_HASH"
echo "==> genesis hash: $GENESIS_HASH"

cat > "$ENV_FILE" <<EOF
PHASE6_GENESIS_ID=$GENESIS_ID
PHASE6_GENESIS_HASH=$GENESIS_HASH
EOF

echo "==> docker compose up -d --build rust-node-4"
docker compose up -d --build rust-node-4

echo ""
echo "cluster started. peek at rounds with:"
echo "    $HERE/status.sh"
echo "tear down with:"
echo "    $HERE/stop.sh"
