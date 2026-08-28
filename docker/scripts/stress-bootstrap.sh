#!/usr/bin/env bash
# stress-bootstrap.sh — lay out the 6-node stress-test network on disk.
#
# Issue #100 wants a mixed cluster where all four participation nodes hold
# registered participation keys. `goal network create` is the only thing that
# produces a self-consistent (genesis.json + per-node .partkey) tree for a
# private network, so we run it once inside the algod image and hand the
# resulting subdirectories out to the compose services.
#
# Steps:
#   1. `goal network create` into docker/stress-netroot/ (skipped if present).
#   2. Overlay each node's config.json: bind 0.0.0.0, blank DNSBootstrapID,
#      and apply the issue's pool/queue tuning to the Go nodes.
#   3. Create the Rust nodes' data dirs with the shared API token.
#   4. Export STRESS_GENESIS_ID / STRESS_RUST{1,2}_PARTKEY for compose.
#
# Sourced by bench-stress.sh; also runnable standalone for debugging.
#
# Usage:
#   bash docker/scripts/stress-bootstrap.sh [--purge]

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(cd "$HERE/.." && pwd)"

NETROOT="${DOCKER_DIR}/stress-netroot"
TEMPLATE="${DOCKER_DIR}/config/stress-template.json"
ALGOD_IMG="algorand/algod:5.0.0-stable"
NUM_ROUNDS="${NUM_ROUNDS:-100000}"
ALGOD_TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
NODES="GoRelay RustRelay GoPart1 GoPart2 RustPart1 RustPart2"
RUST_DATA_DIRS="rust-relay-data rust-part-1-data rust-part-2-data"

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

# `goal network create` writes files owned by uid 1001 (the image's `algorand`
# user). A host-side `rm -rf` can fail on those, so purge from a container.
purge_netroot() {
    if [ -d "${NETROOT}" ]; then
        docker run --rm -v "$(host_path "${NETROOT}"):/netroot" --entrypoint sh "${ALGOD_IMG}" \
            -c 'rm -rf /netroot/* /netroot/.[!.]* 2>/dev/null || true' >/dev/null 2>&1 || true
        rm -rf "${NETROOT}" 2>/dev/null || true
    fi
}

# Git Bash / MSYS rewrites `/netroot` style container paths and mangles the
# host side of `-v` too. Emit a Windows-style host path there and let the
# caller set MSYS_NO_PATHCONV for the container side.
host_path() {
    if [ -n "${MSYSTEM:-}" ]; then
        (cd "$1" 2>/dev/null && pwd -W) || echo "$1"
    else
        echo "$1"
    fi
}

if [ "${PURGE}" = "1" ]; then
    echo "==> purging ${NETROOT}"
    purge_netroot
fi

# ── 1. Bootstrap the netgoal tree ────────────────────────────────────
NEEDS_BOOTSTRAP=0
if [ ! -f "${NETROOT}/network.json" ]; then
    NEEDS_BOOTSTRAP=1
else
    for node in ${NODES}; do
        if [ ! -d "${NETROOT}/${node}" ]; then
            echo "==> half-built netroot (missing ${node}) — rebuilding"
            NEEDS_BOOTSTRAP=1
            break
        fi
    done
fi

if [ "${NEEDS_BOOTSTRAP}" = "1" ]; then
    echo "==> generating ${NETROOT} via goal network create"
    purge_netroot
    mkdir -p "${NETROOT}"
    RENDERED="${DOCKER_DIR}/.stress-template.rendered.json"
    sed "s/NUM_ROUNDS/${NUM_ROUNDS}/" "${TEMPLATE}" > "${RENDERED}"
    MSYS_NO_PATHCONV=1 docker run --rm \
        -v "$(host_path "${NETROOT}"):/netroot" \
        -v "$(host_path "${DOCKER_DIR}")/.stress-template.rendered.json:/template.json:ro" \
        --entrypoint goal "${ALGOD_IMG}" \
        network create -n stressnet -r /netroot -t /template.json
    rm -f "${RENDERED}"
else
    echo "==> reusing existing ${NETROOT} (pass --purge to reset)"
fi

# ── 2. Overlay per-node config ───────────────────────────────────────
#
# `goal network create` hard-codes NetAddress = 127.0.0.1:<port>, which no
# sibling container can reach. Rewrite it, blank DNSBootstrapID so private-net
# nodes don't try to resolve mainnet relays, and apply the issue's devnet
# tuning to the Go nodes (bigger pool + backlog + agreement queues, and a
# 500ms proposal assembly window so blocks fill under sustained load).
#
# Relays listen on 4161; the participation nodes dial out only (NetAddress "").
set_cfg() {
    local node="$1" key="$2" value="$3"
    MSYS_NO_PATHCONV=1 docker run --rm \
        -v "$(host_path "${NETROOT}/${node}"):/algod/data" \
        --entrypoint algocfg "${ALGOD_IMG}" \
        -d /algod/data set -p "${key}" -v "${value}" >/dev/null
}

for node in ${NODES}; do
    [ -d "${NETROOT}/${node}" ] || { echo "error: ${NETROOT}/${node} missing" >&2; exit 1; }
    case "${node}" in
        GoRelay|RustRelay) set_cfg "${node}" NetAddress "0.0.0.0:4161" ;;
        *)                 set_cfg "${node}" NetAddress "" ;;
    esac
    set_cfg "${node}" EndpointAddress "0.0.0.0:8080"
    set_cfg "${node}" DNSBootstrapID ""
    # Issue #100 "Devnet Configuration Tuning". MaxTxnBytesPerBlock is a
    # consensus parameter (not a config.json field) and is therefore fixed by
    # the template's `ConsensusProtocol: "future"`; the rest are node-local.
    set_cfg "${node}" ProposalAssemblyTime 500000000
    set_cfg "${node}" TxPoolSize 150000
    set_cfg "${node}" TxBacklogSize 52000
    set_cfg "${node}" AgreementIncomingVotesQueueLength 40000
    set_cfg "${node}" AgreementIncomingProposalsQueueLength 100
    set_cfg "${node}" EnableDeveloperAPI true
    echo "    configured ${node}"
done

# ── 3. Rust node data dirs ───────────────────────────────────────────
#
# `participate --data-dir` is where the REST server reads/writes algod.token.
# Seeding it with the same well-known token the Go nodes use lets one curl
# header work against all six endpoints.
for d in ${RUST_DATA_DIRS}; do
    mkdir -p "${NETROOT}/${d}"
    printf '%s' "${ALGOD_TOKEN}" > "${NETROOT}/${d}/algod.token"
    printf '%s' "${ALGOD_TOKEN}" > "${NETROOT}/${d}/algod.admin.token"
done

# ── 4. Export the values compose interpolates ────────────────────────
if [ -f "${NETROOT}/genesis.json" ]; then
    GENESIS_SRC="${NETROOT}/genesis.json"
elif [ -f "${NETROOT}/GoRelay/genesis.json" ]; then
    GENESIS_SRC="${NETROOT}/GoRelay/genesis.json"
else
    echo "error: no genesis.json under ${NETROOT}" >&2
    exit 1
fi

# Pass the file *contents* rather than its path: under Git Bash the `python3`
# on PATH is a native Windows build that cannot open an MSYS `/c/...` path.
# `tr -d '\r'` because that same interpreter writes CRLF, and a stray CR in the
# genesis id would be substituted straight into the Rust nodes' --genesis-id.
STRESS_GENESIS_ID="$(python3 -c "
import json, sys
g = json.loads(sys.argv[1])
print('{}-{}'.format(g.get('network', 'stressnet'), g.get('id', 'v1')))
" "$(cat "${GENESIS_SRC}")" | tr -d '\r')"

# The Rust participation nodes import the .partkey `goal` generated for their
# wallet. The filename embeds the validity window, so glob for it rather than
# hard-coding NUM_ROUNDS.
find_partkey() {
    local node="$1"
    local hit
    hit="$(find "${NETROOT}/${node}" -name '*.partkey' -type f | head -1)"
    if [ -z "${hit}" ]; then
        echo "error: no .partkey under ${NETROOT}/${node}" >&2
        exit 1
    fi
    # Emit a path *relative to the netroot* — the compose file prefixes
    # `/netroot/` itself. An absolute POSIX path here would be rewritten to
    # `C:/Program Files/Git/netroot/...` by MSYS path conversion on the way
    # into the Windows `docker compose` binary, and the container would fail
    # to open its own participation key.
    local rel="${hit#"${NETROOT}/"}"
    echo "${rel}"
}

STRESS_RUST1_PARTKEY="$(find_partkey RustPart1)"
STRESS_RUST2_PARTKEY="$(find_partkey RustPart2)"

export STRESS_GENESIS_ID STRESS_RUST1_PARTKEY STRESS_RUST2_PARTKEY

echo "==> genesis id:    ${STRESS_GENESIS_ID}"
echo "==> rust-part-1:   ${STRESS_RUST1_PARTKEY}"
echo "==> rust-part-2:   ${STRESS_RUST2_PARTKEY}"

# Persist for a standalone run (bench-stress.sh sources this file instead).
cat > "${NETROOT}/.stress-env" <<EOF
STRESS_GENESIS_ID=${STRESS_GENESIS_ID}
STRESS_RUST1_PARTKEY=${STRESS_RUST1_PARTKEY}
STRESS_RUST2_PARTKEY=${STRESS_RUST2_PARTKEY}
EOF
