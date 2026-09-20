#!/usr/bin/env bash

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Per-node round + liveness snapshot for the 4-node P2P interop cluster
# (issue #589) — 3 go-algorand P2P nodes + 1 algod-rust `P2pOnly`
# participant. Exits non-zero if any node is unreachable / not running /
# more than LAG_TOLERANCE rounds behind the max. Mirrors
# `ops/mixed-cluster/scripts/status.sh` exactly, adjusted for this
# harness's container names and host ports (5001-5004 rather than
# 4001-4004).

set -euo pipefail

ALGOD_TOKEN="${ALGOD_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"

# Exit non-zero if any node's round lags > LAG_TOLERANCE behind the max.
LAG_TOLERANCE="${LAG_TOLERANCE:-5}"

# Name → (container, host_port). rust-node-4 runs
# `participate --rest-listen 0.0.0.0:8080` in P2pOnly mode, so its round
# comes from the same algod v2 `/v2/status` endpoint as the Go nodes'.
declare -a ROWS=(
    "go-node-1|p2pinterop-go-node-1|5001"
    "go-node-2|p2pinterop-go-node-2|5002"
    "go-node-3|p2pinterop-go-node-3|5003"
    "rust-node-4|p2pinterop-rust-node-4|5004"
)

# ------------------------------------------------------------------ helpers

fetch_round() {
    local port="$1"
    local body
    body="$(curl -sf -H "X-Algo-API-Token: $ALGOD_TOKEN" \
        "http://127.0.0.1:$port/v2/status" 2>/dev/null || true)"
    if [ -z "$body" ]; then
        echo "unreachable"
        return
    fi
    python3 -c "
import json, sys
try:
    s = json.loads(sys.argv[1])
    print(s.get('last-round', 'unknown'))
except Exception as e:
    print('parse-error: {}'.format(e))
" "$body" | tr -d '\r'
}

# Consensus-participation summary for a node, from the #473
# `/v2/participation/status` endpoint. Only the Rust node implements it;
# go-algorand has no equivalent, so a Go node prints "n/a (go)".
fetch_participation() {
    local port="$1"
    local body code
    body="$(curl -s -w '\n%{http_code}' -H "X-Algo-API-Token: $ALGOD_TOKEN" \
        "http://127.0.0.1:$port/v2/participation/status" 2>/dev/null || true)"
    code="$(printf '%s' "$body" | tail -n1 | tr -d '\r')"
    body="$(printf '%s' "$body" | sed '$d')"
    case "$code" in
        200) ;;
        404) echo "not-participating"; return ;;
        "")  echo "unreachable"; return ;;
        *)   echo "http-$code"; return ;;
    esac
    python3 -c "
import json, sys
try:
    s = json.loads(sys.argv[1])
except Exception as e:
    print('parse-error: {}'.format(e))
    raise SystemExit(0)
dur = s.get('round_duration') or {}
print('votes={} prop={}/{} rnd={}ms'.format(
    s.get('votes_cast_total', '?'),
    s.get('proposals_made', '?'),
    s.get('proposals_accepted', '?'),
    dur.get('last_ms', '?'),
))
" "$body" | tr -d '\r'
}

# Returns the container's Docker state string ('running' / 'exited' /
# 'notfound').
container_state() {
    local name="$1"
    local state
    state="$(docker inspect --format='{{.State.Status}}' "$name" 2>/dev/null || true)"
    if [ -z "$state" ]; then
        echo "notfound"
    else
        echo "$state"
    fi
}

# ------------------------------------------------------------------ main

max_round=-1
any_fail=0
printf "%-14s %-10s %-6s %-8s %s\n" "node" "state" "port" "round" "participation"
printf "%-14s %-10s %-6s %-8s %s\n" "----" "-----" "----" "-----" "-------------"

declare -A NODE_ROUND
for row in "${ROWS[@]}"; do
    name="${row%%|*}"
    rest="${row#*|}"
    container="${rest%%|*}"
    port="${rest##*|}"

    state="$(container_state "$container")"

    if [ "$state" != "running" ]; then
        printf "%-14s %-10s %-6s %-8s %s\n" "$name" "$state" "$port" "-" "-"
        any_fail=1
        continue
    fi

    round="$(fetch_round "$port")"
    case "$name" in
        rust-*) participation="$(fetch_participation "$port")" ;;
        *)      participation="n/a (go)" ;;
    esac
    printf "%-14s %-10s %-6s %-8s %s\n" "$name" "$state" "$port" "$round" "$participation"
    NODE_ROUND[$name]="$round"
    if [[ "$round" =~ ^[0-9]+$ ]]; then
        if [ "$round" -gt "$max_round" ]; then max_round="$round"; fi
    elif [ "$round" = "unreachable" ]; then
        any_fail=1
    fi
done

if [ "$any_fail" = "1" ]; then
    echo ""
    echo "at least one node is unreachable or not running — cluster is not healthy." >&2
    exit 1
fi

if [ "$max_round" -lt 0 ]; then
    echo ""
    echo "no numeric rounds observed — cluster may not have started yet." >&2
    exit 2
fi

for name in "${!NODE_ROUND[@]}"; do
    round="${NODE_ROUND[$name]}"
    if [[ "$round" =~ ^[0-9]+$ ]]; then
        lag=$((max_round - round))
        if [ "$lag" -gt "$LAG_TOLERANCE" ]; then
            echo "" >&2
            echo "node $name lags $lag rounds behind max ($round vs $max_round), >LAG_TOLERANCE=$LAG_TOLERANCE" >&2
            any_fail=1
        fi
    fi
done

if [ "$any_fail" = "1" ]; then
    exit 3
fi
echo ""
echo "cluster healthy (max round $max_round, lag tolerance $LAG_TOLERANCE)."
