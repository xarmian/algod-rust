#!/usr/bin/env bash
# Per-node round + liveness snapshot for the 4-node mixed cluster (3 Go
# + 1 Rust, all four consensus participants). Exits non-zero if any node
# is unreachable / not running / more than LAG_TOLERANCE rounds behind
# the max.

set -euo pipefail

ALGOD_TOKEN="${ALGOD_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"

# Exit non-zero if any node's round lags > LAG_TOLERANCE behind the max.
LAG_TOLERANCE="${LAG_TOLERANCE:-5}"

# Name → (container, host_port). Since issue #469 the Rust node runs
# `participate --rest-listen 0.0.0.0:8080`, so its round comes from the
# same algod v2 `/v2/status` endpoint as the Go nodes' — no log-scrape
# or container-state-only fallback.
declare -a ROWS=(
    "go-node-1|phase6-go-node-1|4001"
    "go-node-2|phase6-go-node-2|4002"
    "go-node-3|phase6-go-node-3|4003"
    "rust-node-4|phase6-rust-node-4|4004"
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
    # Pass the body as argv rather than interpolating it into the source:
    # a body containing a stray quote would otherwise be a syntax error,
    # and the native-Windows python3 on Git Bash chokes on MSYS paths.
    python3 -c "
import json, sys
try:
    s = json.loads(sys.argv[1])
    print(s.get('last-round', 'unknown'))
except Exception as e:
    print('parse-error: {}'.format(e))
" "$body" | tr -d '\r'
}

# Returns the container's Docker state string ('running' / 'exited' /
# 'notfound') so we can surface a failure for nodes that don't expose
# REST. Safe to use on any node.
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
printf "%-14s %-10s %-6s %s\n" "node" "state" "port" "round"
printf "%-14s %-10s %-6s %s\n" "----" "-----" "----" "-----"

declare -A NODE_ROUND
for row in "${ROWS[@]}"; do
    name="${row%%|*}"
    rest="${row#*|}"
    container="${rest%%|*}"
    port="${rest##*|}"

    state="$(container_state "$container")"

    # Container liveness is the first gate — if it's not running, the
    # node is unhealthy regardless of whether REST answers.
    if [ "$state" != "running" ]; then
        printf "%-14s %-10s %-6s %s\n" "$name" "$state" "$port" "-"
        any_fail=1
        continue
    fi

    round="$(fetch_round "$port")"
    printf "%-14s %-10s %-6s %s\n" "$name" "$state" "$port" "$round"
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

# Lag check among numeric rounds only.
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
