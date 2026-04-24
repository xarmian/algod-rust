#!/usr/bin/env bash
# Per-node round + peer-count snapshot for the PLAN-32 / TASK-86 mixed
# cluster. Exits non-zero if any node is unreachable or >N rounds behind.

set -euo pipefail

ALGOD_TOKEN="${ALGOD_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"

# Exit non-zero if any node's round lags > LAG_TOLERANCE behind the max.
LAG_TOLERANCE="${LAG_TOLERANCE:-5}"

declare -A NODES=(
    [go-node-1]=4001
    [go-node-2]=4002
    [go-node-3]=4003
    [rust-node-4]=4160
)

# ------------------------------------------------------------------ helpers

fetch_round() {
    local port="$1"
    # Go nodes use X-Algo-API-Token; the Rust `relay` subcommand today
    # does not expose /v2/status, so we fall back to "N/A" for ports >= 4160.
    if [ "$port" -ge 4160 ]; then
        echo "n/a (rust relay lacks REST)"
        return
    fi
    local body
    body="$(curl -sf -H "X-Algo-API-Token: $ALGOD_TOKEN" \
        "http://localhost:$port/v2/status" 2>/dev/null || true)"
    if [ -z "$body" ]; then
        echo "unreachable"
        return
    fi
    python3 -c "
import json, sys
try:
    s = json.loads('''$body''')
    print(s.get('last-round', 'unknown'))
except Exception as e:
    print(f'parse-error: {e}')
"
}

# ------------------------------------------------------------------ main

max_round=-1
any_fail=0
printf "%-14s %-6s %s\n" "node" "port" "round"
printf "%-14s %-6s %s\n" "----" "----" "-----"

for name in "${!NODES[@]}"; do
    port="${NODES[$name]}"
    round="$(fetch_round "$port")"
    printf "%-14s %-6s %s\n" "$name" "$port" "$round"
    # Numeric rounds participate in the lag check.
    if [[ "$round" =~ ^[0-9]+$ ]]; then
        if [ "$round" -gt "$max_round" ]; then max_round="$round"; fi
    elif [ "$round" = "unreachable" ]; then
        any_fail=1
    fi
done

if [ "$any_fail" = "1" ]; then
    echo ""
    echo "at least one Go node is unreachable — cluster is not healthy." >&2
    exit 1
fi

if [ "$max_round" -lt 0 ]; then
    echo ""
    echo "no numeric rounds observed — cluster may not have started yet." >&2
    exit 2
fi

# Lag check among numeric rounds only.
for name in "${!NODES[@]}"; do
    port="${NODES[$name]}"
    round="$(fetch_round "$port")"
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
