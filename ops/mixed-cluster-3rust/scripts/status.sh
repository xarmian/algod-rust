#!/usr/bin/env bash
# Per-node round + liveness snapshot for the issue #496 (Phase 7) 6-node
# mixed cluster (3 Go + 3 Rust, all six consensus participants). Exits
# non-zero if any node is unreachable / not running / more than
# LAG_TOLERANCE rounds behind the max.
#
# Adapted from ../../mixed-cluster/scripts/status.sh for six rows instead
# of four; logic is otherwise identical.

set -euo pipefail

ALGOD_TOKEN="${ALGOD_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
LAG_TOLERANCE="${LAG_TOLERANCE:-5}"

declare -a ROWS=(
    "go-node-1|phase7-go-node-1|4101"
    "go-node-2|phase7-go-node-2|4102"
    "go-node-3|phase7-go-node-3|4103"
    "rust-node-4|phase7-rust-node-4|4104"
    "rust-node-5|phase7-rust-node-5|4105"
    "rust-node-6|phase7-rust-node-6|4106"
)

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
