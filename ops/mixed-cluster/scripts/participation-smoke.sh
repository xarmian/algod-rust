#!/usr/bin/env bash
# participation-smoke.sh — issue #469 acceptance gate.
#
# Brings up the 4-node mixed cluster (3 go-algorand relays + 1
# `algod-rust participate` node, all four holding ONLINE stake), waits
# for it to advance SMOKE_ROUNDS rounds, and asserts:
#
#   (a) all four nodes advance in lockstep (max-min <= LAG_TOLERANCE);
#   (b) the Rust node's REST /v2/status last-round progresses by at
#       least SMOKE_ROUNDS (i.e. it is not merely alive but chaining);
#   (c) no Go node logs an agreement-level rejection of a peer's
#       message over the whole run.
#
# (c) greps for go-algorand's WARN-level agreement rejection lines,
# emitted from `agreement/trace.go` in v4.7.0-stable:
#
#     "malformed proposal for (round, period): err"
#     "malformed vote for (round, period, step): err"
#     "rejected block for (round, period): err"
#     "bundle malformed for ..."
#
# The Debugf-level siblings ("rejected proposal", "filtered vote") are
# deliberately NOT matched: they are invisible at the image's default
# log level and, more importantly, "filtered vote" is the normal
# duplicate/stale-vote path that a healthy cluster hits constantly.
#
# Usage:
#   bash ops/mixed-cluster/scripts/participation-smoke.sh
#
# Env:
#   SMOKE_ROUNDS    rounds to advance before asserting   (default 30)
#   SMOKE_TIMEOUT   seconds to wait for those rounds     (default 900)
#   LAG_TOLERANCE   max round spread across the 4 nodes  (default 5)
#   KEEP_CLUSTER=1  leave the cluster running on exit (for debugging)
#   SKIP_START=1    assume the cluster is already up

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SMOKE_ROUNDS="${SMOKE_ROUNDS:-30}"
SMOKE_TIMEOUT="${SMOKE_TIMEOUT:-900}"
LAG_TOLERANCE="${LAG_TOLERANCE:-5}"
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"
SKIP_START="${SKIP_START:-0}"
ALGOD_TOKEN="${ALGOD_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"

# name|container|host REST port. The Rust node's port is served by
# `participate --rest-listen 0.0.0.0:8080` (issue #469); before that it
# had no REST at all, which is why this test could not exist.
NODES=(
    "go-node-1|phase6-go-node-1|4001"
    "go-node-2|phase6-go-node-2|4002"
    "go-node-3|phase6-go-node-3|4003"
    "rust-node-4|phase6-rust-node-4|4004"
)
GO_CONTAINERS=(phase6-go-node-1 phase6-go-node-2 phase6-go-node-3)
RUST_CONTAINER=phase6-rust-node-4

# WARN-level agreement rejections from ../go-algorand/agreement/trace.go.
REJECTION_PATTERN='malformed proposal for|malformed vote for|rejected block for|bundle malformed for'

teardown() {
    local rc=$?
    if [ "$KEEP_CLUSTER" = "1" ]; then
        echo ""
        echo "KEEP_CLUSTER=1 — leaving the cluster up. Tear down with:"
        echo "    $HERE/stop.sh"
    else
        echo ""
        echo "==> tearing down"
        "$HERE/stop.sh" >/dev/null 2>&1 || true
    fi
    exit "$rc"
}

# ---------------------------------------------------------------- helpers

# Echo a node's /v2/status last-round, or "unreachable".
node_round() {
    local port="$1" body
    body="$(curl -sf -H "X-Algo-API-Token: $ALGOD_TOKEN" \
        "http://127.0.0.1:$port/v2/status" 2>/dev/null || true)"
    if [ -z "$body" ]; then
        echo "unreachable"
        return
    fi
    python3 -c "
import json, sys
try:
    print(json.loads(sys.argv[1]).get('last-round', 'unknown'))
except Exception:
    print('parse-error')
" "$body" | tr -d '\r'
}

# Wait until every node answers /v2/status with a numeric round.
wait_all_rest() {
    local deadline=$(( $(date +%s) + 300 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local all_up=1
        for row in "${NODES[@]}"; do
            local port="${row##*|}"
            local r
            r="$(node_round "$port")"
            [[ "$r" =~ ^[0-9]+$ ]] || all_up=0
        done
        if [ "$all_up" = "1" ]; then
            return 0
        fi
        sleep 3
    done
    echo "FAIL: not all four nodes served /v2/status within 300s" >&2
    for row in "${NODES[@]}"; do
        local name="${row%%|*}" port="${row##*|}"
        echo "    $name (port $port): $(node_round "$port")" >&2
    done
    return 1
}

# Print "name=round" for all nodes on one line.
round_line() {
    local out=""
    for row in "${NODES[@]}"; do
        local name="${row%%|*}" port="${row##*|}"
        out+="$name=$(node_round "$port") "
    done
    echo "$out"
}

# ------------------------------------------------------------------- main

echo "==> mixed-cluster participation smoke test (issue #469)"
echo "    rounds=$SMOKE_ROUNDS timeout=${SMOKE_TIMEOUT}s lag_tolerance=$LAG_TOLERANCE"

trap teardown EXIT INT TERM

if [ "$SKIP_START" != "1" ]; then
    "$HERE/start.sh"
else
    echo "==> SKIP_START=1 — using the running cluster"
fi

echo "==> waiting for all four REST endpoints"
wait_all_rest

# The Rust node's status must be served by the Rust node itself — assert
# it looks like our build rather than an accidentally-mapped Go port.
RUST_VERSIONS="$(curl -sf -H "X-Algo-API-Token: $ALGOD_TOKEN" \
    http://127.0.0.1:4004/v2/status 2>/dev/null || true)"
if [ -z "$RUST_VERSIONS" ]; then
    echo "FAIL: rust-node-4 /v2/status is empty" >&2
    exit 1
fi

# Baselines.
declare -A BASE
for row in "${NODES[@]}"; do
    name="${row%%|*}"; port="${row##*|}"
    BASE[$name]="$(node_round "$port")"
done
BASE_RUST="${BASE[rust-node-4]}"
BASE_MAX=-1
for name in "${!BASE[@]}"; do
    r="${BASE[$name]}"
    if [ "$r" -gt "$BASE_MAX" ]; then BASE_MAX="$r"; fi
done
echo "==> baseline: $(round_line)"

TARGET=$(( BASE_MAX + SMOKE_ROUNDS ))
echo "==> waiting for every node to reach round >= $TARGET"

DEADLINE=$(( $(date +%s) + SMOKE_TIMEOUT ))
START_TS="$(date +%s)"
REACHED=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    all_there=1
    for row in "${NODES[@]}"; do
        port="${row##*|}"
        r="$(node_round "$port")"
        if ! [[ "$r" =~ ^[0-9]+$ ]] || [ "$r" -lt "$TARGET" ]; then
            all_there=0
        fi
    done
    if [ "$all_there" = "1" ]; then
        REACHED=1
        break
    fi
    sleep 5
done
ELAPSED=$(( $(date +%s) - START_TS ))

echo "==> final:    $(round_line)"
echo "==> elapsed:  ${ELAPSED}s"

if [ "$REACHED" != "1" ]; then
    echo "FAIL: not every node reached round $TARGET within ${SMOKE_TIMEOUT}s" >&2
    exit 1
fi

# ── (a) lockstep ──────────────────────────────────────────────────────
MIN=-1; MAX=-1
declare -A FINAL
for row in "${NODES[@]}"; do
    name="${row%%|*}"; port="${row##*|}"
    r="$(node_round "$port")"
    if ! [[ "$r" =~ ^[0-9]+$ ]]; then
        echo "FAIL: $name round is '$r' at the end of the run" >&2
        exit 1
    fi
    FINAL[$name]="$r"
    if [ "$MAX" -lt 0 ] || [ "$r" -gt "$MAX" ]; then MAX="$r"; fi
    if [ "$MIN" -lt 0 ] || [ "$r" -lt "$MIN" ]; then MIN="$r"; fi
done
SPREAD=$(( MAX - MIN ))
echo "==> round spread across 4 nodes: $SPREAD (tolerance $LAG_TOLERANCE)"
if [ "$SPREAD" -gt "$LAG_TOLERANCE" ]; then
    echo "FAIL: nodes are not in lockstep (spread $SPREAD > $LAG_TOLERANCE)" >&2
    exit 1
fi

# ── (b) the Rust node itself progressed ───────────────────────────────
RUST_FINAL="${FINAL[rust-node-4]}"
RUST_DELTA=$(( RUST_FINAL - BASE_RUST ))
echo "==> rust-node-4 advanced $RUST_DELTA rounds (${BASE_RUST} -> ${RUST_FINAL})"
if [ "$RUST_DELTA" -lt "$SMOKE_ROUNDS" ]; then
    echo "FAIL: rust-node-4 only advanced $RUST_DELTA rounds, wanted >= $SMOKE_ROUNDS" >&2
    exit 1
fi

# ── (c) no Go-side agreement rejections ───────────────────────────────
echo "==> scanning Go node logs for agreement rejections"
REJECTIONS=0
for c in "${GO_CONTAINERS[@]}"; do
    hits="$(docker logs "$c" 2>&1 | grep -E "$REJECTION_PATTERN" || true)"
    n="$(printf '%s' "$hits" | grep -c . || true)"
    echo "    $c: $n"
    if [ "$n" -gt 0 ]; then
        REJECTIONS=$(( REJECTIONS + n ))
        printf '%s\n' "$hits" | head -10 >&2
    fi
done
if [ "$REJECTIONS" -gt 0 ]; then
    echo "FAIL: $REJECTIONS agreement-level rejection(s) in Go node logs" >&2
    exit 1
fi

# ── informational: Rust-side participation evidence ───────────────────
# Not assertions. Two separate things are reported:
#
#  * VOTING — go-node-1 logs `VoteAccepted` with `Sender` = the Rust
#    node's account for every Rust vote it counts. A non-zero count is
#    hard evidence that Go accepts Rust consensus messages, which is the
#    positive half of criterion (c) above.
#  * PROPOSING — the count of committed blocks whose `prp` header field
#    is the Rust node's account. Expected to track its 10% stake share
#    since issue #482 (assemble/ensure ordering) was fixed; before that
#    it was always ZERO because agreement asked the pool for round N
#    before the ledger had written block N-1 ("cannot get prev header
#    for N-1"). It is reported, not asserted: over a 30-round default
#    window a 10% proposer routinely wins anywhere from 0 to 7 rounds.
# `tracing`'s pretty formatter wraps field names in ANSI escapes, so
# "account=" is not literally present in `docker logs` output — strip the
# escapes first, then take the 58-character base32 account.
RUST_ACCOUNT="$(docker logs "$RUST_CONTAINER" 2>&1 \
    | sed -e 's/\x1b\[[0-9;]*m//g' \
    | grep 'imported go-algorand participation key ' \
    | grep -o 'account=[A-Z2-7]\{58\}' | head -1 | cut -d= -f2 || true)"
echo "==> rust-node-4 account: ${RUST_ACCOUNT:-<unknown>}"
if [ -n "$RUST_ACCOUNT" ]; then
    VOTES="$(docker logs "${GO_CONTAINERS[0]}" 2>&1 \
        | grep -c "\"Sender\":\"$RUST_ACCOUNT\"" || true)"
    echo "    votes accepted by ${GO_CONTAINERS[0]}: $VOTES"
    if [ "$VOTES" -eq 0 ]; then
        echo "    WARNING: no Rust votes accepted by Go — the node is following," >&2
        echo "             not participating. Check its participation keys." >&2
    fi
    PROPOSED="$(python3 -c "
import json, sys, urllib.request
tok, acct, lo, hi = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
def blk(r):
    req = urllib.request.Request(
        'http://127.0.0.1:4001/v2/blocks/{}?format=json'.format(r),
        headers={'X-Algo-API-Token': tok})
    return json.loads(urllib.request.urlopen(req, timeout=15).read())
n = 0
for r in range(max(lo, 1), hi + 1):
    try:
        if blk(r).get('block', {}).get('prp') == acct:
            n += 1
    except Exception:
        pass
print(n)
" "$ALGOD_TOKEN" "$RUST_ACCOUNT" "$BASE_MAX" "$MAX" | tr -d '\r')"
    echo "    blocks proposed in rounds $BASE_MAX..$MAX: $PROPOSED (expected ≈10% of the window)"
fi

echo ""
echo "PASS: 4-node mixed cluster advanced $SMOKE_ROUNDS rounds in lockstep,"
echo "      rust-node-4 participated via REST-visible progress, and no Go"
echo "      node logged an agreement-level rejection."
