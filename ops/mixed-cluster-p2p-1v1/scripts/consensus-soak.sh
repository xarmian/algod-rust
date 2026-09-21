#!/usr/bin/env bash

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# consensus-soak.sh — issue #1580 (fourth investigation round), 1-1
# 50/50-stake analogue of ops/mixed-cluster-p2p/scripts/consensus-soak.sh.
#
# go-algorand's own CertCommitteeThreshold/CertCommitteeSize is 720/1000
# (72%, config/consensus.go) — with only the one go node holding 50% of
# online stake, its own votes can never reach cert quorum alone. If this
# soak nonetheless reaches ROUNDS rounds and shows VoteAccepted records
# for the Rust account, that is unambiguous proof go accepted Rust's
# votes (there is no other way quorum could have closed). If it stalls,
# that is equally unambiguous proof it did not — no lucky-sampling-window
# ambiguity remains, unlike the 3-go+1-rust 30/30/30/10 harness this
# reduces from.
#
# One command that runs: up -> soak (>= $ROUNDS rounds) -> vote-acceptance
# check -> down.
#
# Usage:
#   bash ops/mixed-cluster-p2p-1v1/scripts/consensus-soak.sh
#
# Env:
#   ROUNDS                 rounds to soak                    (default 100)
#   SOAK_STALL_TIMEOUT     abort if no node advances for Ns   (default 90)
#   LAG_TOLERANCE          max round spread across 2 nodes    (default 5)
#   SKIP_START=1            use an already-running cluster
#   KEEP_CLUSTER=1          leave the cluster up on exit
#   OUT_DIR                 artifact directory (default: a timestamped
#                          directory under ops/mixed-cluster-p2p-1v1/)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

ROUNDS="${ROUNDS:-100}"
SOAK_STALL_TIMEOUT="${SOAK_STALL_TIMEOUT:-90}"
LAG_TOLERANCE="${LAG_TOLERANCE:-5}"
SKIP_START="${SKIP_START:-0}"
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"
ALGOD_TOKEN="${ALGOD_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"

RUN_ID="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$ROOT/soak-$RUN_ID}"

GO_CONTAINER=p2pinterop1v1-go-node-1
RUST_CONTAINER=p2pinterop1v1-rust-node-2

REJECTION_PATTERN='malformed proposal for|malformed vote for|rejected block for|bundle malformed for'

mkdir -p "$OUT_DIR"

CHECKS_FILE="$OUT_DIR/.checks.tsv"
: > "$CHECKS_FILE"

record() {
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$CHECKS_FILE"
    if [ "$2" = "pass" ]; then
        echo "    [PASS] $1: $3"
    else
        echo "    [FAIL] $1: $3" >&2
    fi
}

teardown() {
    local rc=$?
    if [ "$KEEP_CLUSTER" = "1" ]; then
        echo ""
        echo "KEEP_CLUSTER=1 — leaving the cluster up. Tear down with:"
        echo "    $HERE/stop.sh"
    else
        echo ""
        echo "==> tearing down the cluster"
        "$HERE/stop.sh" >/dev/null 2>&1 || true
    fi
    exit "$rc"
}

node_round() {
    local body
    body="$(curl -sf -H "X-Algo-API-Token: $ALGOD_TOKEN" \
        "http://127.0.0.1:$1/v2/status" 2>/dev/null || true)"
    [ -z "$body" ] && { echo "unreachable"; return; }
    printf '%s' "$body" | python3 -c "
import json, sys
try:
    print(json.load(sys.stdin).get('last-round', 'unknown'))
except Exception:
    print('parse-error')
" | tr -d '\r'
}

rust_account() {
    docker logs "$RUST_CONTAINER" 2>&1 \
        | sed -e 's/\x1b\[[0-9;]*m//g' \
        | grep 'imported go-algorand participation key ' \
        | grep -o 'account=[A-Z2-7]\{58\}' | head -1 | cut -d= -f2 || true
}

echo "======================================================================"
echo "issue #1580 P2P 1-1 (50/50 stake) consensus soak"
echo "  rounds=$ROUNDS"
echo "  artifacts: $OUT_DIR"
echo "======================================================================"

trap teardown EXIT INT TERM

# -- 1. Cluster up --------------------------------------------------------
if [ "$SKIP_START" != "1" ]; then
    echo "==> starting the 1-1 P2P cluster"
    "$HERE/start.sh" > "$OUT_DIR/start.log" 2>&1 || {
        record "cluster_start" fail "start.sh failed — see $OUT_DIR/start.log"
        echo "fatal: cluster did not start" >&2
        exit 1
    }
else
    echo "==> SKIP_START=1 — using the running cluster"
fi

echo "==> waiting for both REST endpoints"
deadline=$(( $(date +%s) + 300 ))
all_up=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    all_up=1
    for port in 5101 5102; do
        r="$(node_round "$port")"
        [[ "$r" =~ ^[0-9]+$ ]] || all_up=0
    done
    [ "$all_up" = "1" ] && break
    sleep 3
done
if [ "$all_up" != "1" ]; then
    record "cluster_start" fail "not both nodes served /v2/status within 300s"
    echo "fatal: cluster unhealthy" >&2
    exit 1
fi
record "cluster_start" pass "both nodes serving /v2/status"

RUST_ACCOUNT="$(rust_account)"
if [ -z "$RUST_ACCOUNT" ]; then
    record "rust_account_discovered" fail \
        "could not read the Rust participation account from $RUST_CONTAINER logs"
    echo "fatal: no Rust account — the node is not participating" >&2
    exit 1
fi
record "rust_account_discovered" pass "$RUST_ACCOUNT"

BASELINE_ROUND="$(node_round 5101)"
echo "==> baseline round (go-node-1): $BASELINE_ROUND"

# -- 2. Soak ---------------------------------------------------------------
SOAK_JSONL="$OUT_DIR/soak.jsonl"
echo "==> soak: $ROUNDS rounds"
LOG_SINCE="$(python3 -c "
import datetime
print((datetime.datetime.now(datetime.timezone.utc)
       - datetime.timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ'))
" | tr -d '\r')"
soak_rc=0
"$HERE/soak.sh" --rounds "$ROUNDS" --out "$SOAK_JSONL" \
    --stall-timeout "$SOAK_STALL_TIMEOUT" \
    > "$OUT_DIR/soak.log" 2>&1 || soak_rc=$?
if [ "$soak_rc" -eq 0 ]; then
    record "soak_completed" pass "$ROUNDS rounds observed (see $SOAK_JSONL)"
else
    record "soak_completed" fail "soak.sh exited $soak_rc — see $OUT_DIR/soak.log (this IS the unambiguous stall signal if the network never closed quorum)"
fi

FINAL_ROUND="$(node_round 5101)"
echo "==> final round (go-node-1): $FINAL_ROUND (baseline was $BASELINE_ROUND)"

RUST_LOG="$OUT_DIR/rust-node-2.log"
docker logs --since "$LOG_SINCE" "$RUST_CONTAINER" 2>&1 | sed -e 's/\x1b\[[0-9;]*m//g' > "$RUST_LOG"
GO_LOG="$OUT_DIR/$GO_CONTAINER.log"
docker logs --since "$LOG_SINCE" "$GO_CONTAINER" > "$GO_LOG" 2>&1 || true

# -- 3. Node lockstep --------------------------------------------------
R1="$(node_round 5101)"; R2="$(node_round 5102)"
if [[ "$R1" =~ ^[0-9]+$ ]] && [[ "$R2" =~ ^[0-9]+$ ]]; then
    lag=$(( R1 > R2 ? R1 - R2 : R2 - R1 ))
    if [ "$lag" -le "$LAG_TOLERANCE" ]; then
        record "node_lockstep" pass "go=$R1 rust=$R2 (lag $lag <= $LAG_TOLERANCE)"
    else
        record "node_lockstep" fail "go=$R1 rust=$R2 (lag $lag > $LAG_TOLERANCE)"
    fi
else
    record "node_lockstep" fail "could not read numeric rounds (go=$R1 rust=$R2)"
fi

# -- 4. Go-side telemetry: rejections + Rust vote acceptance ------------
echo "==> Go-side telemetry"
REJECTIONS="$(grep -cE "$REJECTION_PATTERN" "$GO_LOG" || true)"
if [ "$REJECTIONS" -eq 0 ]; then
    record "no_go_side_rejections" pass "0 agreement-level rejections in go-node-1's log"
else
    record "no_go_side_rejections" fail "$REJECTIONS agreement-level rejection(s) in go-node-1's log"
fi

VOTE_STATS="$(python3 -c "
import json, sys
acct = sys.argv[1]
total = 0
with open(sys.argv[2], encoding='utf-8', errors='replace') as f:
    for line in f:
        if 'VoteAccepted' not in line:
            continue
        if '\"Sender\":\"' + acct + '\"' in line:
            total += 1
print(json.dumps({'total': total}))
" "$RUST_ACCOUNT" "$GO_LOG")"
echo "    go-node-1-accepted Rust votes: $VOTE_STATS"
VOTE_TOTAL="$(printf '%s' "$VOTE_STATS" | python3 -c "import json,sys; print(json.load(sys.stdin)['total'])")"
if [ "$VOTE_TOTAL" -gt 0 ]; then
    record "go_accepts_rust_votes" pass "$VOTE_TOTAL VoteAccepted record(s) with the Rust account as sender"
else
    record "go_accepts_rust_votes" fail "no VoteAccepted record for the Rust account in go-node-1's log"
fi

# Rounds actually advanced despite go alone being unable to reach the 72%
# cert threshold at 50% stake — direct corroborating evidence alongside
# the VoteAccepted grep above (a round CANNOT close without Rust
# contributing to quorum in this topology).
ROUNDS_ADVANCED=$(( FINAL_ROUND > BASELINE_ROUND ? FINAL_ROUND - BASELINE_ROUND : 0 ))
if [ "$ROUNDS_ADVANCED" -gt 0 ]; then
    record "rounds_advanced_past_go_alone_quorum" pass \
        "$ROUNDS_ADVANCED round(s) closed; impossible without Rust's votes/cert weight given go's 50% stake < 72% CertCommitteeThreshold"
else
    record "rounds_advanced_past_go_alone_quorum" fail \
        "0 rounds advanced beyond baseline $BASELINE_ROUND — network stalled, consistent with Rust votes never reaching quorum"
fi

# -- 5. Summary -----------------------------------------------------------
FAILED="$(awk -F'\t' '$2=="fail"' "$CHECKS_FILE" | wc -l | tr -d ' ')"
TOTAL="$(wc -l < "$CHECKS_FILE" | tr -d ' ')"

echo ""
echo "======================================================================"
if [ "$FAILED" -eq 0 ]; then
    echo "p2p-1v1-consensus-soak: PASS ($TOTAL checks)"
    echo "======================================================================"
    exit 0
fi
echo "p2p-1v1-consensus-soak: FAIL ($FAILED of $TOTAL checks failed)" >&2
awk -F'\t' '$2=="fail" {print "  - " $1 ": " $3}' "$CHECKS_FILE" >&2
echo "======================================================================" >&2
exit 1
