#!/usr/bin/env bash

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# consensus-soak.sh — issue #594 acceptance gate, extended by issue #596.
#
# The P2P-transport analogue of
# `ops/mixed-cluster/scripts/consensus-conformance.sh` (issue #470).
# Issue #594 originally scoped this to just the soak + analyze stages;
# issue #596 wires up three of the four verifiers the WS-gossip harness's
# own Tier 2 also runs — fork detection, bidirectional cert cross-verify,
# and restart/rejoin scenarios (all opt-in, off by default, identical
# env-var gating to consensus-conformance.sh). Issue #597 added a fourth:
# negative-conformance (malformed-message injection) via a P2P-speaking
# connection backend on `algo-agreement-fuzz`
# (`crates/tools/algo-agreement-fuzz/src/inject_p2p.rs`, `--transport p2p`)
# that speaks the raw `/algorand-ws/2.2.0` libp2p stream instead of
# WS-gossip framing — see negative-conformance.sh's header for the full
# rationale and this harness's one deliberate deviation from the WS-gossip
# script (no BaseLoggerDebugLevel-raise-and-restart for the
# malformed-proposal case, since restarting a P2P node here would churn
# its ephemeral PeerId and fragment the bootstrap-chained mesh).
#
# One command that runs:
#
#   up  ->  soak (>= $ROUNDS rounds)  ->  analyze
#       ->  [opt-in] verify (forks, certs both directions)
#       ->  [opt-in] restart/rejoin scenarios
#       ->  down
#
# Verification covers:
#
#   1. Proposer assertions — analyze.py --rust-account: the Rust account
#      must appear as block proposer with a share inside a documented
#      binomial bound (default 3 sigma two-sided), and never zero.
#   2. Step coverage       — analyze.py --rust-log: the Rust node must
#      have cast BOTH soft and cert votes.
#   3. Stability            — block cadence bounds, node lockstep, and
#      zero Go-side agreement rejections of peer messages (the same
#      REJECTION_PATTERN consensus-round-trip.sh already scans for).
#   4. Machine-readable      — a single summary JSON is written and
#      echoed, and the exit code is 0 only if every check passed.
#   5. (opt-in) Fork-freedom + bidirectional cert authentication —
#      VERIFY_STAGE=1: algo-fork-detector across the 3 Go REST nodes,
#      plus algo-cert-crossverify (Go certs authenticate under Rust) and
#      tools/cert-authenticate (the same certs authenticate under
#      go-algorand's own verifier).
#   6. (opt-in) Restart/rejoin — RESTART_SCENARIOS=1: graceful restart,
#      SIGKILL, and a SIGKILL timed into a round the Rust node is
#      proposing in, each asserting rejoin-within-budget, no stall, no
#      fork, no equivocation.
#
# Usage:
#   bash ops/mixed-cluster-p2p/scripts/consensus-soak.sh
#   make p2p-interop-soak-test ROUNDS=200
#   VERIFY_STAGE=1 RESTART_SCENARIOS=1 make p2p-interop-soak-test
#   NEGATIVE_CASES=1 make p2p-interop-soak-test
#
# Env:
#   ROUNDS                rounds to soak                    (default 200)
#   SOAK_STALL_TIMEOUT    abort if no node advances for Ns  (default 120)
#   LAG_TOLERANCE         max round spread across 4 nodes   (default 5)
#   PROPOSER_SIGMA        binomial bound in sigmas          (default 3.0)
#   RUST_STAKE_FRACTION   Rust share of ONLINE stake        (default 0.10)
#   MAX_MEAN_BLOCK_TIME   cadence bound, seconds            (default 10)
#   MAX_P95_BLOCK_TIME    cadence bound, seconds            (default 20)
#   CERT_STRIDE           sample every Nth round for certs  (default 20)
#   MIN_RUST_VOTE_ROUNDS  required certs carrying a Rust
#                         vote                              (default 0,
#                         see consensus-conformance.sh's own comment on
#                         why — the same 30/30/30/10 stake split applies)
#   VERIFY_STAGE           1 = run fork-detector + bidirectional cert
#                         cross-verify after the soak        (default 0)
#   RESTART_SCENARIOS     1 = also run the P2P restart/rejoin stage
#                         after the soak (graceful restart, SIGKILL,
#                         restart-as-proposer)                (default 0)
#   RESTART_MODE          which restart scenarios to run:
#                         graceful|kill|proposer|all       (default all)
#   NEGATIVE_CASES         1 = also run the issue #597 negative-conformance
#                         stage after the soak (P2P-speaking malformed-
#                         message injection)                     (default 0)
#   SKIP_START=1          use an already-running cluster
#   KEEP_CLUSTER=1        leave the cluster up on exit
#   OUT_DIR               artifact directory (default: a timestamped
#                         directory under ops/mixed-cluster-p2p/)
#   SUMMARY_JSON          summary path (default: $OUT_DIR/summary.json)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"
WS_SCRIPTS="$REPO_ROOT/ops/mixed-cluster/scripts"

ROUNDS="${ROUNDS:-200}"
SOAK_STALL_TIMEOUT="${SOAK_STALL_TIMEOUT:-120}"
LAG_TOLERANCE="${LAG_TOLERANCE:-5}"
PROPOSER_SIGMA="${PROPOSER_SIGMA:-3.0}"
RUST_STAKE_FRACTION="${RUST_STAKE_FRACTION:-0.10}"
MAX_MEAN_BLOCK_TIME="${MAX_MEAN_BLOCK_TIME:-10}"
MAX_P95_BLOCK_TIME="${MAX_P95_BLOCK_TIME:-20}"
CERT_STRIDE="${CERT_STRIDE:-20}"
MIN_RUST_VOTE_ROUNDS="${MIN_RUST_VOTE_ROUNDS:-0}"
VERIFY_STAGE="${VERIFY_STAGE:-0}"
RESTART_SCENARIOS="${RESTART_SCENARIOS:-0}"
RESTART_MODE="${RESTART_MODE:-all}"
NEGATIVE_CASES="${NEGATIVE_CASES:-0}"
SKIP_START="${SKIP_START:-0}"
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"
ALGOD_TOKEN="${ALGOD_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"

RUN_ID="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$ROOT/soak-$RUN_ID}"
SUMMARY_JSON="${SUMMARY_JSON:-$OUT_DIR/summary.json}"

GO_CONTAINERS=(p2pinterop-go-node-1 p2pinterop-go-node-2 p2pinterop-go-node-3)
RUST_CONTAINER=p2pinterop-rust-node-4

# WARN-level agreement rejections from ../go-algorand/agreement/trace.go
# (same pattern consensus-round-trip.sh and the WS-gossip
# consensus-conformance.sh match).
REJECTION_PATTERN='malformed proposal for|malformed vote for|rejected block for|bundle malformed for'

mkdir -p "$OUT_DIR"

# ── result accumulation ────────────────────────────────────────────────
CHECKS_FILE="$OUT_DIR/.checks.tsv"
: > "$CHECKS_FILE"

record() {  # record <name> <pass|fail> <detail>
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

# ── helpers ────────────────────────────────────────────────────────────

node_round() {  # node_round <port>
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

# capture_rust_log <path> [since]
capture_rust_log() {
    if [ $# -ge 2 ] && [ -n "$2" ]; then
        docker logs --since "$2" "$RUST_CONTAINER" 2>&1 \
            | sed -e 's/\x1b\[[0-9;]*m//g' > "$1"
    else
        docker logs "$RUST_CONTAINER" 2>&1 \
            | sed -e 's/\x1b\[[0-9;]*m//g' > "$1"
    fi
}

rust_account() {
    docker logs "$RUST_CONTAINER" 2>&1 \
        | sed -e 's/\x1b\[[0-9;]*m//g' \
        | grep 'imported go-algorand participation key ' \
        | grep -o 'account=[A-Z2-7]\{58\}' | head -1 | cut -d= -f2 || true
}

# ── main ───────────────────────────────────────────────────────────────

echo "======================================================================"
echo "issue #594 P2P consensus soak"
echo "  rounds=$ROUNDS stake_fraction=$RUST_STAKE_FRACTION sigma=$PROPOSER_SIGMA"
echo "  artifacts: $OUT_DIR"
echo "======================================================================"

trap teardown EXIT INT TERM

# -- 0. Self-test the (reused) verifier logic before trusting its verdict --
# analyze.py itself is unchanged from the WS-gossip harness (issue #594's
# own TDD instruction: reusing already-tested code needs no fresh pass) —
# its unit tests live at ops/mixed-cluster/scripts/analyze_test.py and are
# exercised here for the same reason consensus-conformance.sh self-tests
# it: don't trust a verdict from an unverified verifier.
echo "==> verifier self-test (analyze.py unit tests, shared with ops/mixed-cluster)"
if python3 "$WS_SCRIPTS/analyze_test.py" > "$OUT_DIR/analyze_test.log" 2>&1; then
    record "verifier_selftest" pass "analyze.py unit tests green"
else
    record "verifier_selftest" fail "analyze.py unit tests FAILED — see $OUT_DIR/analyze_test.log"
fi

# -- 1. Cluster up ------------------------------------------------------
if [ "$SKIP_START" != "1" ]; then
    echo "==> starting the 4-node P2P cluster"
    "$HERE/start.sh" > "$OUT_DIR/start.log" 2>&1 || {
        record "cluster_start" fail "start.sh failed — see $OUT_DIR/start.log"
        echo "fatal: cluster did not start" >&2
        exit 1
    }
else
    echo "==> SKIP_START=1 — using the running cluster"
fi

echo "==> waiting for all four REST endpoints"
deadline=$(( $(date +%s) + 300 ))
all_up=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    all_up=1
    for port in 5001 5002 5003 5004; do
        r="$(node_round "$port")"
        [[ "$r" =~ ^[0-9]+$ ]] || all_up=0
    done
    [ "$all_up" = "1" ] && break
    sleep 3
done
if [ "$all_up" != "1" ]; then
    record "cluster_start" fail "not all four nodes served /v2/status within 300s"
    echo "fatal: cluster unhealthy" >&2
    exit 1
fi
record "cluster_start" pass "all four nodes serving /v2/status"

RUST_ACCOUNT="$(rust_account)"
if [ -z "$RUST_ACCOUNT" ]; then
    record "rust_account_discovered" fail \
        "could not read the Rust participation account from $RUST_CONTAINER logs"
    echo "fatal: no Rust account — the node is not participating" >&2
    exit 1
fi
record "rust_account_discovered" pass "$RUST_ACCOUNT"

# -- 2. Soak ------------------------------------------------------------
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
    record "soak_completed" fail "soak.sh exited $soak_rc — see $OUT_DIR/soak.log"
fi

# Snapshot the logs the analyzer reads AFTER the soak so they cover it.
RUST_LOG="$OUT_DIR/rust-node-4.log"
capture_rust_log "$RUST_LOG" "$LOG_SINCE"
for c in "${GO_CONTAINERS[@]}"; do
    docker logs --since "$LOG_SINCE" "$c" > "$OUT_DIR/$c.log" 2>&1 || true
done

# -- 3. Analyze: proposer share, step coverage, cadence, lag ------------
# Reuses ops/mixed-cluster/scripts/analyze.py as-is — its logic is
# JSONL-shape-driven, not cluster-specific (no hardcoded container names
# in the analysis path; only its --help text and one print label mention
# the WS-gossip container name cosmetically). See
# docs/P2P_SOAK_METHODOLOGY.md for why this reuse needs no fresh TDD pass.
echo "==> analyze.py (proposer share, step coverage, cadence) — shared verifier"
analyze_rc=0
"$WS_SCRIPTS/analyze.py" "$SOAK_JSONL" \
    --lag-tolerance "$LAG_TOLERANCE" \
    --rust-account "$RUST_ACCOUNT" \
    --rust-stake-fraction "$RUST_STAKE_FRACTION" \
    --proposer-sigma "$PROPOSER_SIGMA" \
    --rust-log "$RUST_LOG" \
    --max-mean-block-time "$MAX_MEAN_BLOCK_TIME" \
    --max-p95-block-time "$MAX_P95_BLOCK_TIME" \
    --json-out "$OUT_DIR/analyze.summary.json" \
    | tee "$OUT_DIR/analyze.log" || analyze_rc=$?

if [ -s "$OUT_DIR/analyze.summary.json" ]; then
    while IFS=$'\t' read -r name status detail; do
        [ -n "$name" ] && record "$name" "$status" "$detail"
    done < <(python3 -c "
import json, sys
s = json.load(open(sys.argv[1]))
rows = []
ps = s.get('rust_proposer_share')
if ps:
    rows.append(('proposer_share', 'pass' if ps['ok'] else 'fail',
                 '{}/{} blocks (z={}), bound {} sigma'.format(
                     ps['rust_proposals'], ps['blocks_with_proposer'],
                     ('%.2f' % ps['z']) if ps['z'] is not None else 'n/a',
                     ps['sigma_bound'])))
sc = s.get('rust_step_coverage')
if sc:
    rows.append(('vote_step_coverage', 'pass' if sc['ok'] else 'fail',
                 'seen={} required={}'.format(
                     ','.join(sc['steps_seen']) or 'none',
                     ','.join(sc['required_steps']))))
cad = s.get('cadence')
if cad:
    rows.append(('block_cadence', 'pass' if cad['ok'] else 'fail',
                 '; '.join(cad['failures']) or 'within bounds'))
lag = s.get('lag_violation')
rows.append(('node_lockstep', 'fail' if lag else 'pass',
             'lag {} > {}'.format(lag['delta'], s['lag_tolerance']) if lag
             else 'spread within tolerance {}'.format(s['lag_tolerance'])))
for name, status, detail in rows:
    print('{}\t{}\t{}'.format(name, status, detail))
" "$OUT_DIR/analyze.summary.json")
else
    record "analyze" fail "analyze.py produced no summary JSON"
fi

# -- 3b. (opt-in) fork detector + bidirectional cert cross-verify -------
# Off by default: needs algo-fork-detector / algo-cert-crossverify built
# and, when RUST_ACCOUNT-gated go-authentication runs, go-algorand's own
# vendored libsodium build via tools/cert-authenticate/run-in-docker.sh
# (issue #596; see verify-soak.sh's header for what each tool proves).
if [ "$VERIFY_STAGE" = "1" ]; then
    echo "==> verify-soak.sh (fork detector + cert cross-verify both directions)"
    TOOLS_DIR="${TOOLS_DIR:-$REPO_ROOT/target/debug}"
    verify_rc=0
    "$HERE/verify-soak.sh" \
        --stride "$CERT_STRIDE" \
        --tools-dir "$TOOLS_DIR" \
        --out-dir "$OUT_DIR" \
        --rust-account "$RUST_ACCOUNT" \
        --min-rust-vote-rounds "$MIN_RUST_VOTE_ROUNDS" \
        > "$OUT_DIR/verify.log" 2>&1 || verify_rc=$?
    tail -20 "$OUT_DIR/verify.log" || true

    if grep -q "fork-detector exit: 0" "$OUT_DIR/verify.log"; then
        record "fork_free" pass "algo-fork-detector reported no forks"
    else
        record "fork_free" fail "fork detector non-zero — see $OUT_DIR/verify.log"
    fi
    if grep -qE "cert-crossverify: .* failed=0 " "$OUT_DIR/verify.log"; then
        record "certs_authenticate_rust" pass "every sampled Go cert authenticated under Rust"
    else
        record "certs_authenticate_rust" fail "Rust-side cert authentication failed — see $OUT_DIR/verify.log"
    fi
    if grep -qE "cert-authenticate \(go-algorand .*\): rounds=[0-9]+ ok=[0-9]+ failed=0 " "$OUT_DIR/verify.log"; then
        record "certs_authenticate_go" pass "every sampled cert authenticated under go-algorand's verifier"
    else
        record "certs_authenticate_go" fail "go-algorand-side cert authentication failed or did not run — see $OUT_DIR/verify.log"
    fi
fi

# -- 3c. (opt-in) restart / rejoin scenarios -----------------------------
# Off by default: each scenario takes the Rust node down and waits for it
# to catch back up, which adds minutes and is a *different* property from
# the steady-state conformance the rest of this script asserts.
if [ "$RESTART_SCENARIOS" = "1" ]; then
    echo "==> restart / rejoin scenarios (issue #596, mode=$RESTART_MODE)"
    restart_rc=0
    MODE="$RESTART_MODE" \
    OUT_DIR="$OUT_DIR/restart" \
    TOOLS_DIR="${TOOLS_DIR:-$REPO_ROOT/target/debug}" \
    LAG_TOLERANCE="$LAG_TOLERANCE" \
        "$HERE/restart-rejoin.sh" > "$OUT_DIR/restart.log" 2>&1 || restart_rc=$?
    tail -30 "$OUT_DIR/restart.log" || true
    if [ -s "$OUT_DIR/restart/restart-summary.json" ]; then
        while IFS=$'\t' read -r name status detail; do
            [ -n "$name" ] && record "$name" "$status" "$detail"
        done < <(python3 -c "
import json, sys
s = json.load(open(sys.argv[1]))
for c in s['checks']:
    status = c['status'] if c['status'] in ('pass', 'fail') else 'pass'
    print('restart_{}_{}\t{}\t{}'.format(
        c['scenario'].replace('-', '_'), c['name'], status, c['detail']))
" "$OUT_DIR/restart/restart-summary.json")
    else
        record "restart_rejoin" fail \
            "restart-rejoin.sh exited $restart_rc with no summary — see $OUT_DIR/restart.log"
    fi
fi

# -- 3d. (opt-in) negative conformance — issue #597 ----------------------
# Off by default: it injects four deliberately malformed agreement messages
# into go-node-1 over its /algorand-ws/2.2.0 stream and asserts each is
# rejected. That is a different property from the steady-state conformance
# above — see negative-conformance.sh's header, mirroring
# consensus-conformance.sh's own NEGATIVE_CASES wiring for the WS-gossip
# harness.
if [ "$NEGATIVE_CASES" = "1" ]; then
    echo "==> negative conformance (issue #597)"
    negative_rc=0
    SKIP_START=1 \
    KEEP_CLUSTER=1 \
    OUT_DIR="$OUT_DIR/negative" \
    TOOLS_DIR="${TOOLS_DIR:-$REPO_ROOT/target/debug}" \
    ALGOD_TOKEN="$ALGOD_TOKEN" \
        "$HERE/negative-conformance.sh" > "$OUT_DIR/negative.log" 2>&1 || negative_rc=$?
    tail -40 "$OUT_DIR/negative.log" || true
    if [ -s "$OUT_DIR/negative/negative-summary.json" ]; then
        while IFS=$'\t' read -r name status detail; do
            [ -n "$name" ] && record "$name" "$status" "$detail"
        done < <(python3 -c "
import json, sys
s = json.load(sys.stdin)
for c in s['checks']:
    status = c['status'] if c['status'] in ('pass', 'fail') else 'pass'
    print('negative_{}_{}\t{}\t{}'.format(
        c['case'].replace('-', '_'), c['name'].replace('-', '_'), status, c['detail']))
" < "$OUT_DIR/negative/negative-summary.json")
    else
        record "negative_conformance" fail \
            "negative-conformance.sh exited $negative_rc with no summary — see $OUT_DIR/negative.log"
    fi
fi

# -- 4. Go-side telemetry: rejections + Rust vote acceptance ------------
echo "==> Go-side telemetry"
REJECTIONS=0
for c in "${GO_CONTAINERS[@]}"; do
    n="$(grep -cE "$REJECTION_PATTERN" "$OUT_DIR/$c.log" || true)"
    REJECTIONS=$(( REJECTIONS + n ))
done
if [ "$REJECTIONS" -eq 0 ]; then
    record "no_go_side_rejections" pass "0 agreement-level rejections across 3 Go nodes"
else
    record "no_go_side_rejections" fail "$REJECTIONS agreement-level rejection(s) in Go logs"
fi

VOTE_STATS="$(python3 -c "
import collections, sys
acct = sys.argv[1]
steps = collections.Counter()
for path in sys.argv[2:]:
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            if 'VoteAccepted' not in line or acct not in line:
                continue
            if acct + '\"' in line and '\"Sender\":\"' + acct + '\"' in line:
                steps['seen'] += 1
name = {0: 'propose', 1: 'soft', 2: 'cert', 3: 'next'}
print(__import__('json').dumps({'total': steps['seen']}))
" "$RUST_ACCOUNT" "$OUT_DIR"/p2pinterop-go-node-*.log)"
echo "    Go-accepted Rust votes: $VOTE_STATS"
VOTE_TOTAL="$(printf '%s' "$VOTE_STATS" | python3 -c "import json,sys; print(json.load(sys.stdin)['total'])")"
if [ "$VOTE_TOTAL" -gt 0 ]; then
    record "go_accepts_rust_votes" pass "$VOTE_TOTAL VoteAccepted record(s) with the Rust account as sender"
else
    record "go_accepts_rust_votes" fail "no Go node logged VoteAccepted for the Rust account"
fi

# -- 5. Machine-readable summary -----------------------------------------
python3 -c "
import json, sys
checks = []
with open(sys.argv[1], encoding='utf-8') as f:
    for line in f:
        parts = line.rstrip('\n').split('\t')
        if len(parts) != 3:
            continue
        checks.append({'name': parts[0], 'status': parts[1], 'detail': parts[2]})
failed = [c for c in checks if c['status'] == 'fail']
summary = {
    'issue': 594,
    'run_id': sys.argv[2],
    'rounds_requested': int(sys.argv[3]),
    'rust_account': sys.argv[4],
    'rust_stake_fraction': float(sys.argv[5]),
    'proposer_sigma': float(sys.argv[6]),
    'go_accepted_rust_votes': json.loads(sys.argv[7]),
    'checks': checks,
    'checks_total': len(checks),
    'checks_failed': len(failed),
    'result': 'FAIL' if failed else 'PASS',
}
with open(sys.argv[8], 'w', encoding='utf-8') as f:
    json.dump(summary, f, indent=2)
print(json.dumps({'result': summary['result'],
                  'checks_total': summary['checks_total'],
                  'checks_failed': summary['checks_failed']}))
" "$CHECKS_FILE" "$RUN_ID" "$ROUNDS" "$RUST_ACCOUNT" "$RUST_STAKE_FRACTION" \
  "$PROPOSER_SIGMA" "$VOTE_STATS" "$SUMMARY_JSON"

FAILED="$(awk -F'\t' '$2=="fail"' "$CHECKS_FILE" | wc -l | tr -d ' ')"
TOTAL="$(wc -l < "$CHECKS_FILE" | tr -d ' ')"

echo ""
echo "======================================================================"
if [ "$FAILED" -eq 0 ]; then
    echo "p2p-consensus-soak: PASS ($TOTAL checks)"
    echo "summary: $SUMMARY_JSON"
    echo "======================================================================"
    exit 0
fi
echo "p2p-consensus-soak: FAIL ($FAILED of $TOTAL checks failed)" >&2
awk -F'\t' '$2=="fail" {print "  - " $1 ": " $3}' "$CHECKS_FILE" >&2
echo "summary: $SUMMARY_JSON" >&2
echo "======================================================================" >&2
exit 1
