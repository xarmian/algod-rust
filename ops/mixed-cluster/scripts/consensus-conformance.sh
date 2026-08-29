#!/usr/bin/env bash

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# consensus-conformance.sh — issue #470 (Epic 42c) acceptance gate.
#
# One command that runs the whole positive Layer-9 conformance suite
# against the 4-node mixed cluster (3 go-algorand relays + 1
# `algod-rust participate` node, 30/30/30/10 ONLINE stake):
#
#   up  ->  [optional forced period advancement]
#       ->  soak (>= $ROUNDS rounds)
#       ->  verify
#       ->  down
#
# Verification covers, per the issue's five scope items:
#
#   1. Proposer assertions   — analyze.py --rust-account: the Rust
#      account must appear as block proposer with a share inside a
#      documented binomial bound (default 3 sigma two-sided), and never
#      zero.
#   2. Certificates          — verify-soak.sh: Go-produced certs
#      authenticate under Rust (`algo-cert-crossverify`), and the same
#      certs authenticate under go-algorand's own verifier
#      (`tools/cert-authenticate`). Rust-vote-in-cert presence is
#      recorded; see MIN_RUST_VOTE_ROUNDS below for why it is not a
#      hard gate by default.
#   3. Step coverage         — analyze.py --rust-log: the Rust node
#      must have cast BOTH soft and cert votes. Additionally the Go
#      nodes' own `VoteAccepted` telemetry is scanned so vote acceptance
#      is asserted from the *other* implementation's point of view.
#   4. Stability             — fork-free (algo-fork-detector), block
#      cadence bounds, node lockstep, and zero Go-side agreement
#      rejections of peer messages.
#   5. Machine-readable      — a single summary JSON is written and
#      echoed, and the exit code is 0 only if every check passed.
#
# Usage:
#   bash ops/mixed-cluster/scripts/consensus-conformance.sh
#   make consensus-cluster-test ROUNDS=200
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
#                         vote                              (default 0)
#   FORCE_NEXT_STEP       1 = pause a Go node before the
#                         soak to force period advancement  (default 1)
#   PAUSE_SECONDS         how long to pause it              (default 25)
#   REQUIRE_NEXT_STEP     1 = fail if no period > 0 vote
#                         was observed                      (default 0)
#   RESTART_SCENARIOS     1 = also run the issue #471 restart/rejoin
#                         stage after the soak (graceful restart,
#                         SIGKILL, restart-as-proposer)      (default 0)
#   RESTART_MODE          which restart scenarios to run:
#                         graceful|kill|proposer|all       (default all)
#   NEGATIVE_CASES        1 = also run the issue #472 negative stage
#                         (inject one malformed agreement message per
#                         case and assert Go rejects it)    (default 0)
#   SKIP_START=1          use an already-running cluster
#   KEEP_CLUSTER=1        leave the cluster up on exit
#   OUT_DIR               artifact directory (default: a timestamped
#                         directory under ops/mixed-cluster/)
#   SUMMARY_JSON          summary path (default: $OUT_DIR/summary.json)
#
# ## Why MIN_RUST_VOTE_ROUNDS defaults to 0
#
# go-algorand's `agreement.makeBundle` (bundle.go) stops packing votes
# the moment the running weight reaches the step's quorum, so a
# certificate contains only as many votes as were needed. In the
# harness's 30/30/30/10 split the three Go accounts carry ~90% of the
# cert committee against a ~74% threshold, so the three Go votes alone
# always suffice and the Rust node's vote — which arrives one relay hop
# later — is dropped from the bundle. Empirically 0 of 301 consecutive
# certificates in a healthy participating run contained it. That is a
# property of the stake split, not a Rust defect, so requiring it by
# default would make the suite fail on a correct node. Vote *acceptance*
# is asserted instead from the Go nodes' own `VoteAccepted` telemetry
# (scope item 3), which is the substantive claim. Set
# MIN_RUST_VOTE_ROUNDS > 0 on a topology where the Rust stake exceeds
# ~26% and is therefore required for quorum.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"

ROUNDS="${ROUNDS:-200}"
SOAK_STALL_TIMEOUT="${SOAK_STALL_TIMEOUT:-120}"
LAG_TOLERANCE="${LAG_TOLERANCE:-5}"
PROPOSER_SIGMA="${PROPOSER_SIGMA:-3.0}"
RUST_STAKE_FRACTION="${RUST_STAKE_FRACTION:-0.10}"
MAX_MEAN_BLOCK_TIME="${MAX_MEAN_BLOCK_TIME:-10}"
MAX_P95_BLOCK_TIME="${MAX_P95_BLOCK_TIME:-20}"
CERT_STRIDE="${CERT_STRIDE:-20}"
MIN_RUST_VOTE_ROUNDS="${MIN_RUST_VOTE_ROUNDS:-0}"
FORCE_NEXT_STEP="${FORCE_NEXT_STEP:-1}"
PAUSE_SECONDS="${PAUSE_SECONDS:-25}"
REQUIRE_NEXT_STEP="${REQUIRE_NEXT_STEP:-0}"
SKIP_START="${SKIP_START:-0}"
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"
ALGOD_TOKEN="${ALGOD_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"

RUN_ID="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$ROOT/conformance-$RUN_ID}"
SUMMARY_JSON="${SUMMARY_JSON:-$OUT_DIR/summary.json}"

GO_CONTAINERS=(phase6-go-node-1 phase6-go-node-2 phase6-go-node-3)
RUST_CONTAINER=phase6-rust-node-4
PAUSE_TARGET="${PAUSE_TARGET:-phase6-go-node-3}"

# WARN-level agreement rejections from ../go-algorand/agreement/trace.go.
# The Debugf-level siblings ("rejected proposal", "filtered vote") are
# deliberately not matched — "filtered vote" is the normal duplicate /
# post-quorum path a healthy cluster hits constantly.
REJECTION_PATTERN='malformed proposal for|malformed vote for|rejected block for|bundle malformed for'

mkdir -p "$OUT_DIR"

# ── result accumulation ────────────────────────────────────────────────
# CHECKS holds one "name<TAB>pass|fail<TAB>detail" row per assertion.
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
# `since` (a RFC3339 timestamp) bounds the capture to the soak window, so
# the step-coverage assertion is about THIS run rather than everything
# the container ever logged.
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
echo "issue #470 consensus conformance suite"
echo "  rounds=$ROUNDS stake_fraction=$RUST_STAKE_FRACTION sigma=$PROPOSER_SIGMA"
echo "  artifacts: $OUT_DIR"
echo "======================================================================"

trap teardown EXIT INT TERM

# -- 0. Self-test the verifier logic before trusting its verdict --------
echo "==> verifier self-test (analyze.py unit tests)"
if python3 "$HERE/analyze_test.py" > "$OUT_DIR/analyze_test.log" 2>&1; then
    record "verifier_selftest" pass "analyze.py unit tests green"
else
    record "verifier_selftest" fail "analyze.py unit tests FAILED — see $OUT_DIR/analyze_test.log"
fi

# -- 1. Cluster up ------------------------------------------------------
if [ "$SKIP_START" != "1" ]; then
    echo "==> starting the 4-node cluster"
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
    for port in 4001 4002 4003 4004; do
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

# -- 2. (optional) force a period advancement ---------------------------
# Pausing one Go relay drops the online voting weight the remaining nodes
# can see from 100% to 70%, below the soft-vote threshold (~74% of the
# committee), so the round cannot complete in period 0 and every node —
# the Rust one included — must advance to the next step / next period.
# Unpausing restores quorum and the cluster catches up.
NEXT_STEP_PHASE="skipped"
if [ "$FORCE_NEXT_STEP" = "1" ]; then
    echo "==> forcing period advancement: pausing $PAUSE_TARGET for ${PAUSE_SECONDS}s"
    before_round="$(node_round 4004)"
    if docker pause "$PAUSE_TARGET" >/dev/null 2>&1; then
        sleep "$PAUSE_SECONDS"
        docker unpause "$PAUSE_TARGET" >/dev/null 2>&1 || true
        echo "    unpaused; waiting for the cluster to recover"
        recovered=0
        mx=-1; mn=-1
        rdeadline=$(( $(date +%s) + 300 ))
        while [ "$(date +%s)" -lt "$rdeadline" ]; do
            spread_ok=1
            mx=-1; mn=-1
            for port in 4001 4002 4003 4004; do
                r="$(node_round "$port")"
                if ! [[ "$r" =~ ^[0-9]+$ ]]; then
                    spread_ok=0
                    break
                fi
                if [ "$mx" -lt 0 ] || [ "$r" -gt "$mx" ]; then mx="$r"; fi
                if [ "$mn" -lt 0 ] || [ "$r" -lt "$mn" ]; then mn="$r"; fi
            done
            if [ "$spread_ok" = "1" ] && [ $(( mx - mn )) -le "$LAG_TOLERANCE" ] \
                    && [ "$mx" -gt "$before_round" ]; then
                recovered=1
                break
            fi
            sleep 5
        done
        if [ "$recovered" = "1" ]; then
            NEXT_STEP_PHASE="forced"
            record "period_advancement_recovery" pass \
                "cluster recovered to round $mx after pausing $PAUSE_TARGET for ${PAUSE_SECONDS}s"
        else
            NEXT_STEP_PHASE="forced_no_recovery"
            record "period_advancement_recovery" fail \
                "cluster did not return to lockstep within 300s after unpausing $PAUSE_TARGET"
        fi
    else
        NEXT_STEP_PHASE="pause_failed"
        record "period_advancement_recovery" fail "docker pause $PAUSE_TARGET failed"
    fi
fi

# -- 3. Soak ------------------------------------------------------------
SOAK_JSONL="$OUT_DIR/soak.jsonl"
echo "==> soak: $ROUNDS rounds"
# Bound the log captures to the run window. Rewind a little so the
# forced-period-advancement phase is inside it too.
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

# Snapshot the logs the analyzers read AFTER the soak so they cover it.
RUST_LOG="$OUT_DIR/rust-node-4.log"
capture_rust_log "$RUST_LOG" "$LOG_SINCE"
for c in "${GO_CONTAINERS[@]}"; do
    docker logs --since "$LOG_SINCE" "$c" > "$OUT_DIR/$c.log" 2>&1 || true
done

# -- 4. Analyze: proposer share, step coverage, cadence, lag ------------
echo "==> analyze.py (proposer share, step coverage, cadence)"
analyze_rc=0
"$HERE/analyze.py" "$SOAK_JSONL" \
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
    # Break the analyzer's single verdict into the individual scope-item
    # checks so the summary says which one failed.
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
    rows.append(('period_advancement_observed',
                 'pass' if sc['period_advancement_observed'] else 'info',
                 'period>0 vote observed' if sc['period_advancement_observed']
                 else 'no period>0 vote in this window'))
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

# -- 5. Verify: forks + certs (both directions) -------------------------
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

# -- 6. Go-side telemetry: rejections + Rust vote acceptance ------------
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

# `VoteAccepted` is go-algorand's own record of counting a peer's vote
# (agreement/trace.go logVoteTrackerResult). Seeing it with the Rust
# account as Sender is the strongest available evidence that Go accepts
# Rust consensus messages, and the ObjectStep field gives per-step
# coverage from the Go side.
VOTE_STATS="$(python3 -c "
import collections, glob, json, sys
acct = sys.argv[1]
steps = collections.Counter()
rounds = collections.defaultdict(set)
for path in sys.argv[2:]:
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            if 'VoteAccepted' not in line or acct not in line:
                continue
            try:
                rec = json.loads(line.strip())
            except Exception:
                continue
            if rec.get('Sender') != acct or rec.get('Type') != 'VoteAccepted':
                continue
            step = rec.get('ObjectStep', rec.get('Step'))
            steps[step] += 1
            rounds[step].add(rec.get('ObjectRound', rec.get('Round')))
name = {0: 'propose', 1: 'soft', 2: 'cert', 3: 'next'}
print(json.dumps({
    'total': sum(steps.values()),
    'by_step': {name.get(k, 'step%s' % k): v for k, v in sorted(steps.items())},
    'rounds_by_step': {name.get(k, 'step%s' % k): len(v) for k, v in sorted(rounds.items())},
}))
" "$RUST_ACCOUNT" "$OUT_DIR"/phase6-go-node-*.log)"
echo "    Go-accepted Rust votes: $VOTE_STATS"
VOTE_TOTAL="$(printf '%s' "$VOTE_STATS" | python3 -c "import json,sys; print(json.load(sys.stdin)['total'])")"
if [ "$VOTE_TOTAL" -gt 0 ]; then
    record "go_accepts_rust_votes" pass "$VOTE_TOTAL VoteAccepted record(s) with the Rust account as sender"
else
    record "go_accepts_rust_votes" fail "no Go node logged VoteAccepted for the Rust account"
fi

# -- 7. Optional hard gate on period advancement ------------------------
if [ "$REQUIRE_NEXT_STEP" = "1" ]; then
    if grep -qE 'attested to .* at \([0-9]+, [1-9][0-9]*, ' "$RUST_LOG"; then
        record "period_advancement_required" pass "Rust voted in a period > 0"
    else
        record "period_advancement_required" fail \
            "no period > 0 vote from the Rust node (REQUIRE_NEXT_STEP=1)"
    fi
fi

# -- 7b. (opt-in) restart / rejoin scenarios — issue #471 ---------------
# Off by default: each scenario takes the Rust node down and waits for it
# to catch back up, which adds minutes and is a *different* property from
# the steady-state conformance the rest of this script asserts. Turn on
# with RESTART_SCENARIOS=1 (make consensus-cluster-test RESTART_SCENARIOS=1).
if [ "${RESTART_SCENARIOS:-0}" = "1" ]; then
    echo "==> restart / rejoin scenarios (issue #471, mode=${RESTART_MODE:-all})"
    restart_rc=0
    MODE="${RESTART_MODE:-all}" \
    OUT_DIR="$OUT_DIR/restart" \
    TOOLS_DIR="$TOOLS_DIR" \
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

# -- 7c. (opt-in) negative conformance — issue #472 --------------------
# Off by default: it injects four deliberately malformed agreement messages
# into go-node-1 and asserts each is rejected. That is a different property
# from the steady-state conformance above, and it briefly restarts
# go-node-1 to raise its log level for the payload case.
if [ "${NEGATIVE_CASES:-0}" = "1" ]; then
    echo "==> negative conformance (issue #472)"
    negative_rc=0
    SKIP_START=1 \
    KEEP_CLUSTER=1 \
    OUT_DIR="$OUT_DIR/negative" \
    TOOLS_DIR="$TOOLS_DIR" \
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

# -- 8. Machine-readable summary ---------------------------------------
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
    'issue': 470,
    'run_id': sys.argv[2],
    'rounds_requested': int(sys.argv[3]),
    'rust_account': sys.argv[4],
    'rust_stake_fraction': float(sys.argv[5]),
    'proposer_sigma': float(sys.argv[6]),
    'min_rust_vote_rounds': int(sys.argv[7]),
    'next_step_phase': sys.argv[8],
    'go_accepted_rust_votes': json.loads(sys.argv[9]),
    'checks': checks,
    'checks_total': len(checks),
    'checks_failed': len(failed),
    'result': 'FAIL' if failed else 'PASS',
}
with open(sys.argv[10], 'w', encoding='utf-8') as f:
    json.dump(summary, f, indent=2)
print(json.dumps({'result': summary['result'],
                  'checks_total': summary['checks_total'],
                  'checks_failed': summary['checks_failed']}))
" "$CHECKS_FILE" "$RUN_ID" "$ROUNDS" "$RUST_ACCOUNT" "$RUST_STAKE_FRACTION" \
  "$PROPOSER_SIGMA" "$MIN_RUST_VOTE_ROUNDS" "$NEXT_STEP_PHASE" "$VOTE_STATS" \
  "$SUMMARY_JSON"

FAILED="$(awk -F'\t' '$2=="fail"' "$CHECKS_FILE" | wc -l | tr -d ' ')"
TOTAL="$(wc -l < "$CHECKS_FILE" | tr -d ' ')"

echo ""
echo "======================================================================"
if [ "$FAILED" -eq 0 ]; then
    echo "consensus-conformance: PASS ($TOTAL checks)"
    echo "summary: $SUMMARY_JSON"
    echo "======================================================================"
    exit 0
fi
echo "consensus-conformance: FAIL ($FAILED of $TOTAL checks failed)" >&2
awk -F'\t' '$2=="fail" {print "  - " $1 ": " $3}' "$CHECKS_FILE" >&2
echo "summary: $SUMMARY_JSON" >&2
echo "======================================================================" >&2
exit 1
