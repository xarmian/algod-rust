#!/usr/bin/env bash
# restart-rejoin.sh — issue #596 (P2P analogue of ops/mixed-cluster's
# restart-rejoin.sh, issue #471).
#
# Restarts the algod-rust P2pOnly node WHILE the P2P cluster is actively
# producing rounds and asserts that it comes back correctly:
#
#   (a) rejoin   — it reconnects over libp2p (re-dials
#                  --p2p-bootstrap-peers), catches back up to the Go
#                  quorum via P2P block/cert fetch (issue #591), and
#                  resumes attesting, within a bounded number of rounds.
#   (b) liveness — the three Go nodes keep cadence throughout the outage
#                  (no stall) and every node agrees on every block in the
#                  window (no fork).
#   (c) SAFETY   — no equivocation, checked from BOTH sides, identically
#                  to the WS-gossip harness's own check.
#
# Ported from ops/mixed-cluster/scripts/restart-rejoin.sh with this
# harness's container names (p2pinterop-*) and host ports (5001-5004).
# The restart/rejoin mechanics themselves (docker kill/restart, REST
# round polling, log-line greps for "attested to" / equivocation
# telemetry) are transport-agnostic — they observe process lifecycle and
# algo-agreement's own logging, not the gossip/P2P wire format — so
# nothing here is new detection logic. See docs/P2P_SOAK_METHODOLOGY.md.
#
# One topology difference from the WS-gossip harness worth calling out:
# this cluster's 3 Go nodes are chain-bootstrapped (1 <- 2 <- 3, no node
# told about a non-adjacent peer — see ../docker-compose.yml), so their
# own peer discovery relies on DHT routing. That affects how the *Go*
# nodes rediscover each other after a restart of one of THEM, but this
# script only ever restarts rust-node-4 (an outbound-only P2P client
# dialing go-node-1 as its sole bootstrap peer, exactly like the
# WS-gossip harness's rust-node-4 dials go-node-1 over TCP gossip) — so
# the rejoin path here is "redial the one bootstrap peer it was ever
# told about", not "rediscover peers via DHT", and needed no additional
# logic versus the WS-gossip original.
#
# Modes: graceful | kill | proposer | all  (default all) — identical
# semantics to the WS-gossip harness; see that script's header for the
# full description of each.
#
# Usage:
#   bash ops/mixed-cluster-p2p/scripts/restart-rejoin.sh [--mode MODE]
#   RESTART_SCENARIOS=1 make p2p-interop-soak-test
#
# Env: identical names/defaults to ops/mixed-cluster/scripts/restart-rejoin.sh
#   MODE REJOIN_ROUND_BUDGET REJOIN_TIMEOUT OBSERVE_ROUNDS LAG_TOLERANCE
#   MAX_STALL_SECONDS PROPOSER_WAIT PROPOSER_KILL_DELAY PROPOSER_ATTEMPTS
#   OUT_DIR SUMMARY_JSON
#
# Exit code 0 only if every check in every requested mode passed.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"
WS_SCRIPTS="$REPO_ROOT/ops/mixed-cluster/scripts"

MODE="${MODE:-all}"
REJOIN_ROUND_BUDGET="${REJOIN_ROUND_BUDGET:-30}"
REJOIN_TIMEOUT="${REJOIN_TIMEOUT:-240}"
OBSERVE_ROUNDS="${OBSERVE_ROUNDS:-10}"
LAG_TOLERANCE="${LAG_TOLERANCE:-5}"
MAX_STALL_SECONDS="${MAX_STALL_SECONDS:-30}"
PROPOSER_WAIT="${PROPOSER_WAIT:-240}"
PROPOSER_KILL_DELAY="${PROPOSER_KILL_DELAY:-0.4}"
PROPOSER_ATTEMPTS="${PROPOSER_ATTEMPTS:-1}"
ALGOD_TOKEN="${ALGOD_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"

RUN_ID="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$ROOT/restart-$RUN_ID}"
SUMMARY_JSON="${SUMMARY_JSON:-$OUT_DIR/restart-summary.json}"

GO_CONTAINERS=(p2pinterop-go-node-1 p2pinterop-go-node-2 p2pinterop-go-node-3)
GO_PORTS=(5001 5002 5003)
RUST_CONTAINER=p2pinterop-rust-node-4
RUST_PORT=5004

while [ $# -gt 0 ]; do
    case "$1" in
        --mode) MODE="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; SUMMARY_JSON="$OUT_DIR/restart-summary.json"; shift 2 ;;
        --observe-rounds) OBSERVE_ROUNDS="$2"; shift 2 ;;
        --rejoin-round-budget) REJOIN_ROUND_BUDGET="$2"; shift 2 ;;
        -h|--help) sed -n '2,50p' "$0"; exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

mkdir -p "$OUT_DIR"
CHECKS_FILE="$OUT_DIR/.checks.tsv"
: > "$CHECKS_FILE"
SCEN_FILE="$OUT_DIR/.scenarios.jsonl"
: > "$SCEN_FILE"

record() {  # record <scenario> <name> <pass|fail|info> <detail>
    printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$CHECKS_FILE"
    case "$3" in
        pass) echo "    [PASS] $1/$2: $4" ;;
        info) echo "    [INFO] $1/$2: $4" ;;
        *)    echo "    [FAIL] $1/$2: $4" >&2 ;;
    esac
}

# ── REST helpers ───────────────────────────────────────────────────────

node_round() {  # node_round <port> -> integer or "unreachable"
    local body
    body="$(curl -sf --max-time 5 -H "X-Algo-API-Token: $ALGOD_TOKEN" \
        "http://127.0.0.1:$1/v2/status" 2>/dev/null || true)"
    [ -z "$body" ] && { echo "unreachable"; return; }
    printf '%s' "$body" | python3 -c "
import json, sys
try:
    v = json.load(sys.stdin).get('last-round')
    print(int(v) if v is not None else 'unreachable')
except Exception:
    print('unreachable')
" | tr -d '\r'
}

go_max_round() {
    local best=-1 r
    for p in "${GO_PORTS[@]}"; do
        r="$(node_round "$p")"
        [[ "$r" =~ ^[0-9]+$ ]] || continue
        [ "$r" -gt "$best" ] && best="$r"
    done
    echo "$best"
}

go_min_round() {
    local worst=-1 r
    for p in "${GO_PORTS[@]}"; do
        r="$(node_round "$p")"
        [[ "$r" =~ ^[0-9]+$ ]] || { echo "-1"; return; }
        if [ "$worst" -lt 0 ] || [ "$r" -lt "$worst" ]; then worst="$r"; fi
    done
    echo "$worst"
}

watch_go_progress() {  # watch_go_progress <n_rounds> <timeout> <samplefile>
    local want="$1" timeout="$2" samples="$3"
    local start_round; start_round="$(go_max_round)"
    local deadline=$(( $(date +%s) + timeout ))
    local last_advance; last_advance="$(date +%s)"
    local last="$start_round" cur
    : > "$samples"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        cur="$(go_max_round)"
        echo "$(date +%s) $cur" >> "$samples"
        if [ "$cur" -gt "$last" ]; then
            last="$cur"
            last_advance="$(date +%s)"
        fi
        [ $(( cur - start_round )) -ge "$want" ] && { echo "$start_round $cur"; return 0; }
        if [ $(( $(date +%s) - last_advance )) -gt "$MAX_STALL_SECONDS" ]; then
            echo "$start_round $cur"
            return 1
        fi
        sleep 1
    done
    echo "$start_round $cur"
    return 2
}

# ── log helpers ────────────────────────────────────────────────────────

strip_ansi() { sed -e 's/\x1b\[[0-9;]*m//g'; }

rust_account() {
    docker logs "$RUST_CONTAINER" 2>&1 | strip_ansi \
        | grep -E 'participation key(s)? (already present|imported)|imported go-algorand participation key ' \
        | grep -o 'account=[A-Z2-7]\{58\}' | head -1 | cut -d= -f2 || true
}

# ── equivocation detector (shared with the WS-gossip harness) ──────────
#
# equivocation.py is pure log-text analysis (regex over "attested to ...
# at (R, P, step)" lines algo-agreement emits identically regardless of
# transport) — reused as-is rather than duplicated, mirroring
# consensus-soak.sh's reuse of analyze.py. See docs/P2P_SOAK_METHODOLOGY.md.
EQUIV_PY="$WS_SCRIPTS/equivocation.py"

# ── one scenario ───────────────────────────────────────────────────────

do_restart() {  # do_restart <graceful|kill>
    if [ "$1" = "graceful" ]; then
        docker restart -t 20 "$RUST_CONTAINER" >/dev/null
        echo "docker restart (SIGTERM)"
    else
        docker kill --signal=KILL "$RUST_CONTAINER" >/dev/null
        local deadline=$(( $(date +%s) + 60 ))
        while [ "$(date +%s)" -lt "$deadline" ]; do
            if [ "$(docker inspect -f '{{.State.Running}}' "$RUST_CONTAINER" 2>/dev/null)" = "true" ]; then
                echo "docker kill -s KILL (restart policy revived it)"
                return 0
            fi
            sleep 1
        done
        docker start "$RUST_CONTAINER" >/dev/null
        echo "docker kill -s KILL + docker start"
    fi
}

wait_for_proposal_round() {
    local deadline=$(( $(date +%s) + PROPOSER_WAIT ))
    local since; since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local hit
        hit="$(docker logs --since "$since" "$RUST_CONTAINER" 2>&1 | strip_ansi \
            | grep -o 'assembled [0-9]* proposal message(s) at ([0-9]*, [0-9]*)' \
            | tail -1 || true)"
        if [ -n "$hit" ]; then
            printf '%s' "$hit" | grep -o '([0-9]*,' | tr -d '(,'
            return 0
        fi
        sleep 0.5
    done
    echo ""
}

run_scenario() {  # run_scenario <name> <graceful|kill|proposer>
    local scen="$1" mode="$2"
    echo ""
    echo "== scenario: $scen (mode=$mode) =============================="

    local rr gmax gmin
    rr="$(node_round "$RUST_PORT")"; gmax="$(go_max_round)"; gmin="$(go_min_round)"
    if ! [[ "$rr" =~ ^[0-9]+$ ]] || [ "$gmax" -lt 0 ] || [ "$gmin" -lt 0 ]; then
        record "$scen" preflight fail "a node was unreachable (rust=$rr go=[$gmin,$gmax])"
        return 1
    fi
    if [ $(( gmax - rr )) -gt "$LAG_TOLERANCE" ] || [ $(( rr - gmax )) -gt "$LAG_TOLERANCE" ]; then
        record "$scen" preflight fail "not in lockstep before the restart (rust=$rr go_max=$gmax)"
        return 1
    fi
    record "$scen" preflight pass "in lockstep at round $gmax (rust=$rr)"

    local proposal_round=""
    if [ "$mode" = "proposer" ]; then
        echo "    waiting up to ${PROPOSER_WAIT}s for a round the Rust node proposes in"
        proposal_round="$(wait_for_proposal_round)"
        if [ -z "$proposal_round" ]; then
            record "$scen" proposer_window fail \
                "no 'assembled N proposal message(s)' line within ${PROPOSER_WAIT}s"
            return 1
        fi
        record "$scen" proposer_window pass \
            "Rust node holds a proposer credential for round $proposal_round"
        sleep "$PROPOSER_KILL_DELAY"
    fi

    local before_rust before_go how t_kill
    before_rust="$(node_round "$RUST_PORT")"
    before_go="$(go_max_round)"
    t_kill="$(date +%s)"
    if [ "$mode" = "graceful" ]; then
        how="$(do_restart graceful)"
    else
        how="$(do_restart kill)"
    fi
    echo "    restarted via: $how  (rust was at $before_rust, go at $before_go)"

    local rejoin_deadline=$(( t_kill + REJOIN_TIMEOUT ))
    local rejoined=0 rejoin_round=-1 t_rejoin=0
    while [ "$(date +%s)" -lt "$rejoin_deadline" ]; do
        rr="$(node_round "$RUST_PORT")"
        gmax="$(go_max_round)"
        if [[ "$rr" =~ ^[0-9]+$ ]] && [ "$gmax" -ge 0 ] \
                && [ $(( gmax - rr )) -le "$LAG_TOLERANCE" ] && [ "$gmax" -gt "$before_go" ]; then
            rejoined=1; rejoin_round="$rr"; t_rejoin="$(date +%s)"
            break
        fi
        sleep 1
    done
    local rejoin_secs=$(( t_rejoin - t_kill ))
    local rejoin_rounds=$(( rejoin_round - before_go ))
    if [ "$rejoined" != "1" ]; then
        record "$scen" rejoin fail \
            "did not return to within $LAG_TOLERANCE rounds of the Go quorum in ${REJOIN_TIMEOUT}s"
    elif [ "$rejoin_rounds" -gt "$REJOIN_ROUND_BUDGET" ]; then
        record "$scen" rejoin fail \
            "rejoined at round $rejoin_round — $rejoin_rounds rounds after the restart, budget $REJOIN_ROUND_BUDGET"
    else
        record "$scen" rejoin pass \
            "back in lockstep at round $rejoin_round after ${rejoin_secs}s / $rejoin_rounds Go rounds"
    fi

    local samples="$OUT_DIR/$scen.go-progress.txt"
    local progress rc=0
    progress="$(watch_go_progress "$OBSERVE_ROUNDS" $(( OBSERVE_ROUNDS * 15 + 60 )) "$samples")" || rc=$?
    local from_r to_r; read -r from_r to_r <<<"$progress"
    if [ "$rc" -eq 0 ]; then
        record "$scen" no_stall pass \
            "Go quorum advanced $from_r -> $to_r with no gap > ${MAX_STALL_SECONDS}s"
    elif [ "$rc" -eq 1 ]; then
        record "$scen" no_stall fail \
            "Go quorum stalled > ${MAX_STALL_SECONDS}s (stuck at $to_r)"
    else
        record "$scen" no_stall fail \
            "Go quorum did not advance $OBSERVE_ROUNDS rounds in time (at $to_r)"
    fi

    local resumed
    resumed="$(docker logs --since "$t_kill" "$RUST_CONTAINER" 2>&1 | strip_ansi \
        | grep -o 'attested to .* at ([0-9]*, [0-9]*, [^)]*)' \
        | grep -o 'at ([0-9]*' | tr -d 'at (' \
        | awk -v b="$before_go" '$1 >= b' | wc -l | tr -d ' ')"
    if [ "${resumed:-0}" -gt 0 ]; then
        record "$scen" resumed_voting pass \
            "$resumed attest(s) at round >= $before_go after the restart"
    else
        record "$scen" resumed_voting fail \
            "no attest for a round >= $before_go after the restart"
    fi

    local fork_from=$(( before_go > 2 ? before_go - 2 : 1 ))
    local fork_to="$to_r"
    local fork_out="$OUT_DIR/$scen.fork.jsonl"
    local fork_rc=0
    if [ -x "$FORK_BIN" ] && [ "$fork_to" -gt "$fork_from" ]; then
        "$FORK_BIN" \
            --nodes "go-node-1=http://127.0.0.1:5001,go-node-2=http://127.0.0.1:5002,go-node-3=http://127.0.0.1:5003,rust-node-4=http://127.0.0.1:5004" \
            --from-round "$fork_from" --to-round "$fork_to" \
            --token-file "$TOKEN_FILE" --jsonl-out "$fork_out" \
            > "$OUT_DIR/$scen.fork.log" 2>&1 || fork_rc=$?
        if [ "$fork_rc" -eq 0 ]; then
            record "$scen" no_fork pass \
                "all 4 nodes agree on blocks $fork_from..$fork_to"
        else
            record "$scen" no_fork fail \
                "algo-fork-detector exit $fork_rc over $fork_from..$fork_to — see $fork_out"
        fi
    else
        record "$scen" no_fork fail "algo-fork-detector unavailable at $FORK_BIN"
    fi

    if [ -n "$proposal_round" ]; then
        local winner
        winner="$(curl -sf --max-time 5 -H "X-Algo-API-Token: $ALGOD_TOKEN" \
            "http://127.0.0.1:5001/v2/blocks/$proposal_round?format=json" 2>/dev/null \
            | python3 -c "
import json, sys
try:
    print(json.load(sys.stdin)['block'].get('prp', ''))
except Exception:
    print('')
" | tr -d '\r')"
        if [ "$winner" = "$RUST_ACCOUNT" ]; then
            record "$scen" proposer_round_outcome info \
                "round $proposal_round was WON by the Rust node — the restart landed inside its own committed proposal"
        elif [ -n "$winner" ]; then
            record "$scen" proposer_round_outcome info \
                "round $proposal_round was won by $winner; the Rust node held a credential but the kill cost it the round"
        else
            record "$scen" proposer_round_outcome info \
                "could not read the proposer of round $proposal_round"
        fi
    fi

    local rust_log="$OUT_DIR/$scen.rust-node-4.log"
    docker logs "$RUST_CONTAINER" 2>&1 | strip_ansi > "$rust_log"
    local eq_json
    eq_json="$(python3 "$EQUIV_PY" "$rust_log")"
    echo "    rust-side vote scan: $eq_json"
    local eq_ok eq_n
    eq_ok="$(printf '%s' "$eq_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['ok'])")"
    eq_n="$(printf '%s' "$eq_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['attests_scanned'])")"
    if [ "$eq_ok" = "True" ] && [ "$eq_n" -gt 0 ]; then
        record "$scen" no_equivocation_rust pass \
            "$eq_n attests scanned across the restart, no coordinate signed twice with different values"
    elif [ "$eq_n" -eq 0 ]; then
        record "$scen" no_equivocation_rust fail \
            "the detector saw zero attests — it cannot have proven anything"
    else
        record "$scen" no_equivocation_rust fail \
            "DOUBLE VOTE detected: $(printf '%s' "$eq_json" | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)['equivocations']))")"
    fi

    local go_hits=0
    for c in "${GO_CONTAINERS[@]}"; do
        docker logs "$c" > "$OUT_DIR/$scen.$c.log" 2>&1 || true
        local n
        n="$(grep -cE "observed an equivocator|EquivocatedVote" "$OUT_DIR/$scen.$c.log" || true)"
        go_hits=$(( go_hits + n ))
    done
    local go_hits_ours=0
    if [ "$go_hits" -gt 0 ] && [ -n "$RUST_ACCOUNT" ]; then
        go_hits_ours="$(grep -hE "observed an equivocator|EquivocatedVote" \
            "$OUT_DIR/$scen".p2pinterop-go-node-*.log | grep -c "$RUST_ACCOUNT" || true)"
    fi
    if [ "$go_hits" -eq 0 ]; then
        record "$scen" no_equivocation_go pass \
            "0 equivocation reports in any Go node's log"
    elif [ "${go_hits_ours:-0}" -eq 0 ]; then
        record "$scen" no_equivocation_go pass \
            "$go_hits equivocation report(s) in Go logs, none naming $RUST_ACCOUNT"
    else
        record "$scen" no_equivocation_go fail \
            "go-algorand reported the Rust account $RUST_ACCOUNT as an equivocator $go_hits_ours time(s)"
    fi

    python3 -c "
import json, sys
print(json.dumps({
    'scenario': sys.argv[1],
    'mode': sys.argv[2],
    'how': sys.argv[3],
    'round_before_restart': int(sys.argv[4]),
    'rejoined': sys.argv[5] == '1',
    'rejoin_round': int(sys.argv[6]),
    'rejoin_seconds': int(sys.argv[7]),
    'rejoin_rounds': int(sys.argv[8]),
    'proposal_round': int(sys.argv[9]) if sys.argv[9] else None,
    'observed_from_round': int(sys.argv[10]),
    'observed_to_round': int(sys.argv[11]),
    'vote_scan': json.loads(sys.argv[12]),
}))" "$scen" "$mode" "$how" "$before_go" "$rejoined" "$rejoin_round" \
     "$rejoin_secs" "$rejoin_rounds" "$proposal_round" "$from_r" "$to_r" \
     "$eq_json" >> "$SCEN_FILE"
}

# ── main ───────────────────────────────────────────────────────────────

echo "======================================================================"
echo "issue #596 P2P restart / rejoin conformance   mode=$MODE"
echo "  artifacts: $OUT_DIR"
echo "======================================================================"

TOOLS_DIR="${TOOLS_DIR:-$REPO_ROOT/target/debug}"
FORK_BIN="$TOOLS_DIR/algo-fork-detector"
[ -x "$FORK_BIN" ] || FORK_BIN="$TOOLS_DIR/algo-fork-detector.exe"
TOKEN_FILE="$OUT_DIR/.algod.token"
printf '%s' "$ALGOD_TOKEN" > "$TOKEN_FILE"

echo "==> detector self-test (equivocation_test.py, shared with ops/mixed-cluster)"
if (cd "$WS_SCRIPTS" && python3 equivocation_test.py) > "$OUT_DIR/equivocation_test.log" 2>&1; then
    record selftest detector_selftest pass "equivocation.py catches a synthetic double vote"
else
    record selftest detector_selftest fail \
        "equivocation detector self-test FAILED — see $OUT_DIR/equivocation_test.log"
fi

RUST_ACCOUNT="$(rust_account)"
if [ -z "$RUST_ACCOUNT" ]; then
    echo "warning: could not read the Rust participation account from the container log;" >&2
    echo "         the Go-side equivocation check will fall back to 'any equivocator'." >&2
fi
echo "  rust account: ${RUST_ACCOUNT:-<unknown>}"
echo "  fork detector: $FORK_BIN"

case "$MODE" in
    graceful) run_scenario graceful graceful || true ;;
    kill)     run_scenario sigkill kill || true ;;
    proposer)
        for i in $(seq 1 "$PROPOSER_ATTEMPTS"); do
            run_scenario "proposer-$i" proposer || true
        done ;;
    all)
        run_scenario graceful graceful || true
        run_scenario sigkill kill || true
        for i in $(seq 1 "$PROPOSER_ATTEMPTS"); do
            run_scenario "proposer-$i" proposer || true
        done ;;
    *) echo "unknown mode: $MODE" >&2; exit 2 ;;
esac

python3 -c "
import json, sys
checks = []
with open(sys.argv[1], encoding='utf-8') as f:
    for line in f:
        parts = line.rstrip('\n').split('\t')
        if len(parts) != 4:
            continue
        checks.append({'scenario': parts[0], 'name': parts[1],
                       'status': parts[2], 'detail': parts[3]})
scenarios = []
try:
    with open(sys.argv[2], encoding='utf-8') as f:
        scenarios = [json.loads(l) for l in f if l.strip()]
except FileNotFoundError:
    pass
failed = [c for c in checks if c['status'] == 'fail']
summary = {
    'issue': 596,
    'run_id': sys.argv[3],
    'mode': sys.argv[4],
    'rust_account': sys.argv[5],
    'scenarios': scenarios,
    'checks': checks,
    'checks_total': len(checks),
    'checks_failed': len(failed),
    'result': 'FAIL' if failed else 'PASS',
}
with open(sys.argv[6], 'w', encoding='utf-8') as f:
    json.dump(summary, f, indent=2)
print(json.dumps({'result': summary['result'],
                  'checks_total': summary['checks_total'],
                  'checks_failed': summary['checks_failed']}))
" "$CHECKS_FILE" "$SCEN_FILE" "$RUN_ID" "$MODE" "${RUST_ACCOUNT:-}" "$SUMMARY_JSON"

FAILED="$(awk -F'\t' '$3=="fail"' "$CHECKS_FILE" | wc -l | tr -d ' ')"
TOTAL="$(wc -l < "$CHECKS_FILE" | tr -d ' ')"

echo ""
echo "======================================================================"
if [ "$FAILED" -eq 0 ]; then
    echo "restart-rejoin: PASS ($TOTAL checks)"
    echo "summary: $SUMMARY_JSON"
    echo "======================================================================"
    exit 0
fi
echo "restart-rejoin: FAIL ($FAILED of $TOTAL checks failed)" >&2
awk -F'\t' '$3=="fail" {print "  - " $1 "/" $2 ": " $4}' "$CHECKS_FILE" >&2
echo "summary: $SUMMARY_JSON" >&2
echo "======================================================================" >&2
exit 1
