#!/usr/bin/env bash

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# PLAN-32 / TASK-87 — mixed-cluster soak harness.
#
# Thin wrapper around scripts/metrics.py that:
#   1. Verifies the cluster is up and healthy (reuses status.sh).
#   2. Launches metrics.py to sample /v2/status, /v2/blocks/{r} and
#      container state until --rounds new rounds have been observed.
#   3. Reports the output path and a one-line summary on exit.
#
# This script DOES NOT start or stop the cluster — run start.sh first
# and stop.sh after. Keeping them decoupled lets you chain multiple
# soak runs against one cluster or leave a cluster up for ad-hoc
# inspection afterwards.
#
# Usage:
#   scripts/soak.sh [--rounds N] [--out PATH] [--interval S]
#                   [--stall-timeout S] [--overall-timeout S]
#                   [--workload plain|rich] [--seed N]
#
# Workloads (issue #1674):
#   plain (default)  submits nothing: every observed block is empty. This is
#                    the historical behaviour and what the nightly runs.
#   rich             runs workload.py next to the collector (boxes, inner
#                    transactions, ASA create/opt-in/transfer/close-out,
#                    app create/call/delete, app-account closes, groups,
#                    min-balance edge cases, and transactions that must be
#                    rejected) AND blockcompare.py --follow, which compares
#                    the raw block bytes of all four nodes round by round.
#                    Output next to --out: workload.jsonl, blockcompare.jsonl.
#                    Also selectable with WORKLOAD=rich; WORKLOAD_SEED sets
#                    the seed. See docs/MIXED_CLUSTER_RUNBOOK.md.
#
# Exit codes:
#   0 — target rounds reached cleanly
#   1 — metrics.py exited with a non-target-reached phase (stall,
#       interrupt, timeout). The JSONL is still captured; inspect it.
#   2 — preflight failed (cluster not healthy). Nothing captured.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

ROUNDS=200
OUT=""
INTERVAL=0.5
STALL_TIMEOUT=60
OVERALL_TIMEOUT=0
SKIP_PREFLIGHT=0
WORKLOAD="${WORKLOAD:-plain}"
WORKLOAD_SEED="${WORKLOAD_SEED:-1674}"
ALGOD_TOKEN="${ALGOD_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"

usage() {
    cat <<EOF
usage: $(basename "$0") [options]

Options:
  --rounds N            Number of new rounds to observe (default: 200).
  --out PATH            Output JSONL path (default: \$ROOT/soak-<ts>.jsonl).
  --interval S          Poll interval in seconds (default: 0.5).
  --stall-timeout S     Abort if no REST node advances for S s (default: 60).
  --overall-timeout S   Abort after S wall-clock s (default: 0 = no cap).
  --skip-preflight      Skip the status.sh health check (useful when
                        chaining runs and the cluster is known healthy).
  --workload KIND       plain (default, no transactions) or rich (issue
                        #1674: seeded transaction workload plus live
                        cross-implementation block comparison).
  --seed N              Workload seed (default 1674; env WORKLOAD_SEED).
  -h, --help            Show this help.

This script expects start.sh to have been run. Tear down afterwards
with stop.sh.
EOF
}

# need_arg FLAG — error out if $2 is missing. Without this, `set -u`
# makes `shift 2` after a bare trailing flag abort with an opaque
# "unbound variable" message; a controlled usage error is nicer.
need_arg() {
    if [ $# -lt 2 ] || [ -z "$2" ] || [ "${2:0:2}" = "--" ]; then
        echo "error: flag '$1' requires a value" >&2
        usage >&2
        exit 2
    fi
}

while [ $# -gt 0 ]; do
    case "$1" in
        --rounds)
            need_arg "$@"; ROUNDS="$2"; shift 2 ;;
        --out)
            need_arg "$@"; OUT="$2"; shift 2 ;;
        --interval)
            need_arg "$@"; INTERVAL="$2"; shift 2 ;;
        --stall-timeout)
            need_arg "$@"; STALL_TIMEOUT="$2"; shift 2 ;;
        --overall-timeout)
            need_arg "$@"; OVERALL_TIMEOUT="$2"; shift 2 ;;
        --skip-preflight)
            SKIP_PREFLIGHT=1; shift ;;
        --workload)
            need_arg "$@"; WORKLOAD="$2"; shift 2 ;;
        --seed)
            need_arg "$@"; WORKLOAD_SEED="$2"; shift 2 ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "unknown arg: $1" >&2
            usage >&2
            exit 2 ;;
    esac
done

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required but not found on PATH" >&2
    exit 2
fi

if [ -z "$OUT" ]; then
    OUT="$ROOT/soak-$(date +%s).jsonl"
fi

# Absolute path for the report.
case "$OUT" in
    /*) : ;;
    *)  OUT="$(pwd)/$OUT" ;;
esac

case "$WORKLOAD" in
    plain|rich) : ;;
    *) echo "error: --workload must be plain or rich (got '$WORKLOAD')" >&2; exit 2 ;;
esac

OUT_DIRNAME="$(dirname "$OUT")"
WORKLOAD_OUT="$OUT_DIRNAME/workload.jsonl"
BLOCKCOMPARE_OUT="$OUT_DIRNAME/blockcompare.jsonl"
BLOCKCOMPARE_STOP="$OUT_DIRNAME/.blockcompare.stop"

# -- Preflight -----------------------------------------------------------
if [ "$SKIP_PREFLIGHT" = "0" ]; then
    echo "==> preflight: running status.sh to verify cluster health"
    if ! "$HERE/status.sh" >/dev/null 2>&1; then
        echo "error: status.sh reports the cluster is unhealthy or not running." >&2
        echo "       run scripts/start.sh first, or pass --skip-preflight to override." >&2
        exit 2
    fi
    echo "    cluster healthy"
else
    echo "==> preflight skipped (--skip-preflight)"
fi

# -- Rich workload (issue #1674) -----------------------------------------
WORKLOAD_PID=""
BLOCKCOMPARE_PID=""
if [ "$WORKLOAD" = "rich" ]; then
    START_JSON="$(curl -sf -H "X-Algo-API-Token: $ALGOD_TOKEN" http://127.0.0.1:4001/v2/status || true)"
    START_ROUND="$(printf '%s' "$START_JSON" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["last-round"])' 2>/dev/null || true)"
    START_ROUND="${START_ROUND//$'\r'/}"
    if ! [[ "$START_ROUND" =~ ^[0-9]+$ ]]; then
        echo "error: could not read the start round from go-node-1 (GET http://127.0.0.1:4001/v2/status failed or returned no last-round)" >&2
        exit 2
    fi
    echo "==> rich workload: seed=$WORKLOAD_SEED start_round=$START_ROUND"
    echo "    workload:     $WORKLOAD_OUT"
    echo "    blockcompare: $BLOCKCOMPARE_OUT"
    rm -f "$BLOCKCOMPARE_STOP"
    python3 "$HERE/blockcompare.py" --follow --out "$BLOCKCOMPARE_OUT"         --from-round "$((START_ROUND + 1))" --to-round "$((START_ROUND + ROUNDS))"         --stop-file "$BLOCKCOMPARE_STOP" --max-idle-s 300         > "$OUT_DIRNAME/blockcompare.log" 2>&1 &
    BLOCKCOMPARE_PID=$!
    python3 "$HERE/workload.py" --out "$WORKLOAD_OUT" --seed "$WORKLOAD_SEED"         --rounds "$ROUNDS" > "$OUT_DIRNAME/workload.log" 2>&1 &
    WORKLOAD_PID=$!
fi

# Stop the helpers on any exit path so a failed collector never leaves a
# workload or comparator running against the cluster.
WORKLOAD_RC=0
BLOCKCOMPARE_RC=0
stop_rich_helpers() {
    if [ -n "$WORKLOAD_PID" ]; then
        # workload.py stops itself a few rounds before the soak ends; give
        # it time to finish its step and write workload_summary, then ask.
        for _ in $(seq 1 60); do
            kill -0 "$WORKLOAD_PID" 2>/dev/null || break
            sleep 2
        done
        if kill -0 "$WORKLOAD_PID" 2>/dev/null; then
            kill -TERM "$WORKLOAD_PID" 2>/dev/null || true
            for _ in $(seq 1 45); do
                kill -0 "$WORKLOAD_PID" 2>/dev/null || break
                sleep 2
            done
            kill -KILL "$WORKLOAD_PID" 2>/dev/null || true
        fi
        wait "$WORKLOAD_PID" || WORKLOAD_RC=$?
    fi
    if [ -n "$BLOCKCOMPARE_PID" ]; then
        # It exits by itself after the last target round; give it time to
        # drain, then ask it to stop.
        for _ in $(seq 1 60); do
            kill -0 "$BLOCKCOMPARE_PID" 2>/dev/null || break
            sleep 2
        done
        if kill -0 "$BLOCKCOMPARE_PID" 2>/dev/null; then
            touch "$BLOCKCOMPARE_STOP"
            for _ in $(seq 1 15); do
                kill -0 "$BLOCKCOMPARE_PID" 2>/dev/null || break
                sleep 2
            done
            kill -TERM "$BLOCKCOMPARE_PID" 2>/dev/null || true
        fi
        wait "$BLOCKCOMPARE_PID" || BLOCKCOMPARE_RC=$?
    fi
    WORKLOAD_PID=""
    BLOCKCOMPARE_PID=""
}
trap stop_rich_helpers EXIT

# -- Metrics collection --------------------------------------------------
echo "==> running metrics collector"
echo "    rounds:          $ROUNDS"
echo "    out:             $OUT"
echo "    interval:        ${INTERVAL}s"
echo "    stall-timeout:   ${STALL_TIMEOUT}s"
echo "    overall-timeout: ${OVERALL_TIMEOUT}s"
echo ""

set +e
python3 "$HERE/metrics.py" \
    --rounds "$ROUNDS" \
    --out "$OUT" \
    --interval "$INTERVAL" \
    --stall-timeout "$STALL_TIMEOUT" \
    --overall-timeout "$OVERALL_TIMEOUT"
rc=$?
set -e

if [ "$WORKLOAD" = "rich" ]; then
    echo "==> stopping rich workload and draining blockcompare"
    stop_rich_helpers
    if [ "$WORKLOAD_RC" -ne 0 ]; then
        echo "error: workload.py exited with status $WORKLOAD_RC - see $OUT_DIRNAME/workload.log" >&2
    fi
    if [ "$BLOCKCOMPARE_RC" -ne 0 ]; then
        echo "error: blockcompare.py exited with status $BLOCKCOMPARE_RC (2 = nodes disagree, 3 = incomplete coverage) - see $OUT_DIRNAME/blockcompare.log" >&2
    fi
    if [ "$rc" -eq 0 ] && { [ "$WORKLOAD_RC" -ne 0 ] || [ "$BLOCKCOMPARE_RC" -ne 0 ]; }; then
        rc=1
    fi
    for f in "$WORKLOAD_OUT" "$BLOCKCOMPARE_OUT"; do
        echo "    $(basename "$f"): $(wc -l < "$f" 2>/dev/null | tr -d ' ') record(s)"
    done
    tail -n 1 "$BLOCKCOMPARE_OUT" 2>/dev/null | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        r = json.loads(line)
    except Exception:
        continue
    if r.get("kind") == "blockcompare_summary":
        print("    blockcompare: rounds={0} non_payment={1} mismatches={2} hash_mismatches={3} degraded={4}".format(
            r.get("rounds_compared"), r.get("rounds_non_payment"), r.get("mismatch_count"),
            r.get("hash_mismatch_count"), r.get("degraded_rounds")))
        print("    blockcompare: incomplete={0} missing_per_node={1}".format(
            r.get("incomplete_rounds"), r.get("nodes_missing")))
' || true
fi

echo ""
echo "==> collector exited with status $rc"
echo "    output: $OUT"
echo ""

# Quick tail summary so the operator doesn't have to parse JSONL by hand.
if [ -s "$OUT" ]; then
    # Print the last run_meta record + any warnings from the tail.
    echo "    last records:"
    tail -n 10 "$OUT" | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        rec = json.loads(line)
    except Exception:
        continue
    k = rec.get("kind")
    if k == "run_meta":
        phase = rec.get("phase")
        elapsed = rec.get("total_elapsed_s")
        final = rec.get("final_max_round")
        blocks = rec.get("blocks_captured")
        if phase and elapsed is not None:
            print("      run_meta phase={0} elapsed={1:.1f}s final_round={2} blocks={3}".format(phase, elapsed, final, blocks))
        else:
            print("      run_meta phase={0}".format(phase))
    elif k == "warning":
        print("      warning: {0}".format(rec.get("msg")))
'
    echo ""
    echo "    analyze with:"
    if [ "$WORKLOAD" = "rich" ]; then
        echo "      $HERE/analyze.py $OUT --workload $WORKLOAD_OUT --blockcompare $BLOCKCOMPARE_OUT"
    else
        echo "      $HERE/analyze.py $OUT"
    fi
fi

if [ "$rc" -eq 0 ]; then
    echo "soak complete — target rounds reached."
else
    echo "soak did NOT cleanly reach target — see JSONL for details." >&2
fi
exit "$rc"
