#!/usr/bin/env bash

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Issue #594 — P2P mixed-cluster soak harness. Thin wrapper around
# scripts/metrics.py, mirroring `ops/mixed-cluster/scripts/soak.sh`
# (PLAN-32 / TASK-87) for `ops/mixed-cluster-p2p/`.
#
# This script DOES NOT start or stop the cluster — run start.sh first
# and stop.sh after (or use the `p2p-interop-soak-test` Makefile target,
# which wraps the whole up -> soak -> analyze -> down sequence). Keeping
# them decoupled lets you chain multiple soak runs against one cluster
# or leave a cluster up for ad-hoc inspection afterwards.
#
# Usage:
#   scripts/soak.sh [--rounds N] [--out PATH] [--interval S]
#                   [--stall-timeout S] [--overall-timeout S]
#
# Env:
#   PREFLIGHT_RETRIES    status.sh retries before giving up   (default 29)
#   PREFLIGHT_INTERVAL   seconds between preflight retries     (default 10)
#                        (29 * 10s + 1 final attempt ~= the same ~5 minute
#                        grace period Tier 1's own workflow-level lockstep
#                        gate uses — see issue #1567)
#
# Exit codes:
#   0 — target rounds reached cleanly
#   1 — metrics.py exited with a non-target-reached phase (stall,
#       interrupt, timeout). The JSONL is still captured; inspect it.
#   2 — preflight failed (cluster not healthy after the retry budget).
#       Nothing captured.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

ROUNDS=200
OUT=""
INTERVAL=0.5
STALL_TIMEOUT=60
OVERALL_TIMEOUT=0
SKIP_PREFLIGHT=0

usage() {
    cat <<EOF
usage: $(basename "$0") [options]

Options:
  --rounds N            Number of new rounds to observe (default: 200).
  --out PATH            Output JSONL path (default: \$ROOT/soak-<ts>.jsonl).
  --interval S          Poll interval in seconds (default: 0.5).
  --stall-timeout S     Abort if no REST node advances for S s (default: 60).
  --overall-timeout S   Abort after S wall-clock s (default: 0 = no cap).
  --skip-preflight      Skip the retrying status.sh health check (useful
                        when chaining runs and the cluster is known
                        healthy).
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

# -- Preflight -----------------------------------------------------------
#
# Issue #1567: between Tier 1 and Tier 2 of the nightly soak workflow,
# stop.sh's `docker compose down -v` wipes the Rust node's named data
# volume (back to round 0) while leaving the Go nodes' bind-mounted
# netroot/ on disk, so start.sh's "reusing existing netroot/" path lets
# the 3 Go nodes resume ~30 rounds ahead of a freshly-recreated
# rust-node-4. A single-shot status.sh call fired seconds after start.sh
# returns and failed on that transient, expected startup lag rather than
# a real health problem — unlike Tier 1's own workflow-level lockstep
# gate (.github/workflows/p2p-consensus-soak.yml "Tier 1 — cluster
# status"), which retries for up to ~5 minutes for exactly this reason.
# Mirror that same retry/grace-period budget here so Tier 2's preflight
# measures steady-state lockstep, not boot/catch-up ordering.
PREFLIGHT_RETRIES="${PREFLIGHT_RETRIES:-29}"
PREFLIGHT_INTERVAL="${PREFLIGHT_INTERVAL:-10}"
if [ "$SKIP_PREFLIGHT" = "0" ]; then
    preflight_budget=$(( (PREFLIGHT_RETRIES + 1) * PREFLIGHT_INTERVAL ))
    echo "==> preflight: running status.sh to verify cluster health"
    echo "    (retrying for up to ${preflight_budget}s to allow the Rust node to catch up"
    echo "     after its data volume was wiped between tiers — see issue #1567)"
    preflight_ok=0
    attempt=1
    while [ "$attempt" -le "$PREFLIGHT_RETRIES" ]; do
        if "$HERE/status.sh" >/dev/null 2>&1; then
            preflight_ok=1
            break
        fi
        sleep "$PREFLIGHT_INTERVAL"
        attempt=$(( attempt + 1 ))
    done
    # Last attempt runs with output shown (not suppressed) so a genuine
    # failure's reason ends up in the log, mirroring Tier 1's own
    # "the last invocation is the one that decides the step" pattern.
    if [ "$preflight_ok" != "1" ] && "$HERE/status.sh"; then
        preflight_ok=1
    fi
    if [ "$preflight_ok" != "1" ]; then
        echo "error: status.sh reports the cluster is unhealthy or not running" \
            "after ${preflight_budget}s of retries." >&2
        echo "       run scripts/start.sh first, or pass --skip-preflight to override." >&2
        exit 2
    fi
    echo "    cluster healthy"
else
    echo "==> preflight skipped (--skip-preflight)"
fi

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
    echo "    analyze with (reuses the WS-gossip analyzer — see"
    echo "    docs/P2P_SOAK_METHODOLOGY.md for why no fork variant exists):"
    echo "      $ROOT/../mixed-cluster/scripts/analyze.py $OUT"
fi

if [ "$rc" -eq 0 ]; then
    echo "soak complete — target rounds reached."
else
    echo "soak did NOT cleanly reach target — see JSONL for details." >&2
fi
exit "$rc"
