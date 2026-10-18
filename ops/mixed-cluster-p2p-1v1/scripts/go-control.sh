#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Issue #1987 control run: does go-algorand settle round 1 when its only
# 50%-stake peer joins late? The 1v1 soak (1 go + 1 algod-rust, 50/50 stake)
# intermittently never closes round 1 right after startup; this runs the same
# topology with a *go-algorand* second participant started SKEW seconds after
# the first, N times, and reports how long round 1 / TARGET_ROUND took.
#
#   RUNS=5 SKEW=60 ops/mixed-cluster-p2p-1v1/scripts/go-control.sh
#
# A go-vs-go stall (or a time to round 1 as long as the algod-rust runs show)
# means the late-joiner race is go-algorand's own behaviour and the harness
# should avoid the skew; a go-vs-go run that always settles quickly points at
# algod-rust.
#
# (secs_to_* are measured from the moment the second node has started, i.e.
# after the SKEW wait, so they are comparable across skews.)
#
# Output: one TSV line per run in $OUT/go-control.tsv (default
# ./go-control-artifacts):
#   run  skew_secs  secs_to_round1  secs_to_target  go1_round  go2_round  verdict

set -uo pipefail
export MSYS_NO_PATHCONV=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNS="${RUNS:-5}"
SKEW="${SKEW:-60}"
TARGET_ROUND="${TARGET_ROUND:-5}"
LIMIT_SECS="${LIMIT_SECS:-400}"
# NODE2=go (default): the control; NODE2=rust: the same loop with the
# algod-rust participant, for a like-for-like distribution to compare with.
NODE2="${NODE2:-go}"
case "$NODE2" in
    go) CONTROL_GO=1; NODE2_CONTAINER=p2pinterop1v1-go-node-2 ;;
    rust) CONTROL_GO=0; NODE2_CONTAINER=p2pinterop1v1-rust-node-2 ;;
    *) echo "NODE2 must be go or rust" >&2; exit 2 ;;
esac
OUT="${OUT:-$PWD/go-control-artifacts}"
TOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
mkdir -p "$OUT"
TSV="$OUT/go-control.tsv"
printf 'run\tskew_secs\tsecs_to_round1\tsecs_to_target\tgo1_round\tgo2_round\tverdict\n' >"$TSV"

round_of() {  # round_of <host-port> -> last-round or -1
    curl -s -m 3 -H "X-Algo-API-Token: $TOKEN" "http://127.0.0.1:$1/v2/status" \
        | python3 -c "import json,sys; r=json.load(sys.stdin).get('last-round'); print(r if isinstance(r, int) else -1)" 2>/dev/null \
        || echo -1
}

stalls=0
for run in $(seq 1 "$RUNS"); do
    echo "== control run $run/$RUNS (skew ${SKEW}s)"
    "$HERE/stop.sh" --purge >/dev/null 2>&1 || true
    NUM_ROUNDS=2000 P2PINTEROP1V1_CONTROL_GO="$CONTROL_GO" P2PINTEROP1V1_START_SKEW_SECS="$SKEW" \
        "$HERE/start.sh" >"$OUT/start-$run.log" 2>&1 || { echo "start failed (see $OUT/start-$run.log)"; \
        docker logs p2pinterop1v1-go-node-1 >"$OUT/go-node-1-$run.log" 2>&1 || true; \
        docker logs "$NODE2_CONTAINER" >"$OUT/node2-$run.log" 2>&1 || true; \
        printf '%s\t%s\t-\t-\t-\t-\tSTART_FAILED\n' "$run" "$SKEW" >>"$TSV"; continue; }
    t0=$(date +%s)
    t_r1=""; t_target=""; r1=-1; r2=-1
    while [ $(( $(date +%s) - t0 )) -lt "$LIMIT_SECS" ]; do
        r1=$(round_of 5101); r2=$(round_of 5102)
        now=$(( $(date +%s) - t0 ))
        if [ -z "$t_r1" ] && [ "$r1" -ge 1 ] && [ "$r2" -ge 1 ]; then t_r1=$now; fi
        if [ "$r1" -ge "$TARGET_ROUND" ] && [ "$r2" -ge "$TARGET_ROUND" ]; then t_target=$now; break; fi
        sleep 2
    done
    if [ -n "$t_target" ]; then verdict=SETTLED; else verdict=STALLED; stalls=$((stalls + 1)); fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$run" "$SKEW" "${t_r1:--}" "${t_target:--}" "$r1" "$r2" "$verdict" | tee -a "$TSV"
    docker logs p2pinterop1v1-go-node-1 >"$OUT/go-node-1-$run.log" 2>&1 || true
    docker logs "$NODE2_CONTAINER" >"$OUT/node2-$run.log" 2>&1 || true
done
"$HERE/stop.sh" --purge >/dev/null 2>&1 || true

echo "== summary: $stalls of $RUNS runs stalled (skew ${SKEW}s)"
cat "$TSV"
# informational: the answer is in the TSV, not in this script's exit code
exit 0
