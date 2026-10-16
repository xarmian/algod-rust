#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Shell test for the SIGKILL path of `do_restart` in BOTH restart-rejoin.sh
# harnesses (issue #1984): ops/mixed-cluster (WS gossip, fixed by #1574) and
# ops/mixed-cluster-p2p (never ported, so every kill-based scenario burned a
# 60 s poll for a restart policy that does not revive the container on the
# GitHub runners -- a 25-round gap that made `resumed_voting` a coin flip).
#
# No Docker and no real waiting: `docker`, `date` and `sleep` are stubs over a
# fake millisecond clock. The function under test is extracted from each
# script by name, so the test exercises the shipped code, not a copy.
#
#   bash ops/mixed-cluster/scripts/restart_rejoin_kill_shell_test.sh

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILS=0

ok() { echo "ok   - $1"; }
bad() { echo "FAIL - $1"; FAILS=$((FAILS + 1)); }
check() {  # check <name> <expected> <actual>
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}

# ── stubs over a fake clock ────────────────────────────────────────────
FAKE_MS=1000000
RUNNING=false
REVIVE_AT_MS=-1      # when the restart policy "revives" the container (-1: never)
KILLED_AT_MS=-1
STARTED_AT_MS=-1
START_CALLS=0

date() {  # only `date +%s` is used by do_restart
    echo $(( FAKE_MS / 1000 ))
}
sleep() {
    local ms
    ms="$(awk -v s="$1" 'BEGIN { printf "%d", s * 1000 }')"
    FAKE_MS=$(( FAKE_MS + ms ))
}
docker() {
    case "$1" in
        restart) RUNNING=true ;;
        kill) RUNNING=false; KILLED_AT_MS=$FAKE_MS ;;
        start)
            START_CALLS=$(( START_CALLS + 1 ))
            STARTED_AT_MS=$FAKE_MS
            RUNNING=true
            ;;
        inspect)
            if [ "$REVIVE_AT_MS" -ge 0 ] && [ "$FAKE_MS" -ge "$REVIVE_AT_MS" ]; then RUNNING=true; fi
            echo "$RUNNING"
            ;;
    esac
    return 0
}

RUST_CONTAINER="rust-node-4"

run_case() {  # run_case <script> <revive_after_ms|never> -> sets OUT
    local script="$1" revive="$2"
    # Extract `do_restart() { ... }` (column-0 closing brace) from the script.
    awk '/^do_restart\(\) \{/ {p=1} p {print} p && /^\}/ {exit}' "$script" > "$TMP/fn.sh"
    if ! grep -q '^do_restart' "$TMP/fn.sh"; then
        bad "$script: do_restart not found"
        OUT=""
        return
    fi
    # shellcheck disable=SC1091
    source "$TMP/fn.sh"
    RUNNING=true; START_CALLS=0; STARTED_AT_MS=-1; KILLED_AT_MS=-1
    FAKE_MS=1000000
    if [ "$revive" = never ]; then REVIVE_AT_MS=-1; else REVIVE_AT_MS=$(( FAKE_MS + revive )); fi
    do_restart kill > "$TMP/out.txt"
    OUT="$(cat "$TMP/out.txt")"
}

for harness in ops/mixed-cluster ops/mixed-cluster-p2p; do
    script="$REPO/$harness/scripts/restart-rejoin.sh"
    name="$harness"

    # 1. The restart policy never revives the container (the CI reality): we
    #    must `docker start` it ourselves within a few seconds, not a minute.
    run_case "$script" never
    check "$name: kill path issues docker start" 1 "$START_CALLS"
    elapsed=$(( STARTED_AT_MS - KILLED_AT_MS ))
    if [ "$STARTED_AT_MS" -ge 0 ] && [ "$elapsed" -le 5000 ]; then
        ok "$name: docker start within 5 s of the kill (${elapsed} ms)"
    else
        bad "$name: docker start came ${elapsed} ms after the kill (limit 5000)"
    fi
    check "$name: reports the manual start" "docker kill -s KILL + docker start" "$OUT"

    # 2. The policy does win inside the grace window: no second start.
    run_case "$script" 1000
    check "$name: no docker start when the policy revived it" 0 "$START_CALLS"
    check "$name: reports the policy revival" "docker kill -s KILL (restart policy revived it)" "$OUT"
done

if [ "$FAILS" -ne 0 ]; then
    echo "$FAILS check(s) failed"
    exit 1
fi
echo "all restart-rejoin kill-path checks passed"
