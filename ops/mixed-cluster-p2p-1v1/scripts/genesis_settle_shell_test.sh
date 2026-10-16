#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Shell test for genesis_settle.sh (issue #1987). No Docker, no real waiting:
# `node_round`, `date` and `sleep` are stubs over a fake clock.
#
#   bash ops/mixed-cluster-p2p-1v1/scripts/genesis_settle_shell_test.sh

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAILS=0
ok() { echo "ok   - $1"; }
bad() { echo "FAIL - $1"; FAILS=$((FAILS + 1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi; }

FAKE_S=1000
FIRST_BLOCK_AT=-1   # fake-clock second at which the node reports round 1 (-1: never)
date() { echo "$FAKE_S"; }
sleep() { FAKE_S=$(( FAKE_S + ${1%.*} )); }
node_round() {
    if [ "$FIRST_BLOCK_AT" -ge 0 ] && [ "$FAKE_S" -ge "$FIRST_BLOCK_AT" ]; then echo 1; else echo 0; fi
}

# shellcheck source=genesis_settle.sh
source "$HERE/genesis_settle.sh"

# 1. A first block after 110 s (longer than the collector's 90 s stall timeout)
#    is still a pass inside a 300 s allowance, and the wait reports it.
FAKE_S=1000; FIRST_BLOCK_AT=1110
out="$(wait_for_first_block 5101 300)"; rc=$?
check "slow first block: returns 0" 0 "$rc"
check "slow first block: reports the seconds waited" 110 "$out"

# 2. Already past round 0: returns at once.
FAKE_S=1000; FIRST_BLOCK_AT=1000
out="$(wait_for_first_block 5101 300)"; rc=$?
check "immediate first block: returns 0" 0 "$rc"
check "immediate first block: 0 s" 0 "$out"

# 3. Never settles: gives up at the timeout and says so.
FAKE_S=1000; FIRST_BLOCK_AT=-1
out="$(wait_for_first_block 5101 120)"; rc=$?
check "no first block: returns 1" 1 "$rc"
if [ "$out" -ge 120 ] && [ "$out" -le 124 ]; then ok "no first block: gives up at ~120 s ($out)"; else bad "no first block: waited $out s"; fi

# 4. A node that is unreachable counts as not yet settled.
node_round() { echo unreachable; }
FAKE_S=1000
out="$(wait_for_first_block 5101 10)"; rc=$?
check "unreachable node: returns 1" 1 "$rc"

if [ "$FAILS" -ne 0 ]; then echo "$FAILS check(s) failed"; exit 1; fi
echo "all genesis-settle checks passed"
