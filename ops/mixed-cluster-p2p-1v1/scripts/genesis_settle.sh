#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Genesis-settle wait for the 1-1 (50/50 stake) P2P cluster (issue #1987).
#
# The two nodes cannot be started in the same instant (the Rust node needs the
# Go node's PeerId and genesis hash, so the Go node runs alone for a few
# seconds first). With 50/50 stake neither node can close a round alone, so
# round 1's period-0 votes miss each other and the pair has to walk through
# several agreement periods (step deadlines 3/4/6/10/18/34 s ...) before the
# first block. Measured: 63 s in a passing nightly (run 38874236497), more than
# 90 s in the runs that tripped the collector's 90 s stall timeout
# (38388453900, 38906199002, 38911195018). That is start-up settling, not a
# steady-state stall, so it gets its own, longer allowance; the collector's
# stall timeout then guards the soak proper.
#
# Source this file; it needs `node_round <port>` (echoes the last round or a
# non-numeric word) and `date`/`sleep`.

# wait_for_first_block <port> <timeout_s>
#   Echoes the seconds it took and returns 0 once <port> reports round >= 1;
#   echoes the seconds waited and returns 1 on timeout.
wait_for_first_block() {
    local port="$1" timeout="$2" start now r
    start="$(date +%s)"
    while :; do
        r="$(node_round "$port")"
        now="$(date +%s)"
        if [[ "$r" =~ ^[0-9]+$ ]] && [ "$r" -ge 1 ]; then
            echo $(( now - start ))
            return 0
        fi
        if [ $(( now - start )) -ge "$timeout" ]; then
            echo $(( now - start ))
            return 1
        fi
        sleep 2
    done
}
