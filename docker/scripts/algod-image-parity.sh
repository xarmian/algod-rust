#!/usr/bin/env bash
# Copyright (C) 2019-2026 Algorand Foundation Ltd.
# Modifications Copyright (C) 2026 Algod DAO
# This file is part of algod-rust, a modified work based on go-algorand
# (https://github.com/algorand/go-algorand).
#
# algod-rust is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# algod-rust is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Side-by-side parity check of the algod-rust `algod` image against
# `algorand/algod` (issue #1994, epic #1989): both images are run with the
# same environment and the observable behaviour an operator relies on is
# compared -- the /algod/data layout, `goal node status`, `goal network
# status`, `goal account list`, the REST status shape, the lifecycle messages
# of `goal node stop/start/restart` and `goal kmd stop/start`, and the
# behaviour across `docker restart` / `docker stop`.
#
# Usage: docker/scripts/algod-image-parity.sh <algod-rust-image> [go-image]
#   go-image defaults to algorand/algod:5.0.3-stable
#
# Differences are expected to be listed in docker/scripts/algod-image-parity.known
# (`check|reason`); an unlisted difference fails the run, and so does a listed
# one that no longer differs (the list must not rot).
#
# The scenario is DEV_MODE=1 + START_KMD=1: it needs no external network and
# is deterministic.

set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_IMAGE="${1:?usage: $0 <algod-rust-image> [go-image]}"
GO_IMAGE="${2:-algorand/algod:5.0.3-stable}"
KNOWN="${KNOWN:-$HERE/algod-image-parity.known}"
OUT="${OUT:-$(mktemp -d)}"
TOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
# Git Bash on Windows rewrites /paths in docker arguments
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

declare -A PORT=([go]=18090 [rust]=18091)
declare -A TPORT=([go]=18092 [rust]=18093)
declare -A IMAGE=([go]="$GO_IMAGE" [rust]="$RUST_IMAGE")

cleanup() {
    for l in go rust; do
        docker rm -f "parity-$l" "parity-$l-t" >/dev/null 2>&1
        docker volume rm -f "parity-$l-vol" >/dev/null 2>&1
    done
}
trap cleanup EXIT
cleanup

# normalise what legitimately differs between two runs of the *same* node:
# times, rounds, addresses, hashes, hex
norm() {
    sed -E \
        -e 's/[A-Z2-7]{58}/ADDR/g' \
        -e 's/[A-Za-z0-9+\/]{43}=/HASH/g' \
        -e 's/[0-9]+\.[0-9]+s/Ns/g' \
        -e 's/[0-9]{4,}/N/g'
}

wait_health() {  # wait_health <port> <seconds>
    local i
    for i in $(seq 1 "$2"); do
        curl -sf "http://127.0.0.1:$1/health" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

collect() {  # collect <go|rust> [extra docker run args...]
    local l="$1"; shift
    local d="$OUT/$l"; mkdir -p "$d"
    local c="parity-$l" p="${PORT[$l]}"
    docker run -d --name "$c" -e DEV_MODE=1 -e START_KMD=1 -e NUM_ROUNDS=1000 \
        -e TOKEN="$TOKEN" -p "$p:8080" "$@" "${IMAGE[$l]}" >/dev/null || return 1
    if ! wait_health "$p" 180; then
        echo "FAIL: $l did not become healthy" >&2
        docker logs "$c" 2>&1 | tail -30 >&2
        return 1
    fi
    sleep 3   # let a block or two happen and kmd settle
    local x="docker exec $c"
    local api=(curl -s -H "X-Algo-API-Token: $TOKEN")

    # the interesting files of the data directory (runtime logs/locks differ by design)
    $x ls -A /algod/data | grep -Ev '^(.*\.log|algod\.(lock|pid|net)|node\.archive|.*-v1)$' | sort >"$d/data_layout.txt"
    $x sh -c 'ls -A /algod | sort' >"$d/algod_root.txt"
    $x sh -c 'cat /algod/data/genesis.json' | python3 -c "
import json,sys
g=json.load(sys.stdin)
print(sorted(g.keys()))
print(g.get('network'), g.get('id'), g.get('proto'), g.get('devmode'))
print(len(g['alloc']))" >"$d/genesis_shape.txt" 2>&1

    $x goal node status 2>&1 | norm >"$d/goal_node_status.txt"
    $x goal network status -r /algod 2>&1 | norm >"$d/goal_network_status.txt"
    $x goal account list 2>&1 | norm | sort >"$d/goal_account_list.txt"
    "${api[@]}" "http://127.0.0.1:$p/v2/status" | python3 -c "import json,sys; print(sorted(json.load(sys.stdin)))" >"$d/rest_status_keys.txt" 2>&1
    "${api[@]}" "http://127.0.0.1:$p/v2/transactions/params" | python3 -c "import json,sys; print(sorted(json.load(sys.stdin)))" >"$d/rest_params_keys.txt" 2>&1
    "${api[@]}" "http://127.0.0.1:$p/versions" | python3 -c "import json,sys; d=json.load(sys.stdin); print(sorted(d)); print(d.get('genesis_id'))" >"$d/rest_versions_shape.txt" 2>&1
    curl -s -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:$p/health" >"$d/health_code.txt"
    curl -s -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:$p/v2/status" >"$d/status_without_token.txt"

    # lifecycle messages
    { $x goal kmd stop 2>&1; $x goal kmd start 2>&1; } | norm >"$d/goal_kmd_lifecycle.txt"
    { $x goal node stop 2>&1; echo "rc=$?"; $x goal node status 2>&1 | head -1; $x goal node start 2>&1; echo "rc=$?"; } | norm >"$d/goal_node_lifecycle.txt"
    wait_health "$p" 60 || echo "unhealthy after goal node start" >>"$d/goal_node_lifecycle.txt"
    # the data directory is the same one that was started: the network resumes
    docker restart -t 30 "$c" >/dev/null
    if wait_health "$p" 120; then echo "healthy after docker restart" >"$d/docker_restart.txt"; else echo "NOT healthy after docker restart" >"$d/docker_restart.txt"; fi
    $x goal node status 2>&1 | head -1 | norm >>"$d/docker_restart.txt"

    # docker stop is prompt (go's image tails a log and is killed after the
    # grace period; ours stops the network on SIGTERM)
    local t0 t1
    t0=$(date +%s); docker stop -t 30 "$c" >/dev/null; t1=$(date +%s)
    echo $((t1 - t0)) >"$d/stop_seconds.txt"
    docker logs "$c" >"$d/container.log" 2>&1
}

# A public network first start with FAST_CATCHUP=1 on a named volume, then a
# second start on the same volume (go's "existing data directory" branch). The
# node is only observed -- it is not synced to the head of testnet.
collect_testnet() {  # collect_testnet <go|rust>
    local l="$1" d="$OUT/$1"; mkdir -p "$d"
    local c="parity-$l-t" p="${TPORT[$l]}" vol="parity-$l-vol"
    docker volume create "$vol" >/dev/null
    docker run -d --name "$c" -e NETWORK=testnet -e FAST_CATCHUP=1 -e TOKEN="$TOKEN" \
        -p "$p:8080" -v "$vol:/algod/data" "${IMAGE[$l]}" >/dev/null || return 1
    if ! wait_health "$p" 240; then
        echo "FAIL: $l testnet did not become healthy" >&2; docker logs "$c" 2>&1 | tail -30 >&2; return 1
    fi
    local x="docker exec $c"
    # FAST_CATCHUP issues `goal node catchup` after CATCHUP_DELAY: wait (bounded)
    # until the node reports a catchpoint it is catching up to
    local started=False i
    for i in $(seq 1 45); do
        if curl -s -H "X-Algo-API-Token: $TOKEN" "http://127.0.0.1:$p/v2/status" \
            | python3 -c "import json,sys; sys.exit(0 if json.load(sys.stdin).get('catchpoint') else 1)" 2>/dev/null; then
            started=True; break
        fi
        sleep 2
    done
    echo "$started" >"$d/testnet_catchup_started.txt"
    $x ls -A /algod/data | grep -Ev '^(.*\.log|algod\.(lock|pid|net)|node\.archive|.*-v1)$' | sort >"$d/testnet_data_layout.txt"
    $x sh -c 'ls -ln /algod/data/genesis.json | awk "{print \$3, \$4}"' >"$d/testnet_genesis_owner.txt"
    $x goal node status 2>&1 | grep -E '^(Genesis ID|Last consensus protocol)' >"$d/testnet_node_status.txt"
    if [ "$started" = False ]; then
        # (after every capture, it changes the node's state) diagnostics for a catchup that never started: what does the command
        # the entrypoint ran say when run by hand, and is it still running?
        { echo "== ps"; docker exec "$c" sh -c 'ps aux 2>/dev/null || ls /proc | head -50';           echo "== goal node catchup"; timeout 90 docker exec "$c" goal node catchup --force --min 1000000 2>&1; echo "rc=$?"; }             >"$d/testnet_catchup_cmd.log" 2>&1
    fi
    curl -s -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:$p/health" >"$d/testnet_health_code.txt"
    docker logs "$c" >"$d/testnet_container.log" 2>&1   # (.log: kept as an artifact, not compared)
    local t0 t1
    t0=$(date +%s); docker stop -t 30 "$c" >/dev/null; t1=$(date +%s)
    echo $((t1 - t0)) >"$d/testnet_stop_seconds.txt"
    docker rm "$c" >/dev/null
    # second start on the same volume: the existing data directory is reused
    docker run -d --name "$c" -e TOKEN="$TOKEN" -p "$p:8080" -v "$vol:/algod/data" "${IMAGE[$l]}" >/dev/null || return 1
    if wait_health "$p" 180; then
        echo "resumed" >"$d/testnet_reuse.txt"
        $x goal node status 2>&1 | grep -E '^Genesis ID' >>"$d/testnet_reuse.txt"
    else
        echo "NOT resumed" >"$d/testnet_reuse.txt"
        docker logs "$c" 2>&1 | tail -20 >&2
    fi
    docker stop -t 30 "$c" >/dev/null
    docker rm "$c" >/dev/null
}

echo "== running $GO_IMAGE and $RUST_IMAGE (output in $OUT)"
collect go || exit 2
collect rust || exit 2
if [ "${SKIP_TESTNET:-0}" != "1" ]; then
    echo "== public network (testnet, FAST_CATCHUP=1) and data directory reuse"
    collect_testnet go || exit 2
    collect_testnet rust || exit 2
fi

# ---- compare ---------------------------------------------------------------
fails=0
for f in "$OUT"/go/*.txt; do
    name="$(basename "$f" .txt)"
    case "$name" in stop_seconds | testnet_stop_seconds) continue ;; esac
    if diff -u "$OUT/go/$name.txt" "$OUT/rust/$name.txt" >"$OUT/$name.diff"; then
        if grep -q "^$name|" "$KNOWN" 2>/dev/null; then
            echo "STALE  $name is listed in $KNOWN but no longer differs"; fails=$((fails + 1))
        else
            echo "SAME   $name"
        fi
    else
        if grep -q "^$name|" "$KNOWN" 2>/dev/null; then
            echo "KNOWN  $name ($(grep "^$name|" "$KNOWN" | head -1 | cut -d'|' -f2))"
        else
            echo "DIFF   $name"; sed 's/^/        /' "$OUT/$name.diff"; fails=$((fails + 1))
        fi
    fi
done
if [ -s "$OUT/rust/testnet_container.log" ] && ! diff -q "$OUT/go/testnet_catchup_started.txt" "$OUT/rust/testnet_catchup_started.txt" >/dev/null 2>&1; then
    echo "---- rust testnet container log (tail) ----"
    cat "$OUT/rust/testnet_catchup_cmd.log" 2>/dev/null | head -30
    sed 's/\[[0-9;]*m//g' "$OUT/rust/testnet_container.log" | grep -v "gossip_block_source" | grep -iE "catchup|catchpoint|dns|discovery|phonebook|peers|error|warn" | head -40
fi
echo "docker stop: go $(cat "$OUT/go/stop_seconds.txt")s, rust $(cat "$OUT/rust/stop_seconds.txt")s"
if [ "$(cat "$OUT/rust/stop_seconds.txt")" -ge 20 ]; then
    echo "DIFF   rust docker stop took too long"; fails=$((fails + 1))
fi
if [ -f "$OUT/rust/testnet_stop_seconds.txt" ]; then
    echo "docker stop (testnet): go $(cat "$OUT/go/testnet_stop_seconds.txt")s, rust $(cat "$OUT/rust/testnet_stop_seconds.txt")s"
    if [ "$(cat "$OUT/rust/testnet_stop_seconds.txt")" -ge 20 ]; then
        echo "DIFF   rust testnet docker stop took too long"; fails=$((fails + 1))
    fi
fi

if [ "$fails" -ne 0 ]; then
    echo "$fails unexpected difference(s); artifacts in $OUT"
    exit 1
fi
echo "parity OK (artifacts in $OUT)"
