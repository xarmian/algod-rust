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
declare -A IMAGE=([go]="$GO_IMAGE" [rust]="$RUST_IMAGE")

cleanup() {
    for l in go rust; do docker rm -f "parity-$l" >/dev/null 2>&1; done
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

echo "== running $GO_IMAGE and $RUST_IMAGE (output in $OUT)"
collect go || exit 2
collect rust || exit 2

# ---- compare ---------------------------------------------------------------
fails=0
for f in "$OUT"/go/*.txt; do
    name="$(basename "$f" .txt)"
    case "$name" in stop_seconds) continue ;; esac
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
echo "docker stop: go $(cat "$OUT/go/stop_seconds.txt")s, rust $(cat "$OUT/rust/stop_seconds.txt")s"
if [ "$(cat "$OUT/rust/stop_seconds.txt")" -ge 20 ]; then
    echo "DIFF   rust docker stop took too long"; fails=$((fails + 1))
fi

if [ "$fails" -ne 0 ]; then
    echo "$fails unexpected difference(s); artifacts in $OUT"
    exit 1
fi
echo "parity OK (artifacts in $OUT)"
