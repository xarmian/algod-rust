#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Shell test for ports.sh (issue #1956): the host-port base resolution every
# harness script sources, and the bound-port check start.sh runs before
# `docker compose up`. No Docker: the "occupied" port is a python listener.
#
#   bash ops/mixed-cluster/scripts/ports_shell_test.sh

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
LISTENER_PID=""
trap '[ -n "$LISTENER_PID" ] && kill "$LISTENER_PID" 2>/dev/null; rm -rf "$TMP"' EXIT
FAILS=0

ok() { echo "ok   - $1"; }
bad() { echo "FAIL - $1"; FAILS=$((FAILS + 1)); }
check() {  # check <name> <expected> <actual>
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}

free_port() {
    python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()' | tr -d '\r'
}

# 1. defaults (no env, no env file)
unset PHASE6_HOST_PORT_BASE
export PHASE6_ENV_FILE="$TMP/does-not-exist"
# shellcheck source=ports.sh
source "$HERE/ports.sh"
check "default base" 4000 "$PHASE6_HOST_PORT_BASE"
check "default go-node-1" 4001 "$PHASE6_GO1_PORT"
check "default go-node-2" 4002 "$PHASE6_GO2_PORT"
check "default go-node-3" 4003 "$PHASE6_GO3_PORT"
check "default rust-node-4" 4004 "$PHASE6_RUST_PORT"
check "default go-node-5" 4005 "$PHASE6_GO5_PORT"
check "phase6_node_port by name" 4004 "$(phase6_node_port rust-node-4)"
check "phase6_node_port unknown name fails" 1 "$(phase6_node_port no-such-node >/dev/null 2>&1; echo $?)"

# 2. env var override
export PHASE6_HOST_PORT_BASE=5000
source "$HERE/ports.sh"
check "env base" 5000 "$PHASE6_HOST_PORT_BASE"
check "env rust-node-4" 5004 "$PHASE6_RUST_PORT"
check "env go-node-5" 5005 "$PHASE6_GO5_PORT"

# 3. env file written by start.sh is the fallback when the env var is unset
unset PHASE6_HOST_PORT_BASE
printf 'PHASE6_GENESIS_ID=phase6net-v1\r\nPHASE6_HOST_PORT_BASE=6000\r\n' > "$TMP/env"
export PHASE6_ENV_FILE="$TMP/env"
source "$HERE/ports.sh"
check "env-file base" 6000 "$PHASE6_HOST_PORT_BASE"
check "env-file go-node-1" 6001 "$PHASE6_GO1_PORT"
export PHASE6_HOST_PORT_BASE=7000
source "$HERE/ports.sh"
check "env var beats env file" 7001 "$PHASE6_GO1_PORT"

# 4. invalid values are rejected (sourcing returns non-zero, message names the var)
for bad_val in abc 0 65531 -5; do
    out="$(PHASE6_HOST_PORT_BASE="$bad_val" bash -c "source '$HERE/ports.sh'" 2>&1)"
    rc=$?
    check "invalid base '$bad_val' rejected" 1 "$rc"
    case "$out" in
        *PHASE6_HOST_PORT_BASE*) ok "invalid base '$bad_val' message" ;;
        *) bad "invalid base '$bad_val' message: $out" ;;
    esac
done

# 5. bound-port detection: occupy a free port with a python listener
export PHASE6_HOST_PORT_BASE=4000
export PHASE6_ENV_FILE="$TMP/does-not-exist"
source "$HERE/ports.sh"
BUSY="$(free_port)"
python3 -c 'import socket, sys, time
s = socket.socket()
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(1)
time.sleep(60)' "$BUSY" &
LISTENER_PID=$!
for _ in $(seq 1 50); do
    if phase6_port_in_use "$BUSY"; then break; fi
    sleep 0.1
done
check "bound port detected" 0 "$(phase6_port_in_use "$BUSY"; echo $?)"
FREE="$(free_port)"
check "free port not flagged" 1 "$(phase6_port_in_use "$FREE"; echo $?)"

# 6. phase6_check_ports_free: fails on the busy port, names it and the override
out="$(phase6_check_ports_free "go-node-2=$BUSY" "rust-node-4=$FREE" 2>&1)"
rc=$?
check "check_ports_free fails on a bound port" 1 "$rc"
case "$out" in *"$BUSY"*) ok "message names the port" ;; *) bad "message names the port: $out" ;; esac
case "$out" in *go-node-2*) ok "message names the node" ;; *) bad "message names the node: $out" ;; esac
case "$out" in *PHASE6_HOST_PORT_BASE*) ok "message names the override" ;; *) bad "message names the override: $out" ;; esac
out="$(phase6_check_ports_free "go-node-2=$FREE" 2>&1)"
rc=$?
check "check_ports_free passes on free ports" 0 "$rc"
check "no output on free ports" "" "$out"

echo
if [ "$FAILS" -eq 0 ]; then
    echo "all ports.sh checks passed"
else
    echo "$FAILS ports.sh check(s) FAILED"
    exit 1
fi
