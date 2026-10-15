#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Sourced by every mixed-cluster script (issue #1956): the host-port table.
#
# Every node's REST API is published on 127.0.0.1:<base>+N where N is the
# node number (go-node-1..3, rust-node-4, go-node-5) and base is
# PHASE6_HOST_PORT_BASE (default 4000 = the historical 4001..4005). The
# environment wins; otherwise the base start.sh persisted in
# netroot/.phase6-env (PHASE6_ENV_FILE overrides the path) is used, so a
# status/verify script run later in another shell still finds the cluster.
#
# Exports PHASE6_HOST_PORT_BASE and the per-node variables docker-compose.yml
# interpolates: PHASE6_GO1_PORT PHASE6_GO2_PORT PHASE6_GO3_PORT
# PHASE6_RUST_PORT PHASE6_GO5_PORT. ports.py is the python twin.
#
#   phase6_node_port <name>                   prints the node's host port
#   phase6_port_in_use <port>                 0 when something is bound to it
#   phase6_check_ports_free <name=port>...    1 + a message naming the node,
#                                             the port and the override when
#                                             any is bound; silent 0 otherwise

_phase6_ports_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_phase6_env_file="${PHASE6_ENV_FILE:-$_phase6_ports_dir/../netroot/.phase6-env}"

if [ -z "${PHASE6_HOST_PORT_BASE:-}" ] && [ -f "$_phase6_env_file" ]; then
    PHASE6_HOST_PORT_BASE="$(sed -n 's/^PHASE6_HOST_PORT_BASE=//p' "$_phase6_env_file" | tail -n 1 | tr -d '\r ')"
fi
PHASE6_HOST_PORT_BASE="${PHASE6_HOST_PORT_BASE:-4000}"

if ! [[ "$PHASE6_HOST_PORT_BASE" =~ ^[0-9]+$ ]] || [ "$PHASE6_HOST_PORT_BASE" -lt 1 ] || [ "$PHASE6_HOST_PORT_BASE" -gt 65530 ]; then
    echo "error: PHASE6_HOST_PORT_BASE='$PHASE6_HOST_PORT_BASE' is not a port base in 1..65530" >&2
    return 1 2>/dev/null || exit 1
fi

export PHASE6_HOST_PORT_BASE
export PHASE6_GO1_PORT=$((PHASE6_HOST_PORT_BASE + 1))
export PHASE6_GO2_PORT=$((PHASE6_HOST_PORT_BASE + 2))
export PHASE6_GO3_PORT=$((PHASE6_HOST_PORT_BASE + 3))
export PHASE6_RUST_PORT=$((PHASE6_HOST_PORT_BASE + 4))
export PHASE6_GO5_PORT=$((PHASE6_HOST_PORT_BASE + 5))

phase6_node_port() {
    case "$1" in
        go-node-1) echo "$PHASE6_GO1_PORT" ;;
        go-node-2) echo "$PHASE6_GO2_PORT" ;;
        go-node-3) echo "$PHASE6_GO3_PORT" ;;
        rust-node-4) echo "$PHASE6_RUST_PORT" ;;
        go-node-5) echo "$PHASE6_GO5_PORT" ;;
        *) echo "error: unknown mixed-cluster node '$1'" >&2; return 1 ;;
    esac
}

# Bound-port probe. A bind() attempt (no SO_REUSEADDR) fails on every platform
# when a listener holds the port, including Docker Desktop's wslrelay/backend
# listeners on Windows; the /dev/tcp connect probe is the python-less fallback.
phase6_port_in_use() {
    local port="$1"
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import socket, sys
s = socket.socket()
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(0)
finally:
    s.close()
sys.exit(1)' "$port"
        return $?
    fi
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null
}

phase6_check_ports_free() {
    local pair name port busy=0
    for pair in "$@"; do
        name="${pair%%=*}"
        port="${pair#*=}"
        if phase6_port_in_use "$port"; then
            echo "error: host port $port (for $name) is already bound by another process." >&2
            busy=1
        fi
    done
    if [ "$busy" = 1 ]; then
        echo "       An AlgoKit localnet uses 4001/4002 by default. Re-run with another base, e.g." >&2
        echo "       PHASE6_HOST_PORT_BASE=5000 (nodes are then published on 5001..5005)." >&2
        return 1
    fi
    return 0
}
