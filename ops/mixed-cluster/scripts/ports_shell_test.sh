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

# 3b. leading zeros are decimal (bash arithmetic would read 04000 as octal)
export PHASE6_HOST_PORT_BASE=04000
source "$HERE/ports.sh"
check "leading-zero base is decimal" 4001 "$PHASE6_GO1_PORT"
check "leading-zero base normalised" 4000 "$PHASE6_HOST_PORT_BASE"

# 3c. only a base from the environment is exported to children; a file-derived
# one is not, so a child start.sh after a purge does not inherit it
unset PHASE6_HOST_PORT_BASE
export PHASE6_ENV_FILE="$TMP/env"
source "$HERE/ports.sh"
check "file-derived base not exported" unset "$(bash -c 'echo "${PHASE6_HOST_PORT_BASE:-unset}"')"
check "per-node ports exported regardless" 6001 "$(bash -c 'echo "$PHASE6_GO1_PORT"')"
export PHASE6_HOST_PORT_BASE=7000
source "$HERE/ports.sh"
check "env base exported" 7000 "$(bash -c 'echo "${PHASE6_HOST_PORT_BASE:-unset}"')"

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

# 5b. an unusable python3 (the Windows Store alias stub exits 9009) must not
# turn the probe into "everything is free": the /dev/tcp probe takes over
mkdir -p "$TMP/stubbin"
printf '#!/usr/bin/env bash
exit 9009
' > "$TMP/stubbin/python3"
chmod +x "$TMP/stubbin/python3"
check "bound port detected without a working python3" 0     "$(PATH="$TMP/stubbin:$PATH" phase6_port_in_use "$BUSY"; echo $?)"
check "free port not flagged without a working python3" 1     "$(PATH="$TMP/stubbin:$PATH" phase6_port_in_use "$FREE"; echo $?)"

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

# 7. phase6_check_cluster_ports_free: the node's own container publishing the
# port exempts it; a container on another port, or none, means a real probe
mkdir -p "$TMP/fakedocker"
cat > "$TMP/fakedocker/docker" <<'EOF'
#!/usr/bin/env bash
# docker port phase6-<node> 8080 -> $FAKE_PORT_<node-with-dashes-as-underscores>
[ "$1" = "port" ] || exit 1
var="FAKE_PORT_${2#phase6-}"; var="${var//-/_}"
val="${!var:-}"
[ -n "$val" ] || exit 1
printf '127.0.0.1:%s\n[::]:%s\n' "$val" "$val"
EOF
chmod +x "$TMP/fakedocker/docker"
export PHASE6_HOST_PORT_BASE="$((BUSY - 2))"   # go-node-2 lands on the busy port
export PHASE6_ENV_FILE="$TMP/does-not-exist"
source "$HERE/ports.sh"
check "go-node-2 maps to the busy port" "$BUSY" "$PHASE6_GO2_PORT"
out="$(PATH="$TMP/fakedocker:$PATH" FAKE_PORT_go_node_2="$BUSY" phase6_check_cluster_ports_free go-node-2 2>&1)"
check "own container on that port is exempt" 0 "$?"
check "no output when exempt" "" "$out"
out="$(PATH="$TMP/fakedocker:$PATH" FAKE_PORT_go_node_2="$((BUSY + 1000))" phase6_check_cluster_ports_free go-node-2 2>&1)"
check "own container on another base does not mask the conflict" 1 "$?"
case "$out" in *"$BUSY"*go-node-2*) ok "conflict message names node and port" ;; *) bad "conflict message: $out" ;; esac
out="$(PATH="$TMP/fakedocker:$PATH" phase6_check_cluster_ports_free go-node-2 2>&1)"
check "no container -> probed -> conflict" 1 "$?"
check "unknown node fails" 1 "$(phase6_check_cluster_ports_free no-such-node 2>/dev/null; echo $?)"

echo
if [ "$FAILS" -eq 0 ]; then
    echo "all ports.sh checks passed"
else
    echo "$FAILS ports.sh check(s) FAILED"
    exit 1
fi
