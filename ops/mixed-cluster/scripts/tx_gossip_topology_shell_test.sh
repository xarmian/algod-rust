#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Shell test for tx-gossip-topology.sh (issue #2280 follow-up). On a CI runner
# a repetition's cluster was gone (`docker compose down` had returned) while its
# published host ports were still bound for a moment, so the next repetition's
# start.sh refused to start ("host port 4001 already bound") and the dispatch
# run failed on repetitions 2 and 3. The script must therefore tear the cluster
# down after EVERY repetition, also when the check fails, and wait until the
# node ports are really free before the next start.
#
# No Docker: the script is copied next to stubs of start.sh / stop.sh /
# tx_gossip.py / topology.py, a fake `docker` and `curl`, and the "lingering"
# port is a python listener the stop stub leaves behind for a while.
#
#   bash ops/mixed-cluster/scripts/tx_gossip_topology_shell_test.sh

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILS=0
ok() { echo "ok   - $1"; }
bad() { echo "FAIL - $1"; FAILS=$((FAILS + 1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi; }

SC="$TMP/scripts"
BIN="$TMP/bin"
mkdir -p "$SC" "$BIN"
cp "$HERE/tx-gossip-topology.sh" "$HERE/ports.sh" "$SC/"
EVENTS="$TMP/events"

# A base whose node ports (base+1..base+4) are all free.
BASE="$(python3 - <<'PY' | tr -d '\r'
import random, socket
while True:
    base = random.randint(20000, 60000)
    socks = []
    try:
        for p in range(base + 1, base + 5):
            s = socket.socket(); s.bind(("127.0.0.1", p)); socks.append(s)
        break
    except OSError:
        pass
    finally:
        for s in socks:
            s.close()
print(base)
PY
)"
GO1_PORT=$((BASE + 1))

cat > "$SC/start.sh" <<'STUB'
#!/usr/bin/env bash
# bound = a node port still held when the cluster is started
bound=0
for p in $((PHASE6_HOST_PORT_BASE + 1)) $((PHASE6_HOST_PORT_BASE + 2)) $((PHASE6_HOST_PORT_BASE + 3)) $((PHASE6_HOST_PORT_BASE + 4)); do
    python3 -c 'import socket,sys
s=socket.socket()
try:
    s.bind(("127.0.0.1",int(sys.argv[1])))
except OSError:
    sys.exit(1)' "$p" || bound=1
done
echo "start bound=$bound" >> "$EVENTS"
exit 0
STUB
cat > "$SC/stop.sh" <<'STUB'
#!/usr/bin/env bash
echo "stop $*" >> "$EVENTS"
if [ "${LINGER_S:-0}" != 0 ]; then
    # the containers are gone but the published port is released only later
    python3 -c 'import socket,sys,time
s=socket.socket(); s.bind(("127.0.0.1",int(sys.argv[1]))); s.listen(1); time.sleep(float(sys.argv[2]))' \
        "$((PHASE6_HOST_PORT_BASE + 1))" "$LINGER_S" >/dev/null 2>&1 &
    sleep 0.3
fi
exit 0
STUB
cat > "$SC/tx_gossip.py" <<'STUB'
import json, os, sys
out = sys.argv[sys.argv.index("--out") + 1]
open(os.environ["EVENTS"], "a").write("gossip\n")
json.dump({"pass": os.environ.get("TXG_RC", "0") == "0"}, open(out, "w"))
sys.exit(int(os.environ.get("TXG_RC", "0")))
STUB
cat > "$SC/topology.py" <<'STUB'
import sys
print("topology ok")
sys.exit(0)
STUB
cat > "$BIN/docker" <<'STUB'
#!/usr/bin/env bash
echo "log of $2"
STUB
cat > "$BIN/curl" <<'STUB'
#!/usr/bin/env bash
echo '{"last-round": 99}'
STUB
chmod +x "$SC"/*.sh "$BIN/docker" "$BIN/curl"

run_script() {  # run_script <out dir> [env assignments...] -> exit code
    local out="$1"; shift
    ( export PATH="$BIN:$PATH" EVENTS PHASE6_HOST_PORT_BASE="$BASE" PHASE6_ENV_FILE="$TMP/none" \
        PHASE6_TOPOLOGY=rust-relay OUT_DIR="$out" WARMUP_ROUNDS=1 WARMUP_TIMEOUT_S=20 \
        PORTS_FREE_TIMEOUT_S=8 "$@"; bash "$SC/tx-gossip-topology.sh" >"$out.log" 2>&1 )
}

# 1. a clean repetition: started once, checked once, torn down at the end too
: > "$EVENTS"
run_script "$TMP/o1"; rc=$?
check "clean run exits 0" 0 "$rc"
check "clean run: start saw free ports" "start bound=0" "$(grep '^start' "$EVENTS")"
check "clean run: gossip ran once" 1 "$(grep -c '^gossip' "$EVENTS")"
check "clean run: stopped before the start and after the check" 2 "$(grep -c '^stop' "$EVENTS")"
check "clean run: the last event is a stop" "stop --purge" "$(tail -n 1 "$EVENTS")"

# 2. a failing check still tears the cluster down (EXIT trap) and fails the run
: > "$EVENTS"
run_script "$TMP/o2" TXG_RC=1; rc=$?
check "failing check exits non-zero" 1 "$rc"
check "failing check: the last event is a stop" "stop --purge" "$(tail -n 1 "$EVENTS")"

# 3. the cluster is gone but its port is released late (the CI failure): the
#    next start must wait for it instead of finding it bound
: > "$EVENTS"
run_script "$TMP/o3a" LINGER_S=2; rc1=$?
run_script "$TMP/o3b" LINGER_S=2; rc2=$?
check "lingering port: first repetition exits 0" 0 "$rc1"
check "lingering port: second repetition exits 0" 0 "$rc2"
check "lingering port: every start saw free ports" 0 "$(grep -c 'start bound=1' "$EVENTS")"
check "lingering port: both repetitions started" 2 "$(grep -c '^start' "$EVENTS")"

# 4. a port that never frees is reported (naming the port) instead of hanging
: > "$EVENTS"
run_script "$TMP/o4" LINGER_S=30 PORTS_FREE_TIMEOUT_S=2; rc=$?
check "stuck port: exits non-zero" 1 "$rc"
check "stuck port: the cluster is not started" 0 "$(grep -c '^start' "$EVENTS")"
check "stuck port: the message names the port" 1 "$([ "$(grep -c "$GO1_PORT" "$TMP/o4.log")" -ge 1 ] && echo 1 || echo 0)"

# 5. phase6_wait_ports_free itself
source "$SC/ports.sh"
PHASE6_HOST_PORT_BASE="$BASE" source "$SC/ports.sh"
P5="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()' | tr -d '')"
check "wait_ports_free returns at once when nothing is bound" 0 "$(phase6_wait_ports_free 3 "$P5" >/dev/null 2>&1; echo $?)"
python3 -c 'import socket,sys,time
s=socket.socket(); s.bind(("127.0.0.1",int(sys.argv[1]))); s.listen(1); time.sleep(30)' "$P5" &
LPID=$!
sleep 0.5
check "wait_ports_free times out on a held port" 1 "$(phase6_wait_ports_free 1 "$P5" >/dev/null 2>&1; echo $?)"
kill "$LPID" 2>/dev/null; wait "$LPID" 2>/dev/null
check "wait_ports_free sees the port freed" 0 "$(phase6_wait_ports_free 3 "$P5" >/dev/null 2>&1; echo $?)"

echo
if [ "$FAILS" -eq 0 ]; then echo "tx_gossip_topology_shell_test: all checks passed"; exit 0; fi
echo "tx_gossip_topology_shell_test: $FAILS check(s) FAILED" >&2
exit 1
