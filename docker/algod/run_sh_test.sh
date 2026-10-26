#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Docker-free test of the algod image's entrypoint and command wrappers
# (issue #1991). `algod`, `algocfg`, `diagcfg`, `goal`, `curl`, `kmd` are stubs
# that log their command line; run.sh is sourced and `exec_algod` replaced, so
# no process is started. Every environment variable and /etc/algorand file of
# go's docker/README.md is exercised.
#
#   bash docker/algod/run_sh_test.sh

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN="$HERE/run.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILS=0

ok() { echo "ok   - $1"; }
bad() { echo "FAIL - $1"; FAILS=$((FAILS + 1)); }
has() {  # has <name> <pattern> <file>
    if grep -qE -- "$2" "$3"; then ok "$1"; else bad "$1 (no match for '$2' in: $(tr '\n' '|' <"$3"))"; fi
}
hasnt() {
    if grep -qE -- "$2" "$3"; then bad "$1 (unexpected '$2' in: $(tr '\n' '|' <"$3"))"; else ok "$1"; fi
}

# ---- stub commands ---------------------------------------------------------
BIN="$TMP/bin"
mkdir -p "$BIN"
for cmd in algod algocfg diagcfg goal kmd; do
    cat >"$BIN/$cmd" <<'EOF'
#!/usr/bin/env bash
echo "$(basename "$0") $*" >>"$CALLS"
EOF
    chmod +x "$BIN/$cmd"
done
cat >"$BIN/curl" <<'EOF'
#!/usr/bin/env bash
echo "curl $*" >>"$CALLS"
# a canned response body for `curl URL` (no -o), like the catchpoint-label lookup
if [ -n "${CURL_BODY:-}" ]; then printf '%s' "$CURL_BODY"; fi
while [ $# -gt 0 ]; do
    if [ "$1" = "-o" ]; then echo downloaded >"$2"; fi
    shift
done
EOF
chmod +x "$BIN/curl"
export PATH="$BIN:$PATH"

# ---- one scenario ----------------------------------------------------------
CASE=0
new_case() {  # sets D (case dir), DATA, CALLS and a clean environment
    CASE=$((CASE + 1))
    D="$TMP/case$CASE"
    DATA="$D/data"
    mkdir -p "$DATA"
    CALLS="$D/calls.log"
    : >"$CALLS"
    export CALLS
    unset NETWORK PROFILE DEV_MODE START_KMD FAST_CATCHUP TOKEN ADMIN_TOKEN KMD_TOKEN \
        TELEMETRY_NAME TELEMETRY_URL NUM_ROUNDS GENESIS_ADDRESS PEER_ADDRESS GOSSIP_PORT \
        ALGOD_PORT KMD_PORT DEBUG CATCHPOINT CATCHPOINT_STATUS_URL CATCHPOINT_LABEL_TRIES CATCHUP_MIN CATCHUP_WAIT_TRIES CURL_BODY
    export ALGOD_ENTRYPOINT_TEST=1 ALGORAND_DATA="$DATA" ETC_DIR="$D/etc" \
        GENESIS_DIR="$D/genesis" CATCHUP_DELAY=0
    mkdir -p "$ETC_DIR" "$GENESIS_DIR/testnet" "$GENESIS_DIR/mainnet" "$GENESIS_DIR/fnet" "$GENESIS_DIR/voimain"
    echo '{"id":"testnet-genesis"}' >"$GENESIS_DIR/testnet/genesis.json"
    echo '{"id":"mainnet-genesis"}' >"$GENESIS_DIR/mainnet/genesis.json"
    echo '{"id":"fnet-genesis"}' >"$GENESIS_DIR/fnet/genesis.json"
    echo '{"id":"voimain-genesis"}' >"$GENESIS_DIR/voimain/genesis.json"
}

# run main in a subshell with exec_algod / start_kmd stubbed; output -> $D/out.log
run_main() {
    (
        set +u   # run.sh is written for plain `set -e`, like go's script
        # shellcheck disable=SC1090
        source "$RUN"
        exec_algod() { echo "algod $*" >>"$CALLS"; wait; }
        # like the real one, a no-op unless START_KMD=1
        start_kmd() { if [ "${START_KMD:-}" = "1" ]; then echo "start_kmd" >>"$CALLS"; fi; }
        main
    ) >"$D/out.log" 2>&1
    RC=$?
}

# ---- 1. an existing public data dir ------------------------------------------
new_case
echo '{"id":"x"}' >"$DATA/genesis.json"
run_main
has "existing dir: algod is started on stdout logging" '^algod -o$' "$CALLS"
has "existing dir: REST bound to 0.0.0.0:8080" '^algocfg set -p EndpointAddress -v 0.0.0.0:8080 -d \.$' "$CALLS"
has "existing dir: telemetry disabled without a logging.config" '^diagcfg telemetry disable$' "$CALLS"
hasnt "existing dir: no peers, no catchup, no kmd" '(algod -o -p|catchup|start_kmd)' "$CALLS"

# ---- 2. ALGOD_PORT, PEER_ADDRESS, GOSSIP_PORT, PROFILE ----------------------------
new_case
echo '{"id":"x"}' >"$DATA/genesis.json"
export ALGOD_PORT=9090 PEER_ADDRESS="1.2.3.4:4160;5.6.7.8:4160" GOSSIP_PORT=4161 PROFILE=participation
run_main
has "ALGOD_PORT sets EndpointAddress" '^algocfg set -p EndpointAddress -v 0.0.0.0:9090 -d \.$' "$CALLS"
has "the peers are announced on their own line" '^Using peer\(s\): 1\.2\.3\.4:4160;5\.6\.7\.8:4160$' "$D/out.log"
has "PEER_ADDRESS is handed to algod -p" '^algod -o -p 1.2.3.4:4160;5.6.7.8:4160$' "$CALLS"
has "GOSSIP_PORT sets NetAddress" '^algocfg set -p NetAddress -v 0.0.0.0:4161 -d \.$' "$CALLS"
has "GOSSIP_PORT enables networking" '^algocfg set -p DisableNetworking -v false -d \.$' "$CALLS"
has "GOSSIP_PORT raises the connection limit" '^algocfg set -p IncomingConnectionsLimit -v 1000 -d \.$' "$CALLS"
has "PROFILE is applied" "^algocfg profile set participation --yes -d $DATA\$" "$CALLS"

# ---- 3. token overrides -------------------------------------------------------------
new_case
echo '{"id":"x"}' >"$DATA/genesis.json"
export TOKEN=aaaa ADMIN_TOKEN=bbbb
run_main
[ "$(cat "$DATA/algod.token" 2>/dev/null)" = "aaaa" ] && ok "TOKEN written to algod.token" || bad "TOKEN not written"
# a token that echo would treat as an option or escape is stored verbatim
new_case
echo '{"id":"x"}' >"$DATA/genesis.json"
export TOKEN='-n\tx'
run_main
[ "$(cat "$DATA/algod.token" 2>/dev/null)" = '-n\tx' ] && ok "an echo-hostile TOKEN is stored verbatim" || bad "TOKEN mangled: $(cat "$DATA/algod.token" 2>/dev/null)"
new_case
echo '{"id":"x"}' >"$DATA/genesis.json"
export TOKEN=aaaa ADMIN_TOKEN=bbbb
run_main
[ "$(cat "$DATA/algod.admin.token" 2>/dev/null)" = "bbbb" ] && ok "ADMIN_TOKEN written to algod.admin.token" || bad "ADMIN_TOKEN not written"

# ---- 4. /etc/algorand overrides -----------------------------------------------------
new_case
echo '{"id":"x"}' >"$DATA/genesis.json"
echo '{"GossipFanout": 3}' >"$ETC_DIR/config.json"
echo mytoken >"$ETC_DIR/algod.token"
echo myadmin >"$ETC_DIR/algod.admin.token"
echo '{}' >"$ETC_DIR/logging.config"
run_main
[ "$(cat "$DATA/config.json")" = '{"GossipFanout": 3}' ] && ok "/etc/algorand/config.json copied" || bad "config.json not copied"
[ "$(cat "$DATA/algod.token")" = "mytoken" ] && ok "/etc/algorand/algod.token copied" || bad "algod.token not copied"
[ "$(cat "$DATA/algod.admin.token")" = "myadmin" ] && ok "/etc/algorand/algod.admin.token copied" || bad "admin token not copied"
[ -f "$DATA/logging.config" ] && ok "/etc/algorand/logging.config copied" || bad "logging.config not copied"
hasnt "a provided logging.config keeps telemetry untouched" '^diagcfg telemetry disable$' "$CALLS"

# ---- 5. a new public network ----------------------------------------------------------
new_case
export NETWORK=testnet FAST_CATCHUP=1
run_main
[ "$(cat "$DATA/genesis.json")" = '{"id":"testnet-genesis"}' ] && ok "NETWORK installs that network's genesis.json" || bad "genesis.json not installed"
has "FAST_CATCHUP starts a forced catchup" '^goal node catchup --force --min 1000000$' "$CALLS"
has "a new network is started" '^algod -o$' "$CALLS"

# ---- 5b. Voi mainnet (issue #2074): the label comes from the network's REST gateway ---
new_case
export NETWORK=voimain FAST_CATCHUP=1 CATCHUP_WAIT_TRIES=1
export CURL_BODY='{"catchup-time":0,"last-catchpoint":"23900000#KFAWCWWDOOSID3YYDJZOWIYYVW2KEKLMVPF5BHBLY6CFRCARJFMA","last-round":5}'
run_main
[ "$(cat "$DATA/genesis.json")" = '{"id":"voimain-genesis"}' ] && ok "voimain installs its genesis.json" || bad "voimain genesis not installed"
has "voimain asks the Voi gateway for the last catchpoint" '^curl .*https://mainnet-api\.voi\.nodely\.dev/v2/status' "$CALLS"
has "voimain catches up to the gateway's last-catchpoint" '^goal node catchup --force --min 1000000 23900000#KFAWCWWDOOSID3YYDJZOWIYYVW2KEKLMVPF5BHBLY6CFRCARJFMA$' "$CALLS"
hasnt "voimain does not override the preset's DNS bootstrap" 'DNSBootstrapID' "$CALLS"
has "voimain node is started" '^algod -o$' "$CALLS"

new_case
export NETWORK=voimain FAST_CATCHUP=1 CATCHPOINT='24000000#ABC' CATCHUP_MIN=500 CATCHPOINT_STATUS_URL=
run_main
has "CATCHPOINT overrides the lookup (and CATCHUP_MIN applies)" '^goal node catchup --force --min 500 24000000#ABC$' "$CALLS"
hasnt "CATCHPOINT skips the gateway request" '^curl .*v2/status' "$CALLS"

new_case
export NETWORK=voimain FAST_CATCHUP=1 CATCHPOINT_STATUS_URL=http://gw.example/v2/status CATCHPOINT_LABEL_TRIES=2
export CURL_BODY='{"last-round":5}'
run_main
has "CATCHPOINT_STATUS_URL overrides the gateway" '^curl .*http://gw\.example/v2/status' "$CALLS"
hasnt "no catchpoint advertised: no catchup is attempted" '^goal node catchup' "$CALLS"
has "no catchpoint advertised: the node still starts and says why" 'no catchpoint label' "$D/out.log"
has "no catchpoint advertised: node is started" '^algod -o$' "$CALLS"

new_case
export NETWORK=voimain PEER_ADDRESS="9.9.9.9:5011"
run_main
hasnt "PEER_ADDRESS on voimain keeps the preset DNS bootstrap" 'DNSBootstrapID' "$CALLS"
has "PEER_ADDRESS on voimain is handed to algod -p" '^algod -o -p 9.9.9.9:5011$' "$CALLS"

new_case
export NETWORK=mainnet PEER_ADDRESS="9.9.9.9:4160"
run_main
has "PEER_ADDRESS on mainnet sets the DNS bootstrap" '^algocfg set -p DNSBootstrapID -v <network>\.algorand\.network -d ' "$CALLS"

new_case
export NETWORK=fnet
run_main
has "fnet sets its own DNS bootstrap" '^algocfg set -p DNSBootstrapID -v <network>\.algorand\.tech -d ' "$CALLS"

new_case
export NETWORK=nope
run_main
[ "$RC" = 1 ] && ok "unknown network exits 1" || bad "unknown network exit code $RC"
has "unknown network says so" "No genesis file for 'nope' is available\." "$D/out.log"

new_case
export NETWORK=testnet GENESIS_ADDRESS="http://peer:8080"
run_main
has "GENESIS_ADDRESS downloads the genesis from the peer" '^curl -fsS http://peer:8080/genesis -o genesis\.json$' "$CALLS"
[ "$(cat "$DATA/genesis.json")" = "downloaded" ] && ok "downloaded genesis is used" || bad "downloaded genesis not used"

# a failed download leaves no genesis.json behind and exits 1
new_case
export NETWORK=testnet GENESIS_ADDRESS="http://peer:8080"
cat >"$BIN/curl" <<'EOF2'
#!/usr/bin/env bash
echo "curl $*" >>"$CALLS"
# a canned response body for `curl URL` (no -o), like the catchpoint-label lookup
if [ -n "${CURL_BODY:-}" ]; then printf '%s' "$CURL_BODY"; fi
while [ $# -gt 0 ]; do
    if [ "$1" = "-o" ]; then echo "<html>404</html>" >"$2"; fi
    shift
done
exit 22
EOF2
run_main
[ "$RC" = 1 ] && ok "a failed genesis download exits 1" || bad "failed download exit code $RC"
[ ! -e "$DATA/genesis.json" ] && ok "a failed download leaves no genesis.json" || bad "error page kept as genesis.json"
has "a failed download says so" 'Unable to download the genesis file from http://peer:8080' "$D/out.log"
# restore the working stub
cat >"$BIN/curl" <<'EOF2'
#!/usr/bin/env bash
echo "curl $*" >>"$CALLS"
# a canned response body for `curl URL` (no -o), like the catchpoint-label lookup
if [ -n "${CURL_BODY:-}" ]; then printf '%s' "$CURL_BODY"; fi
while [ $# -gt 0 ]; do
    if [ "$1" = "-o" ]; then echo downloaded >"$2"; fi
    shift
done
EOF2

# ---- 6. telemetry options are accepted --------------------------------------------------
new_case
echo '{"id":"x"}' >"$DATA/genesis.json"
export TELEMETRY_NAME=node1 TELEMETRY_URL=https://t.example
run_main
has "TELEMETRY_NAME warns that it is ignored" 'TELEMETRY_NAME is accepted but ignored' "$D/out.log"
has "TELEMETRY_NAME is passed to diagcfg" "^diagcfg telemetry name -n node1 -d $DATA\$" "$CALLS"
has "TELEMETRY_URL is passed to diagcfg" "^diagcfg telemetry endpoint -e https://t\.example -d $DATA\$" "$CALLS"
has "telemetry is enabled" "^diagcfg telemetry enable -d $DATA\$" "$CALLS"

# ---- 7. kmd ---------------------------------------------------------------------------------------
new_case
echo '{"id":"x"}' >"$DATA/genesis.json"
export START_KMD=1 KMD_TOKEN=kmdtok KMD_PORT=7000
run_main
has "START_KMD starts kmd in the background" '^start_kmd$' "$CALLS"
[ -d "$DATA/kmd-v0.5" ] && ok "kmd data dir created" || bad "kmd data dir missing"
case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*) ok "kmd data dir mode (skipped: no POSIX modes on this filesystem)" ;;
    *) [ "$(stat -c %a "$DATA/kmd-v0.5")" = 700 ] && ok "kmd data dir is 0700" || bad "kmd data dir mode" ;;
esac
has "kmd_config.json binds KMD_PORT" '0\.0\.0\.0:7000' "$DATA/kmd-v0.5/kmd_config.json"
[ "$(cat "$DATA/kmd-v0.5/kmd.token")" = "kmdtok" ] && ok "KMD_TOKEN written" || bad "KMD_TOKEN not written"

new_case
echo '{"id":"x"}' >"$DATA/genesis.json"
(
    set +u
    export START_KMD=1 KMD_PORT=7833
    # shellcheck disable=SC1090
    source "$RUN"
    start_kmd
) >/dev/null 2>&1
has "start_kmd runs kmd serve on KMD_PORT" "^kmd serve -d $DATA/kmd-v0\.5 -a 0\.0\.0\.0:7833 --allow-origin \*\$" "$CALLS"

# ---- 6b. catchup waits for the node and retries ---------------------------------------------------
# algod-rust resolves its peers before its REST API answers (go's answers at
# once): the forced catchup must not be fired at a node that is still starting
new_case
(
    set +u
    export CATCHUP_DELAY=0 CATCHUP_WAIT_SLEEP=0
    # shellcheck disable=SC1090
    source "$RUN"
    N=0; C=0
    goal() {
        echo "goal $*" >>"$CALLS"
        case "$2" in
        status) N=$((N + 1)); [ "$N" -ge 4 ] ;;                  # answers from the 4th probe on
        catchup) C=$((C + 1)); [ "$C" -ge 3 ] ;;                 # refused twice, then accepted
        esac
    }
    catchup
) >/dev/null 2>&1
rc=$?
[ "$rc" = 0 ] && ok "catchup succeeds once the node answers" || bad "catchup exit code $rc"
[ "$(grep -c '^goal node status' "$CALLS")" = 4 ] && ok "catchup waits for the node (4 status probes)" || bad "status probes: $(grep -c '^goal node status' "$CALLS")"
[ "$(grep -c '^goal node catchup' "$CALLS")" = 3 ] && ok "a refused catchup is retried" || bad "catchup attempts: $(grep -c '^goal node catchup' "$CALLS")"
first_catchup=$(grep -n '^goal node catchup' "$CALLS" | head -1 | cut -d: -f1)
last_status=$(grep -n '^goal node status' "$CALLS" | tail -1 | cut -d: -f1)
[ "$first_catchup" -gt "$last_status" ] && ok "no catchup before the node answered" || bad "catchup fired before the node answered"

# ---- 7b. secrets never reach the log ----------------------------------------------------------
new_case
echo '{"id":"x"}' >"$DATA/genesis.json"
export TOKEN=supersecrettoken ADMIN_TOKEN=supersecretadmin KMD_TOKEN=supersecretkmd
run_main
hasnt "no token value in the startup banner" 'supersecret' "$D/out.log"
has "the banner says the tokens are set" 'TOKEN:           Set' "$D/out.log"
has "ADMIN_TOKEN is reported as set" 'ADMIN_TOKEN:     Set' "$D/out.log"
new_case
echo '{"id":"x"}' >"$DATA/genesis.json"
run_main
has "unset tokens read Not Set" 'TOKEN:           Not Set' "$D/out.log"

# ---- 7c. PEER_ADDRESS without NETWORK or GENESIS_ADDRESS ----------------------------------------
new_case
export PEER_ADDRESS="1.2.3.4:4160"
run_main
[ "$RC" = 1 ] && ok "PEER_ADDRESS alone exits 1" || bad "PEER_ADDRESS alone exit code $RC"
has "PEER_ADDRESS alone gets go's message, not a cp error" "No genesis file for '' is available\." "$D/out.log"

# ---- 8. private networks -------------------------------------------------------------------
# (the real follow_private_network tails logs until told to stop; it has its own
# test below, so here it is replaced by a recorder)
run_private() {
    (
        set +u
        # shellcheck disable=SC1090
        source "$RUN"
        exec_algod() { echo "algod $*" >>"$CALLS"; }
        start_kmd() { if [ "${START_KMD:-}" = "1" ]; then echo "start_kmd" >>"$CALLS"; fi; }
        follow_private_network() { echo "follow" >>"$CALLS"; }
        main
    ) >"$D/out.log" 2>&1
    RC=$?
}
new_private_case() {
    new_case
    export RUN_DIR="$D/run"
    mkdir -p "$RUN_DIR"
    cp "$HERE"/templates/*.json "$RUN_DIR/"
}

new_private_case
run_private
has "private: the network is created in the parent of the data dir" "^goal network create --noclean -n dockernet -r $DATA/\.\. -t $RUN_DIR/template\.json\$" "$CALLS"
has "private: the network is then started" "^goal network start -r $DATA/\.\.\$" "$CALLS"
has "private: and followed" '^follow$' "$CALLS"
hasnt "private: NUM_ROUNDS placeholder is replaced (default 30000)" 'NUM_ROUNDS' "$RUN_DIR/template.json"
has "private: default NUM_ROUNDS is 30000" '"LastPartKeyRound": *30000' "$RUN_DIR/template.json"
hasnt "private: no pregenerated keys" 'template\.json -p ' "$CALLS"

new_private_case
export DEV_MODE=1 NUM_ROUNDS=77
run_private
has "DEV_MODE uses the devmode template" "-t $RUN_DIR/devmode_template\.json\$" "$CALLS"
has "NUM_ROUNDS fills the template" '"LastPartKeyRound": *77' "$RUN_DIR/devmode_template.json"

new_private_case
echo '{"Genesis":{"LastPartKeyRound": NUM_ROUNDS}}' >"$ETC_DIR/template.json"
export DEV_MODE=1
run_private
has "a mounted template wins over DEV_MODE" "-t $RUN_DIR/template\.json\$" "$CALLS"
has "the mounted template is the one used" '"LastPartKeyRound": 30000' "$RUN_DIR/template.json"

new_private_case
mkdir -p "$ETC_DIR/keys"
echo k >"$ETC_DIR/keys/Wallet1.rootkey"
run_private
has "mounted keys are passed as the pregen dir" "-t $RUN_DIR/template\.json -p $RUN_DIR/keys\$" "$CALLS"
[ -f "$RUN_DIR/keys/Wallet1.rootkey" ] && ok "mounted keys are copied" || bad "mounted keys not copied"

new_private_case
export START_KMD=1 TOKEN=privtok
run_private
has "private: START_KMD starts kmd" '^start_kmd$' "$CALLS"
has "private: configure_data_dir ran (REST on all interfaces)" '^algocfg set -p EndpointAddress -v 0\.0\.0\.0:8080 -d \.$' "$CALLS"

# an existing private network is only started
new_private_case
echo '{}' >"$D/network.json"
run_private
hasnt "existing network: no create" 'goal network create' "$CALLS"
has "existing network: started" "^goal network start -r $DATA/\.\.\$" "$CALLS"
[ "$RC" = 1 ] && ok "existing network: exit 1 if it ever returns" || bad "exit code $RC"

# SIGTERM stops the network (docker stop) and exits 0
new_private_case
(
    set +u
    # shellcheck disable=SC1090
    source "$RUN"
    follow_private_network
) >"$D/out.log" 2>&1 &
FOLLOW=$!
for _ in $(seq 1 50); do sleep 0.1; kill -0 "$FOLLOW" 2>/dev/null || break; [ -s "$CALLS" ] && break; kill -0 "$FOLLOW" 2>/dev/null && break; done
sleep 0.5
kill -TERM "$FOLLOW"
wait "$FOLLOW"; rc=$?
[ "$rc" = 0 ] && ok "SIGTERM exits 0" || bad "SIGTERM exit code $rc"
has "SIGTERM stops the network" "^goal network stop -r $DATA/\.\.\$" "$CALLS"

# SIGTERM *during* startup (issue #2018): the entrypoint is PID 1 in the container,
# where a signal without a handler is dropped, so a `docker stop` that lands while
# `goal network start` is still running must already be handled
new_private_case
echo '{}' >"$D/network.json"
(
    set +u
    # shellcheck disable=SC1090
    source "$RUN"
    goal() {
        echo "goal $*" >>"$CALLS"
        if [ "$2" = start ]; then sleep 2; fi
    }
    start_kmd() { :; }
    main
) >"$D/out.log" 2>&1 &
STARTING=$!
sleep 0.5
kill -TERM "$STARTING"
t0=$SECONDS
wait "$STARTING"; rc=$?
took=$((SECONDS - t0))
[ "$rc" = 0 ] && ok "SIGTERM during startup exits 0" || bad "SIGTERM during startup: exit code $rc"
[ "$took" -le 4 ] && ok "SIGTERM during startup is handled promptly (${took}s)" || bad "SIGTERM during startup took ${took}s"
has "SIGTERM during startup stops the network" "^goal network stop -r $DATA/\.\.\$" "$CALLS"

# ---- 9. ALGORAND_DATA may not be overridden -------------------------------------------------------
out="$(env -u ALGOD_ENTRYPOINT_TEST ALGORAND_DATA=/tmp/elsewhere bash "$RUN" 2>&1)"; rc=$?
[ "$rc" = 1 ] && echo "$out" | grep -q "Do not override 'ALGORAND_DATA'" && ok "ALGORAND_DATA override is refused" || bad "ALGORAND_DATA override: rc=$rc out=$out"

# ---- 10. command wrappers ---------------------------------------------------------------------------
W="$HERE/bin"
WBIN="$TMP/wbin"
mkdir -p "$WBIN"
for cmd in algod-rust goal-rust algokey-rust kmd-rust; do
    cat >"$WBIN/$cmd" <<'EOF'
#!/usr/bin/env bash
echo "$(basename "$0") $*" >>"$CALLS"
EOF
    chmod +x "$WBIN/$cmd"
done
new_case
(
    export PATH="$WBIN:/usr/bin:/bin"
    bash "$W/algocfg" -d . set -p NetAddress -v :4161
    bash "$W/algocfg" set -p NetAddress -v :4161 -d .
    bash "$W/algocfg" get -p NetAddress
    bash "$W/algod" -d /algod/data -o
    bash "$W/goal" node status
    bash "$W/algokey" generate
    bash "$W/kmd" -d /k -t 0
    bash "$W/kmd" serve -d /k
    bash "$W/diagcfg" telemetry disable
    echo "diagcfg-exit $?" >>"$CALLS"
)
has "algocfg moves a leading -d behind the sub-command" '^algod-rust algocfg set -p NetAddress -v :4161 -d \.$' "$CALLS"
[ "$(grep -c '^algod-rust algocfg set -p NetAddress -v :4161 -d \.$' "$CALLS")" = 2 ] && ok "algocfg with -d last is unchanged" || bad "algocfg -d placement"
has "algocfg without -d passes through" '^algod-rust algocfg get -p NetAddress$' "$CALLS"
has "algod is algod-rust algod" '^algod-rust algod -d /algod/data -o$' "$CALLS"
has "goal is goal-rust" '^goal-rust node status$' "$CALLS"
has "algokey is algokey-rust" '^algokey-rust generate$' "$CALLS"
has "kmd -d gets serve put in front" '^kmd-rust serve -d /k -t 0$' "$CALLS"
has "kmd serve is passed through" '^kmd-rust serve -d /k$' "$CALLS"
has "diagcfg is a successful no-op" '^diagcfg-exit 0$' "$CALLS"

if [ "$FAILS" -ne 0 ]; then
    echo "$FAILS check(s) failed"
    exit 1
fi
echo "all algod image entrypoint checks passed"
