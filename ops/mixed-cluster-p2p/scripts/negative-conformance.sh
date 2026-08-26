#!/usr/bin/env bash
# negative-conformance.sh — issue #597, the P2P-transport analogue of
# `ops/mixed-cluster/scripts/negative-conformance.sh` (issue #472).
#
# The WS-gossip harness's injector (`algo-agreement-fuzz`) speaks
# go-algorand's WS-gossip handshake/framing, which has no listener at all
# in this cluster — every go-algorand node here runs with `EnableP2P=true`
# (see ../docker-compose.yml), so AV/PP/VB agreement traffic travels
# exclusively over the raw `/algorand-ws/2.2.0` libp2p stream
# (`crates/node/algo-p2p/src/wsproto.rs`). Issue #597 added a second
# connection backend to the same injector
# (`crates/tools/algo-agreement-fuzz/src/inject_p2p.rs`, `--transport p2p`)
# that speaks that stream instead — this script is the live-cluster driver
# for it, reusing the exact same four fault cases and fault-construction
# logic as issue #472; only the transport differs.
#
# Cases (each sends exactly ONE message per run) — identical to issue #472:
#
#   1 bad-vrf-proof          a valid-shaped VRF proof that does not verify
#                            under the account's registered selection key.
#                            Go: "could not verify VRF Proof".
#   2 wrong-committee-weight an entirely honest credential for a (round,
#                            period, step) at which the account's real online
#                            stake wins ZERO committee seats.
#                            Go: "credential has weight 0".
#   3 wrong-ots-domain       signed by the correct one-time key over the
#                            correct body, under the wrong domain-separation
#                            prefix ("PL" instead of "VO").
#                            Go: "could not verify FS signature on vote".
#   4 malformed-proposal     a genuine proposal payload captured off the wire
#                            with exactly one block field corrupted.
#                            Go: rejects the payload, does not adopt it.
#
# All three vote cases must make Go reject the injector's stream — in P2P
# mode `network/p2pNetwork.go`'s `Disconnect`/`disconnect` both resets the
# `/algorand-ws/2.2.0` stream (`wsPeerConnP2P.CloseWithoutFlush` ->
# `stream.Reset()`) and tears down the whole libp2p connection
# (`n.service.ClosePeer`) — either way the injector's read side errors out,
# which `inject_p2p::inject_one_p2p` reports as `disconnected: true` — AND
# log the case-specific error through `agreement/trace.go`'s "malformed
# vote for (r, p, s)" line (agreement-level logging is transport-agnostic).
# The stream/connection reset alone is not attribution — an undecodable
# payload would also produce it — so both are required, exactly as in the
# WS-gossip script.
#
# Unlike the WS-gossip script, this one does NOT raise go-node-1's
# BaseLoggerDebugLevel + restart it for the malformed-proposal case: this
# harness's go nodes get a fresh, ephemeral libp2p PeerId on every restart
# by default (`P2PPersistPeerID` defaults to false — see
# `../go-algorand/network/p2p/peerID.go`), and go-node-2/go-node-3 are only
# ever told go-node-1's multiaddr once, at startup (see ../scripts/start.sh's
# chain-bootstrap comment) — restarting go-node-1 here would silently
# fragment the 3-node mesh instead of just raising a log level, which is a
# strictly worse trade than skipping the DEBUG-only corroboration. The
# `not-adopted` assertion (the network never committed the corrupted block)
# is the decisive check for that case regardless; see its `info`-level
# handling below.
#
# SAFETY: the injected identity is Wallet4 (rust-node-4's own participation
# key, read from netroot/Node4Rust/), but every injected vote is INVALID, so
# go-algorand discards it inside `unauthenticatedVote.verify` before it can
# reach the vote tracker — it can never be recorded as an equivocating vote.
# No valid vote is ever injected. Mirrors the WS-gossip script's own SAFETY
# note.
#
# Usage:
#   bash ops/mixed-cluster-p2p/scripts/negative-conformance.sh
#
# Env:
#   CASES              space-separated subset to run (default: all four)
#   SKIP_START=1       use an already-running cluster
#   KEEP_CLUSTER=1     do not tear the cluster down at the end
#   OBSERVE_SECS       seconds to wait for Go to reset the stream    (20)
#   CAPTURE_SECS       seconds to wait for a proposal to capture     (60)
#   HEALTH_ROUNDS      rounds the quorum must still advance after    (5)
#   HEALTH_TIMEOUT     wall-clock cap on that, seconds                (90)
#   ALGOD_TOKEN        algod API token
#   OUT_DIR            artifact directory
#
# Exit code 0 only if every requested case was rejected AND the cluster
# stayed healthy.

set -euo pipefail

# Under Git Bash, an argument that *looks* like a POSIX absolute path (e.g.
# the P2P multiaddr `/ip4/127.0.0.1/tcp/5161/p2p/<peerid>` passed to
# `--p2p-multiaddr` below) gets silently rewritten into a bogus Windows path
# before it ever reaches the injector .exe (a non-MSYS program) — the same
# mangling `start.sh` works around for its own multiaddr-bearing
# `docker compose` calls (issue #564). Export for the whole script so every
# invocation of the injector below is covered.
export MSYS_NO_PATHCONV=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"

CASES="${CASES:-bad-vrf-proof wrong-committee-weight wrong-ots-domain malformed-proposal}"
SKIP_START="${SKIP_START:-0}"
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"
OBSERVE_SECS="${OBSERVE_SECS:-20}"
CAPTURE_SECS="${CAPTURE_SECS:-60}"
HEALTH_ROUNDS="${HEALTH_ROUNDS:-5}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-90}"
ALGOD_TOKEN="${ALGOD_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"

RUN_ID="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$ROOT/negative-$RUN_ID}"
SUMMARY_JSON="${SUMMARY_JSON:-$OUT_DIR/negative-summary.json}"

TARGET_CONTAINER=p2pinterop-go-node-1
TARGET_REST=http://127.0.0.1:5001
GO_PORTS=(5001 5002 5003)

# Under Git Bash the shell hands out MSYS paths (/c/...) that neither the
# Windows `algo-agreement-fuzz.exe` nor a Windows python3 can open. Convert to
# a native path for anything handed to a non-MSYS program. Same idiom as
# ops/mixed-cluster/scripts/negative-conformance.sh.
host_path() {
    if [ -n "${MSYSTEM:-}" ]; then
        (cd "$1" 2>/dev/null && pwd -W) || echo "$1"
    else
        echo "$1"
    fi
}
host_file() {  # host_file <path whose directory exists>
    echo "$(host_path "$(dirname "$1")")/$(basename "$1")"
}

mkdir -p "$OUT_DIR"
OUT_DIR_HOST="$(host_path "$OUT_DIR")"
CHECKS_FILE="$OUT_DIR/.checks.tsv"
: > "$CHECKS_FILE"

record() {  # record <case> <name> <pass|fail|info> <detail>
    printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$CHECKS_FILE"
    case "$3" in
        pass) echo "    [PASS] $1/$2: $4" ;;
        info) echo "    [INFO] $1/$2: $4" ;;
        *)    echo "    [FAIL] $1/$2: $4" >&2 ;;
    esac
}

node_round() {  # node_round <port> -> integer or "unreachable"
    local body
    body="$(curl -sf --max-time 5 -H "X-Algo-API-Token: $ALGOD_TOKEN" \
        "http://127.0.0.1:$1/v2/status" 2>/dev/null || true)"
    [ -z "$body" ] && { echo "unreachable"; return; }
    printf '%s' "$body" | python3 -c "
import json, sys
try:
    v = json.load(sys.stdin).get('last-round')
    print(int(v) if v is not None else 'unreachable')
except Exception:
    print('unreachable')
" | tr -d '\r'
}

go_max_round() {
    local best=-1 r
    for p in "${GO_PORTS[@]}"; do
        r="$(node_round "$p")"
        [[ "$r" =~ ^[0-9]+$ ]] || continue
        [ "$r" -gt "$best" ] && best="$r"
    done
    echo "$best"
}

teardown() {
    if [ "$KEEP_CLUSTER" = "1" ]; then
        echo "==> KEEP_CLUSTER=1, leaving the cluster up"
        return
    fi
    if [ "$STARTED_CLUSTER" = "1" ]; then
        echo "==> tearing the cluster down"
        bash "$HERE/stop.sh" >/dev/null 2>&1 || true
    fi
}

STARTED_CLUSTER=0
trap teardown EXIT

# ── bring the cluster up ───────────────────────────────────────────────

if [ "$SKIP_START" != "1" ]; then
    echo "==> starting the P2P mixed cluster"
    bash "$HERE/start.sh" > "$OUT_DIR/start.log" 2>&1 || {
        echo "start.sh failed; see $OUT_DIR/start.log" >&2
        exit 1
    }
    STARTED_CLUSTER=1
fi

if [ ! -f "$ROOT/netroot/.p2pinterop-env" ]; then
    echo "could not read $ROOT/netroot/.p2pinterop-env — run start.sh first" >&2
    exit 1
fi
# shellcheck disable=SC1091
. "$ROOT/netroot/.p2pinterop-env"
GENESIS_ID="${P2PINTEROP_GENESIS_ID:-}"
if [ -z "$GENESIS_ID" ]; then
    echo "P2PINTEROP_GENESIS_ID not set by $ROOT/netroot/.p2pinterop-env" >&2
    exit 1
fi

MULTIADDR_FILE="$ROOT/netroot/.p2p-multiaddr-1"
if [ ! -f "$MULTIADDR_FILE" ]; then
    echo "could not read $MULTIADDR_FILE — run start.sh first" >&2
    exit 1
fi
TARGET_P2P_MULTIADDR="$(cat "$MULTIADDR_FILE" | tr -d '\r\n')"
if [ -z "$TARGET_P2P_MULTIADDR" ]; then
    echo "$MULTIADDR_FILE is empty" >&2
    exit 1
fi

PARTKEY="$(ls "$ROOT"/netroot/Node4Rust/"$GENESIS_ID"/*.partkey 2>/dev/null | head -1)"
if [ -z "$PARTKEY" ]; then
    echo "no participation key found under $ROOT/netroot/Node4Rust/$GENESIS_ID" >&2
    exit 1
fi
PARTKEY_HOST="$(host_file "$PARTKEY")"
echo "==> genesis=$GENESIS_ID partkey=$PARTKEY_HOST"
echo "==> target: $TARGET_CONTAINER  rest=$TARGET_REST  p2p=$TARGET_P2P_MULTIADDR"

echo "==> waiting for the Go quorum to produce rounds"
deadline=$(( $(date +%s) + 180 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    r="$(go_max_round)"
    [[ "$r" =~ ^[0-9]+$ ]] && [ "$r" -ge 2 ] && break
    sleep 2
done
[[ "$(go_max_round)" =~ ^[0-9]+$ ]] || { echo "cluster never reported a round" >&2; exit 1; }

# The injector binary — shared with ops/mixed-cluster/scripts/negative-conformance.sh,
# just invoked with --transport p2p below.
TOOLS_DIR="${TOOLS_DIR:-$REPO_ROOT/target/debug}"
FUZZ="$TOOLS_DIR/algo-agreement-fuzz"
[ -x "$FUZZ" ] || FUZZ="$TOOLS_DIR/algo-agreement-fuzz.exe"
if [ ! -x "$FUZZ" ]; then
    if command -v cargo >/dev/null 2>&1; then
        echo "==> building the injector"
        ( cd "$REPO_ROOT" && cargo build -p algo-agreement-fuzz ) > "$OUT_DIR/build.log" 2>&1 || {
            echo "cargo build -p algo-agreement-fuzz failed; see $OUT_DIR/build.log" >&2
            exit 1
        }
        FUZZ="$TOOLS_DIR/algo-agreement-fuzz"
        [ -x "$FUZZ" ] || FUZZ="$TOOLS_DIR/algo-agreement-fuzz.exe"
    fi
fi
[ -x "$FUZZ" ] || {
    echo "injector binary not found under $TOOLS_DIR — run 'cargo build -p algo-agreement-fuzz' first" >&2
    exit 1
}
echo "==> injector: $FUZZ --transport p2p"

# ── the expected go-algorand error text, per case ──────────────────────

expected_go_error() {
    case "$1" in
        bad-vrf-proof)          echo "could not verify VRF Proof" ;;
        wrong-committee-weight) echo "credential has weight 0" ;;
        wrong-ots-domain)       echo "could not verify FS signature on vote" ;;
        malformed-proposal)     echo "" ;;
        *) echo "" ;;
    esac
}

FAILED=0

run_case() {  # run_case <case>
    local case="$1"
    local since report log
    since="$(date +%s)"
    report="$OUT_DIR/$case.report.json"
    log="$OUT_DIR/$case.node.log"

    echo
    echo "==> case: $case"

    local before after
    before="$(go_max_round)"

    local rc=0
    "$FUZZ" \
        --case "$case" \
        --node "$TARGET_REST" \
        --token "$ALGOD_TOKEN" \
        --transport p2p \
        --p2p-multiaddr "$TARGET_P2P_MULTIADDR" \
        --genesis-id "$GENESIS_ID" \
        --partkey "$PARTKEY_HOST" \
        --observe-secs "$OBSERVE_SECS" \
        --capture-secs "$CAPTURE_SECS" \
        --out "$OUT_DIR_HOST/$case.report.json" > "$OUT_DIR/$case.injector.log" 2>&1 || rc=$?

    # Give the node a moment to flush its log after the reset.
    sleep 3
    docker logs --since "$since" "$TARGET_CONTAINER" > "$log" 2>&1 || true

    if [ ! -s "$report" ]; then
        record "$case" "injector" fail "injector produced no report (exit $rc); see $OUT_DIR/$case.injector.log"
        FAILED=1
        return
    fi
    record "$case" "injector" info "exit $rc, report $report"

    # Read the report through stdin: a Windows python3 under Git Bash cannot
    # open an MSYS path, but the shell can.
    report_field() {  # report_field <key>
        python3 -c "import json,sys;print(json.load(sys.stdin).get(sys.argv[1]))" "$1" \
            < "$report" | tr -d '\r'
    }

    local tag disconnected weight differing
    tag="$(report_field tag)"
    disconnected="$(report_field disconnected)"
    weight="$(report_field committee_weight)"
    differing="$(report_field differing_byte_count)"
    record "$case" "single-fault-diff" info "$differing byte(s) differ from the honest baseline; sortition weight $weight"

    # ── the case-specific go-algorand error text ───────────────────────
    local want; want="$(expected_go_error "$case")"
    if [ -n "$want" ]; then
        if grep -qF "$want" "$log"; then
            record "$case" "go-error-text" pass "node logged \"$want\""
        else
            record "$case" "go-error-text" fail "node never logged \"$want\" (see $log)"
            FAILED=1
        fi
        # ...and it must be the *vote* rejection path, not something else.
        if grep -Eq 'malformed vote for|malformed proposal for' "$log"; then
            record "$case" "go-reject-path" pass "rejected via the agreement vote path"
        else
            record "$case" "go-reject-path" fail "no 'malformed vote/proposal for' line (see $log)"
            FAILED=1
        fi
    fi

    # ── the stream/connection reset ─────────────────────────────────────
    if [ "$tag" = "AV" ]; then
        if [ "$disconnected" = "True" ]; then
            record "$case" "disconnected" pass "Go reset the injector's /algorand-ws/2.2.0 stream"
        else
            record "$case" "disconnected" fail \
                "Go did NOT reset the stream after a malformed vote — possible real conformance finding"
            FAILED=1
        fi
        # go-algorand's P2P disconnect path (network/p2pNetwork.go's
        # Disconnect/disconnect) does not emit the WS-only "disconnected:
        # BadData" line (that is WebsocketNetwork-specific), so this is
        # purely informational — never a failure — unlike the WS-gossip
        # script's equivalent check.
        if grep -qF "disconnected: BadData" "$log"; then
            record "$case" "bad-data" pass "node logged 'disconnected: BadData'"
        else
            record "$case" "bad-data" info "no 'disconnected: BadData' line (P2P disconnect path does not log it; see this script's header)"
        fi
    else
        # A malformed payload is answered with ignoreAction, not a
        # disconnect (agreement/player.go, payloadMalformed/payloadRejected),
        # so the decisive assertion is that the network never committed the
        # corrupted block. Unlike the WS-gossip script, this harness never
        # raises go-node-1's log level for this case (see this script's
        # header on why restarting it would fragment the P2P mesh), so the
        # corroborating "rejected block for ..." log line is not expected —
        # `not-adopted` alone is the assertion here.
        local adopted injected_digest
        adopted="$(report_field corrupted_block_adopted)"
        injected_digest="$(report_field injected_block_digest)"
        [ "$injected_digest" = "None" ] && injected_digest=""

        if [ "$adopted" = "False" ]; then
            record "$case" "not-adopted" pass "the corrupted block was never committed"
        else
            record "$case" "not-adopted" fail \
                "the network COMMITTED the corrupted block — genuine consensus-safety finding"
            FAILED=1
        fi

        if [ -n "$injected_digest" ] && grep -F "$injected_digest" "$log" | grep -qF "rejected block for"; then
            record "$case" "go-rejected-payload" pass \
                "node logged 'rejected block for' against our payload digest $injected_digest"
        else
            record "$case" "go-rejected-payload" info \
                "payload rejection is logged at DEBUG; log level was not raised (see this script's header), relying on not-adopted"
        fi
    fi

    # ── the node survived and kept going ───────────────────────────────
    local d=$(( $(date +%s) + HEALTH_TIMEOUT ))
    local ok=0
    while [ "$(date +%s)" -lt "$d" ]; do
        after="$(go_max_round)"
        if [[ "$after" =~ ^[0-9]+$ ]] && [ "$after" -ge $(( before + HEALTH_ROUNDS )) ]; then
            ok=1; break
        fi
        sleep 2
    done
    if [ "$ok" = "1" ]; then
        record "$case" "liveness" pass "quorum advanced $before -> $after"
    else
        record "$case" "liveness" fail "quorum did not advance $HEALTH_ROUNDS rounds within ${HEALTH_TIMEOUT}s"
        FAILED=1
    fi

    if grep -Eqi 'panic:|fatal error:' "$log"; then
        record "$case" "no-crash" fail "node log contains a panic"
        FAILED=1
    else
        record "$case" "no-crash" pass "no panic in the node log"
    fi
}

for case in $CASES; do
    run_case "$case"
done

# ── summary ────────────────────────────────────────────────────────────

# stdin/stdout only, so no MSYS path ever reaches python3.
SUMMARISE='
import json, sys
checks = []
for line in sys.stdin:
    parts = line.rstrip("\n").rstrip("\r").split("\t")
    if len(parts) == 4:
        checks.append(dict(case=parts[0], name=parts[1], status=parts[2], detail=parts[3]))
summary = {
    "issue": 597,
    "checks": checks,
    "failed": [c for c in checks if c["status"] == "fail"],
    "passed": sum(1 for c in checks if c["status"] == "pass"),
}
json.dump(summary, sys.stdout, indent=2)
'
python3 -c "$SUMMARISE" < "$CHECKS_FILE" > "$SUMMARY_JSON"

REPORT='
import json, sys
summary = json.load(sys.stdin)
print("")
print("%d check(s) passed, %d failed" % (summary["passed"], len(summary["failed"])))
for c in summary["failed"]:
    print("  FAIL %s/%s: %s" % (c["case"], c["name"], c["detail"]))
'
python3 -c "$REPORT" < "$SUMMARY_JSON"

echo "==> artifacts in $OUT_DIR"
exit "$FAILED"
