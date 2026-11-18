#!/usr/bin/env bash

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# negative-conformance.sh — issue #472 (Epic 42e) negative Layer-9 conformance.
#
# The positive suite (#470) proves a Go quorum ACCEPTS the Rust node's valid
# agreement messages. This one proves the converse: go-algorand REJECTS a
# Rust-constructed agreement message that carries exactly one injected fault,
# stays up, and keeps making rounds.
#
# Cases (each sends exactly ONE message per run):
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
#   5 unknown-field-proposal a genuine proposal payload with ONE unknown key
#                            added (to its first transaction, else the top
#                            level); the block itself is untouched (issue
#                            #2394). go's generated msgp decoder fails with
#                            ErrNoField and drops the payload: "dropping
#                            proposal that failed to decode: Unknown field: zzunk".
#                            Opt-in (CASES=unknown-field-proposal): the
#                            honest copy is what the network commits, so the
#                            evidence is that log line plus liveness.
#   6 unknown-field-proposal-rust
#                            the same payload injected into the ALGOD-RUST
#                            node (issue #2398): captured off go-node-1, sent
#                            to rust-node-4's inbound WS-gossip listener
#                            (container 4162, published on 127.0.0.1:
#                            PHASE6_RUST_GOSSIP_PORT). algod-rust's demux must
#                            log "dropping proposal that failed to decode: ...
#                            with key zzunk", keep the injector connected (go
#                            does not disconnect either, #2431), commit the
#                            same block as go at that round and keep making
#                            rounds. Opt-in (CASES=unknown-field-proposal-rust).
#
# Both unknown-field cases also require algod-rust's own decoder to refuse the
# bytes for the unknown key itself, not a msgp allocbound (#2427) or a repeated
# key (#2424): the injector records that error in the report
# (`rust_decode_error`), see unknown_field_proposal.sh.
#
# All three vote cases must make Go disconnect the injector with `BadData`
# (agreement/player.go `voteMalformed` -> disconnectAction -> wsNetwork
# `disconnectBadData`, network/wsPeer.go:141) AND log the case-specific error
# through `agreement/trace.go`'s "malformed vote for (r, p, s)" line. The
# disconnect alone is not attribution — an undecodable payload would also
# produce it — so both are required.
#
# SAFETY: the injected identity is Wallet4, the algod-rust node's own account,
# but every injected vote is INVALID, so go-algorand discards it inside
# `unauthenticatedVote.verify` before it can reach the vote tracker. It can
# therefore never be recorded as an equivocating vote. No valid vote is ever
# injected, and only go-node-1's gossip port is published to the host
# (plus rust-node-4's, which only ever receives the unknown-field proposal).
#
# Usage:
#   bash ops/mixed-cluster/scripts/negative-conformance.sh
#   make consensus-cluster-negative
#
# Env:
#   CASES              space-separated subset to run (default: all four)
#   SKIP_START=1       use an already-running cluster
#   KEEP_CLUSTER=1     do not tear the cluster down at the end
#   OBSERVE_SECS       seconds to wait for Go to disconnect us      (20)
#   CAPTURE_SECS       seconds to wait for a proposal to capture    (60)
#   HEALTH_ROUNDS      rounds the quorum must still advance after   (5)
#   HEALTH_TIMEOUT     wall-clock cap on that, seconds              (90)
#   PHASE6_RUST_GOSSIP_PORT  host port of rust-node-4's WS-gossip listener (4162)
#   ALGOD_TOKEN        algod API token
#   OUT_DIR            artifact directory
#
# Exit code 0 only if every requested case was rejected AND the cluster stayed
# healthy.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ports.sh
source "$HERE/ports.sh"  # PHASE6_HOST_PORT_BASE -> PHASE6_*_PORT (issue #1956)
# shellcheck source=unknown_field_proposal.sh
source "$HERE/unknown_field_proposal.sh"  # ufp_* checks (issues #2394, #2398)
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

TARGET_CONTAINER=phase6-go-node-1
TARGET_REST="http://127.0.0.1:$PHASE6_GO1_PORT"
TARGET_GOSSIP=127.0.0.1:4161
RUST_CONTAINER=phase6-rust-node-4
RUST_GOSSIP="127.0.0.1:${PHASE6_RUST_GOSSIP_PORT:-4162}"
GO_PORTS=("$PHASE6_GO1_PORT" "$PHASE6_GO2_PORT" "$PHASE6_GO3_PORT")

# Under Git Bash the shell hands out MSYS paths (/c/...) that neither the
# Windows `algo-agreement-fuzz.exe` nor a Windows python3 can open. Convert to
# a native path for anything handed to a non-MSYS program. Same idiom as
# start.sh / consensus-conformance.sh.
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

block_hash() {  # block_hash <port> <round> -> base32 block hash or ""
    curl -sf --max-time 5 -H "X-Algo-API-Token: $ALGOD_TOKEN" \
        "http://127.0.0.1:$1/v2/blocks/$2/hash" 2>/dev/null | python3 -c "
import json, sys
try:
    print(json.load(sys.stdin).get('blockHash') or '')
except Exception:
    print('')
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
    echo "==> starting the mixed cluster"
    bash "$HERE/start.sh" > "$OUT_DIR/start.log" 2>&1 || {
        echo "start.sh failed; see $OUT_DIR/start.log" >&2
        exit 1
    }
    STARTED_CLUSTER=1
fi

GENESIS_ID="$(cat "$ROOT/netroot/.phase6-genesis-id" 2>/dev/null | tr -d '\r\n')"
if [ -z "$GENESIS_ID" ]; then
    echo "could not read $ROOT/netroot/.phase6-genesis-id" >&2
    exit 1
fi
PARTKEY="$(ls "$ROOT"/netroot/Node4Rust/"$GENESIS_ID"/*.partkey 2>/dev/null | head -1)"
if [ -z "$PARTKEY" ]; then
    echo "no participation key found under $ROOT/netroot/Node4Rust/$GENESIS_ID" >&2
    exit 1
fi
PARTKEY_HOST="$(host_file "$PARTKEY")"
echo "==> genesis=$GENESIS_ID partkey=$PARTKEY_HOST"

echo "==> waiting for the Go quorum to produce rounds"
deadline=$(( $(date +%s) + 180 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    r="$(go_max_round)"
    [[ "$r" =~ ^[0-9]+$ ]] && [ "$r" -ge 2 ] && break
    sleep 2
done
[[ "$(go_max_round)" =~ ^[0-9]+$ ]] || { echo "cluster never reported a round" >&2; exit 1; }

# The injector binary. `make consensus-cluster-negative` builds it first; when the
# script is run directly we build it here, but only if cargo is actually on
# PATH (it is not, under Git Bash on the Windows dev boxes this harness also
# targets — see CLAUDE.md).
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
echo "==> injector: $FUZZ"

# ── the expected go-algorand error text, per case ──────────────────────

expected_go_error() {
    case "$1" in
        bad-vrf-proof)          echo "could not verify VRF Proof" ;;
        wrong-committee-weight) echo "credential has weight 0" ;;
        wrong-ots-domain)       echo "could not verify FS signature on vote" ;;
        malformed-proposal)     echo "" ;;
        unknown-field-proposal) echo "" ;;
        unknown-field-proposal-rust) echo "" ;;
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

    # A rejected proposal payload is answered with `ignoreAction`, and the
    # tracer logs it at DEBUG (agreement/trace.go:327), so raise go-node-1's
    # log level for the payload case only. The other two Go nodes are
    # untouched, so the quorum keeps cadence across the restart.
    local raised=0
    if [ "$case" = "malformed-proposal" ]; then
        if docker exec "$TARGET_CONTAINER" sh -c 'algocfg -d /algod/data set -p BaseLoggerDebugLevel -v 5' >/dev/null 2>&1 \
            && docker restart "$TARGET_CONTAINER" >/dev/null 2>&1; then
            raised=1
            local wd=$(( $(date +%s) + 90 ))
            while [ "$(date +%s)" -lt "$wd" ]; do
                [[ "$(node_round "$PHASE6_GO1_PORT")" =~ ^[0-9]+$ ]] && break
                sleep 2
            done
            since="$(date +%s)"
            record "$case" "debug-logging" info "raised BaseLoggerDebugLevel on $TARGET_CONTAINER"
        fi
    fi

    local rc=0
    # unknown-field-proposal is the injector's malformed-proposal case with the
    # `unknown-field` fault (issue #2394)
    local inject_case="$case" inject_extra=() gossip="$TARGET_GOSSIP" container="$TARGET_CONTAINER"
    if [ "$case" = "unknown-field-proposal" ]; then
        inject_case="malformed-proposal"
        inject_extra=(--proposal-fault unknown-field)
    elif [ "$case" = "unknown-field-proposal-rust" ]; then
        # captured off go-node-1, injected into the Rust node's own listener
        # (issue #2398)
        inject_case="malformed-proposal"
        inject_extra=(--proposal-fault unknown-field --capture-gossip "$TARGET_GOSSIP")
        gossip="$RUST_GOSSIP"
        container="$RUST_CONTAINER"
    fi
    local rust_before; rust_before="$(node_round "$PHASE6_RUST_PORT")"
    "$FUZZ" \
        --case "$inject_case" \
        ${inject_extra[@]+"${inject_extra[@]}"} \
        --node "$TARGET_REST" \
        --token "$ALGOD_TOKEN" \
        --gossip "$gossip" \
        --genesis-id "$GENESIS_ID" \
        --partkey "$PARTKEY_HOST" \
        --observe-secs "$OBSERVE_SECS" \
        --capture-secs "$CAPTURE_SECS" \
        --out "$OUT_DIR_HOST/$case.report.json" > "$OUT_DIR/$case.injector.log" 2>&1 || rc=$?

    # Give the node a moment to flush its log after the disconnect.
    sleep 3
    docker logs --since "$since" "$container" > "$log" 2>&1 || true

    if [ "$raised" = "1" ]; then
        docker exec "$TARGET_CONTAINER" sh -c 'algocfg -d /algod/data set -p BaseLoggerDebugLevel -v 4' >/dev/null 2>&1 || true
        docker restart "$TARGET_CONTAINER" >/dev/null 2>&1 || true
    fi

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

    # ── the disconnect ─────────────────────────────────────────────────
    if [ "$tag" = "AV" ]; then
        if [ "$disconnected" = "True" ]; then
            record "$case" "disconnected" pass "Go closed the injector's connection"
        else
            record "$case" "disconnected" fail \
                "Go did NOT disconnect after a malformed vote — possible real conformance finding"
            FAILED=1
        fi
        if grep -qF "disconnected: BadData" "$log"; then
            record "$case" "bad-data" pass "node logged 'disconnected: BadData'"
        else
            record "$case" "bad-data" info "no 'disconnected: BadData' line (log level may hide it)"
        fi
    elif [ "$case" = "unknown-field-proposal" ] || [ "$case" = "unknown-field-proposal-rust" ]; then
        # The receiver drops the payload at decode ("dropping proposal that
        # failed to decode": go agreement/demux.go, algod-rust demux.rs) at
        # WARN level, without a disconnect.
        if [ "$case" = "unknown-field-proposal" ]; then
            if ufp_go_dropped "$log"; then
                record "$case" "go-dropped-at-decode" pass \
                    "node logged 'dropping proposal that failed to decode: Unknown field: zzunk'"
            else
                record "$case" "go-dropped-at-decode" fail \
                    "node never dropped the payload at decode for key zzunk (see $log)"
                FAILED=1
            fi
        elif ufp_rust_dropped "$log"; then
            record "$case" "rust-dropped-at-decode" pass \
                "algod-rust logged 'dropping proposal that failed to decode: ... with key zzunk'"
        else
            record "$case" "rust-dropped-at-decode" fail \
                "algod-rust never dropped the payload at decode for key zzunk (see $log)"
            FAILED=1
        fi
        local rust_err; rust_err="$(report_field rust_decode_error)"
        if ufp_rust_decoder_reason "$rust_err"; then
            record "$case" "rust-decoder-rejects" pass "algod-rust's decoder refuses the bytes for the key: $rust_err"
        else
            record "$case" "rust-decoder-rejects" fail "algod-rust's decoder did not refuse the bytes for the unknown key: $rust_err"
            FAILED=1
        fi
        if ufp_not_disconnected "$disconnected"; then
            record "$case" "no-disconnect" pass "the receiver kept the injector connected for ${OBSERVE_SECS}s"
        else
            record "$case" "no-disconnect" fail "the receiver disconnected the injector (disconnected=$disconnected)"
            FAILED=1
        fi
        if [ "$case" = "unknown-field-proposal-rust" ]; then
            # the Rust node commits the same block as go at the injected round
            local round go_hash rust_hash=""
            round="$(report_field round)"
            go_hash="$(block_hash "$PHASE6_GO1_PORT" "$round")"
            local wr=$(( $(date +%s) + HEALTH_TIMEOUT ))
            while [ "$(date +%s)" -lt "$wr" ]; do
                rust_hash="$(block_hash "$PHASE6_RUST_PORT" "$round")"
                [ -n "$rust_hash" ] && break
                sleep 2
            done
            if ufp_same_block_hash "$go_hash" "$rust_hash"; then
                record "$case" "rust-same-block" pass "round $round: algod-rust and go-node-1 committed $rust_hash"
            else
                record "$case" "rust-same-block" fail "round $round: go-node-1 '$go_hash' vs algod-rust '$rust_hash'"
                FAILED=1
            fi
        fi
    else
        # A malformed payload is answered with ignoreAction, not a disconnect
        # (agreement/player.go, payloadMalformed/payloadRejected), so the
        # decisive assertion is that the network never committed the corrupted
        # block. The log line is corroborating evidence, matched on the exact
        # block digest we sent so it cannot be confused with the ordinary
        # duplicate-payload rejections a relay logs constantly.
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
        elif [ "$raised" = "1" ]; then
            record "$case" "go-rejected-payload" fail \
                "no 'rejected block for' line carrying digest $injected_digest (see $log)"
            FAILED=1
        else
            record "$case" "go-rejected-payload" info \
                "payload rejection is logged at DEBUG; log level was not raised, relying on not-adopted"
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
    if [ "$case" = "unknown-field-proposal-rust" ]; then
        # ...and so does the Rust node, which only learns blocks from its go
        # peers: it kept them after dropping the payload.
        local rust_after="" rok=0
        d=$(( $(date +%s) + HEALTH_TIMEOUT ))
        while [ "$(date +%s)" -lt "$d" ]; do
            rust_after="$(node_round "$PHASE6_RUST_PORT")"
            if [[ "$rust_before" =~ ^[0-9]+$ ]] && [[ "$rust_after" =~ ^[0-9]+$ ]] \
                && [ "$rust_after" -ge $(( rust_before + HEALTH_ROUNDS )) ]; then
                rok=1; break
            fi
            sleep 2
        done
        if [ "$rok" = "1" ]; then
            record "$case" "rust-liveness" pass "algod-rust advanced $rust_before -> $rust_after"
        else
            record "$case" "rust-liveness" fail "algod-rust did not advance $HEALTH_ROUNDS rounds from $rust_before (now $rust_after)"
            FAILED=1
        fi
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
    "issue": 472,
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
