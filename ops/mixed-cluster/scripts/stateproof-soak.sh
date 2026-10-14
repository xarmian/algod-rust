#!/usr/bin/env bash

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# stateproof-soak.sh — Phase 21 / DIV-001, issue #1948.
#
# Brings up the 4-node mixed cluster (3 go-algorand relays + 1 algod-rust
# participation node) from a fresh genesis with the Rust node's state-proof
# worker enabled, waits until the FIRST state proof is committed (round 512
# on a fresh chain: StateProofInterval = 256), and asserts with
# stateproof_check.py that every node -- Go and Rust -- serves the identical
# proof and agrees on every block hash around the block that carries it.
# That block is validated, reveal signatures and all, by go-algorand's
# Falcon verifier on the Go nodes and by algod-rust's on the Rust node, and
# the Rust node signs its own state-proof messages with the Falcon key it
# imported from `goal`'s partkey, so this is the live cross-implementation
# check of the det1024 backend selected for the Rust node.
#
# Usage:
#   bash ops/mixed-cluster/scripts/stateproof-soak.sh
#   PHASE6_FALCON_BACKEND=c bash ops/mixed-cluster/scripts/stateproof-soak.sh   # control run
#
# Env:
#   PHASE6_FALCON_BACKEND  rust|c -> "FalconBackend" in the Rust node's
#                          config.json (unset: crate default, i.e. rust)
#   SP_ROUND               round whose proof must be committed   (default 512)
#   SP_MARGIN              rounds past the COMMIT round to wait for / compare
#                          (default 8)
#   SP_TIMEOUT             seconds for the chain to reach SP_ROUND (default 3600)
#   SP_PROOF_TIMEOUT       seconds after that for the proof to be committed
#                          (default 1800; go-algorand re-broadcasts each
#                          account's signature only every StateProofInterval/2
#                          rounds, so the proof lands up to ~128 rounds late)
#   SKIP_START=1           use an already-running cluster
#   KEEP_CLUSTER=1         leave the cluster up on exit
#   REUSE_NETROOT=1        keep netroot/ (default: purge for a fresh genesis,
#                          issue #1590)
#   OUT_DIR                artifact dir (default ops/mixed-cluster/stateproof-<ts>-<backend>)
#
# Exit: 0 all checks passed; non-zero otherwise. Artifacts: summary.json,
# stateproof_check.json, rust-node.log, go-node-*.log tails, start.log.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

SP_ROUND="${SP_ROUND:-512}"
SP_MARGIN="${SP_MARGIN:-8}"
SP_TIMEOUT="${SP_TIMEOUT:-3600}"
SP_PROOF_TIMEOUT="${SP_PROOF_TIMEOUT:-1800}"
SKIP_START="${SKIP_START:-0}"
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"
BACKEND_LABEL="${PHASE6_FALCON_BACKEND:-default}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$ROOT/stateproof-$RUN_ID-$BACKEND_LABEL}"
mkdir -p "$OUT_DIR"

export PHASE6_ENABLE_STATE_PROOF_WORKER=1

teardown() {
    local rc=$?
    if [ "$KEEP_CLUSTER" = "1" ]; then
        echo "KEEP_CLUSTER=1 — leaving the cluster up. Tear down with: $HERE/stop.sh"
    else
        echo "==> tearing down the cluster"
        "$HERE/stop.sh" >/dev/null 2>&1 || true
    fi
    exit "$rc"
}
trap teardown EXIT

if [ "$SKIP_START" != "1" ]; then
    if [ "${REUSE_NETROOT:-0}" != "1" ]; then
        echo "==> purging netroot/ for a fresh genesis"
        "$HERE/stop.sh" --purge > "$OUT_DIR/purge.log" 2>&1 || true
    fi
    echo "==> starting the cluster (state-proof worker on, FalconBackend=$BACKEND_LABEL)"
    "$HERE/start.sh" > "$OUT_DIR/start.log" 2>&1 || {
        echo "start.sh failed — see $OUT_DIR/start.log" >&2
        exit 1
    }
fi

echo "==> waiting for round $SP_ROUND (${SP_TIMEOUT}s), then for its state proof to be committed (${SP_PROOF_TIMEOUT}s)"
set +e
python3 "$HERE/stateproof_check.py" \
    --state-proof-round "$SP_ROUND" --margin "$SP_MARGIN" \
    --timeout "$SP_TIMEOUT" --proof-timeout "$SP_PROOF_TIMEOUT" \
    | tr -d '\r' > "$OUT_DIR/stateproof_check.json"
CHECK_RC=${PIPESTATUS[0]}
set -e
cat "$OUT_DIR/stateproof_check.json"

# Evidence from the nodes themselves.
# Full logs are scanned for the state-proof lines (a tail would have scrolled
# past the round-512 events by the time the proof commits); only the
# state-proof lines are kept as artifacts.
for c in phase6-go-node-1 phase6-go-node-2 phase6-go-node-3; do
    docker logs "$c" 2>&1 | sed -e 's/\x1b\[[0-9;]*m//g' > "$OUT_DIR/$c.log.full" || true
    grep 'go-algorand/stateproof' "$OUT_DIR/$c.log.full" > "$OUT_DIR/$c.stateproof.log" || true
    tail -300 "$OUT_DIR/$c.log.full" > "$OUT_DIR/$c.log.tail" || true
done
docker logs phase6-rust-node-4 2>&1 | sed -e 's/\x1b\[[0-9;]*m//g' > "$OUT_DIR/rust-node.log" || true

RUST_SP_LINES="$(grep -ci 'state.proof\|stateproof' "$OUT_DIR/rust-node.log" || true)"
# "stateproof: signed state proof message round=512 signer=..." -- the Rust node
# signed with the Falcon key it imported from goal's partkey.
RUST_SIGNED="$(grep -ci 'stateproof: signed state proof message' "$OUT_DIR/rust-node.log" || true)"
# Go's state-proof worker only logs "starts gathering signatures" once it has
# accepted a signature for the round.
GO_GATHERING="$(cat "$OUT_DIR"/phase6-go-node-*.stateproof.log | grep -c 'handleSig: starts gathering signatures' || true)"
GO_SP_WARN="$(cat "$OUT_DIR"/phase6-go-node-*.stateproof.log | grep -c '"level":"\(warning\|error\)"' || true)"
# Falcon signatures from go-algorand nodes that the Rust node accepted (verified
# with the selected backend) and the proof it submitted itself.
RUST_ACCEPTED_PEER_SIGS="$(grep -c 'stateproof: accepted signature from peer' "$OUT_DIR/rust-node.log" || true)"
RUST_SUBMITTED="$(grep -c 'stateproof: submitted StateProofTx' "$OUT_DIR/rust-node.log" || true)"
rm -f "$OUT_DIR"/phase6-go-node-*.log.full
RUST_FALCON_ERR="$(grep -i 'falcon' "$OUT_DIR/rust-node.log" | grep -ci 'error\|fail\|invalid' || true)"
RUST_BACKEND_LINE="$(grep -i 'falcon-1024 backend selected' "$OUT_DIR/rust-node.log" | tail -1 | tr -d '\r' || true)"
RUST_LAST_ROUND="$(curl -sf -H "X-Algo-API-Token: ${ALGOD_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}" http://127.0.0.1:4004/v2/status 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('last-round'))" 2>/dev/null | tr -d '\r' || true)"

SUMMARY_OK=false
if [ "$CHECK_RC" = "0" ] && [ "${RUST_FALCON_ERR:-0}" = "0" ] && [ "${RUST_SIGNED:-0}" -ge 1 ] \
    && [ "${GO_GATHERING:-0}" -ge 1 ] && [ "${RUST_ACCEPTED_PEER_SIGS:-0}" -ge 1 ]; then
    SUMMARY_OK=true
fi
python3 - "$OUT_DIR/summary.json" "$SUMMARY_OK" "$BACKEND_LABEL" "$SP_ROUND" "$CHECK_RC" \
    "${RUST_SP_LINES:-0}" "${RUST_SIGNED:-0}" "${RUST_FALCON_ERR:-0}" "${RUST_BACKEND_LINE:-}" "${RUST_LAST_ROUND:-}" \
    "${GO_GATHERING:-0}" "${GO_SP_WARN:-0}" "${RUST_ACCEPTED_PEER_SIGS:-0}" "${RUST_SUBMITTED:-0}" <<'PY'
import json, sys
path, ok, backend, sp_round, rc, sp_lines, signed, falcon_err, backend_line, last, gathering, go_warn, accepted, submitted = sys.argv[1:15]
json.dump({
    "event": "stateproof_soak",
    "ok": ok == "true",
    "falcon_backend_requested": backend,
    "rust_backend_log_line": backend_line,
    "state_proof_round": int(sp_round),
    "stateproof_check_exit": int(rc),
    "rust_log_state_proof_lines": int(sp_lines),
    "rust_log_state_proof_sign_lines": int(signed),
    "rust_log_falcon_errors": int(falcon_err),
    "rust_accepted_peer_signatures": int(accepted),
    "rust_submitted_state_proof_txns": int(submitted),
    "go_nodes_gathering_signatures_lines": int(gathering),
    "go_stateproof_warn_or_error_lines": int(go_warn),
    "rust_last_round": last,
}, open(path, "w"), indent=2)
print(open(path).read())
PY

[ "$SUMMARY_OK" = "true" ]
