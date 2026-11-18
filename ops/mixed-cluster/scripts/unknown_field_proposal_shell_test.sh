#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Docker-free test of unknown_field_proposal.sh (issue #2398), the checks the
# WS-gossip and P2P negative-conformance scripts apply to the opt-in
# `unknown-field-proposal` / `unknown-field-proposal-rust` cases. The log
# lines are copied from the live run recorded in PR for issue #2398.
#
#   bash ops/mixed-cluster/scripts/unknown_field_proposal_shell_test.sh

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILS=0

ok() { echo "ok   - $1"; }
bad() { echo "FAIL - $1"; FAILS=$((FAILS + 1)); }
yes() { if "${@:2}"; then ok "$1"; else bad "$1"; fi; }
no() { if "${@:2}"; then bad "$1"; else ok "$1"; fi; }

# shellcheck source=unknown_field_proposal.sh
source "$HERE/unknown_field_proposal.sh"

# go-algorand v5.0.5 JSON log line (agreement/demux.go tokenizeMessages)
GO_LINE='{"Context":"Agreement","file":"demux.go","function":"github.com/algorand/go-algorand/agreement.(*demux).tokenizeMessages.func1","level":"warning","line":129,"msg":"dropping proposal that failed to decode: Unknown field: zzunk","time":"2026-11-18T08:05:44.024244Z"}'
# algod-rust tracing line (algo-agreement demux.rs handle_raw_proposal)
RUST_LINE='2026-11-18T08:06:11.285862Z  WARN algo_agreement::demux: dropping proposal that failed to decode: decode error: block decode: codec error: msgpack decode error: no matching struct field found when decoding stream map with key zzunk: msgpack decode error: no matching struct field found when decoding stream map with key zzunk len=1277'

printf '%s\n' "noise" "$GO_LINE" > "$TMP/go.log"
printf '%s\n' "noise" "$RUST_LINE" > "$TMP/rust.log"
# the same drop for a different reason (an allocbound, #2427) must not count
printf '%s\n' '{"level":"warning","msg":"dropping proposal that failed to decode: (Block) txns: msgp: length overflow: 70000 > 65536"}' > "$TMP/go-other.log"
printf '%s\n' 'WARN algo_agreement::demux: dropping proposal that failed to decode: decode error: allocbound exceeded' > "$TMP/rust-other.log"
# the key named, but not on a decode-drop line
printf '%s\n' 'INFO something else mentions Unknown field: zzunk and with key zzunk' > "$TMP/unrelated.log"

yes "go drop line is recognised"            ufp_go_dropped "$TMP/go.log"
no  "go drop for another reason is not"     ufp_go_dropped "$TMP/go-other.log"
no  "go: key outside a drop line is not"    ufp_go_dropped "$TMP/unrelated.log"
no  "go: rust's line is not go's"           ufp_go_dropped "$TMP/rust.log"
no  "go: missing log file is a failure"     ufp_go_dropped "$TMP/absent.log"

yes "rust drop line is recognised"          ufp_rust_dropped "$TMP/rust.log"
no  "rust drop for another reason is not"   ufp_rust_dropped "$TMP/rust-other.log"
no  "rust: key outside a drop line is not"  ufp_rust_dropped "$TMP/unrelated.log"
no  "rust: go's line is not rust's"         ufp_rust_dropped "$TMP/go.log"

yes "decoder reason: unknown-key error" ufp_rust_decoder_reason \
    "decode error: block decode: msgpack decode error [pos 412]: no matching struct field found when decoding stream map with key zzunk"
no  "decoder reason: report had none"        ufp_rust_decoder_reason "None"
no  "decoder reason: another key"            ufp_rust_decoder_reason \
    "no matching struct field found when decoding stream map with key other"
no  "decoder reason: an allocbound"          ufp_rust_decoder_reason "allocbound exceeded: zzunk"

yes "not disconnected: False"                ufp_not_disconnected False
no  "not disconnected: True"                 ufp_not_disconnected True
no  "not disconnected: None (no outcome)"    ufp_not_disconnected None

yes "same block hash"                        ufp_same_block_hash ABC ABC
no  "different block hash"                   ufp_same_block_hash ABC ABD
no  "missing rust hash"                      ufp_same_block_hash ABC ""
no  "both hashes missing"                    ufp_same_block_hash "" ""

# Both negative-conformance scripts source the checks and know the cases.
WS="$HERE/negative-conformance.sh"
P2P="$HERE/../../mixed-cluster-p2p/scripts/negative-conformance.sh"
for f in "$WS" "$P2P"; do
    yes "$(basename "$(dirname "$(dirname "$f")")") sources unknown_field_proposal.sh" \
        grep -q 'unknown_field_proposal.sh' "$f"
    yes "$(basename "$(dirname "$(dirname "$f")")") checks rust_decode_error" \
        grep -q 'ufp_rust_decoder_reason' "$f"
    yes "$(basename "$(dirname "$(dirname "$f")")") checks no-disconnect" \
        grep -q 'ufp_not_disconnected' "$f"
    yes "$(basename "$(dirname "$(dirname "$f")")") parses" bash -n "$f"
done
yes "ws script has the rust-injection case" grep -q 'unknown-field-proposal-rust)' "$WS"
yes "ws script captures off go for the rust case" grep -q -- '--capture-gossip "\$TARGET_GOSSIP"' "$WS"
yes "compose publishes rust-node-4's listener" \
    grep -q 'PHASE6_RUST_GOSSIP_PORT:-4162}:4162' "$HERE/../docker-compose.yml"

if [ "$FAILS" -ne 0 ]; then
    echo "$FAILS failure(s)"
    exit 1
fi
echo "all unknown_field_proposal checks passed"
