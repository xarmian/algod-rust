#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Unit tests of network_image_smoke_lib.sh's log classification (issue
# #2121): sample node logs in, `node`/`external` and the fatal-panic filter
# out. No Docker. Run by `make consensus-cluster-analyzer`.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=network_image_smoke_lib.sh
. "$HERE/network_image_smoke_lib.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0

log() { printf '%s\n' "$@" > "$TMP/log"; }
class_is() {
  local want="$1" what="$2" got
  got="$(smoke_failure_class "$TMP/log")"
  if [ "$got" = "$want" ]; then echo "ok: $what"; else echo "FAIL: $what (got $got, want $want)"; fails=$((fails + 1)); fi
}
fatal_is() {
  local want="$1" what="$2" got=no
  [ -n "$(smoke_fatal_panics "$TMP/log")" ] && got=yes
  if [ "$got" = "$want" ]; then echo "ok: $what"; else echo "FAIL: $what (fatal=$got, want $want)"; fails=$((fails + 1)); fi
}

# --- external network: relays failed and nothing was ever served
log "No relay answered with the catchpoint file; leaving the peers to DNS discovery." \
  " WARN algod_rust::commands::catchpoint_sync: block fetch failed, rotating to the next peer round=5 error=network error: block 5: every candidate peer failed: http://r1: x | http://r2: y"
class_is external "no relay served the catchpoint or any block"

log " WARN catchup: block 9: REST /v2/blocks failed (not found: 404 page not found)"
class_is external "REST block fetches failing, no progress"

# --- node: healthy-run noise alone is not relay evidence
log " WARN algo_network: WS block fetch failed round=7 error=timeout" \
  " WARN x: error sending request for url (http://r1:4160/v1/x/block/7)"
class_is node "only the routine WS warning and a bare 'error sending request'"

# --- node: relays served something, so a stall is the node's
log " INFO algo_ledger::catchup_service: catchup service: periodic sync advanced the ledger from=1 to=229" \
  " WARN catchpoint_sync: block fetch failed, rotating to the next peer error=every candidate peer failed"
class_is node "a stall after the ledger advanced"

log " INFO algo_rest_client::catchpoint_download: catchpoint download complete round=22507000" \
  " ERROR algo_ledger::sync: lookback block download failed: every candidate peer failed"
class_is node "a lookback failure after the catchpoint was served"

# --- node: no evidence either way
log " INFO algod: starting the node"
class_is node "a stall with no relay errors"

# --- fatal panics
log "thread '<unnamed>' (337) panicked at /cargo/tokio-1.54.1/src/runtime/time/entry.rs:534:9:" \
  "A Tokio 1.x context was found, but it is being shutdown." \
  "No relay answered with the catchpoint file; leaving the peers to DNS discovery."
fatal_is yes "a timer registered on a dying runtime"
class_is node "relay errors plus a shutdown panic"

log "thread 'main' (1) panicked at bin/algod-rust/src/main.rs:10:5:" "boom"
fatal_is yes "a main-thread panic"

log "thread 'tokio-runtime-worker' (12) panicked at crates/core/algo-ledger/src/proposal_eval.rs:99:9:" \
  "index out of bounds" \
  " WARN algo_ledger::proposal_eval: proposal evaluation panicked; rejecting the proposal"
fatal_is no "a panic the node contains with catch_unwind"

if [ "$fails" -ne 0 ]; then
  echo "$fails network-image smoke classification test(s) failed"
  exit 1
fi
echo "all network-image smoke classification tests passed"
