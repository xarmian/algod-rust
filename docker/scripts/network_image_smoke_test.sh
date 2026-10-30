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

# --- external network: transport failures and nothing was ever served
log "relay de-k4-s1.example:14161: catchpoint file HTTP 000"   "No relay answered with the catchpoint file; leaving the peers to DNS discovery."   " WARN catchpoint_sync: block 5: every candidate peer failed: http://r1: network error: error sending request for url (http://r1/v2/blocks/5): connection refused"
class_is external "relays unreachable, nothing ever served"

log " WARN catchpoint_sync: block 9: REST /v2/blocks failed (HTTP 503 Service Unavailable)"
class_is external "relays answering 5xx, no progress"

# --- reqwest's "error sending request" counts only with a transport cause
log " WARN catchpoint_sync: block 5: error sending request for url (http://r1/v2/blocks/5): builder error: invalid URL"
class_is node "error sending request + builder error / invalid URL"

log " WARN catchpoint_sync: block 5: error sending request for url (htp:/r1/v2/blocks/5): invalid URL, scheme is not http"
class_is node "error sending request + invalid URL"

log " WARN catchpoint_sync: block 5: error sending request for url (http://r1/v2/blocks/5): client error (Connect): tcp connect error: Connection refused (os error 111)"
class_is external "error sending request + Connection refused"

# --- "tls"/"handshake" count only as an error phrase, never inside a hostname
log " WARN catchpoint_sync: block 5: error sending request for url (http://tls-relay.example:4160/v2/blocks/5): builder error"
class_is node "a hostname containing 'tls' plus 'error sending request' and no cause"

log " WARN catchpoint_sync: block 5: error sending request for url (http://r1/v2/blocks/5): client error (Connect): tls handshake eof"
class_is external "error sending request + a tls handshake failure"

# --- a 5xx counts only on a relay line
log " INFO http: handler answered HTTP 500 for GET /v2/status (unrelated)"
class_is node "an unrelated line that says HTTP 500"

log "relay r1.example:4160: catchpoint file HTTP 502"
class_is external "the entrypoint probe getting a 502"

# --- node: a 404 everywhere is what a wrong URL looks like too
log " WARN catchpoint_sync: block 9: REST /v2/blocks failed (not found: GET /v2/blocks/9?format=msgpack: 404 page not found)"   " WARN catchpoint_sync: block 9: every candidate peer failed: http://r1: not found | http://r2: not found"
class_is node "404 on every fetch with no progress"

log "relay r1:4160: catchpoint file HTTP 404"   "No relay answered with the catchpoint file; leaving the peers to DNS discovery."
class_is node "the catchpoint probe got 404 from every relay"

# --- node: the agreement certificate channel is not a TLS certificate
log " INFO algo_ledger::catchup_service: catchup cert-service: certificate channel closed, exiting"
class_is node "a healthy-startup certificate line"

# --- node: the routine WS warning alone is not relay evidence
log " WARN algo_network: WS block fetch failed round=7 error=request timed out"
class_is node "only the routine WS warning"

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
