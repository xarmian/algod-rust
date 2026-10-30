# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Log classification for docker/scripts/network-image-smoke.sh (issue #2121),
# sourced by it and unit-tested by network_image_smoke_test.sh.

# smoke_fatal_panics <log>: print the panics in <log> the node does not
# recover from, nothing if there are none. Those are a timer registered on a
# runtime that is being shut down (always a shutdown-ordering bug) and a
# panic on the main thread. Panics the node deliberately contains with
# `catch_unwind` (proposal evaluation, batch verification, simulation, the
# REST adapter, sqlite, the catchup service threads) still print through the
# panic hook but are not counted; a crash they did cause shows up as the
# container exiting or a non-zero exit code instead.
smoke_fatal_panics() {
  grep -a -B1 -A1 -E "it is being shutdown|thread 'main'.*panicked at" "$1" 2>/dev/null || true
}

# Lines that prove a relay served the node something.
SMOKE_PROGRESS_RE="catchpoint download complete|periodic sync advanced the ledger|lookback blocks downloaded|catchpoint import complete"
# Lines that show a TRANSPORT-level failure reaching a relay. Deliberately not
# a 404 or "every candidate peer failed": a node bug that builds a wrong URL
# gets those too. All matched after dropping the routine `WS block fetch
# failed` warning, which healthy runs log.
#
# 1. Transport error phrases (case-insensitive, as the OS and TLS libraries
#    capitalize them differently): refused/reset/timed-out connections, DNS and
#    TLS failures as error PHRASES (never a bare "tls" or "handshake", which a
#    hostname such as tls-relay.example contains).
SMOKE_TRANSPORT_ERROR_RE="connection refused|connection reset|(operation|connection|request) timed out|dns error|failed to lookup address|tls handshake|ssl error|invalid peer certificate"
# 2. reqwest's bare "error sending request" counts only with such a cause on
#    the same line: a "builder error" / "invalid URL" there is the node's own
#    fault.
SMOKE_SEND_ERROR_RE="error sending request.*($SMOKE_TRANSPORT_ERROR_RE)"
# 3. A 5xx answer, or the entrypoint probe getting no HTTP answer (000), but
#    only on the lines that are about a relay (the entrypoint's probe line, the
#    REST block client, the block service, the catchpoint client), never on an
#    unrelated line that happens to say "HTTP 500". Case-sensitive.
SMOKE_RELAY_5XX_RE="(^relay [^ ]+: catchpoint file HTTP (000|5[0-9][0-9])$|(REST /v2/blocks failed|/v1 block-service|catchpoint (GET|connect)).*(HTTP|status)[ :]+5[0-9][0-9])"

# smoke_has_relay_error <log>: whether <log> shows a transport-level relay
# failure (see above).
smoke_has_relay_error() {
  local log="$1"
  grep -av "WS block fetch failed" "$log" 2>/dev/null | {
    local found=no line
    while IFS= read -r line; do
      if printf '%s\n' "$line" | grep -qiE "$SMOKE_TRANSPORT_ERROR_RE|$SMOKE_SEND_ERROR_RE" \
        || printf '%s\n' "$line" | grep -qE "$SMOKE_RELAY_5XX_RE"; then
        found=yes
        break
      fi
    done
    [ "$found" = yes ]
  }
}

# smoke_failure_class <log>: print `external` when <log> is strong evidence
# that the relays, not the node, failed the run: no fatal panic, not a single
# successful catchpoint/block fetch or ledger advance, and at least one
# transport-level relay failure. Anything else prints `node`, ambiguous cases
# included: a 404 on every fetch with no progress is a node failure.
smoke_failure_class() {
  local log="$1"
  if [ -n "$(smoke_fatal_panics "$log")" ]; then
    echo node
  elif grep -aqE "$SMOKE_PROGRESS_RE" "$log" 2>/dev/null; then
    echo node
  elif smoke_has_relay_error "$log"; then
    echo external
  else
    echo node
  fi
}
