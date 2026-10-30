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
# Lines that show a TRANSPORT-level failure reaching a relay: refused or
# timed-out connections, DNS and TLS errors, 5xx answers, and the
# entrypoint's probe getting no HTTP answer (000) or a 5xx. reqwest's bare
# "error sending request" counts only with such a cause on the same line: a
# "builder error" / "invalid URL" there is the node's own fault. Deliberately not
# a 404 or "every candidate peer failed": a node bug that builds a wrong URL
# gets those too. Matched after dropping the routine `WS block fetch failed`
# warning, which healthy runs log.
SMOKE_RELAY_ERROR_RE="error sending request.*(timed out|dns error|tls|handshake)|connection refused|connection reset|operation timed out|connection timed out|dns error|failed to lookup address|tls handshake|invalid peer certificate|HTTP 5[0-9][0-9]|status(: | code )5[0-9][0-9]|catchpoint file HTTP (000|5[0-9][0-9])"

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
  elif grep -av "WS block fetch failed" "$log" 2>/dev/null | grep -aqiE "$SMOKE_RELAY_ERROR_RE"; then
    echo external
  else
    echo node
  fi
}
