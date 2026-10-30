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
# Lines that say a relay refused or failed to serve. Deliberately not the
# routine `WS block fetch failed` warning nor a bare `error sending request`:
# both appear in healthy runs.
SMOKE_RELAY_ERROR_RE="No relay answered with the catchpoint file|every candidate peer failed|REST /v2/blocks failed|catchpoint connect |catchpoint GET |lookback block download failed"

# smoke_failure_class <log>: print `external` when <log> is strong evidence
# that the relays, not the node, failed the run: no fatal panic, not a single
# successful catchpoint/block fetch or ledger advance, and at least one relay
# failure. Anything else, ambiguous cases included, prints `node`.
smoke_failure_class() {
  local log="$1"
  if [ -n "$(smoke_fatal_panics "$log")" ]; then
    echo node
  elif grep -aqE "$SMOKE_PROGRESS_RE" "$log" 2>/dev/null; then
    echo node
  elif grep -aqE "$SMOKE_RELAY_ERROR_RE" "$log" 2>/dev/null; then
    echo external
  else
    echo node
  fi
}
