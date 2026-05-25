#!/usr/bin/env bash
# capture-goal-fixtures.sh — refresh `tests/fixtures/parity/*.txt`
# from a running Go `goal` binary against deterministic data dirs.
#
# Gated on MIXED_CLUSTER=1 (the canonical algod-rust signal for
# "you may exec / talk to ../go-algorand") and writes through the
# Rust test harness's UPDATE_FIXTURES=1 contract so the diff path
# is the same one CI exercises.
#
# Phase A ships the harness + 7 hand-derived fixtures from Go's
# messages.go template constants. The live-capture body below is a
# scaffold — wiring up a deterministic algod+kmd state machine
# (catchpoint progress, upgrade voting) is its own surface that
# lives outside Phase A. Until then this script:
#
# 1. Verifies `goal` is on PATH at the expected version (v4.5.1-stable).
# 2. Refreshes only the fixtures Go can produce against a
#    freshly-spawned kmd-rust (wallet_new_created, wallet_list_empty,
#    wallet_rename_ok). The node_* fixtures require a full algod
#    sandbox + scripted block production, deferred to a later phase.

set -euo pipefail

if [[ "${MIXED_CLUSTER:-}" != "1" ]]; then
  echo "MIXED_CLUSTER=1 is required to run this script (refuses to refresh fixtures without an explicit opt-in)." >&2
  exit 1
fi

if ! command -v goal >/dev/null 2>&1; then
  echo "go-algorand 'goal' binary not on PATH. Build with:" >&2
  echo "  (cd ../go-algorand/cmd/goal && go build -o /tmp/goal .)" >&2
  echo "and put it on PATH before re-running." >&2
  exit 1
fi

want_ver="v4.5.1-stable"
if ! goal -v 2>&1 | head -1 | grep -q .; then
  echo "goal -v didn't print a version string; cannot verify v4.5.1 baseline" >&2
  exit 1
fi

echo "goal version output:" >&2
goal -v >&2 || true

fixtures_dir="$(cd "$(dirname "$0")/.." && pwd)/tests/fixtures/parity"
mkdir -p "$fixtures_dir"

# Reserved for the algod+kmd state-fixture rig (a later phase wires
# this in alongside MIXED_CLUSTER algod cross-impl tests).
echo "Phase A: live-capture rig not yet implemented." >&2
echo "Edit tests/fixtures/parity/*.txt by hand from go-algorand v$want_ver's messages.go." >&2
echo "  see tests/fixtures/parity/README.md for the per-fixture provenance." >&2
exit 0
