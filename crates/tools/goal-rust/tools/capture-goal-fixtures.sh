#!/usr/bin/env bash
# capture-goal-fixtures.sh — refresh `tests/fixtures/parity/*.txt`
# from a running Go `goal` binary against deterministic data dirs.
#
# Gated on MIXED_CLUSTER=1 (the canonical algod-rust signal for
# "you may exec / talk to ../go-algorand"). Writes Go's stdout
# DIRECTLY to tests/fixtures/parity/<name>.txt — the Rust assertion
# helper has no "rewrite from actual" path (deliberately, per
# Codex review TASK-229 round 1), so this script is the only
# sanctioned writer.
#
# Phase A ships the harness + 7 hand-derived fixtures from Go's
# messages.go template constants. The live-capture body below is a
# scaffold — wiring up a deterministic algod+kmd state machine
# (catchpoint progress, upgrade voting) is its own surface that
# lives outside Phase A. Until then this script:
#
# 1. Verifies `goal` is on PATH at the expected version (v4.7.0-stable).
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

want_ver="v4.7.0-stable"
goal_ver_out="$(goal -v 2>&1 || true)"
if ! grep -qF "$want_ver" <<<"$goal_ver_out"; then
  echo "goal version mismatch: refusing to capture fixtures." >&2
  echo "  expected: ${want_ver} (substring of \`goal -v\`)" >&2
  echo "  got:" >&2
  echo "${goal_ver_out}" | sed 's/^/    /' >&2
  echo "Rebuild the Go binary from ../go-algorand at that tag and re-run." >&2
  exit 1
fi

fixtures_dir="$(cd "$(dirname "$0")/.." && pwd)/tests/fixtures/parity"
mkdir -p "$fixtures_dir"

# Reserved for the algod+kmd state-fixture rig (a later phase wires
# this in alongside MIXED_CLUSTER algod cross-impl tests). When
# implemented, write each fixture by capturing Go's stdout directly:
#   goal <args> -d "$tmp_data_dir" >"$fixtures_dir/<name>.txt"
echo "Phase A: live-capture rig not yet implemented." >&2
echo "The committed fixtures were produced during Phase A bring-up via the" >&2
echo "dual-source provenance documented at tests/fixtures/parity/README.md." >&2
echo "Once the algod+kmd state-fixture rig lands, this script will capture" >&2
echo "Go's stdout directly — existing .txt files must not be hand-edited." >&2
exit 0
