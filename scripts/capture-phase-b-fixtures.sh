#!/usr/bin/env bash
# Capture Phase B algokey fixtures from go-algorand.
#
# Usage:
#   bash scripts/capture-phase-b-fixtures.sh
#
# Requires:
#   - ../go-algorand checkout pinned to v4.6.0-stable (the version this
#     repo tracks)
#   - `go` on PATH
#
# Outputs:
#   crates/tools/algokey-rust/tests/fixtures/algokey/sign/
#   crates/tools/algokey-rust/tests/fixtures/algokey/multisig/
#   crates/tools/algokey-rust/tests/fixtures/algokey/keyreg/
#
# Unlike the Phase A capture script (which shells out to the algokey
# binary), this one links against the Go crypto stack directly so we
# get deterministic seeded inputs. The Go program lives at
# scripts/build-phase-b-fixtures.go.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIX_DIR="$REPO_ROOT/crates/tools/algokey-rust/tests/fixtures/algokey"
mkdir -p "$FIX_DIR/sign" "$FIX_DIR/multisig" "$FIX_DIR/keyreg"
cd "$REPO_ROOT/../go-algorand" && go run "$REPO_ROOT/scripts/build-phase-b-fixtures.go" "$FIX_DIR"
echo "Phase B fixtures regenerated under $FIX_DIR"
