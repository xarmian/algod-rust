#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
#
# Real-chain strict-decode sweep (issue #2439): fetch the last N rounds of
# mainnet, testnet, voimain and aramidmain from public algod endpoints and
# decode every block through algod-rust's strict readers
# (crates/core/algo-codec/tests/real_chain_decode_sweep_test.rs). Every block
# was accepted by the network's go nodes, so any rejection is a bug.
#
#   scripts/strict-decode/decode_sweep.sh [N] [OUT_DIR]
#
# N defaults to 3000; OUT_DIR to target/decode-sweep. Set NETWORKS to a subset
# (e.g. NETWORKS="aramidmain mainnet") and CARGO to override the cargo command.
set -euo pipefail

N="${1:-3000}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${2:-$REPO/target/decode-sweep}"
CARGO="${CARGO:-cargo}"
NETWORKS="${NETWORKS:-mainnet testnet voimain aramidmain}"
mkdir -p "$OUT"

endpoint() {
  case "$1" in
    mainnet) echo https://mainnet-api.algonode.cloud ;;
    testnet) echo https://testnet-api.algonode.cloud ;;
    voimain) echo https://mainnet-api.voi.nodely.dev ;;
    aramidmain) echo https://algod.aramidmain.a-wallet.net ;;
    *) echo "unknown network $1" >&2; exit 2 ;;
  esac
}

status=0
for net in $NETWORKS; do
  file="$OUT/$net.bin"
  python3 "$REPO/scripts/strict-decode/fetch_block_range.py" \
    --endpoint "$(endpoint "$net")" --last-n "$N" --out "$file"
  network=""
  [ "$net" = aramidmain ] && network=aramidmain
  if ! (cd "$REPO" && ALGOD_RUST_DECODE_SWEEP="$file" ALGOD_RUST_DECODE_SWEEP_NETWORK="$network" \
        $CARGO test -p algo-codec --test real_chain_decode_sweep_test -- --nocapture); then
    echo "decode_sweep: $net: go-accepted blocks rejected" >&2
    status=1
  fi
done
exit $status
