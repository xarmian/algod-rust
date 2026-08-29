#!/usr/bin/env bash

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Capture golden block-header fixtures from a real go-algorand node running
# under the `vFuture`/"future" consensus protocol (issue #548).
#
# Why this exists: docs/CONFORMANCE_STRATEGY.md's fixture/conformance
# harness only ever stood up nodes at the network's *current* consensus
# version (V41), so there was no way to byte-exact-verify vFuture-only
# behavior (e.g. the `Load`/`CongestionTax` ("ld"/"ct") header fields added
# in #534/PR #547) against a real go-algorand binary. This script drives
# `docker/docker-compose.vfuture.yml` (a single-node, 100%-stake private
# network pinned to "future", see docker/scripts/vfuture-entrypoint.sh) and
# floods it with payment transactions so the block-size-dependent `Load`
# field crosses the 50%-full threshold that also makes `CongestionTax`
# non-zero the following round (data/bookkeeping/block.go's
# NextCongestionTax) — see docker/config/vfuture-consensus.json for why
# MaxTxnBytesPerBlock is overridden down to make that reachable with a
# handful of transactions instead of megabytes of traffic.
#
# Usage:
#   docker/scripts/capture-vfuture-fixtures.sh [output_dir]
#
# Requires: docker, curl, python3, and a built `algod-rust` binary
# (release preferred -- see docs/DEV_WORKFLOW.md's "vFuture Fixture
# Capture" section for why debug builds can stack-overflow on Windows).
set -euo pipefail

# On Windows/Git-Bash, MSYS path conversion mangles the `/algod/data`
# in-container path passed to `docker exec ... -d /algod/data` (it gets
# rewritten as a host path). No-op on Linux/macOS.
export MSYS_NO_PATHCONV=1

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$REPO_ROOT/crates/core/algo-ledger/tests/fixtures/vfuture}"
ALGOD_URL="http://127.0.0.1:4010"
ALGOD_TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
CONTAINER="algod-go-vfuture"
FLOOD_COUNT="${VFUTURE_FLOOD_COUNT:-40}"

cd "$REPO_ROOT"
mkdir -p "$OUT_DIR"

echo "==> Bringing up algod-go-vfuture..."
docker compose -f docker/docker-compose.vfuture.yml up -d

echo "==> Waiting for the REST API to answer..."
for _ in $(seq 1 60); do
    if curl -sf -H "X-Algo-API-Token: $ALGOD_TOKEN" "$ALGOD_URL/v2/status" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
curl -sf -H "X-Algo-API-Token: $ALGOD_TOKEN" "$ALGOD_URL/v2/status" >/dev/null

echo "==> Starting kmd and discovering the funded wallet address..."
docker exec "$CONTAINER" goal kmd start -d /algod/data >/dev/null 2>&1 || true
ADDR="$(docker exec "$CONTAINER" goal account list -d /algod/data | awk '{print $2; exit}')"
echo "    funded address: $ADDR"

echo "==> Flooding $FLOOD_COUNT no-wait payment transactions to push a block over 50% full..."
for i in $(seq 1 "$FLOOD_COUNT"); do
    docker exec "$CONTAINER" goal clerk send -a 1000 -f "$ADDR" -t "$ADDR" \
        -d /algod/data -n "vfuture-capture-$i" -N >/dev/null 2>&1 &
done
wait

echo "==> Waiting a few more rounds for the congestion-tax response to land..."
sleep 5

echo "==> Scanning recent rounds for one with non-zero Load *and* one with non-zero CongestionTax..."
STATUS_ROUND="$(curl -s -H "X-Algo-API-Token: $ALGOD_TOKEN" "$ALGOD_URL/v2/status" | python3 -c 'import json,sys; print(json.load(sys.stdin)["last-round"])')"

LOAD_ROUND=""
TAX_ROUND=""
for r in $(seq "$STATUS_ROUND" -1 1); do
    read -r ld ct <<<"$(curl -s -H "X-Algo-API-Token: $ALGOD_TOKEN" "$ALGOD_URL/v2/blocks/$r" | python3 -c '
import json, sys
b = json.load(sys.stdin)["block"]
print(b.get("ld", 0), b.get("ct", 0))
')"
    if [ -z "$LOAD_ROUND" ] && [ "$ld" != "0" ]; then
        LOAD_ROUND="$r"
    fi
    if [ -z "$TAX_ROUND" ] && [ "$ct" != "0" ]; then
        TAX_ROUND="$r"
    fi
    if [ -n "$LOAD_ROUND" ] && [ -n "$TAX_ROUND" ]; then
        break
    fi
done

if [ -z "$LOAD_ROUND" ] || [ -z "$TAX_ROUND" ]; then
    echo "ERROR: could not find a round with non-zero Load and a round with non-zero CongestionTax" >&2
    echo "       (LOAD_ROUND=$LOAD_ROUND TAX_ROUND=$TAX_ROUND) -- try VFUTURE_FLOOD_COUNT=80 or re-run" >&2
    exit 1
fi
echo "    Load became non-zero at round $LOAD_ROUND; CongestionTax at round $TAX_ROUND"

START=$((LOAD_ROUND < TAX_ROUND ? LOAD_ROUND : TAX_ROUND))
START=$((START > 2 ? START - 2 : 1))
END=$((LOAD_ROUND > TAX_ROUND ? LOAD_ROUND : TAX_ROUND))
END=$((END + 1))

echo "==> Capturing rounds $START-$END via the algod-rust capture pipeline..."
RUST_BIN="$REPO_ROOT/target/release/algod-rust"
if [ ! -x "$RUST_BIN" ] && [ ! -x "$RUST_BIN.exe" ]; then
    RUST_BIN="$REPO_ROOT/target/debug/algod-rust"
fi
"$RUST_BIN" capture \
    --algod-url "$ALGOD_URL" --algod-token "$ALGOD_TOKEN" \
    --start "$START" --end "$END" --out "$OUT_DIR"

echo "==> Writing capture metadata..."
cat >"$OUT_DIR/README.md" <<EOF
# vFuture golden fixtures (issue #548)

Captured from a real \`algorand/algod:4.7.3-stable\` node running under the
\`future\` consensus protocol (\`docker/docker-compose.vfuture.yml\`), with
\`MaxTxnBytesPerBlock\` shrunk via \`docker/config/vfuture-consensus.json\`
(see \`tools/vfuture-consensus-override/\`) so a small burst of payment
transactions could push a block over 50% full — the threshold at which
\`CongestionTax\` becomes non-zero the following round.

- Round $LOAD_ROUND: first round with non-zero \`Load\` ("ld").
- Round $TAX_ROUND: first round with non-zero \`CongestionTax\` ("ct").

Regenerate with: \`docker/scripts/capture-vfuture-fixtures.sh\`
(see docs/DEV_WORKFLOW.md -> "vFuture Fixture Capture").
EOF

echo "==> Tearing down algod-go-vfuture..."
docker compose -f docker/docker-compose.vfuture.yml down -v

echo "==> Done. Fixtures written to $OUT_DIR"
