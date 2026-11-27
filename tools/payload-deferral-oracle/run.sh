#!/bin/bash
# Copyright (C) 2026 Algod DAO
# This file is part of algod-rust, a modified work based on go-algorand
# (https://github.com/algorand/go-algorand). Licensed AGPL-3.0-or-later.
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Issue #2552: stage payload_deferral_oracle_test.go.txt into a go-algorand
# v5.1.1-stable checkout's agreement package, run it, and write the fixture.
#
#   GOALGORAND=$HOME/go-algorand tools/payload-deferral-oracle/run.sh
#
# Needs `make libsodium` done in that checkout and Go 1.27.4 (the checkout's
# toolchain line). Run it on Linux/WSL, not on a CRLF Windows checkout.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
G=${GOALGORAND:-$HOME/go-algorand}
FIX=$REPO/crates/core/algo-agreement/tests/fixtures/payload_deferral
mkdir -p "$FIX"
SEEDS=$(mktemp)
grep '"kind": "payload"' "$REPO/crates/core/algo-agreement/tests/fixtures/strict_decode/seeds.jsonl" | grep -E '"name": "(wire_tpayload_|payload_rand[01])' > "$SEEDS" || true
sed 's/\r$//' "$HERE/payload_deferral_oracle_test.go.txt" > "$G/agreement/zz_payload_deferral_oracle_test.go"
trap 'rm -f "$G/agreement/zz_payload_deferral_oracle_test.go" "$SEEDS"' EXIT
cd "$G"
PD_SEEDS=$SEEDS PD_OUT=$FIX/cases.jsonl go test -count=1 -run '^TestPayloadDeferralOracle$' -v ./agreement/ | tail -15
wc -lc "$FIX/cases.jsonl"
