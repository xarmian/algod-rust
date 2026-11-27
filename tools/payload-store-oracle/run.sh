#!/bin/bash
# Copyright (C) 2026 Algod DAO
# This file is part of algod-rust, a modified work based on go-algorand
# (https://github.com/algorand/go-algorand). Licensed AGPL-3.0-or-later.
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Issue #2552: stage payload_store_oracle_test.go.txt into a go-algorand
# v5.1.1-stable checkout's agreement package, run it, write the fixture.
#
#   GOALGORAND=$HOME/go-algorand tools/payload-store-oracle/run.sh
#
# Needs `make libsodium` in that checkout and Go 1.27.4. Run on Linux/WSL.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
G=${GOALGORAND:-$HOME/go-algorand}
FIX=$REPO/crates/core/algo-agreement/tests/fixtures/payload_store
mkdir -p "$FIX"
sed 's/\r$//' "$HERE/payload_store_oracle_test.go.txt" > "$G/agreement/zz_payload_store_oracle_test.go"
trap 'rm -f "$G/agreement/zz_payload_store_oracle_test.go"' EXIT
cd "$G"
PS_OUT=$FIX/scenarios.jsonl go test -count=1 -run '^TestPayloadStoreOracle$' -v ./agreement/ | tail -15
wc -lc "$FIX/scenarios.jsonl"
