#!/bin/bash
# Copyright (C) 2026 Algod DAO
# This file is part of algod-rust, a modified work based on go-algorand
# (https://github.com/algorand/go-algorand). Licensed AGPL-3.0-or-later.
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Issue #2554: stage network_oracle_test.go.txt into a go-algorand
# v5.1.1-stable checkout's network package, run it, and write the fixtures.
#
#   GOALGORAND=$HOME/go-algorand tools/network-oracle/run.sh
#
# Needs `make libsodium` done in that checkout and Go 1.27.4 (the checkout's
# toolchain line). Run it on Linux/WSL, not on a CRLF Windows checkout.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
G=${GOALGORAND:-$HOME/go-algorand}
FIX=$REPO/crates/node/algo-network/tests/fixtures/network_oracle
mkdir -p "$FIX"
sed 's/\r$//' "$HERE/network_oracle_test.go.txt" > "$G/network/zz_network_oracle_test.go"
trap 'rm -f "$G/network/zz_network_oracle_test.go"' EXIT
cd "$G"
NETORACLE_ZSTD_OUT=$FIX/zstd_proposal.jsonl go test -count=1 -run '^TestZstdProposalOracle$' -v ./network/ | tail -15
AFIX=$REPO/crates/node/algo-p2p/tests/fixtures
mkdir -p "$AFIX"
sed 's/\r$//' "$HERE/addr_oracle_test.go.txt" > "$G/network/addr/zz_addr_oracle_test.go"
trap 'rm -f "$G/network/zz_network_oracle_test.go" "$G/network/addr/zz_addr_oracle_test.go"' EXIT
NETORACLE_ADDR_OUT=$AFIX/addr_oracle.jsonl go test -count=1 -run '^TestAddrOracle$' -v ./network/addr/ | tail -15
wc -lc "$FIX"/*.jsonl "$AFIX"/addr_oracle.jsonl
