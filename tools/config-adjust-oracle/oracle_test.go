// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Parity oracle for algod-rust issue #2556: go-algorand v5.1.1-stable's
// `Local.AdjustConnectionLimits` (config/localTemplate.go), which v5.1 changed
// to compare the connection limits with the REST delta as unsigned numbers
// (`limit > 0 && uint64(limit) > restDelta`) instead of converting the delta to
// an int. One JSON row per input: the required/max file descriptors, the four
// limits, the listen modes, and the result. The Rust test
// crates/node/algo-config/src/lib.rs
// (`adjust_connection_limits_matches_go_on_every_oracle_row`) replays them.
//
// The test is staged into config/ of a go-algorand checkout at the pin:
//
//	cp tools/config-adjust-oracle/oracle_test.go \
//	   ../go-algorand/config/zz_algod_rust_adjust_oracle_test.go
//	(cd ../go-algorand && ORACLE_OUT=$PWD/adjust_out.jsonl go test -count=1 \
//	   -run '^TestAlgodRustAdjustOracle$' ./config/)
//	cp ../go-algorand/adjust_out.jsonl \
//	   crates/node/algo-config/tests/fixtures/adjust_connection_limits.jsonl
package config

import (
	"encoding/json"
	"math"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAlgodRustAdjustOracle(t *testing.T) {
	outPath := os.Getenv("ORACLE_OUT")
	require.NotEmpty(t, outPath, "set ORACLE_OUT")
	f, err := os.Create(outPath)
	require.NoError(t, err)
	defer f.Close()
	enc := json.NewEncoder(f)

	required := []uint64{100, 5000, math.MaxInt64 + 1, math.MaxInt64 + 10, math.MaxUint64}
	maxFDs := []uint64{0, 990}
	soft := []uint64{5, 100}
	hard := []uint64{0, 1000}
	incoming := []int{math.MinInt64, -5, 5, 800, math.MaxInt64}
	p2pIncoming := []int{-1, 50, math.MaxInt64}
	modes := []struct {
		net, p2pNet string
		p2p, hybrid bool
	}{
		{"", "", false, false},
		{":4160", "", false, false},
		{":4160", "", true, false},
		{":4160", ":4190", false, true},
		{":4160", ":4190", true, true},
	}
	for _, req := range required {
		for _, max := range maxFDs {
			for _, s := range soft {
				for _, h := range hard {
					for _, inc := range incoming {
						for _, p2pInc := range p2pIncoming {
							for _, m := range modes {
								cfg := GetDefaultLocal()
								cfg.NetAddress = m.net
								cfg.P2PHybridNetAddress = m.p2pNet
								cfg.EnableP2P = m.p2p
								cfg.EnableP2PHybridMode = m.hybrid
								cfg.RestConnectionsSoftLimit = s
								cfg.RestConnectionsHardLimit = h
								cfg.IncomingConnectionsLimit = inc
								cfg.P2PHybridIncomingConnectionsLimit = p2pInc
								updated := cfg.AdjustConnectionLimits(req, max)
								require.NoError(t, enc.Encode(map[string]any{
									"required": req, "max": max, "soft": s, "hard": h, "incoming": inc, "p2p_incoming": p2pInc,
									"net": m.net, "p2p_net": m.p2pNet, "enable_p2p": m.p2p, "hybrid": m.hybrid,
									"updated": updated, "soft_out": cfg.RestConnectionsSoftLimit, "hard_out": cfg.RestConnectionsHardLimit,
									"incoming_out": cfg.IncomingConnectionsLimit, "p2p_incoming_out": cfg.P2PHybridIncomingConnectionsLimit,
								}))
							}
						}
					}
				}
			}
		}
	}
}
