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

// Parity oracle for algod-rust issue #2606: go-algorand v5.1.1-stable's
// generate-only cross-type lookup check (`roundCowBase.noteMiss`) as simulate
// reports it. The real, unmodified go Simulator runs on a real in-memory
// ledger in which account A holds an app (local state) and an asset (holding)
// and a creator made both; each case is one transaction group whose approval
// program looks an id up as the creatable type it is not (or does not). The
// rows give the group's failure message and failed-at path with the account
// addresses and txids replaced by $A / $B / $CREATOR / $TXID<n>, and the ids
// (the same on every run: the genesis txn counter plus the setup txns) kept.
// The Rust test crates/core/algo-ledger/tests/simulation_cross_type_test.rs
// builds the same state and compares.
//
// Staged into ledger/simulation of a go-algorand checkout at the pin
// (`make libsodium` first):
//
//	cp tools/simulate-cross-type-oracle/oracle_test.go \
//	   ../go-algorand/ledger/simulation/zz_algod_rust_cross_type_oracle_test.go
//	(cd ../go-algorand && ORACLE_OUT=$PWD/out.jsonl go test -count=1 \
//	   -run '^TestAlgodRustCrossTypeOracle$' ./ledger/simulation/)
//	cp ../go-algorand/out.jsonl crates/core/algo-ledger/tests/fixtures/simulate_cross_type.jsonl
package simulation_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/simulation"
	simulationtesting "github.com/algorand/go-algorand/ledger/simulation/testing"
	"github.com/algorand/go-algorand/protocol"
)

type crossTypeRow struct {
	Name           string   `json:"name"`
	FailedAt       []uint64 `json:"failed_at"`
	FailureMessage string   `json:"failure_message"`
}

func TestAlgodRustCrossTypeOracle(t *testing.T) {
	env := simulationtesting.PrepareSimulatorTest(t)
	defer env.Close()

	a, b, creator := env.Accounts[0], env.Accounts[1], env.Accounts[2]

	// An app the creator made and A opted in to, and an asset the creator made
	// and A opted in to.
	appX := env.CreateApp(creator.Addr, simulationtesting.AppParams{
		ApprovalProgram:   "#pragma version 8\nint 1",
		ClearStateProgram: "#pragma version 8\nint 1",
	})
	env.OptIntoApp(a.Addr, appX)
	asaS := env.CreateAsset(creator.Addr, basics.AssetParams{Total: 100, UnitName: "S"})
	env.OptIntoAsset(a.Addr, asaS)
	// An asset A created, so A holds its params.
	created := env.CreateAsset(a.Addr, basics.AssetParams{Total: 1, UnitName: "C"})

	// Probe apps: look the first foreign id up as an asset holding / as an
	// app opt-in of the sender (creation, ApplicationID 0, skips the lookup).
	probeAsset := env.CreateApp(creator.Addr, simulationtesting.AppParams{
		ApprovalProgram:   "#pragma version 8\ntxn ApplicationID\nbz end\ntxn Sender\ntxn Assets 0\nasset_holding_get AssetBalance\npop\npop\nend:\nint 1",
		ClearStateProgram: "#pragma version 8\nint 1",
	})
	probeApp := env.CreateApp(creator.Addr, simulationtesting.AppParams{
		ApprovalProgram:   "#pragma version 8\ntxn ApplicationID\nbz end\ntxn Sender\ntxn Applications 1\napp_opted_in\npop\nend:\nint 1",
		ClearStateProgram: "#pragma version 8\nint 1",
	})
	t.Logf("ids: appX=%d asaS=%d created=%d probeAsset=%d probeApp=%d", appX, asaS, created, probeAsset, probeApp)

	call := func(sender simulationtesting.Account, app basics.AppIndex, oc transactions.OnCompletion, assets []basics.AssetIndex, apps []basics.AppIndex) transactions.SignedTxn {
		txn := env.TxnInfo.NewTxn(txntest.Txn{
			Type:          protocol.ApplicationCallTx,
			Sender:        sender.Addr,
			ApplicationID: app,
			OnCompletion:  oc,
			ForeignAssets: assets,
			ForeignApps:   apps,
		})
		return txn.Txn().Sign(sender.Sk)
	}
	cases := []struct {
		name string
		make func() []transactions.SignedTxn
	}{
		{"app_id_looked_up_as_an_asset_it_holds", func() []transactions.SignedTxn {
			return []transactions.SignedTxn{call(a, probeAsset, 0, []basics.AssetIndex{basics.AssetIndex(appX)}, nil)}
		}},
		{"asset_id_looked_up_as_an_app_it_holds", func() []transactions.SignedTxn {
			return []transactions.SignedTxn{call(a, probeApp, 0, nil, []basics.AppIndex{basics.AppIndex(asaS)})}
		}},
		{"asset_id_created_by_the_sender_looked_up_as_an_app", func() []transactions.SignedTxn {
			return []transactions.SignedTxn{call(a, probeApp, 0, nil, []basics.AppIndex{basics.AppIndex(created)})}
		}},
		{"id_of_the_type_asked_for_is_an_ordinary_miss", func() []transactions.SignedTxn {
			return []transactions.SignedTxn{call(b, probeAsset, 0, []basics.AssetIndex{asaS}, nil)}
		}},
		{"other_account_does_not_hold_the_id", func() []transactions.SignedTxn {
			return []transactions.SignedTxn{call(b, probeAsset, 0, []basics.AssetIndex{basics.AssetIndex(appX)}, nil)}
		}},
		{"held_as_the_type_asked_for_is_a_hit", func() []transactions.SignedTxn {
			return []transactions.SignedTxn{call(a, probeAsset, 0, []basics.AssetIndex{asaS}, nil)}
		}},
		{"id_above_the_counter", func() []transactions.SignedTxn {
			return []transactions.SignedTxn{call(a, probeAsset, 0, []basics.AssetIndex{basics.AssetIndex(1_000_000)}, nil)}
		}},
		{"second_txn_of_a_group_after_clear_state_removed_the_local_state", func() []transactions.SignedTxn {
			first := env.TxnInfo.NewTxn(txntest.Txn{
				Type: protocol.ApplicationCallTx, Sender: a.Addr, ApplicationID: appX, OnCompletion: transactions.ClearStateOC,
			})
			second := env.TxnInfo.NewTxn(txntest.Txn{
				Type: protocol.ApplicationCallTx, Sender: a.Addr, ApplicationID: probeAsset,
				ForeignAssets: []basics.AssetIndex{basics.AssetIndex(appX)},
			})
			txntest.Group(&first, &second)
			return []transactions.SignedTxn{first.Txn().Sign(a.Sk), second.Txn().Sign(a.Sk)}
		}},
		{"second_txn_of_a_group_after_a_clean_first", func() []transactions.SignedTxn {
			first := env.TxnInfo.NewTxn(txntest.Txn{
				Type: protocol.PaymentTx, Sender: b.Addr, Receiver: b.Addr, Amount: 0,
			})
			second := env.TxnInfo.NewTxn(txntest.Txn{
				Type: protocol.ApplicationCallTx, Sender: a.Addr, ApplicationID: probeApp,
				ForeignApps: []basics.AppIndex{basics.AppIndex(asaS)},
			})
			txntest.Group(&first, &second)
			return []transactions.SignedTxn{first.Txn().Sign(b.Sk), second.Txn().Sign(a.Sk)}
		}},
	}

	out, err := os.Create(os.Getenv("ORACLE_OUT"))
	require.NoError(t, err)
	defer out.Close()
	enc := json.NewEncoder(out)
	for _, c := range cases {
		txns := c.make()
		result, err := simulation.MakeSimulator(env.Ledger, false).Simulate(simulation.Request{
			TxnGroups: [][]transactions.SignedTxn{txns},
		})
		require.NoError(t, err)
		group := result.TxnGroups[0]
		msg := group.FailureMessage
		for i, stxn := range txns {
			msg = strings.ReplaceAll(msg, stxn.Txn.ID().String(), "$TXID"+string(rune('0'+i)))
		}
		for name, addr := range map[string]basics.Address{"$A": a.Addr, "$B": b.Addr, "$CREATOR": creator.Addr} {
			msg = strings.ReplaceAll(msg, addr.String(), name)
		}
		row := crossTypeRow{Name: c.name, FailedAt: []uint64{}, FailureMessage: msg}
		for _, p := range group.FailedAt {
			row.FailedAt = append(row.FailedAt, uint64(p))
		}
		require.NoError(t, enc.Encode(row))
		t.Logf("%s: failedAt=%v msg=%q", c.name, group.FailedAt, msg)
	}
}
