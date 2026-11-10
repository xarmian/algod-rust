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

// App-mode error text oracle: go-algorand oracle for issue #2225.
//
// The execution errors of the application-only opcodes (app_*, asset_*,
// acct_params_get, box_*, itxn*, gitxn*, gload*, gaid*, log, block, ...) cannot
// be reached from a LogicSig (there they only hit the mode gate, which the
// avm-opcode-capture vectors pin). Here each scenario is an application
// CREATION call whose approval program provokes one error, simulated through
// the real, unmodified go `Simulator` on a real in-memory ledger with only the
// genesis accounts (an empty block gives it a header). The result, the
// failure message (go's `EvalError` text with its pc and the txid) and the
// failed-at path, goes to tests/fixtures/simulate_app_errors/oracle.json; the
// Rust side is crates/core/algo-ledger/tests/simulation_app_error_oracle_test.rs.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/simulation"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

const appErrGenesisID = "simulate-app-errors-oracle-v1"

type appErrScenario struct {
	Name           string   `json:"name"`
	Source         string   `json:"source"`
	GroupMsgpack   string   `json:"group_msgpack"`
	FailureMessage string   `json:"failure_message"`
	FailedAt       []uint64 `json:"failed_at"`
}

type appErrFixture struct {
	Comment     string           `json:"_comment"`
	Protocol    string           `json:"protocol"`
	GenesisID   string           `json:"genesis_id"`
	GenesisHash string           `json:"genesis_hash"`
	FeeSink     string           `json:"fee_sink"`
	RewardsPool string           `json:"rewards_pool"`
	Accounts    []account        `json:"genesis_accounts"`
	Blocks      []string         `json:"blocks"`
	Scenarios   []appErrScenario `json:"scenarios"`
}

// appErrPrograms: name -> approval program body (after the pragma). Each one
// is meant to fail with one go error text; "ok_control" must succeed.
var appErrPrograms = []struct{ name, body string }{
	{"ok_control", "int 1"},
	// clean rejects and plain program errors
	{"reject_zero", "int 0"},
	{"err_opcode", "err"},
	{"assert_zero", "int 0; assert; int 1"},
	{"stack_empty_at_end", "int 1; int 1"},
	// application state
	{"app_global_put_key_too_long", "int 65; bzero; int 1; app_global_put; int 1"},
	{"app_global_put_value_too_long", `byte "k"; int 200; bzero; app_global_put; int 1`},
	{"app_global_put_over_schema", `byte "k"; int 1; app_global_put; int 1`},
	{"app_global_get_ex_unavailable_app", `int 99; byte "k"; app_global_get_ex; pop; pop; int 1`},
	{"app_local_get_bad_account_index", `int 5; byte "k"; app_local_get; pop; int 1`},
	{"app_local_get_not_opted_in", `txn Sender; byte "k"; app_local_get; pop; int 1`},
	{"app_local_put_not_opted_in", `txn Sender; byte "k"; int 1; app_local_put; int 1`},
	{"app_local_del_not_opted_in", `txn Sender; byte "k"; app_local_del; int 1`},
	{"app_local_get_ex_unavailable_app", `txn Sender; int 99; byte "k"; app_local_get_ex; pop; pop; int 1`},
	{"app_opted_in_unavailable_app", `txn Sender; int 99; app_opted_in; pop; int 1`},
	{"app_opted_in_bad_account_index", `int 5; int 0; app_opted_in; pop; int 1`},
	// accounts, assets, applications
	{"balance_bad_account_index", `int 9; balance; pop; int 1`},
	{"min_balance_unavailable_account", `byte 0x0101010101010101010101010101010101010101010101010101010101010101; min_balance; pop; int 1`},
	{"asset_holding_get_unavailable_asset", `txn Sender; int 99; asset_holding_get AssetBalance; pop; pop; int 1`},
	{"asset_holding_get_bad_account_index", `int 7; int 99; asset_holding_get AssetBalance; pop; pop; int 1`},
	{"asset_params_get_unavailable_asset", `int 99; asset_params_get AssetTotal; pop; pop; int 1`},
	{"app_params_get_unavailable_app", `int 99; app_params_get AppCreator; pop; pop; int 1`},
	{"acct_params_get_bad_account_index", `int 7; acct_params_get AcctBalance; pop; pop; int 1`},
	// boxes
	{"box_create_empty_name", `int 0; bzero; int 10; box_create; pop; int 1`},
	{"box_create_name_too_long", `int 65; bzero; int 10; box_create; pop; int 1`},
	{"box_create_too_large", `byte "b"; int 40000; box_create; pop; int 1`},
	{"box_create_no_balance", `byte "b"; int 10; box_create; pop; int 1`},
	{"box_extract_missing", `byte "b"; int 0; int 1; box_extract; pop; int 1`},
	{"box_replace_missing", `byte "b"; int 0; byte 0x01; box_replace; int 1`},
	{"box_resize_missing", `byte "b"; int 5; box_resize; int 1`},
	{"box_put_empty_name", `int 0; bzero; byte "v"; box_put; int 1`},
	{"box_get_empty_name", `int 0; bzero; box_get; pop; pop; int 1`},
	// inner transactions
	{"itxn_submit_without_begin", `itxn_submit; int 1`},
	{"itxn_field_without_begin", `int 1; itxn_field Amount; int 1`},
	{"itxn_next_without_begin", `itxn_next; int 1`},
	{"itxn_begin_submit_no_type", `itxn_begin; itxn_submit; int 1`},
	{"itxn_begin_pay_no_funds", `itxn_begin; int pay; itxn_field TypeEnum; txn Sender; itxn_field Receiver; int 1; itxn_field Amount; itxn_submit; int 1`},
	{"itxn_field_wrong_type", `itxn_begin; byte "x"; callsub ident; itxn_field Amount; int 1; return
ident: retsub`},
	{"itxn_field_wrong_type_sender", `itxn_begin; int 1; callsub ident; itxn_field Sender; int 1; return
ident: retsub`},
	{"itxn_field_bad_type_enum", `itxn_begin; int 99; itxn_field TypeEnum; int 1`},
	{"itxn_read_without_previous", `itxn Fee; pop; int 1`},
	{"itxna_read_without_previous", `itxna Logs 0; pop; int 1`},
	{"gitxn_read_without_previous", `gitxn 0 Fee; pop; int 1`},
	{"itxn_begin_twice", `itxn_begin; itxn_begin; int 1`},
	// group and misc
	{"gload_self", `gload 0 0; pop; int 1`},
	{"gloads_self", `int 0; gloads 0; pop; int 1`},
	{"gaid_self", `gaid 0; pop; int 1`},
	{"log_too_many", `byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; byte "x"; log; int 1`},
	{"log_too_large", `int 1025; bzero; log; int 1`},
	{"block_unavailable_round", `int 9999; block BlkSeed; pop; int 1`},
	{"txn_logs_index", `txna Logs 0; pop; int 1`},
	{"arg_gate_box_create_wrong_type", `int 5; callsub ident; int 10; box_create; pop; int 1; return
ident: retsub`},
}

func appErrOracle() {
	proto := protocol.ConsensusCurrentVersion
	params := config.Consensus[proto]
	accts := map[basics.Address]basics.AccountData{
		acctA: {Status: basics.Offline, MicroAlgos: basics.MicroAlgos{Raw: 1_000_000_000}},
		acctB: {Status: basics.Offline, MicroAlgos: basics.MicroAlgos{Raw: 1_000_000_000}},
		acctC: {Status: basics.Offline, MicroAlgos: basics.MicroAlgos{Raw: 10_000_000}},
		// A pool of exactly MinBalance gives a zero rewards rate.
		pool: {Status: basics.NotParticipating, MicroAlgos: basics.MicroAlgos{Raw: params.MinBalance}},
		sink: {Status: basics.NotParticipating, MicroAlgos: basics.MicroAlgos{Raw: 1_000_000}},
	}
	genesisHash := crypto.Hash([]byte(appErrGenesisID))
	gb := bookkeeping.MakeTimestampedGenesisBalances(accts, sink, pool, 0)
	genesis, err := bookkeeping.MakeGenesisBlock(proto, gb, appErrGenesisID, genesisHash)
	must(err)
	genesis.TxnCommitments, err = genesis.PaysetCommit()
	must(err)

	log := logging.NewLogger()
	log.SetLevel(logging.Warn)
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	initState := ledgercore.InitState{Block: genesis, Accounts: accts, GenesisHash: genesisHash}
	actual, err := ledger.OpenLedger(log, appErrGenesisID+"-ledger", true, initState, cfg)
	must(err)
	defer actual.Close()
	l := &data.Ledger{Ledger: actual}

	// One empty block, generated as a proposer would.
	hdr, err := l.BlockHdr(l.Latest())
	must(err)
	next := bookkeeping.MakeBlock(hdr).BlockHeader
	next.TimeStamp = 1_700_000_000 + int64(next.Round)*5
	ev, err := l.StartEvaluator(next, 0, 0, nil)
	must(err)
	ub, err := ev.GenerateBlock(nil)
	must(err)
	must(l.AddValidatedBlock(ledgercore.MakeValidatedBlock(ub.UnfinishedBlock(), ub.UnfinishedDeltas()), agreement.Certificate{}))
	blk, err := l.Block(l.Latest())
	must(err)

	f := appErrFixture{
		Comment:     "Generated by tools/simulate-rewards-oracle (apperr.go, issue #2225); do not edit by hand.",
		Protocol:    string(proto),
		GenesisID:   appErrGenesisID,
		GenesisHash: b64(genesisHash[:]),
		FeeSink:     b64(sink[:]),
		RewardsPool: b64(pool[:]),
		Blocks:      []string{b64(protocol.Encode(&blk))},
	}
	for _, a := range []basics.Address{acctA, acctB, acctC, pool, sink} {
		ad := accts[a]
		f.Accounts = append(f.Accounts, account{
			Addr:       b64(a[:]),
			Status:     ad.Status.String(),
			MicroAlgos: ad.MicroAlgos.Raw,
		})
	}

	clear, err := logic.AssembleString("#pragma version 10\nint 1")
	must(err)
	sim := simulation.MakeSimulator(l, false)
	for _, p := range appErrPrograms {
		src := "#pragma version 10\n" + p.body
		approval, err := logic.AssembleString(src)
		if err != nil {
			panic(fmt.Sprintf("scenario %s does not assemble: %v", p.name, err))
		}
		t := transactions.Transaction{
			Type: protocol.ApplicationCallTx,
			Header: transactions.Header{
				Sender:      acctA,
				Fee:         basics.MicroAlgos{Raw: params.MinTxnFee},
				FirstValid:  1,
				LastValid:   1000,
				Note:        []byte(p.name),
				GenesisID:   appErrGenesisID,
				GenesisHash: genesisHash,
			},
			ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
				OnCompletion:      transactions.NoOpOC,
				ApprovalProgram:   approval.Program,
				ClearStateProgram: clear.Program,
			},
		}
		stxn := transactions.SignedTxn{Txn: t}
		res, err := sim.Simulate(simulation.Request{
			TxnGroups:            [][]transactions.SignedTxn{{stxn}},
			AllowEmptySignatures: true,
		})
		must(err)
		g := res.TxnGroups[0]
		out := appErrScenario{
			Name:           p.name,
			Source:         src,
			GroupMsgpack:   b64(protocol.Encode(&stxn)),
			FailureMessage: g.FailureMessage,
			FailedAt:       []uint64{},
		}
		for _, pos := range g.FailedAt {
			out.FailedAt = append(out.FailedAt, uint64(pos))
		}
		f.Scenarios = append(f.Scenarios, out)
	}

	path := filepath.Join("..", "..", "crates", "core", "algo-ledger", "tests", "fixtures", "simulate_app_errors", "oracle.json")
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	js, err := json.MarshalIndent(f, "", "  ")
	must(err)
	must(os.WriteFile(path, append(js, '\n'), 0o644))
	fmt.Println("wrote", path)
}
