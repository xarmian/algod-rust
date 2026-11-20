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

// ClearState pooled-budget oracle: go-algorand oracle for issue #2499.
//
// A top-level ClearState program interacts with the group's pooled opcode
// budget in three ways (data/transactions/logic/eval.go):
//
//   - `step()` takes every opcode it executes out of
//     `*cx.PooledApplicationBudget`, even under IsolateClearState (v31+),
//     where `remainingBudget()` caps the program itself at
//     `MaxAppProgramCost - cx.cost`;
//   - under IsolateClearState, `EvalContract` refuses to start it while the
//     pool holds less than `MaxAppProgramCost` ("attempted ClearState
//     execution with low OpcodeBudget"), a plain error that fails the
//     transaction;
//   - before IsolateClearState (v30) it runs on the pool like an approval
//     program, with no low-budget gate, and may issue inner transactions
//     (`opItxnBegin` only refuses them under IsolateClearState).
//
// For the current protocol and for v30, this builds a real in-memory ledger
// whose block 1 creates the apps below and opts the sender in, then simulates
// each scenario group through the unmodified go `Simulator`. The result
// (failure message, failed-at, the budget figures, every transaction's logs
// and inner transaction count) goes to
// tests/fixtures/simulate_clearstate_pool/oracle.json; the Rust side is
// crates/core/algo-ledger/tests/simulation_clearstate_pool_oracle_test.rs.
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

type csPoolTxn struct {
	AppBudgetConsumed uint64   `json:"app_budget_consumed"`
	Logs              []string `json:"logs"`
	InnerTxns         int      `json:"inner_txns"`
}

type csPoolScenario struct {
	Name              string      `json:"name"`
	GroupMsgpack      string      `json:"group_msgpack"`
	FailureMessage    string      `json:"failure_message"`
	FailedAt          []uint64    `json:"failed_at"`
	AppBudgetAdded    uint64      `json:"app_budget_added"`
	AppBudgetConsumed uint64      `json:"app_budget_consumed"`
	Txns              []csPoolTxn `json:"txns"`
}

type csPoolLedger struct {
	Protocol    string            `json:"protocol"`
	GenesisID   string            `json:"genesis_id"`
	GenesisHash string            `json:"genesis_hash"`
	FeeSink     string            `json:"fee_sink"`
	RewardsPool string            `json:"rewards_pool"`
	Accounts    []account         `json:"genesis_accounts"`
	Blocks      []string          `json:"blocks"`
	Apps        map[string]uint64 `json:"apps"`
	Scenarios   []csPoolScenario  `json:"scenarios"`
}

type csPoolFixture struct {
	Comment string         `json:"_comment"`
	Ledgers []csPoolLedger `json:"ledgers"`
}

// A countdown loop of n iterations (4 opcodes each).
func csLoop(n int) string {
	return fmt.Sprintf("int %d\nloop:\nint 1\n-\ndup\nbnz loop\npop\n", n)
}

type csApp struct {
	name            string
	approval, clear string
	optIn, fund     bool
}

// Approval programs approve every call; the loops sit in ClearState programs,
// except for the burner, whose approval loops on every call after creation.
func csApps(current bool) []csApp {
	v5 := "#pragma version 5\n"
	apps := []csApp{
		// ClearState costs a few hundred opcodes, then logs.
		{name: "csp_small", approval: v5 + "int 1", clear: v5 + csLoop(75) + "byte \"cleared\"\nlog\nint 1", optIn: true},
		// ClearState needs more than MaxAppProgramCost, then logs.
		{name: "csp_big", approval: v5 + "int 1", clear: v5 + csLoop(250) + "byte \"cleared\"\nlog\nint 1", optIn: true},
		// ClearState pays the sender 2000 through an inner transaction.
		{name: "csp_inner_pay", approval: v5 + "int 1", clear: v5 + `itxn_begin
int pay
itxn_field TypeEnum
int 2000
itxn_field Amount
txn Sender
itxn_field Receiver
itxn_submit
int 1`, optIn: true, fund: true},
		// ClearState pays the sender 2000, then rejects: the pay must be
		// rolled back. The approval logs the app's and the sender's balance.
		{name: "csp_pay_reject", approval: v5 + `global CurrentApplicationAddress
balance
itob
log
txn Sender
balance
itob
log
int 1`, clear: v5 + `itxn_begin
int pay
itxn_field TypeEnum
int 2000
itxn_field Amount
txn Sender
itxn_field Receiver
itxn_submit
int 0`, optIn: true, fund: true},
		// Approval spends about 1000 opcodes on every call after creation.
		{name: "burner", approval: v5 + "txn ApplicationID\nbz ok\n" + csLoop(250) + "ok:\nint 1", clear: v5 + "int 1"},
	}
	if current {
		// Logs `global OpcodeBudget` (v6+): the pool a later sibling sees.
		apps = append(apps, csApp{name: "logger", approval: "#pragma version 6\nglobal OpcodeBudget\nitob\nlog\nint 1", clear: "#pragma version 6\nint 1"})
	}
	return apps
}

type csCall struct {
	app   string
	clear bool
}

type csScenarioDef struct {
	name  string
	calls []csCall
}

func csScenarios(current bool) []csScenarioDef {
	cs := func(app string) csCall { return csCall{app: app, clear: true} }
	call := func(app string) csCall { return csCall{app: app} }
	out := []csScenarioDef{
		{"csp_small_alone", []csCall{cs("csp_small")}},
		{"csp_big_alone", []csCall{cs("csp_big")}},
		{"csp_big_then_call", []csCall{cs("csp_big"), call("csp_small")}},
		{"burner_then_csp_small", []csCall{call("burner"), cs("csp_small")}},
		{"csp_inner_pay", []csCall{cs("csp_inner_pay")}},
		{"csp_pay_reject_then_balances", []csCall{cs("csp_pay_reject"), call("csp_pay_reject")}},
	}
	if current {
		out = append(out,
			csScenarioDef{"csp_small_then_logger", []csCall{cs("csp_small"), call("logger")}},
			csScenarioDef{"csp_big_then_logger", []csCall{cs("csp_big"), call("logger")}},
			csScenarioDef{"logger_alone", []csCall{call("logger")}},
		)
	}
	return out
}

func csPoolLedgerFor(proto protocol.ConsensusVersion, genesisID string) csPoolLedger {
	current := proto == protocol.ConsensusCurrentVersion
	params := config.Consensus[proto]
	var seed crypto.Seed
	for i := range seed {
		seed[i] = 0xC5
	}
	secrets := crypto.GenerateSignatureSecrets(seed)
	sender := basics.Address(secrets.SignatureVerifier)
	accts := map[basics.Address]basics.AccountData{
		sender: {Status: basics.Offline, MicroAlgos: basics.MicroAlgos{Raw: 1_000_000_000}},
		// A pool of exactly MinBalance gives a zero rewards rate.
		pool: {Status: basics.NotParticipating, MicroAlgos: basics.MicroAlgos{Raw: params.MinBalance}},
		sink: {Status: basics.NotParticipating, MicroAlgos: basics.MicroAlgos{Raw: 1_000_000}},
	}
	genesisHash := crypto.Hash([]byte(genesisID))
	gb := bookkeeping.MakeTimestampedGenesisBalances(accts, sink, pool, 0)
	genesis, err := bookkeeping.MakeGenesisBlock(proto, gb, genesisID, genesisHash)
	must(err)
	genesis.TxnCommitments, err = genesis.PaysetCommit()
	must(err)

	log := logging.NewLogger()
	log.SetLevel(logging.Warn)
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	initState := ledgercore.InitState{Block: genesis, Accounts: accts, GenesisHash: genesisHash}
	actual, err := ledger.OpenLedger(log, genesisID+"-ledger", true, initState, cfg)
	must(err)
	defer actual.Close()
	l := &data.Ledger{Ledger: actual}

	header := func(note string) transactions.Header {
		return transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: params.MinTxnFee},
			FirstValid:  1,
			LastValid:   1000,
			Note:        []byte(note),
			GenesisID:   genesisID,
			GenesisHash: genesisHash,
		}
	}
	assemble := func(src string) []byte {
		ops, err := logic.AssembleString(src)
		if err != nil {
			panic(fmt.Sprintf("%q does not assemble: %v", src, err))
		}
		return ops.Program
	}

	// Block 1: create every app, opt the sender in, fund the app accounts
	// that pay.
	hdr, err := l.BlockHdr(l.Latest())
	must(err)
	next := bookkeeping.MakeBlock(hdr).BlockHeader
	next.TimeStamp = 1_700_000_000 + int64(next.Round)*5
	ev, err := l.StartEvaluator(next, 0, 0, nil)
	must(err)
	apps := map[string]uint64{}
	counter := hdr.TxnCounter
	var follow []transactions.Transaction
	for _, a := range csApps(current) {
		create := transactions.Transaction{
			Type:   protocol.ApplicationCallTx,
			Header: header("create-" + a.name),
			ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
				ApprovalProgram:   assemble(a.approval),
				ClearStateProgram: assemble(a.clear),
			},
		}
		must(ev.TransactionGroup(transactions.SignedTxnWithAD{SignedTxn: create.Sign(secrets)}))
		counter++
		id := basics.AppIndex(counter)
		apps[a.name] = uint64(id)
		if a.optIn {
			follow = append(follow, transactions.Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: header("optin-" + a.name),
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID: id,
					OnCompletion:  transactions.OptInOC,
				},
			})
		}
		if a.fund {
			follow = append(follow, transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: header("fund-" + a.name),
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: id.Address(),
					Amount:   basics.MicroAlgos{Raw: 1_000_000},
				},
			})
		}
	}
	for _, t := range follow {
		must(ev.TransactionGroup(transactions.SignedTxnWithAD{SignedTxn: t.Sign(secrets)}))
	}
	ub, err := ev.GenerateBlock(nil)
	must(err)
	must(l.AddValidatedBlock(ledgercore.MakeValidatedBlock(ub.UnfinishedBlock(), ub.UnfinishedDeltas()), agreement.Certificate{}))
	blk, err := l.Block(l.Latest())
	must(err)

	out := csPoolLedger{
		Protocol:    string(proto),
		GenesisID:   genesisID,
		GenesisHash: b64(genesisHash[:]),
		FeeSink:     b64(sink[:]),
		RewardsPool: b64(pool[:]),
		Blocks:      []string{b64(protocol.Encode(&blk))},
		Apps:        apps,
	}
	for _, a := range []basics.Address{sender, pool, sink} {
		ad := accts[a]
		out.Accounts = append(out.Accounts, account{
			Addr:       b64(a[:]),
			Status:     ad.Status.String(),
			MicroAlgos: ad.MicroAlgos.Raw,
		})
	}

	sim := simulation.MakeSimulator(l, false)
	for _, sc := range csScenarios(current) {
		var txns []transactions.Transaction
		var hashes []crypto.Digest
		for i, c := range sc.calls {
			oc := transactions.NoOpOC
			if c.clear {
				oc = transactions.ClearStateOC
			}
			t := transactions.Transaction{
				Type:   protocol.ApplicationCallTx,
				Header: header(fmt.Sprintf("%s-%d", sc.name, i)),
				ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
					ApplicationID: basics.AppIndex(apps[c.app]),
					OnCompletion:  oc,
				},
			}
			txns = append(txns, t)
			hashes = append(hashes, crypto.Digest(t.ID()))
		}
		if len(txns) > 1 {
			gid := crypto.HashObj(transactions.TxGroup{TxGroupHashes: hashes})
			for i := range txns {
				txns[i].Group = gid
			}
		}
		var group []transactions.SignedTxn
		var enc []byte
		for i := range txns {
			stxn := transactions.SignedTxn{Txn: txns[i]}
			group = append(group, stxn)
			enc = append(enc, protocol.Encode(&stxn)...)
		}
		res, err := sim.Simulate(simulation.Request{
			TxnGroups:            [][]transactions.SignedTxn{group},
			AllowEmptySignatures: true,
		})
		must(err)
		g := res.TxnGroups[0]
		s := csPoolScenario{
			Name:              sc.name,
			GroupMsgpack:      b64(enc),
			FailureMessage:    g.FailureMessage,
			FailedAt:          []uint64{},
			AppBudgetAdded:    uint64(g.AppBudgetAdded),
			AppBudgetConsumed: uint64(g.AppBudgetConsumed),
		}
		for _, pos := range g.FailedAt {
			s.FailedAt = append(s.FailedAt, uint64(pos))
		}
		for _, tr := range g.Txns {
			t := csPoolTxn{
				AppBudgetConsumed: uint64(tr.AppBudgetConsumed),
				Logs:              []string{},
				InnerTxns:         len(tr.Txn.ApplyData.EvalDelta.InnerTxns),
			}
			for _, lg := range tr.Txn.ApplyData.EvalDelta.Logs {
				t.Logs = append(t.Logs, b64([]byte(lg)))
			}
			s.Txns = append(s.Txns, t)
		}
		out.Scenarios = append(out.Scenarios, s)
	}
	return out
}

func clearStatePoolOracle() {
	f := csPoolFixture{
		Comment: "Generated by tools/simulate-rewards-oracle (clearstatepool.go, issue #2499); do not edit by hand.",
		Ledgers: []csPoolLedger{
			csPoolLedgerFor(protocol.ConsensusCurrentVersion, "simulate-clearstate-pool-oracle-v1"),
			csPoolLedgerFor(protocol.ConsensusV30, "simulate-clearstate-pool-oracle-v30"),
		},
	}
	path := filepath.Join("..", "..", "crates", "core", "algo-ledger", "tests", "fixtures", "simulate_clearstate_pool", "oracle.json")
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	js, err := json.MarshalIndent(f, "", "  ")
	must(err)
	must(os.WriteFile(path, append(js, '\n'), 0o644))
	fmt.Println("wrote", path)
}
