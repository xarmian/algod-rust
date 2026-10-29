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

// checkdup oracle: go-algorand oracle for issue #2125.
//
// Under `Validate: true`, go's `BlockEvaluator.transaction`
// (ledger/eval/eval.go) runs `BlockHeader.Alive`, then
// `cow.checkDup(FirstValid, LastValid, txid, Txlease{Sender, Lease})`, then
// the authorizer check. checkDup looks at the group's own earlier
// transactions first (the txid, then the lease), then at the ledger's txtail
// (the lease, then the txid). go's simulate runs that evaluator, so
// simulating a transaction that is already in a block fails.
//
// This builds a real in-memory go-algorand ledger, commits one block with
// two payments from A (one plain, one with a lease), and simulates each
// scenario below through the real, unmodified `Simulator`. It writes the
// genesis, the committed block and every scenario's result to
// tests/fixtures/simulate_checkdup/oracle.json. The Rust side is
// crates/core/algo-ledger/tests/simulation_checkdup_oracle_test.rs.
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
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/simulation"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

const checkDupGenesisID = "simulate-checkdup-oracle-v1"

type checkDupScenario struct {
	Name           string   `json:"name"`
	GroupMsgpack   string   `json:"group_msgpack"`
	FailureMessage string   `json:"failure_message"`
	FailedAt       []uint64 `json:"failed_at"`
}

type checkDupFixture struct {
	Comment     string             `json:"_comment"`
	Protocol    string             `json:"protocol"`
	GenesisID   string             `json:"genesis_id"`
	GenesisHash string             `json:"genesis_hash"`
	FeeSink     string             `json:"fee_sink"`
	RewardsPool string             `json:"rewards_pool"`
	Accounts    []account          `json:"genesis_accounts"`
	Block       string             `json:"block"`
	Scenarios   []checkDupScenario `json:"scenarios"`
}

func checkDupOracle() {
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
	genesisHash := crypto.Hash([]byte(checkDupGenesisID))
	gb := bookkeeping.MakeTimestampedGenesisBalances(accts, sink, pool, 0)
	genesis, err := bookkeeping.MakeGenesisBlock(proto, gb, checkDupGenesisID, genesisHash)
	must(err)
	genesis.TxnCommitments, err = genesis.PaysetCommit()
	must(err)

	log := logging.NewLogger()
	log.SetLevel(logging.Warn)
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	initState := ledgercore.InitState{Block: genesis, Accounts: accts, GenesisHash: genesisHash}
	real, err := ledger.OpenLedger(log, checkDupGenesisID+"-ledger", true, initState, cfg)
	must(err)
	defer real.Close()
	l := &data.Ledger{Ledger: real}

	header := transactions.Header{
		Sender:      acctA,
		Fee:         basics.MicroAlgos{Raw: params.MinTxnFee},
		FirstValid:  1,
		LastValid:   1000,
		GenesisID:   checkDupGenesisID,
		GenesisHash: genesisHash,
	}
	var lease, lease2 [32]byte
	for i := range lease {
		lease[i] = 0x11
		lease2[i] = 0x22
	}
	pay := func(note string, l [32]byte) transactions.Transaction {
		h := header
		h.Note = []byte(note)
		h.Lease = l
		return transactions.Transaction{
			Type:   protocol.PaymentTx,
			Header: h,
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: acctB,
				Amount:   basics.MicroAlgos{Raw: 1_000_000},
			},
		}
	}
	committed := pay("committed", [32]byte{})
	committedLeased := pay("committed-leased", lease)

	// Block 1 carries both payments, generated exactly as a proposer would.
	hdr0, err := l.BlockHdr(0)
	must(err)
	next := bookkeeping.MakeBlock(hdr0).BlockHeader
	next.TimeStamp = 1_700_000_005
	ev, err := l.StartEvaluator(next, 2, 0, nil)
	must(err)
	for _, t := range []transactions.Transaction{committed, committedLeased} {
		must(ev.TransactionGroup(transactions.SignedTxnWithAD{SignedTxn: transactions.SignedTxn{Txn: t}}))
	}
	ub, err := ev.GenerateBlock(nil)
	must(err)
	vb := ledgercore.MakeValidatedBlock(ub.UnfinishedBlock(), ub.UnfinishedDeltas())
	must(l.AddValidatedBlock(vb, agreement.Certificate{}))
	blk1, err := l.Block(1)
	must(err)

	f := checkDupFixture{
		Comment:     "Generated by tools/simulate-rewards-oracle (checkdup.go, issue #2125); do not edit by hand.",
		Protocol:    string(proto),
		GenesisID:   checkDupGenesisID,
		GenesisHash: b64(genesisHash[:]),
		FeeSink:     b64(sink[:]),
		RewardsPool: b64(pool[:]),
		Block:       b64(protocol.Encode(&blk1)),
	}
	for _, a := range []basics.Address{acctA, acctB, acctC, pool, sink} {
		ad := accts[a]
		f.Accounts = append(f.Accounts, account{
			Addr:       b64(a[:]),
			Status:     ad.Status.String(),
			MicroAlgos: ad.MicroAlgos.Raw,
		})
	}

	grouped := func(txns ...transactions.Transaction) []transactions.SignedTxn {
		var hashes []crypto.Digest
		for _, t := range txns {
			hashes = append(hashes, crypto.Digest(t.ID()))
		}
		gid := crypto.HashObj(transactions.TxGroup{TxGroupHashes: hashes})
		out := make([]transactions.SignedTxn, len(txns))
		for i, t := range txns {
			t.Group = gid
			out[i] = transactions.SignedTxn{Txn: t}
		}
		return out
	}
	single := func(t transactions.Transaction) []transactions.SignedTxn {
		return []transactions.SignedTxn{{Txn: t}}
	}
	wrongAuth := func(g []transactions.SignedTxn) []transactions.SignedTxn {
		g[0].AuthAddr = acctC
		return g
	}

	scenarios := []struct {
		name  string
		group []transactions.SignedTxn
	}{
		// The committed payment again: its txid is in the txtail.
		{"committed_txid", single(committed)},
		// The committed leased payment again: the lease is checked first.
		{"committed_txid_with_lease", single(committedLeased)},
		// A new payment reusing the committed lease.
		{"committed_lease", single(pay("new-leased", lease))},
		// checkDup runs before the authorizer check.
		{"committed_txid_wrong_authorizer", wrongAuth(single(committed))},
		{"committed_lease_wrong_authorizer", wrongAuth(single(pay("new-leased", lease)))},
		// The same transaction twice in one group.
		{"group_duplicate_txid", grouped(pay("twice", [32]byte{}), pay("twice", [32]byte{}))},
		// Two transactions of one group sharing a fresh lease.
		{"group_duplicate_lease", grouped(pay("lease-a", lease2), pay("lease-b", lease2))},
		// Control: a new payment succeeds.
		{"fresh", single(pay("fresh", [32]byte{}))},
	}
	sim := simulation.MakeSimulator(l, false)
	for _, sc := range scenarios {
		var enc []byte
		for i := range sc.group {
			enc = append(enc, protocol.Encode(&sc.group[i])...)
		}
		res, err := sim.Simulate(simulation.Request{TxnGroups: [][]transactions.SignedTxn{sc.group}, AllowEmptySignatures: true})
		must(err)
		g := res.TxnGroups[0]
		out := checkDupScenario{
			Name:           sc.name,
			GroupMsgpack:   b64(enc),
			FailureMessage: g.FailureMessage,
			FailedAt:       []uint64{},
		}
		for _, p := range g.FailedAt {
			out.FailedAt = append(out.FailedAt, uint64(p))
		}
		f.Scenarios = append(f.Scenarios, out)
	}

	path := filepath.Join("..", "..", "crates", "core", "algo-ledger", "tests", "fixtures", "simulate_checkdup", "oracle.json")
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	js, err := json.MarshalIndent(f, "", "  ")
	must(err)
	must(os.WriteFile(path, append(js, '\n'), 0o644))
	fmt.Println("wrote", path)
}
