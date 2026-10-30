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
// (the lease over rounds [current-MaxTxnLife, current], then the txid). go's
// simulate runs that evaluator, so simulating a transaction that is already
// in a block fails.
//
// This builds a real in-memory go-algorand ledger and commits three blocks
// of payments from A:
//
//	block 1: "committed" (plain), "committed-leased" (lease 0x11..) and
//	         "below-leased" (lease 0x55.., valid until 1 + MaxTxnLife)
//	block 2: "edge" (plain) and "edge-leased" (lease 0x44..), both valid
//	         until round 2 + MaxTxnLife
//	block 3: "late" (lease 0x33..)
//
// Stage "A" simulates at latest = 3 (some scenarios at the past round 1).
// Stage "B" first appends empty blocks up to round 2 + MaxTxnLife - 1, so
// the simulated round is 2 + MaxTxnLife and block 2 sits exactly on the
// round - MaxTxnLife boundary of go's lease scan. Stage "C" adds two rounds
// and simulates at that same round as a past round. Every scenario goes
// through the real, unmodified `Simulator`. The result is written to
// tests/fixtures/simulate_checkdup/oracle.json; the Rust side is
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
	Stage          string   `json:"stage"`
	Round          uint64   `json:"round"`
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
	MaxTxnLife  uint64             `json:"max_txn_life"`
	Accounts    []account          `json:"genesis_accounts"`
	Blocks      []string           `json:"blocks"`
	StageBLast  uint64             `json:"stage_b_latest"`
	StageCLast  uint64             `json:"stage_c_latest"`
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
	actual, err := ledger.OpenLedger(log, checkDupGenesisID+"-ledger", true, initState, cfg)
	must(err)
	defer actual.Close()
	l := &data.Ledger{Ledger: actual}

	maxLife := basics.Round(params.MaxTxnLife)
	leaseOf := func(b byte) (out [32]byte) {
		for i := range out {
			out[i] = b
		}
		return
	}
	lease, lease2, lateLease, edgeLease := leaseOf(0x11), leaseOf(0x22), leaseOf(0x33), leaseOf(0x44)
	belowLease := leaseOf(0x55)
	payIn := func(note string, l [32]byte, fv, lv basics.Round) transactions.Transaction {
		return transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      acctA,
				Fee:         basics.MicroAlgos{Raw: params.MinTxnFee},
				FirstValid:  fv,
				LastValid:   lv,
				Note:        []byte(note),
				Lease:       l,
				GenesisID:   checkDupGenesisID,
				GenesisHash: genesisHash,
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: acctB,
				Amount:   basics.MicroAlgos{Raw: 1_000_000},
			},
		}
	}
	pay := func(note string, l [32]byte) transactions.Transaction { return payIn(note, l, 1, 1000) }
	committed := pay("committed", [32]byte{})
	committedLeased := pay("committed-leased", lease)
	edge := payIn("edge", [32]byte{}, 2, 2+maxLife)
	edgeLeased := payIn("edge-leased", edgeLease, 2, 2+maxLife)
	late := pay("late", lateLease)
	// Leased in round 1, in force until round 1 + MaxTxnLife.
	belowLeased := payIn("below-leased", belowLease, 1, 1+maxLife)

	// Each block is generated exactly as a proposer would.
	addBlock := func(txns ...transactions.Transaction) bookkeeping.Block {
		hdr, err := l.BlockHdr(l.Latest())
		must(err)
		next := bookkeeping.MakeBlock(hdr).BlockHeader
		next.TimeStamp = 1_700_000_000 + int64(next.Round)*5
		ev, err := l.StartEvaluator(next, len(txns), 0, nil)
		must(err)
		for _, t := range txns {
			must(ev.TransactionGroup(transactions.SignedTxnWithAD{SignedTxn: transactions.SignedTxn{Txn: t}}))
		}
		ub, err := ev.GenerateBlock(nil)
		must(err)
		vb := ledgercore.MakeValidatedBlock(ub.UnfinishedBlock(), ub.UnfinishedDeltas())
		must(l.AddValidatedBlock(vb, agreement.Certificate{}))
		blk, err := l.Block(l.Latest())
		must(err)
		return blk
	}

	f := checkDupFixture{
		Comment:     "Generated by tools/simulate-rewards-oracle (checkdup.go, issue #2125); do not edit by hand.",
		Protocol:    string(proto),
		GenesisID:   checkDupGenesisID,
		GenesisHash: b64(genesisHash[:]),
		FeeSink:     b64(sink[:]),
		RewardsPool: b64(pool[:]),
		MaxTxnLife:  params.MaxTxnLife,
	}
	for _, txns := range [][]transactions.Transaction{{committed, committedLeased, belowLeased}, {edge, edgeLeased}, {late}} {
		blk := addBlock(txns...)
		f.Blocks = append(f.Blocks, b64(protocol.Encode(&blk)))
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

	type scenario struct {
		name  string
		round basics.Round
		group []transactions.SignedTxn
	}
	sim := simulation.MakeSimulator(l, false)
	run := func(stage string, scenarios []scenario) {
		for _, sc := range scenarios {
			var enc []byte
			for i := range sc.group {
				enc = append(enc, protocol.Encode(&sc.group[i])...)
			}
			res, err := sim.Simulate(simulation.Request{
				Round:                sc.round,
				TxnGroups:            [][]transactions.SignedTxn{sc.group},
				AllowEmptySignatures: true,
			})
			must(err)
			g := res.TxnGroups[0]
			out := checkDupScenario{
				Name:           sc.name,
				Stage:          stage,
				Round:          uint64(sc.round),
				GroupMsgpack:   b64(enc),
				FailureMessage: g.FailureMessage,
				FailedAt:       []uint64{},
			}
			for _, p := range g.FailedAt {
				out.FailedAt = append(out.FailedAt, uint64(p))
			}
			f.Scenarios = append(f.Scenarios, out)
		}
	}

	run("A", []scenario{
		// The committed payment again, two blocks back: its txid is in the txtail.
		{"committed_txid", 0, single(committed)},
		// The committed leased payment again: the lease is checked first.
		{"committed_txid_with_lease", 0, single(committedLeased)},
		// A new payment reusing the committed lease.
		{"committed_lease", 0, single(pay("new-leased", lease))},
		// checkDup runs before the authorizer check.
		{"committed_txid_wrong_authorizer", 0, wrongAuth(single(committed))},
		{"committed_lease_wrong_authorizer", 0, wrongAuth(single(pay("new-leased", lease)))},
		// The same transaction twice in one group.
		{"group_duplicate_txid", 0, grouped(pay("twice", [32]byte{}), pay("twice", [32]byte{}))},
		// Two transactions of one group sharing a fresh lease.
		{"group_duplicate_lease", 0, grouped(pay("lease-a", lease2), pay("lease-b", lease2))},
		// Past round 1 (simulated round 2): the txid check reads today's
		// txtail, so a txn committed in round 3 is still a duplicate...
		{"past_round_txid_committed_later", 1, single(late)},
		// ...but the lease scan stops at the simulated round, so a lease
		// committed in round 3 is not in force...
		{"past_round_lease_committed_later", 1, single(pay("past-new", lateLease))},
		// ...while one committed in round 1 is.
		{"past_round_lease_committed_before", 1, single(pay("past-new", lease))},
		// Control: a new payment succeeds.
		{"fresh", 0, single(pay("fresh", [32]byte{}))},
	})

	// Stage B: the simulated round becomes 2 + MaxTxnLife.
	for l.Latest() < 1+maxLife {
		addBlock()
	}
	f.StageBLast = uint64(l.Latest())
	simRound := l.Latest() + 1
	run("B", []scenario{
		// Committed in round 2 = simulated round - MaxTxnLife.
		{"edge_txid", 0, single(edge)},
		// Leased in round 2, the first round of go's lease scan.
		{"edge_lease", 0, single(payIn("edge-new", edgeLease, simRound, simRound))},
		{"edge_fresh", 0, single(payIn("edge-fresh", [32]byte{}, simRound, simRound))},
	})

	// Stage C: two more rounds, then the past round 2 + MaxTxnLife - 1, so
	// the simulated round is again 2 + MaxTxnLife (go only keeps a few
	// rounds of account history for a past-round simulate).
	for l.Latest() < 3+maxLife {
		addBlock()
	}
	f.StageCLast = uint64(l.Latest())
	pastRound := 1 + maxLife
	pastSim := pastRound + 1
	pastLast := pastSim + maxLife
	run("C", []scenario{
		// A LastValid below the txtail's low-water mark (the latest
		// round): go's txTail cannot answer and fails the check.
		{"past_round_last_valid_below_latest", pastRound, single(payIn("past-short", [32]byte{}, pastSim, pastSim))},
		// Leased in round 2 = simulated round - MaxTxnLife, until round
		// 2 + MaxTxnLife. The scan window [round - MaxTxnLife, round]
		// would include it, but go's txTail.recent has already pruned
		// round 2 (it keeps only latest - MaxTxnLife = 3 onward), so the
		// lease is not seen and the payment succeeds.
		{"past_window_lease_at_edge", pastRound, single(payIn("past-edge-new", edgeLease, pastSim, pastLast))},
		// Leased in round 1, one round below the window: it expired at
		// 1 + MaxTxnLife, so it is not in force.
		{"past_window_lease_below_edge", pastRound, single(payIn("past-below-new", belowLease, pastSim, pastLast))},
	})

	path := filepath.Join("..", "..", "crates", "core", "algo-ledger", "tests", "fixtures", "simulate_checkdup", "oracle.json")
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	js, err := json.MarshalIndent(f, "", "  ")
	must(err)
	must(os.WriteFile(path, append(js, '\n'), 0o644))
	fmt.Println("wrote", path)
}
