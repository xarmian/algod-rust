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

package main

// Issue #2148: go's `Simulator.Simulate` serves `Request.Round` back to the
// tracker's dbRound, reading accounts, the rewards state and Totals as of that
// round. This oracle builds a real in-memory go ledger on a rewards-accruing
// chain (a large pool, so the level advances every block) whose third block
// spends most of the sender's balance, then simulates the same payment at
// rounds 1, 2 and 3 (the latest). The result of each (failure message and the
// rewards credited) goes to tests/fixtures/simulate_past_round/oracle.json; the
// Rust side is crates/core/algo-ledger/tests/simulate_past_round_oracle_test.rs.

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

const pastRoundGenesisID = "simulate-past-round-oracle-v1"

type pastRoundScenario struct {
	Name            string `json:"name"`
	Round           uint64 `json:"round"`
	Amount          uint64 `json:"amount"`
	GroupMsgpack    string `json:"group_msgpack"`
	LastRound       uint64 `json:"last_round"`
	FailureMessage  string `json:"failure_message"`
	SenderRewards   uint64 `json:"sender_rewards"`
	ReceiverRewards uint64 `json:"receiver_rewards"`
}

type pastRoundFixture struct {
	Comment     string              `json:"_comment"`
	Protocol    string              `json:"protocol"`
	GenesisID   string              `json:"genesis_id"`
	GenesisHash string              `json:"genesis_hash"`
	FeeSink     string              `json:"fee_sink"`
	RewardsPool string              `json:"rewards_pool"`
	Accounts    []account           `json:"genesis_accounts"`
	Blocks      []string            `json:"blocks"`
	Scenarios   []pastRoundScenario `json:"scenarios"`
}

func pastRoundOracle() {
	proto := protocol.ConsensusCurrentVersion
	params := config.Consensus[proto]
	var seed crypto.Seed
	for i := range seed {
		seed[i] = 0xB7
	}
	secrets := crypto.GenerateSignatureSecrets(seed)
	sender := basics.Address(secrets.SignatureVerifier)
	accts := map[basics.Address]basics.AccountData{
		sender: {Status: basics.Offline, MicroAlgos: basics.MicroAlgos{Raw: 1_000_000_000}},
		acctB:  {Status: basics.Offline, MicroAlgos: basics.MicroAlgos{Raw: 1_000_000_000}},
		// A rate of (pool - MinBalance) / RewardsRateRefreshInterval = 1e9
		// microAlgos per round over the 2000 reward units of the two accounts.
		pool: {Status: basics.NotParticipating, MicroAlgos: basics.MicroAlgos{Raw: 500_000_000_000_000 + params.MinBalance}},
		sink: {Status: basics.NotParticipating, MicroAlgos: basics.MicroAlgos{Raw: 1_000_000}},
	}
	genesisHash := crypto.Hash([]byte(pastRoundGenesisID))
	gb := bookkeeping.MakeTimestampedGenesisBalances(accts, sink, pool, 0)
	genesis, err := bookkeeping.MakeGenesisBlock(proto, gb, pastRoundGenesisID, genesisHash)
	must(err)
	genesis.TxnCommitments, err = genesis.PaysetCommit()
	must(err)

	log := logging.NewLogger()
	log.SetLevel(logging.Warn)
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	initState := ledgercore.InitState{Block: genesis, Accounts: accts, GenesisHash: genesisHash}
	actual, err := ledger.OpenLedger(log, pastRoundGenesisID+"-ledger", true, initState, cfg)
	must(err)
	defer actual.Close()
	l := &data.Ledger{Ledger: actual}

	payment := func(note string, amount uint64) transactions.Transaction {
		return transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      sender,
				Fee:         basics.MicroAlgos{Raw: params.MinTxnFee},
				FirstValid:  1,
				LastValid:   1000,
				Note:        []byte(note),
				GenesisID:   pastRoundGenesisID,
				GenesisHash: genesisHash,
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: acctB,
				Amount:   basics.MicroAlgos{Raw: amount},
			},
		}
	}

	// Blocks 1 and 2 are empty (the rewards level still advances); block 3
	// spends 800 Algo of the sender's 1000.
	for round := 1; round <= 3; round++ {
		hdr, err := l.BlockHdr(l.Latest())
		must(err)
		next := bookkeeping.MakeBlock(hdr).BlockHeader
		next.TimeStamp = 1_700_000_000 + int64(next.Round)*5
		ev, err := l.StartEvaluator(next, 1, 0, nil)
		must(err)
		if round == 3 {
			spend := payment("block-3-spend", 800_000_000).Sign(secrets)
			must(ev.TransactionGroup(transactions.SignedTxnWithAD{SignedTxn: spend}))
		}
		ub, err := ev.GenerateBlock(nil)
		must(err)
		must(l.AddValidatedBlock(ledgercore.MakeValidatedBlock(ub.UnfinishedBlock(), ub.UnfinishedDeltas()), agreement.Certificate{}))
	}
	latest := l.Latest()

	f := pastRoundFixture{
		Comment:     "Generated by tools/simulate-rewards-oracle (pastround.go, issue #2148); do not edit by hand.",
		Protocol:    string(proto),
		GenesisID:   pastRoundGenesisID,
		GenesisHash: b64(genesisHash[:]),
		FeeSink:     b64(sink[:]),
		RewardsPool: b64(pool[:]),
	}
	for _, a := range []basics.Address{sender, acctB, pool, sink} {
		ad := accts[a]
		f.Accounts = append(f.Accounts, account{
			Addr:       b64(a[:]),
			Status:     ad.Status.String(),
			MicroAlgos: ad.MicroAlgos.Raw,
		})
	}
	for r := basics.Round(1); r <= latest; r++ {
		blk, err := l.Block(r)
		must(err)
		f.Blocks = append(f.Blocks, b64(protocol.Encode(&blk)))
	}

	sim := simulation.MakeSimulator(l, false)
	// 500 Algo is affordable at every round here; each round credits different rewards
	// (the sender is credited rewards first); 100 000 microAlgos is affordable everywhere and
	// shows the rewards credited at each round's level.
	for _, sc := range []struct {
		name   string
		round  basics.Round
		amount uint64
	}{
		{"affordable_at_round_1", 1, 500_000_000},
		{"affordable_at_round_2", 2, 500_000_000},
		{"large_at_the_latest_round", latest, 500_000_000},
		{"small_at_round_1", 1, 100_000},
		{"small_at_round_2", 2, 100_000},
		{"small_at_the_latest_round", latest, 100_000},
	} {
		stxn := transactions.SignedTxn{Txn: payment("sim-"+sc.name, sc.amount)}
		res, err := sim.Simulate(simulation.Request{
			TxnGroups:            [][]transactions.SignedTxn{{stxn}},
			AllowEmptySignatures: true,
			Round:                sc.round,
		})
		must(err)
		g := res.TxnGroups[0]
		out := pastRoundScenario{
			Name:           sc.name,
			Round:          uint64(sc.round),
			Amount:         sc.amount,
			GroupMsgpack:   b64(protocol.Encode(&stxn)),
			LastRound:      uint64(res.LastRound),
			FailureMessage: g.FailureMessage,
		}
		if len(g.Txns) > 0 {
			ad := g.Txns[0].Txn.ApplyData
			out.SenderRewards = ad.SenderRewards.Raw
			out.ReceiverRewards = ad.ReceiverRewards.Raw
		}
		f.Scenarios = append(f.Scenarios, out)
	}

	path := filepath.Join("..", "..", "crates", "core", "algo-ledger", "tests", "fixtures", "simulate_past_round", "oracle.json")
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	js, err := json.MarshalIndent(f, "", "  ")
	must(err)
	must(os.WriteFile(path, append(js, '\n'), 0o644))
	fmt.Println("wrote", path)
}
