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

// blockdup oracle: go-algorand oracle for issue #2127.
//
// go evaluates a block with `Validate: true` when it validates a proposal
// or a block it has not seen (`Ledger.Validate`, `eval.Eval(..., true,
// ...)`), and with `Validate: false` when it adds a certified block
// (`Ledger.AddBlock`, catchup). Only the validating evaluation runs
// `BlockEvaluator.transaction`'s `checkDup`, so a block that replays a
// committed transaction, repeats one, or reuses a live lease is rejected
// by `Validate` and accepted by `AddBlock`.
//
// This builds a real in-memory go-algorand ledger, commits block 1 (a
// signed payment and a signed leased payment from A), then hand-builds
// candidate blocks for round 2 and runs each through the real `Validate`
// and through `eval.Eval` with validate=false (which does not commit). The
// result is written to tests/fixtures/block_checkdup/oracle.json; the Rust
// side is crates/core/algo-ledger/tests/block_checkdup_oracle_test.rs.
package main

import (
	"context"
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
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/eval"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/execpool"
)

const blockDupGenesisID = "block-checkdup-oracle-v1"

type blockDupScenario struct {
	Name          string `json:"name"`
	Block         string `json:"block"`
	ValidateError string `json:"validate_error"`
	ReplayError   string `json:"replay_error"`
}

type blockDupFixture struct {
	Comment     string             `json:"_comment"`
	Protocol    string             `json:"protocol"`
	GenesisID   string             `json:"genesis_id"`
	GenesisHash string             `json:"genesis_hash"`
	FeeSink     string             `json:"fee_sink"`
	RewardsPool string             `json:"rewards_pool"`
	Accounts    []account          `json:"genesis_accounts"`
	Block1      string             `json:"block1"`
	Scenarios   []blockDupScenario `json:"scenarios"`
	// Issue #2129: a group whose members hold distinct leases; both
	// Validate and replay accept it.
	Control blockDupScenario `json:"control_distinct_leases"`
	// Issue #2129: the transaction-pool admission stage, as go's
	// data/pools runs it on its Generate+Validate block evaluator: the
	// per-transaction `TestTransactionGroup`, then `TransactionGroup`.
	Pool []blockDupPoolScenario `json:"pool"`
}

type blockDupPoolScenario struct {
	Name         string `json:"name"`
	GroupMsgpack string `json:"group_msgpack"`
	TestError    string `json:"test_error"`
	AddError     string `json:"add_error"`
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func blockDupOracle() {
	proto := protocol.ConsensusCurrentVersion
	params := config.Consensus[proto]
	var seed crypto.Seed
	for i := range seed {
		seed[i] = 0xA1
	}
	secrets := crypto.GenerateSignatureSecrets(seed)
	sender := basics.Address(secrets.SignatureVerifier)
	accts := map[basics.Address]basics.AccountData{
		sender: {Status: basics.Offline, MicroAlgos: basics.MicroAlgos{Raw: 1_000_000_000}},
		acctB:  {Status: basics.Offline, MicroAlgos: basics.MicroAlgos{Raw: 1_000_000_000}},
		pool:   {Status: basics.NotParticipating, MicroAlgos: basics.MicroAlgos{Raw: params.MinBalance}},
		sink:   {Status: basics.NotParticipating, MicroAlgos: basics.MicroAlgos{Raw: 1_000_000}},
	}
	genesisHash := crypto.Hash([]byte(blockDupGenesisID))
	gb := bookkeeping.MakeTimestampedGenesisBalances(accts, sink, pool, 0)
	genesis, err := bookkeeping.MakeGenesisBlock(proto, gb, blockDupGenesisID, genesisHash)
	must(err)
	genesis.TxnCommitments, err = genesis.PaysetCommit()
	must(err)

	log := logging.NewLogger()
	log.SetLevel(logging.Warn)
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	initState := ledgercore.InitState{Block: genesis, Accounts: accts, GenesisHash: genesisHash}
	actual, err := ledger.OpenLedger(log, blockDupGenesisID+"-ledger", true, initState, cfg)
	must(err)
	defer actual.Close()
	l := &data.Ledger{Ledger: actual}

	payTxn := func(note string, lease [32]byte) transactions.Transaction {
		return transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      sender,
				Fee:         basics.MicroAlgos{Raw: params.MinTxnFee},
				FirstValid:  1,
				LastValid:   1000,
				Note:        []byte(note),
				Lease:       lease,
				GenesisID:   blockDupGenesisID,
				GenesisHash: genesisHash,
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: acctB,
				Amount:   basics.MicroAlgos{Raw: 1_000_000},
			},
		}
	}
	pay := func(note string, lease [32]byte) transactions.SignedTxn {
		return payTxn(note, lease).Sign(secrets)
	}
	// One atomic group of signed payments (issue #2129): every member
	// carries the group ID computed over the members without it.
	grouped := func(txns ...transactions.Transaction) []transactions.SignedTxn {
		var hashes []crypto.Digest
		for _, t := range txns {
			hashes = append(hashes, crypto.Digest(t.ID()))
		}
		gid := crypto.HashObj(transactions.TxGroup{TxGroupHashes: hashes})
		out := make([]transactions.SignedTxn, len(txns))
		for i, t := range txns {
			t.Group = gid
			out[i] = t.Sign(secrets)
		}
		return out
	}
	var lease, freshLease, lease2 [32]byte
	for i := range lease {
		lease[i] = 0x11
		freshLease[i] = 0x66
		lease2[i] = 0x67
	}
	committed := pay("committed", [32]byte{})
	committedLeased := pay("committed-leased", lease)

	// Block 1, generated exactly as a proposer would.
	hdr0, err := l.BlockHdr(0)
	must(err)
	next := bookkeeping.MakeBlock(hdr0).BlockHeader
	next.TimeStamp = 1_700_000_005
	ev, err := l.StartEvaluator(next, 2, 0, nil)
	must(err)
	for _, s := range []transactions.SignedTxn{committed, committedLeased} {
		must(ev.TransactionGroup(transactions.SignedTxnWithAD{SignedTxn: s}))
	}
	ub, err := ev.GenerateBlock(nil)
	must(err)
	vb := ledgercore.MakeValidatedBlock(ub.UnfinishedBlock(), ub.UnfinishedDeltas())
	must(l.AddValidatedBlock(vb, agreement.Certificate{}))
	blk1, err := l.Block(1)
	must(err)

	f := blockDupFixture{
		Comment:     "Generated by tools/simulate-rewards-oracle (blockdup.go, issue #2127); do not edit by hand.",
		Protocol:    string(proto),
		GenesisID:   blockDupGenesisID,
		GenesisHash: b64(genesisHash[:]),
		FeeSink:     b64(sink[:]),
		RewardsPool: b64(pool[:]),
		Block1:      b64(protocol.Encode(&blk1)),
	}
	for _, a := range []basics.Address{sender, acctB, pool, sink} {
		ad := accts[a]
		f.Accounts = append(f.Accounts, account{
			Addr:       b64(a[:]),
			Status:     ad.Status.String(),
			MicroAlgos: ad.MicroAlgos.Raw,
		})
	}

	// A hand-built round-2 block carrying `payset` (each its own group).
	// Its header comes from an empty generated block (not committed), so
	// the rewards state is the one the evaluator expects.
	hdr1 := blk1.BlockHeader
	tmplHdr := bookkeeping.MakeBlock(hdr1).BlockHeader
	tmplHdr.TimeStamp = 1_700_000_010
	ev2, err := l.StartEvaluator(tmplHdr, 0, 0, nil)
	must(err)
	tmpl, err := ev2.GenerateBlock(nil)
	must(err)
	build := func(payset ...transactions.SignedTxn) bookkeeping.Block {
		blk := bookkeeping.Block{BlockHeader: tmpl.UnfinishedBlock().BlockHeader}
		for _, s := range payset {
			txib, err := blk.EncodeSignedTxn(s, transactions.ApplyData{})
			must(err)
			blk.Payset = append(blk.Payset, txib)
		}
		// The congestion load the payset implies (go `eval.ComputeLoad`), so
		// the header passes the stateless checks and the evaluation reaches
		// the transactions.
		size := 0
		for _, txib := range blk.Payset {
			size += txib.GetEncodedLength()
		}
		if params.LoadTracking {
			blk.Load = eval.ComputeLoad(size, params.MaxTxnBytesPerBlock)
		}
		blk.TxnCounter = hdr1.TxnCounter + uint64(len(payset))
		blk.TxnCommitments, err = blk.PaysetCommit()
		must(err)
		return blk
	}
	twice := pay("twice", [32]byte{})
	scenarios := []struct {
		name string
		blk  bookkeeping.Block
	}{
		// Block 1's payment again: its txid is in the txtail.
		{"committed_txid", build(committed)},
		// The same signed payment twice in one block.
		{"in_block_duplicate_txid", build(twice, twice)},
		// Two payments of one block sharing a fresh lease.
		{"in_block_lease_conflict", build(pay("lease-a", freshLease), pay("lease-b", freshLease))},
		// A new payment reusing block 1's lease, still in force.
		{"cross_block_lease_conflict", build(pay("new-leased", lease))},
		// Issue #2129: two members of ONE group sharing a fresh lease. go has
		// no stateless group-lease rule; only checkDup catches it.
		{"in_group_lease_conflict", build(grouped(payTxn("grp-a", freshLease), payTxn("grp-b", freshLease))...)},
	}
	// Issue #2129: the control, a group whose members hold distinct leases.
	// Generated as a proposer would (a hand-built header would not carry the
	// fees the payset collects), so go accepts it on both paths.
	controlHdr := bookkeeping.MakeBlock(hdr1).BlockHeader
	controlHdr.TimeStamp = 1_700_000_010
	cev, err := l.StartEvaluator(controlHdr, 2, 0, nil)
	must(err)
	var controlAD []transactions.SignedTxnWithAD
	for _, s := range grouped(payTxn("ok-a", freshLease), payTxn("ok-b", lease2)) {
		controlAD = append(controlAD, transactions.SignedTxnWithAD{SignedTxn: s})
	}
	must(cev.TransactionGroup(controlAD...))
	cub, err := cev.GenerateBlock(nil)
	must(err)
	controlOK := cub.FinishBlock(committee.Seed{}, sender, false)
	backlog := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlog.Shutdown()
	for _, sc := range scenarios {
		_, verr := l.Validate(context.Background(), sc.blk, backlog)
		_, rerr := eval.Eval(context.Background(), l, sc.blk, false, nil, nil, nil)
		f.Scenarios = append(f.Scenarios, blockDupScenario{
			Name:          sc.name,
			Block:         b64(protocol.Encode(&sc.blk)),
			ValidateError: errText(verr),
			ReplayError:   errText(rerr),
		})
	}

	{
		_, verr := l.Validate(context.Background(), controlOK, backlog)
		_, rerr := eval.Eval(context.Background(), l, controlOK, false, nil, nil, nil)
		f.Control = blockDupScenario{
			Name:          "in_group_distinct_leases",
			Block:         b64(protocol.Encode(&controlOK)),
			ValidateError: errText(verr),
			ReplayError:   errText(rerr),
		}
	}

	// Pool admission (issue #2129): a fresh Generate+Validate evaluator per
	// group, like the pool's pending-block evaluator. TestTransactionGroup
	// checks every member against the unmodified state (so it cannot see a
	// sibling's lease); TransactionGroup applies the members in order and
	// does.
	poolHdr := bookkeeping.MakeBlock(hdr1).BlockHeader
	poolHdr.TimeStamp = 1_700_000_010
	for _, ps := range []struct {
		name  string
		group []transactions.SignedTxn
	}{
		{"in_group_lease_conflict", grouped(payTxn("grp-a", freshLease), payTxn("grp-b", freshLease))},
		{"in_group_distinct_leases", grouped(payTxn("ok-a", freshLease), payTxn("ok-b", lease2))},
	} {
		pev, err := l.StartEvaluator(poolHdr, 0, 0, nil)
		must(err)
		terr := pev.TestTransactionGroup(ps.group)
		var withAD []transactions.SignedTxnWithAD
		var enc []byte
		for i := range ps.group {
			withAD = append(withAD, transactions.SignedTxnWithAD{SignedTxn: ps.group[i]})
			enc = append(enc, protocol.Encode(&ps.group[i])...)
		}
		aerr := pev.TransactionGroup(withAD...)
		f.Pool = append(f.Pool, blockDupPoolScenario{
			Name:         ps.name,
			GroupMsgpack: b64(enc),
			TestError:    errText(terr),
			AddError:     errText(aerr),
		})
	}

	path := filepath.Join("..", "..", "crates", "core", "algo-ledger", "tests", "fixtures", "block_checkdup", "oracle.json")
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	js, err := json.MarshalIndent(f, "", "  ")
	must(err)
	must(os.WriteFile(path, append(js, '\n'), 0o644))
	fmt.Println("wrote", path)
}
