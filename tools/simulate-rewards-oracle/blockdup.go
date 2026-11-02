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
	// Issue #2130: the pool evaluator's per-transaction order
	// (`Alive` -> `checkDup` -> authorizer -> apply) on groups whose members
	// fail at different stages.
	PoolOrder []blockDupOrderScenario `json:"pool_order"`
}

// blockDupOrderScenario is one pool-admission verdict: `Pre` groups are
// applied to a fresh Generate+Validate evaluator first (the pool's pending
// block), then go's `TestTransactionGroup` and `TransactionGroup` run on
// `Group`. Each transaction is one base64 msgpack `SignedTxn`.
type blockDupOrderScenario struct {
	Name      string     `json:"name"`
	Pre       [][]string `json:"pre"`
	Group     []string   `json:"group"`
	TestError string     `json:"test_error"`
	AddError  string     `json:"add_error"`
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
	// An account that sits above zero but below its minimum balance
	// (issue #2186): go's `checkMinBalance` only covers the accounts a
	// transaction actually modified, so a zero-amount payment to it passes.
	acctLow := addr(0x5A)
	accts := map[basics.Address]basics.AccountData{
		sender:  {Status: basics.Offline, MicroAlgos: basics.MicroAlgos{Raw: 1_000_000_000}},
		acctB:   {Status: basics.Offline, MicroAlgos: basics.MicroAlgos{Raw: 1_000_000_000}},
		acctLow: {Status: basics.Offline, MicroAlgos: basics.MicroAlgos{Raw: 50_000}},
		pool:    {Status: basics.NotParticipating, MicroAlgos: basics.MicroAlgos{Raw: params.MinBalance}},
		sink:    {Status: basics.NotParticipating, MicroAlgos: basics.MicroAlgos{Raw: 1_000_000}},
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
	for _, a := range []basics.Address{sender, acctB, acctLow, pool, sink} {
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
		if verr != nil || rerr != nil {
			panic(fmt.Sprintf("blockdup oracle: the distinct-lease control group must be accepted by both Validate and replay; Validate: %v, replay: %v", verr, rerr))
		}
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
		name         string
		group        []transactions.SignedTxn
		wantAddError bool
	}{
		{"in_group_lease_conflict", grouped(payTxn("grp-a", freshLease), payTxn("grp-b", freshLease)), true},
		{"in_group_distinct_leases", grouped(payTxn("ok-a", freshLease), payTxn("ok-b", lease2)), false},
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
		// The test stage never sees a sibling's lease; only the apply stage
		// does. Fail the generation if go's behaviour is not as pinned.
		if terr != nil || (aerr != nil) != ps.wantAddError {
			panic(fmt.Sprintf("blockdup oracle: pool scenario %s: TestTransactionGroup error %v (want none), TransactionGroup error %v (want error: %v)", ps.name, terr, aerr, ps.wantAddError))
		}
		f.Pool = append(f.Pool, blockDupPoolScenario{
			Name:         ps.name,
			GroupMsgpack: b64(enc),
			TestError:    errText(terr),
			AddError:     errText(aerr),
		})
	}

	// Issue #2130: the order go's `BlockEvaluator.transaction` runs its
	// checks in, per transaction: `Alive`, `checkDup`, the authorizer, then
	// the apply (fee and amount moves). A group whose members fail at
	// different stages is therefore reported for its FIRST failing member,
	// whatever the failing stage of a later one. Each scenario is evaluated
	// by a fresh Generate+Validate evaluator, like the pool's.
	var seed2 crypto.Seed
	for i := range seed2 {
		seed2[i] = 0xB2
	}
	secrets2 := crypto.GenerateSignatureSecrets(seed2)
	otherAuth := basics.Address(secrets2.SignatureVerifier)
	var leaseF, leaseP, leaseQ [32]byte
	for i := range leaseF {
		leaseF[i] = 0x71
		leaseP[i] = 0x72
		leaseQ[i] = 0x73
	}
	// wrongAuth signs with a key that is not the sender's authorizer.
	wrongAuth := func(t transactions.Transaction) transactions.SignedTxn {
		s := t.Sign(secrets2)
		s.AuthAddr = otherAuth
		return s
	}
	signAll := func(sign func(transactions.Transaction) transactions.SignedTxn, txns ...transactions.Transaction) []transactions.SignedTxn {
		var hashes []crypto.Digest
		for _, t := range txns {
			hashes = append(hashes, crypto.Digest(t.ID()))
		}
		gid := crypto.HashObj(transactions.TxGroup{TxGroupHashes: hashes})
		out := make([]transactions.SignedTxn, len(txns))
		for i, t := range txns {
			t.Group = gid
			out[i] = sign(t)
		}
		return out
	}
	good := func(t transactions.Transaction) transactions.SignedTxn { return t.Sign(secrets) }
	withAmount := func(t transactions.Transaction, amount uint64) transactions.Transaction {
		t.Amount = basics.MicroAlgos{Raw: amount}
		return t
	}
	withValidity := func(t transactions.Transaction, first, last uint64) transactions.Transaction {
		t.FirstValid = basics.Round(first)
		t.LastValid = basics.Round(last)
		return t
	}
	overspend := uint64(5_000_000_000)

	badAuthT := payTxn("order-bad-auth", [32]byte{})
	overT := withAmount(payTxn("order-overspend", [32]byte{}), overspend)
	twinT := payTxn("order-twin", [32]byte{})
	acfgFeeT := transactions.Transaction{
		Type: protocol.AssetConfigTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: overspend},
			FirstValid:  1,
			LastValid:   1000,
			Note:        []byte("order-acfg-fee"),
			GenesisID:   blockDupGenesisID,
			GenesisHash: genesisHash,
		},
		AssetConfigTxnFields: transactions.AssetConfigTxnFields{
			AssetParams: basics.AssetParams{Total: 1},
		},
	}
	// Leaves 50 microAlgos: below the minimum balance.
	minBalT := withAmount(payTxn("order-min-balance", [32]byte{}), 997_998_000-1000-50)
	// Issue #2186: a failing application call (the app does not exist), then
	// a payment that leaves the sender below the minimum balance. go applies
	// member 0 fully first, so member 0's error is the group's.
	badAppT := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: params.MinTxnFee},
			FirstValid:  1,
			LastValid:   1000,
			Note:        []byte("order-bad-app"),
			GenesisID:   blockDupGenesisID,
			GenesisHash: genesisHash,
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: 99999,
		},
	}
	minBalAfterAppT := withAmount(payTxn("order-min-balance-after-app", [32]byte{}), 997_998_000-2*1000-50)
	toLow := func(t transactions.Transaction, amount uint64) transactions.Transaction {
		t.Receiver = acctLow
		t.Amount = basics.MicroAlgos{Raw: amount}
		return t
	}
	type orderSpec struct {
		name  string
		pre   [][]transactions.SignedTxn
		group []transactions.SignedTxn
	}
	one := func(s transactions.SignedTxn) []transactions.SignedTxn { return []transactions.SignedTxn{s} }
	pending := pay("order-pending", leaseP)
	orderSpecs := []orderSpec{
		// member 0 fails the authorizer; member 1 repeats member 0 (a dup).
		{"auth_then_dup", nil, signAll(wrongAuth, badAuthT, badAuthT)},
		// member 0 overspends; member 1 repeats member 0.
		{"overspend_then_dup", nil, signAll(good, overT, overT)},
		// member 0 overspends under a fresh lease; member 1 reuses the lease.
		{"overspend_then_lease_conflict", nil, signAll(good,
			withAmount(payTxn("order-over-leased", leaseF), overspend), payTxn("order-lease-twin", leaseF))},
		// member 0 holds the lease; member 1 reuses it AND overspends.
		{"lease_conflict_then_overspend", nil, signAll(good,
			payTxn("order-lease-first", leaseF), withAmount(payTxn("order-lease-over", leaseF), overspend))},
		// member 0 reuses a lease block 1 holds; member 1 is not yet valid.
		{"ledger_lease_then_early", nil, signAll(good,
			payTxn("order-ledger-lease", lease), withValidity(payTxn("order-early", [32]byte{}), 5000, 6000))},
		// member 0 is fine; member 1 is not yet valid.
		{"early_member", nil, signAll(good,
			payTxn("order-fine", [32]byte{}), withValidity(payTxn("order-early", [32]byte{}), 5000, 6000))},
		// member 0 reuses a live ledger lease and has the wrong authorizer:
		// checkDup comes first.
		{"lease_conflict_before_authorizer", nil, one(wrongAuth(payTxn("order-lease-auth", lease)))},
		// member 0 has the wrong authorizer and overspends: authorizer first.
		{"authorizer_before_apply", nil, one(wrongAuth(overT))},
		// a replay of a committed transaction, alone.
		{"committed_txid", nil, one(committed)},
		// a transaction an earlier group of the pending block holds.
		{"pending_txid", [][]transactions.SignedTxn{one(pending)}, one(pending)},
		// a lease an earlier group of the pending block holds.
		{"pending_lease", [][]transactions.SignedTxn{one(pending)}, one(pay("order-pending-twin", leaseP))},
		// an expired transaction, alone (the pool also pre-checks LastValid).
		{"expired_alone", nil, one(good(withValidity(payTxn("order-expired", [32]byte{}), 1, 1)))},
		// member 0 reuses a live ledger lease; member 1 is expired.
		{"ledger_lease_then_expired", nil, signAll(good,
			payTxn("order-ledger-lease-2", lease), withValidity(payTxn("order-expired-2", [32]byte{}), 1, 1))},
		// the same transaction twice, nothing else wrong: go's TEST stage
		// cannot see a sibling (txid twin included), its apply stage can.
		{"in_group_txid_twin", nil, signAll(good, twinT, twinT)},
		// a non-payment member 0 whose fee exceeds the balance: the fee move
		// that opens its apply fails (the precheck models the fee only).
		{"non_payment_fee_overspend", nil, one(good(acfgFeeT))},
		// member 0 leaves the sender below the minimum balance (an apply-stage
		// failure the precheck does not model).
		{"min_balance_member0", nil, one(good(minBalT))},
		// ... and member 1 repeats it: member 0's apply failure ranks first.
		{"min_balance_then_dup", nil, signAll(good, minBalT, minBalT)},
		// member 0 is an application call that fails; member 1 would leave
		// the sender below the minimum balance: member 0's error ranks first.
		{"app_fail_then_min_balance", nil, signAll(good, badAppT, minBalAfterAppT)},
		// a zero-amount payment to an account below its minimum balance does
		// not modify it, so go accepts ...
		{"zero_amount_to_low_account", nil, one(good(toLow(payTxn("order-zero-low", [32]byte{}), 0)))},
		// ... while any positive amount modifies it and go rejects it.
		{"positive_amount_to_low_account", nil, one(good(toLow(payTxn("order-pos-low", [32]byte{}), 1)))},
		// control: a clean group.
		{"clean_group", nil, signAll(good, payTxn("order-clean-a", leaseQ), payTxn("order-clean-b", [32]byte{}))},
	}

	// Issue #2184: the gossip test stage. go's `txHandler.checkAlreadyCommitted`
	// calls `txPool.Test` (`TestTransactionGroup`) BEFORE any signature check,
	// so a group with several problems is reported for the first one in
	// Test's order: the group size, every member's well-formedness, then per
	// member `Alive` + `checkDup` + that member's group-ID consistency, then
	// the group's completeness. Only `test_error` is meaningful for these
	// rows: go's REST path (`verify.TxnGroup` first) and its apply stage order
	// the same checks differently.
	badSig := func(s transactions.SignedTxn) transactions.SignedTxn {
		s.Sig[0] ^= 0x01
		return s
	}
	// A validity window longer than MaxTxnLife is not well formed.
	tooLong := func(t transactions.Transaction) transactions.Transaction {
		return withValidity(t, 1, 100_000)
	}
	withGroup := func(s transactions.SignedTxn, g crypto.Digest) transactions.SignedTxn {
		t := s.Txn
		t.Group = g
		return t.Sign(secrets)
	}
	var bogusGroup crypto.Digest
	for i := range bogusGroup {
		bogusGroup[i] = 0xAB
	}
	var seventeen []transactions.Transaction
	for i := 0; i < 17; i++ {
		seventeen = append(seventeen, payTxn(fmt.Sprintf("order-big-%d", i), [32]byte{}))
	}
	pairLease := signAll(good, payTxn("g-ledger-lease", lease), payTxn("g-pair-b", [32]byte{}))
	pairExpired := signAll(good,
		withValidity(payTxn("g-expired", [32]byte{}), 1, 1), payTxn("g-pair-c", [32]byte{}))
	pairClean := signAll(good, payTxn("g-clean-a", [32]byte{}), payTxn("g-clean-b", [32]byte{}))
	orderSpecs = append(orderSpecs, []orderSpec{
		// a replayed transaction with a corrupted signature: Test never
		// looks at the signature, so it is the duplicate that is reported.
		{"gossip_badsig_dup", nil, one(badSig(committed))},
		// a corrupted signature alone: Test passes (verification comes later).
		{"gossip_badsig_alone", nil, one(badSig(pay("g-bad-sig", [32]byte{})))},
		// member 0 reuses a live ledger lease; member 1 lost its group.
		{"gossip_dup_then_inconsistent_group", nil,
			[]transactions.SignedTxn{pairLease[0], good(payTxn("g-pair-b", [32]byte{}))}},
		// member 0 is expired; member 1 lost its group.
		{"gossip_expired_then_inconsistent_group", nil,
			[]transactions.SignedTxn{pairExpired[0], good(payTxn("g-pair-c", [32]byte{}))}},
		// no transaction fails Alive/checkDup; member 1 lost its group.
		{"gossip_inconsistent_group_only", nil,
			[]transactions.SignedTxn{pairClean[0], good(payTxn("g-clean-b", [32]byte{}))}},
		// member 1 both reuses a live ledger lease and lost its group: its
		// testTransaction runs before its group check.
		{"gossip_member1_dup_and_inconsistent", nil,
			[]transactions.SignedTxn{pairClean[0], good(payTxn("g-ledger-lease-2", lease))}},
		// two ungrouped transactions submitted together.
		{"gossip_zero_group_in_group", nil,
			[]transactions.SignedTxn{good(payTxn("g-zero-a", [32]byte{})), good(payTxn("g-zero-b", [32]byte{}))}},
		// only the first member of a two-member group.
		{"gossip_incomplete_group", nil, one(pairClean[0])},
		// only the first member of a group, and it reuses a live ledger lease.
		{"gossip_dup_then_incomplete_group", nil, one(pairLease[0])},
		// a group ID no member set hashes to.
		{"gossip_bogus_group_id", nil, []transactions.SignedTxn{
			withGroup(good(payTxn("g-bogus-a", [32]byte{})), bogusGroup),
			withGroup(good(payTxn("g-bogus-b", [32]byte{})), bogusGroup)}},
		// member 0 is not well formed.
		{"gossip_malformed_member", nil, one(good(tooLong(payTxn("g-long", [32]byte{}))))},
		// member 0 reuses a live ledger lease; member 1 is not well formed:
		// WellFormed runs for every member before any testTransaction.
		{"gossip_dup_then_malformed", nil, []transactions.SignedTxn{
			pairLease[0], good(tooLong(payTxn("g-long-2", [32]byte{})))}},
		// one more than MaxTxGroupSize.
		{"gossip_group_too_large", nil, signAll(good, seventeen...)},
	}...)
	for _, os := range orderSpecs {
		pev, err := l.StartEvaluator(poolHdr, 0, 0, nil)
		must(err)
		enc := func(g []transactions.SignedTxn) []string {
			var out []string
			for i := range g {
				out = append(out, b64(protocol.Encode(&g[i])))
			}
			return out
		}
		sc := blockDupOrderScenario{Name: os.name, Group: enc(os.group)}
		for _, pre := range os.pre {
			var ad []transactions.SignedTxnWithAD
			for i := range pre {
				ad = append(ad, transactions.SignedTxnWithAD{SignedTxn: pre[i]})
			}
			must(pev.TransactionGroup(ad...))
			sc.Pre = append(sc.Pre, enc(pre))
		}
		sc.TestError = errText(pev.TestTransactionGroup(os.group))
		var ad []transactions.SignedTxnWithAD
		for i := range os.group {
			ad = append(ad, transactions.SignedTxnWithAD{SignedTxn: os.group[i]})
		}
		sc.AddError = errText(pev.TransactionGroup(ad...))
		f.PoolOrder = append(f.PoolOrder, sc)
	}

	path := filepath.Join("..", "..", "crates", "core", "algo-ledger", "tests", "fixtures", "block_checkdup", "oracle.json")
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	js, err := json.MarshalIndent(f, "", "  ")
	must(err)
	must(os.WriteFile(path, append(js, '\n'), 0o644))
	fmt.Println("wrote", path)
}
