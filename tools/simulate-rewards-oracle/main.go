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

// simulate-rewards-oracle: go-algorand oracle for issue #2118.
//
// go's `Simulator.Simulate` (ledger/simulation/simulator.go) evaluates the
// simulated group in a block built by `bookkeeping.MakeBlock(prevHdr)` with
// `Generate: true`, so `eval.StartEvaluator` (ledger/eval/eval.go) gives
// that block `prevHdr.NextRewardsState(...)` and withdraws the block's
// rewards from the pool before the group runs. On a chain with a non-zero
// rewards rate this changes every rewards claim (ApplyData rs/rr/rc), the
// balances the AVM sees and closing amounts.
//
// This tool builds a real in-memory go-algorand ledger whose genesis pool
// funds a non-zero rewards rate, generates two empty blocks, then simulates
// a three-transaction group through the real, unmodified `Simulator`:
//
//	txn 0: B creates an app that logs balance(A), min_balance(A),
//	       AcctBalance(pool), AcctBalance(A), balance(B);
//	txn 1: A pays B 1 Algo and closes to C;
//	txn 2: valid only from round latest+1 (the simulated block), B creates
//	       an app that logs, for the now-closed A, acct_params_get
//	       AcctBalance (exists flag, value), AcctMinBalance (exists flag,
//	       value) and balance, then global Round.
//
// It writes the ledger state the Rust test must seed (latest header rewards
// state, account data without rewards, txn counter) plus the simulate
// result to tests/fixtures/simulate_rewards/oracle.json. The Rust side is
// crates/core/algo-ledger/tests/simulation_rewards_oracle_test.rs.
//
// The same run also writes the issue #2125 duplicate-txid / lease oracle,
// tests/fixtures/simulate_checkdup/oracle.json (see checkdup.go).
// And the issue #2127 block-validation oracle,
// tests/fixtures/block_checkdup/oracle.json (see blockdup.go).
//
// Regenerate (needs cgo + the vendored libsodium: `make libsodium` in the
// go-algorand checkout first):
//
//	cd tools/simulate-rewards-oracle && go run .
package main

import (
	"encoding/base64"
	"encoding/binary"
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

const genesisID = "simulate-rewards-oracle-v1"

func addr(b byte) basics.Address {
	var a basics.Address
	for i := range a {
		a[i] = b
	}
	return a
}

var (
	acctA = addr(0x0A)
	acctB = addr(0x0B)
	acctC = addr(0x0C)
	pool  = addr(0xEE)
	sink  = addr(0xFE)
)

const approvalSrc = `#pragma version 10
txna Accounts 1
balance
itob
log
txna Accounts 1
min_balance
itob
log
txna Accounts 2
acct_params_get AcctBalance
assert
itob
log
txna Accounts 1
acct_params_get AcctBalance
assert
itob
log
txn Sender
balance
itob
log
int 1
`

const closedSrc = `#pragma version 10
txna Accounts 1
acct_params_get AcctBalance
itob
log
itob
log
txna Accounts 1
acct_params_get AcctMinBalance
itob
log
itob
log
txna Accounts 1
balance
itob
log
global Round
itob
log
int 1
`

const clearSrc = "#pragma version 10\nint 1\n"

type rewardsState struct {
	Level       uint64 `json:"rewards_level"`
	Rate        uint64 `json:"rewards_rate"`
	Residue     uint64 `json:"rewards_residue"`
	RecalcRound uint64 `json:"rewards_recalculation_round"`
}

type account struct {
	Addr               string `json:"addr"`
	Status             string `json:"status"`
	MicroAlgos         uint64 `json:"micro_algos"`
	RewardsBase        uint64 `json:"rewards_base"`
	RewardedMicroAlgos uint64 `json:"rewarded_micro_algos"`
}

type txnResult struct {
	SenderRewards   uint64   `json:"sender_rewards"`
	ReceiverRewards uint64   `json:"receiver_rewards"`
	CloseRewards    uint64   `json:"close_rewards"`
	ClosingAmount   uint64   `json:"closing_amount"`
	ApplicationID   uint64   `json:"application_id"`
	Logs            []uint64 `json:"logs"`
}

type fixture struct {
	Comment          string       `json:"_comment"`
	Protocol         string       `json:"protocol"`
	GenesisID        string       `json:"genesis_id"`
	GenesisHash      string       `json:"genesis_hash"`
	Round            uint64       `json:"round"`
	TxnCounter       uint64       `json:"txn_counter"`
	FeeSink          string       `json:"fee_sink"`
	RewardsPool      string       `json:"rewards_pool"`
	RewardsState     rewardsState `json:"rewards_state"`
	NextRewardsState rewardsState `json:"next_rewards_state"`
	RewardUnits      uint64       `json:"reward_units"`
	Accounts         []account    `json:"accounts"`
	PrevHeader       string       `json:"prev_header"`
	GroupMsgpack     string       `json:"group_msgpack"`
	LastRound        uint64       `json:"last_round"`
	FailureMessage   string       `json:"failure_message"`
	Txns             []txnResult  `json:"txns"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func rs(s bookkeeping.RewardsState) rewardsState {
	return rewardsState{s.RewardsLevel, s.RewardsRate, s.RewardsResidue, uint64(s.RewardsRecalculationRound)}
}

func main() {
	proto := protocol.ConsensusCurrentVersion
	params := config.Consensus[proto]
	accts := map[basics.Address]basics.AccountData{
		acctA: {Status: basics.Offline, MicroAlgos: basics.MicroAlgos{Raw: 1_000_000_000}},
		acctB: {Status: basics.Offline, MicroAlgos: basics.MicroAlgos{Raw: 1_000_000_000}},
		acctC: {Status: basics.Offline, MicroAlgos: basics.MicroAlgos{Raw: 10_000_000}},
		// A rate of (pool - MinBalance) / RewardsRateRefreshInterval
		// = 5e14 / 5e5 = 1e9 microAlgos per round over 2010 reward units.
		pool: {Status: basics.NotParticipating, MicroAlgos: basics.MicroAlgos{Raw: 500_000_000_000_000 + params.MinBalance}},
		sink: {Status: basics.NotParticipating, MicroAlgos: basics.MicroAlgos{Raw: 1_000_000}},
	}
	genesisHash := crypto.Hash([]byte(genesisID))
	gb := bookkeeping.MakeTimestampedGenesisBalances(accts, sink, pool, 0)
	blk, err := bookkeeping.MakeGenesisBlock(proto, gb, genesisID, genesisHash)
	must(err)
	blk.TxnCommitments, err = blk.PaysetCommit()
	must(err)

	log := logging.NewLogger()
	log.SetLevel(logging.Warn)
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	initState := ledgercore.InitState{Block: blk, Accounts: accts, GenesisHash: genesisHash}
	real, err := ledger.OpenLedger(log, genesisID, true, initState, cfg)
	must(err)
	defer real.Close()
	l := &data.Ledger{Ledger: real}

	// Two empty blocks, generated exactly as a proposer would.
	for i := 0; i < 2; i++ {
		hdr, err := l.BlockHdr(l.Latest())
		must(err)
		next := bookkeeping.MakeBlock(hdr).BlockHeader
		// A fixed timestamp keeps the recorded header deterministic.
		next.TimeStamp = 1_700_000_000 + int64(next.Round)*5
		ev, err := l.StartEvaluator(next, 0, 0, nil)
		must(err)
		ub, err := ev.GenerateBlock(nil)
		must(err)
		vb := ledgercore.MakeValidatedBlock(ub.UnfinishedBlock(), ub.UnfinishedDeltas())
		must(l.AddValidatedBlock(vb, agreement.Certificate{}))
	}

	latest := l.Latest()
	hdr, err := l.BlockHdr(latest)
	must(err)
	totals, err := l.Totals(latest)
	must(err)

	f := fixture{
		Comment:      "Generated by tools/simulate-rewards-oracle (issue #2118); do not edit by hand.",
		Protocol:     string(hdr.CurrentProtocol),
		GenesisID:    genesisID,
		GenesisHash:  b64(genesisHash[:]),
		Round:        uint64(latest),
		TxnCounter:   hdr.TxnCounter,
		FeeSink:      b64(sink[:]),
		RewardsPool:  b64(pool[:]),
		RewardsState: rs(hdr.RewardsState),
		RewardUnits:  totals.RewardUnits(),
	}
	f.PrevHeader = b64(protocol.Encode(&hdr))
	poolData, _, err := l.LookupWithoutRewards(latest, pool)
	must(err)
	poolBal := poolData.WithUpdatedRewards(params.RewardUnit, hdr.RewardsLevel).MicroAlgos
	f.NextRewardsState = rs(hdr.NextRewardsState(latest+1, params, poolBal, totals.RewardUnits(), log))

	for _, a := range []basics.Address{acctA, acctB, acctC, pool, sink} {
		ad, _, err := l.LookupWithoutRewards(latest, a)
		must(err)
		f.Accounts = append(f.Accounts, account{
			Addr:               b64(a[:]),
			Status:             ad.Status.String(),
			MicroAlgos:         ad.MicroAlgos.Raw,
			RewardsBase:        ad.RewardsBase,
			RewardedMicroAlgos: ad.RewardedMicroAlgos.Raw,
		})
	}

	approval, err := logic.AssembleString(approvalSrc)
	must(err)
	clear, err := logic.AssembleString(clearSrc)
	must(err)
	closed, err := logic.AssembleString(closedSrc)
	must(err)
	header := transactions.Header{
		Fee:         basics.MicroAlgos{Raw: params.MinTxnFee},
		FirstValid:  1,
		LastValid:   1000,
		GenesisID:   genesisID,
		GenesisHash: genesisHash,
	}
	h0 := header
	h0.Sender = acctB
	t0 := transactions.Transaction{
		Type:   protocol.ApplicationCallTx,
		Header: h0,
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApprovalProgram:   approval.Program,
			ClearStateProgram: clear.Program,
			Accounts:          []basics.Address{acctA, pool},
		},
	}
	h1 := header
	h1.Sender = acctA
	t1 := transactions.Transaction{
		Type:   protocol.PaymentTx,
		Header: h1,
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver:         acctB,
			Amount:           basics.MicroAlgos{Raw: 1_000_000},
			CloseRemainderTo: acctC,
		},
	}
	h2 := header
	h2.Sender = acctB
	h2.FirstValid = latest + 1
	t2 := transactions.Transaction{
		Type:   protocol.ApplicationCallTx,
		Header: h2,
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApprovalProgram:   closed.Program,
			ClearStateProgram: clear.Program,
			Accounts:          []basics.Address{acctA},
		},
	}
	gid := crypto.HashObj(transactions.TxGroup{TxGroupHashes: []crypto.Digest{crypto.Digest(t0.ID()), crypto.Digest(t1.ID()), crypto.Digest(t2.ID())}})
	t0.Group = gid
	t1.Group = gid
	t2.Group = gid
	group := []transactions.SignedTxn{{Txn: t0}, {Txn: t1}, {Txn: t2}}
	var enc []byte
	for i := range group {
		enc = append(enc, protocol.Encode(&group[i])...)
	}
	f.GroupMsgpack = b64(enc)

	sim := simulation.MakeSimulator(l, false)
	res, err := sim.Simulate(simulation.Request{TxnGroups: [][]transactions.SignedTxn{group}, AllowEmptySignatures: true})
	must(err)
	f.LastRound = uint64(res.LastRound)
	g := res.TxnGroups[0]
	f.FailureMessage = g.FailureMessage
	for _, tr := range g.Txns {
		ad := tr.Txn.ApplyData
		r := txnResult{
			SenderRewards:   ad.SenderRewards.Raw,
			ReceiverRewards: ad.ReceiverRewards.Raw,
			CloseRewards:    ad.CloseRewards.Raw,
			ClosingAmount:   ad.ClosingAmount.Raw,
			ApplicationID:   uint64(ad.ApplicationID),
			Logs:            []uint64{},
		}
		for _, lg := range ad.EvalDelta.Logs {
			if len(lg) != 8 {
				panic(fmt.Sprintf("unexpected log length %d", len(lg)))
			}
			r.Logs = append(r.Logs, binary.BigEndian.Uint64([]byte(lg)))
		}
		f.Txns = append(f.Txns, r)
	}

	out := filepath.Join("..", "..", "crates", "core", "algo-ledger", "tests", "fixtures", "simulate_rewards", "oracle.json")
	must(os.MkdirAll(filepath.Dir(out), 0o755))
	js, err := json.MarshalIndent(f, "", "  ")
	must(err)
	must(os.WriteFile(out, append(js, '\n'), 0o644))
	fmt.Println("wrote", out)

	// The issue #2125 oracle (checkdup.go) shares this module.
	checkDupOracle()
	// The issue #2127 oracle (blockdup.go) too.
	blockDupOracle()
}
