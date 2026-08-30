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

// rewards-innertxid-oracle: byte-level go-algorand oracle for two of the
// verification-depth gaps issue #760 (follow-up to #747/PR #759) closes:
//
//  1. `bookkeeping.RewardsState.NextRewardsState` (data/bookkeeping/block.go),
//     specifically the `PendingResidueRewards` (v18+) and
//     `RewardsCalculationFix` (v31+) gated branches that
//     `algo_ledger::rewards::next_rewards_state` ports.
//  2. `transactions.Transaction.InnerID` (data/transactions/transaction.go),
//     the parent-folding hash `algo_avm::itxn::compute_inner_txn_id` ports
//     (consumed by `UnifyInnerTxIDs`-gated inner-txn-ID computation).
//
// #747/PR #759 verified both ports only by direct line-by-line arithmetic
// comparison against the go source (a human/model reading both
// implementations side-by-side), not by running go-algorand's own code and
// diffing real output. This tool runs the real, unmodified go-algorand
// functions against fixed inputs and emits the results as a JSON corpus, so
// the Rust side's parity test (`crates/core/algo-ledger/tests/
// rewards_state_oracle.rs`, `crates/core/algo-avm/tests/
// inner_txn_id_oracle.rs`) asserts "Rust agrees with go-algorand's actual
// bytes" rather than "Rust agrees with what we thought go-algorand computes".
//
// # Why one shared rewards scenario across every consensus version
//
// `NextRewardsState`'s only version-gated behavior is the two boolean flags
// above; `MinBalance` (100000) and `RewardsRateRefreshInterval` (500000)
// have been constant since v9 (config/consensus.go). Running the exact same
// (prev-state, next-round, incentive-pool-balance, total-reward-units)
// input through every version from V10 (this repo's oldest tracked
// protocol -- see algo_types::consensus::KNOWN_PROTOCOL_VERSIONS) through
// V42 therefore both:
//   - exercises the V17->V18 (PendingResidueRewards) and V30->V31
//     (RewardsCalculationFix) boundaries with real go-algorand output, and
//   - guards every other version against a future silent change to those
//     "constant" params, at zero extra cost (same call, different cparams).
//
// The scenario is hand-tuned (see inline comments) so each flag's ON/OFF
// state actually changes the *emitted* RewardsState, not just an
// intermediate value that happens to round to the same output either way.
//
// # Why fixed InnerID vectors, not a version sweep
//
// `Transaction.InnerID`'s formula (`"TX" || parent || big-endian index ||
// canonical-msgpack(txn)`) does not change across consensus versions -- what
// *is* version-gated (`UnifyInnerTxIDs`, v34+) is which parent id
// `algo_ledger::avm_context` feeds into it (this context's own txn hash vs.
// the propagated ancestor id), which is pure Rust-side control flow already
// covered by `avm_context.rs`'s `unify_inner_tx_ids_activation_boundary`
// unit test. The byte-level gap this tool closes is narrower and
// version-independent: does `compute_inner_txn_id`'s encoding (prefix,
// parent, index, canonical txn bytes) match `InnerID`'s byte-for-byte for
// real transactions with varied field shapes (addresses, note bytes, asset
// amounts, application-call argument arrays)? A handful of representative
// transactions x a few (parent, index) pairs covers that; a full version
// sweep would add no signal since the formula itself is invariant.
//
// go-algorand references (v5.0.0-stable):
//
//	data/bookkeeping/block.go:413   — RewardsState.NextRewardsState
//	config/consensus.go:1058        — v18.PendingResidueRewards = true
//	config/consensus.go:1312        — v31.RewardsCalculationFix = true
//	data/transactions/transaction.go:297 — Transaction.InnerID
//
// Regeneration: see docs/DEV_WORKFLOW.md -> "Rewards/InnerTxnID Oracle
// Regeneration".
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

const expectedGoAlgorandPin = "v5.0.0-stable"

func goAlgorandDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Clean(filepath.Join("..", "..", "..", "go-algorand"))
	}
	toolDir := filepath.Dir(thisFile)
	repoRoot := filepath.Clean(filepath.Join(toolDir, "..", ".."))
	return filepath.Clean(filepath.Join(repoRoot, "..", "go-algorand"))
}

func defaultOutputPath() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("crates", "core", "algo-ledger", "tests", "fixtures", "rewards_innertxid", "oracle.json")
	}
	toolDir := filepath.Dir(thisFile)
	repoRoot := filepath.Clean(filepath.Join(toolDir, "..", ".."))
	return filepath.Join(repoRoot, "crates", "core", "algo-ledger", "tests", "fixtures", "rewards_innertxid", "oracle.json")
}

func verifyGoAlgorandPin(path string) error {
	cmd := exec.Command("git", "-C", path, "describe", "--tags", "--exact-match", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		rev, _ := exec.Command("git", "-C", path, "rev-parse", "HEAD").Output()
		return fmt.Errorf(
			"go-algorand at %q is not pinned to %s (HEAD=%s). "+
				"Fix: cd %s && git fetch --tags && git checkout %s  (or pass --allow-unpinned)",
			path, expectedGoAlgorandPin, strings.TrimSpace(string(rev)), path, expectedGoAlgorandPin,
		)
	}
	if got := strings.TrimSpace(string(out)); got != expectedGoAlgorandPin {
		return fmt.Errorf(
			"go-algorand at %q is on tag %q, expected %q. "+
				"Fix: cd %s && git checkout %s  (or pass --allow-unpinned)",
			path, got, expectedGoAlgorandPin, path, expectedGoAlgorandPin,
		)
	}

	statusCmd := exec.Command("git", "-C", path, "status", "--porcelain",
		"--", "config", "data/bookkeeping", "data/transactions", "data/basics", "protocol", "crypto")
	statusOut, err := statusCmd.Output()
	if err != nil {
		return fmt.Errorf("checking git status of %s: %w", path, err)
	}
	if dirty := strings.TrimSpace(string(statusOut)); dirty != "" {
		return fmt.Errorf(
			"go-algorand at %q has uncommitted changes affecting this capture:\n%s\n"+
				"Clean the tree or pass --allow-unpinned.", path, dirty,
		)
	}
	return nil
}

// allVersions returns every consensus version this repo's own
// ConsensusParams table tracks (algo_types::consensus::KNOWN_PROTOCOL_VERSIONS
// starts at v10), through the harness's current pin (v42).
func allVersions() []protocol.ConsensusVersion {
	return []protocol.ConsensusVersion{
		protocol.ConsensusV10, protocol.ConsensusV11, protocol.ConsensusV12,
		protocol.ConsensusV13, protocol.ConsensusV14, protocol.ConsensusV15,
		protocol.ConsensusV16, protocol.ConsensusV17, protocol.ConsensusV18,
		protocol.ConsensusV19, protocol.ConsensusV20, protocol.ConsensusV21,
		protocol.ConsensusV22, protocol.ConsensusV23, protocol.ConsensusV24,
		protocol.ConsensusV25, protocol.ConsensusV26, protocol.ConsensusV27,
		protocol.ConsensusV28, protocol.ConsensusV29, protocol.ConsensusV30,
		protocol.ConsensusV31, protocol.ConsensusV32, protocol.ConsensusV33,
		protocol.ConsensusV34, protocol.ConsensusV35, protocol.ConsensusV36,
		protocol.ConsensusV37, protocol.ConsensusV38, protocol.ConsensusV39,
		protocol.ConsensusV40, protocol.ConsensusV41, protocol.ConsensusV42,
	}
}

// RewardsVector is one (version, real go-algorand output) tuple for the
// shared scenario described in the module docs.
type RewardsVector struct {
	Version                    string `json:"version"`
	PendingResidueRewards      bool   `json:"pending_residue_rewards"`
	RewardsCalculationFix      bool   `json:"rewards_calculation_fix"`
	MinBalance                 uint64 `json:"min_balance"`
	RewardsRateRefreshInterval uint64 `json:"rewards_rate_refresh_interval"`
	NextLevel                  uint64 `json:"next_level"`
	NextRate                   uint64 `json:"next_rate"`
	NextResidue                uint64 `json:"next_residue"`
	NextRecalculationRound     uint64 `json:"next_recalculation_round"`
}

// rewardsScenario is the single, fixed input shared across every version
// (see module docs for why this exact combination distinguishes both
// gated flags in the emitted output, not just an intermediate value).
type rewardsScenario struct {
	prevLevel            uint64
	prevRate             uint64
	prevResidue          uint64
	prevRecalcRound      uint64
	nextRound            uint64
	incentivePoolBalance uint64
	totalRewardUnits     uint64
}

func fixedRewardsScenario() rewardsScenario {
	return rewardsScenario{
		prevLevel:            1000,
		prevRate:             250,
		prevResidue:          1000,
		prevRecalcRound:      1_000_000,
		nextRound:            1_000_000, // == prevRecalcRound: triggers the rate-refresh branch
		incentivePoolBalance: 600_400,
		totalRewardUnits:     7,
	}
}

func runRewardsScenario(cparams config.ConsensusParams, s rewardsScenario) bookkeeping.RewardsState {
	prev := bookkeeping.RewardsState{
		RewardsLevel:              s.prevLevel,
		RewardsRate:               s.prevRate,
		RewardsResidue:            s.prevResidue,
		RewardsRecalculationRound: basics.Round(s.prevRecalcRound),
	}
	log := logging.NewLogger()
	return prev.NextRewardsState(
		basics.Round(s.nextRound),
		cparams,
		basics.MicroAlgos{Raw: s.incentivePoolBalance},
		s.totalRewardUnits,
		log,
	)
}

// InnerIDVector is one (transaction shape, parent, index) -> real
// go-algorand InnerID digest tuple.
type InnerIDVector struct {
	TxnLabel string `json:"txn_label"`
	Parent   string `json:"parent_hex"`
	Index    int    `json:"index"`
	InnerID  string `json:"inner_id_hex"`
}

func addr(b byte) basics.Address {
	var a basics.Address
	for i := range a {
		a[i] = b
	}
	return a
}

func digest32(b byte) crypto.Digest {
	var d crypto.Digest
	for i := range d {
		d[i] = b
	}
	return d
}

// innerIDTransactions returns a handful of representative transactions
// covering distinct field shapes: a plain payment, a payment with
// note/close-remainder-to, an asset transfer, and an application call with
// argument arrays and foreign-app/-asset references.
func innerIDTransactions() map[string]transactions.Transaction {
	base := func() transactions.Header {
		return transactions.Header{
			Sender:      addr(0x01),
			Fee:         basics.MicroAlgos{Raw: 1000},
			FirstValid:  100,
			LastValid:   1100,
			GenesisID:   "oracle-test",
			GenesisHash: digest32(0x99),
		}
	}

	pay := transactions.Transaction{
		Type:   protocol.PaymentTx,
		Header: base(),
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addr(0x02),
			Amount:   basics.MicroAlgos{Raw: 5_000_000},
		},
	}

	payWithExtras := transactions.Transaction{
		Type:   protocol.PaymentTx,
		Header: base(),
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver:         addr(0x02),
			Amount:           basics.MicroAlgos{Raw: 5_000_000},
			CloseRemainderTo: addr(0x03),
		},
	}
	payWithExtras.Note = []byte("live_rewards_innertxid_oracle")

	axfer := transactions.Transaction{
		Type:   protocol.AssetTransferTx,
		Header: base(),
		AssetTransferTxnFields: transactions.AssetTransferTxnFields{
			XferAsset:     999999999,
			AssetAmount:   42,
			AssetReceiver: addr(0x02),
		},
	}

	appl := transactions.Transaction{
		Type:   protocol.ApplicationCallTx,
		Header: base(),
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: 123456789,
			OnCompletion:  transactions.NoOpOC,
			ApplicationArgs: [][]byte{
				[]byte("hello"),
				{0x01, 0x02, 0x03},
			},
			ForeignApps:   []basics.AppIndex{111, 222},
			ForeignAssets: []basics.AssetIndex{333},
		},
	}

	return map[string]transactions.Transaction{
		"pay_simple":      pay,
		"pay_with_extras": payWithExtras,
		"axfer":           axfer,
		"appl_call":       appl,
	}
}

// Corpus is the on-disk envelope.
type Corpus struct {
	Source         string          `json:"source"`
	GoAlgorandPin  string          `json:"go_algorand_pin"`
	RewardsVectors []RewardsVector `json:"rewards_vectors"`
	InnerIDVectors []InnerIDVector `json:"inner_id_vectors"`
}

func resolveGoAlgorandPin(path string, pinVerified bool) string {
	if pinVerified {
		return expectedGoAlgorandPin
	}
	out, err := exec.Command("git", "-C", path, "describe", "--tags", "--always", "--dirty=+dirty").Output()
	if err != nil {
		if rev, rerr := exec.Command("git", "-C", path, "rev-parse", "HEAD").Output(); rerr == nil {
			return strings.TrimSpace(string(rev)) + " (unpinned)"
		}
		return "unknown (unpinned)"
	}
	return strings.TrimSpace(string(out)) + " (unpinned)"
}

func main() {
	var (
		outPath       = flag.String("out", defaultOutputPath(), "path to write the JSON corpus")
		allowUnpinned = flag.Bool("allow-unpinned", false, "skip the go-algorand tag/cleanliness check (captures will not be reproducible across developers)")
	)
	flag.Parse()

	pinVerified := !*allowUnpinned
	if pinVerified {
		if err := verifyGoAlgorandPin(goAlgorandDir()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}

	corpus := Corpus{
		Source:        "algod-rust/tools/rewards-innertxid-oracle (issue #760)",
		GoAlgorandPin: resolveGoAlgorandPin(goAlgorandDir(), pinVerified),
	}

	scenario := fixedRewardsScenario()
	for _, v := range allVersions() {
		cparams, ok := config.Consensus[v]
		if !ok {
			fmt.Fprintf(os.Stderr, "consensus version %q not present in go-algorand's Consensus map\n", v)
			os.Exit(3)
		}
		next := runRewardsScenario(cparams, scenario)
		corpus.RewardsVectors = append(corpus.RewardsVectors, RewardsVector{
			Version:                    string(v),
			PendingResidueRewards:      cparams.PendingResidueRewards,
			RewardsCalculationFix:      cparams.RewardsCalculationFix,
			MinBalance:                 cparams.MinBalance,
			RewardsRateRefreshInterval: cparams.RewardsRateRefreshInterval,
			NextLevel:                  next.RewardsLevel,
			NextRate:                   next.RewardsRate,
			NextResidue:                next.RewardsResidue,
			NextRecalculationRound:     uint64(next.RewardsRecalculationRound),
		})
	}

	parents := map[string]crypto.Digest{
		"parent_ab": digest32(0xAB),
		"parent_cd": digest32(0xCD),
	}
	indices := []int{0, 1, 7}

	// Sorted iteration for deterministic output.
	txnLabels := []string{"pay_simple", "pay_with_extras", "axfer", "appl_call"}
	parentLabels := []string{"parent_ab", "parent_cd"}
	txns := innerIDTransactions()

	for _, txnLabel := range txnLabels {
		txn := txns[txnLabel]
		for _, parentLabel := range parentLabels {
			parent := parents[parentLabel]
			parentTxid := transactions.Txid(parent)
			for _, idx := range indices {
				id := txn.InnerID(parentTxid, idx)
				corpus.InnerIDVectors = append(corpus.InnerIDVectors, InnerIDVector{
					TxnLabel: txnLabel,
					Parent:   hex.EncodeToString(parent[:]),
					Index:    idx,
					InnerID:  hex.EncodeToString(id[:]),
				})
			}
		}
	}

	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(4)
	}
	buf, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(5)
	}
	buf = append(buf, '\n')
	if err := os.WriteFile(*outPath, buf, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(6)
	}
	fmt.Fprintf(os.Stderr, "wrote %d rewards vectors and %d inner-id vectors to %s\n",
		len(corpus.RewardsVectors), len(corpus.InnerIDVectors), *outPath)

	// Also print to stdout so a CI job's log carries the exact captured
	// bytes even when the workflow doesn't (or can't) commit the file back
	// to the PR branch.
	fmt.Println(string(buf))
}
