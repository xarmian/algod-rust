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

// WellFormed oracle: go-algorand oracle for issue #2193.
//
// One row per `Transaction.WellFormed` rule (data/transactions/transaction.go
// and the per-type `wellFormed` methods), plus multi-problem rows that pin the
// ORDER the rules run in (the first failing rule decides the text). Every row
// is a single signed transaction (the signature is irrelevant: WellFormed does
// not look at it) run through two real go paths, from blockdup.go's ledger:
//
//   - `BlockEvaluator.TestTransactionGroup` (the gossip test stage), whose
//     error is `transaction <txid>: malformed: <WellFormed error>`; and
//   - `verify.TxnGroup` (the REST submit path), whose error is
//     `transaction <%+v of the SignedTxn> invalid : <WellFormed error>`.
//
// The `%+v` struct dump is go's own formatting of its in-memory type, so the
// Rust side compares the part after ` invalid : ` for those rows.
package main

import (
	"fmt"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

// wfRow is one WellFormed row: a name, one transaction and a comment on what
// rule it pins.
type wfRow struct {
	name string
	tx   transactions.SignedTxn
}

// wfEnv is what blockdup.go's ledger provides to the generator.
type wfEnv struct {
	params      config.ConsensusParams
	sender      basics.Address
	receiver    basics.Address
	sink        basics.Address
	pool        basics.Address
	genesisHash crypto.Digest
	sign        func(transactions.Transaction) transactions.SignedTxn
}

func wellFormedRows(e wfEnv) []wfRow {
	p := e.params
	var rows []wfRow
	add := func(name string, t transactions.Transaction) {
		rows = append(rows, wfRow{name: "wf_" + name, tx: e.sign(t)})
	}
	header := func(note string) transactions.Header {
		return transactions.Header{
			Sender:      e.sender,
			Fee:         basics.MicroAlgos{Raw: p.MinTxnFee},
			FirstValid:  1,
			LastValid:   1000,
			Note:        []byte("wf-" + note),
			GenesisID:   blockDupGenesisID,
			GenesisHash: e.genesisHash,
		}
	}
	mk := func(note string, typ protocol.TxType) transactions.Transaction {
		return transactions.Transaction{Type: typ, Header: header(note)}
	}
	pay := func(note string) transactions.Transaction {
		t := mk(note, protocol.PaymentTx)
		t.Receiver = e.receiver
		t.Amount = basics.MicroAlgos{Raw: 1_000_000}
		return t
	}
	var key32 [32]byte
	for i := range key32 {
		key32[i] = 0x42
	}
	var sprf [64]byte
	for i := range sprf {
		sprf[i] = 0x43
	}
	filler := func(n int) []byte { return make([]byte, n) }
	str := func(n int) string { return strings.Repeat("a", n) }
	other := e.receiver

	// ---- the common checks at the end of WellFormed ----
	{
		t := pay("range")
		t.FirstValid, t.LastValid = 500, 400
		add("invalid_range", t)
		t = pay("window")
		t.FirstValid, t.LastValid = 1, 100_000
		add("window_excessive", t)
		t = pay("note")
		t.Note = filler(p.MaxAbsoluteTxnNoteBytes + 1)
		add("note_too_big", t)
		t = pay("pool")
		t.Sender = e.pool
		add("rewards_pool_sender", t)
		// a payment from the zero address is "closing to its sender" first
		// (the per-type rule runs before the common sender checks) ...
		t = pay("zero-pay")
		t.Sender = basics.Address{}
		add("zero_sender_payment", t)
		// ... any other type reaches the common zero-sender rule.
		t = mk("zero-axfer", protocol.AssetTransferTx)
		t.Sender = basics.Address{}
		t.XferAsset = 1
		add("zero_sender_axfer", t)
		// WellFormed has no fee rule at all (go checks fees for the whole
		// group, later): a zero fee is well formed.
		t = pay("fee0")
		t.Fee = basics.MicroAlgos{}
		add("zero_fee_is_well_formed", t)
	}

	// ---- the cross-type field rule ----
	{
		type iso struct {
			name string
			mut  func(*transactions.Transaction)
		}
		for _, s := range []iso{
			{"pay_with_keyreg_fields", func(t *transactions.Transaction) { t.VoteKeyDilution = 1 }},
			{"pay_with_acfg_fields", func(t *transactions.Transaction) { t.ConfigAsset = 1 }},
			{"pay_with_axfer_fields", func(t *transactions.Transaction) { t.XferAsset = 1 }},
			{"pay_with_afrz_fields", func(t *transactions.Transaction) { t.FreezeAsset = 1 }},
			{"pay_with_appl_fields", func(t *transactions.Transaction) { t.ApplicationID = 1 }},
			{"pay_with_stpf_fields", func(t *transactions.Transaction) { t.StateProofType = 1 }},
			{"pay_with_hb_fields", func(t *transactions.Transaction) {
				t.HeartbeatTxnFields = &transactions.HeartbeatTxnFields{HbKeyDilution: 1}
			}},
		} {
			t := pay(s.name)
			s.mut(&t)
			add("iso_"+s.name, t)
		}
		t := mk("iso-acfg-with-pay", protocol.AssetConfigTx)
		t.Receiver = e.receiver
		add("iso_acfg_with_pay_fields", t)
		t = mk("iso-appl-with-axfer", protocol.ApplicationCallTx)
		t.ApplicationID = 1
		t.XferAsset = 1
		add("iso_appl_with_axfer_fields", t)
	}

	// ---- payment ----
	{
		t := pay("close-self")
		t.CloseRemainderTo = e.sender
		add("pay_close_to_sender", t)
		t = pay("sink")
		t.Sender = e.sink
		add("pay_fee_sink_sender", t)
		t = pay("sink-pool")
		t.Sender = e.sink
		t.Receiver = e.pool
		add("pay_fee_sink_to_pool", t)
		t = pay("sink-close")
		t.Sender = e.sink
		t.Receiver = e.pool
		t.CloseRemainderTo = other
		add("pay_fee_sink_close", t)
	}

	// ---- keyreg ----
	{
		kr := func(note string, f func(*transactions.Transaction)) transactions.Transaction {
			t := mk(note, protocol.KeyRegistrationTx)
			f(&t)
			return t
		}
		online := func(t *transactions.Transaction) {
			t.VotePK = crypto.OneTimeSignatureVerifier(key32)
			t.SelectionPK = crypto.VRFVerifier(key32)
			t.VoteKeyDilution = 1
			t.VoteFirst, t.VoteLast = 1, 10
			t.StateProofPK = sprf
		}
		add("keyreg_fee_sink", kr("kr-sink", func(t *transactions.Transaction) { online(t); t.Sender = e.sink }))
		add("keyreg_first_after_last", kr("kr-order", func(t *transactions.Transaction) {
			online(t)
			t.VoteFirst, t.VoteLast = 10, 5
		}))
		add("keyreg_votekey_only", kr("kr-votekey", func(t *transactions.Transaction) {
			t.VotePK = crypto.OneTimeSignatureVerifier(key32)
		}))
		add("keyreg_keys_without_dilution", kr("kr-nokd", func(t *transactions.Transaction) {
			online(t)
			t.VoteKeyDilution = 0
		}))
		add("keyreg_offline_with_rounds", kr("kr-off-rounds", func(t *transactions.Transaction) {
			t.VoteLast = 5
		}))
		add("keyreg_offline_with_first_round_only", kr("kr-off-first", func(t *transactions.Transaction) {
			t.VoteFirst = 1
		}))
		add("keyreg_online_vote_last_zero", kr("kr-last0", func(t *transactions.Transaction) {
			online(t)
			t.VoteFirst, t.VoteLast = 0, 0
		}))
		add("keyreg_first_beyond_last_valid", kr("kr-beyond", func(t *transactions.Transaction) {
			online(t)
			t.VoteFirst, t.VoteLast = 2000, 3000
		}))
		add("keyreg_nonpart_with_keys", kr("kr-nonpart-keys", func(t *transactions.Transaction) {
			online(t)
			t.Nonparticipation = true
		}))
		add("keyreg_nonpart_with_sprf", kr("kr-nonpart-sprf", func(t *transactions.Transaction) {
			t.Nonparticipation = true
			t.StateProofPK = sprf
		}))
		add("keyreg_offline_with_sprf", kr("kr-off-sprf", func(t *transactions.Transaction) {
			t.StateProofPK = sprf
		}))
		add("keyreg_online_empty_sprf", kr("kr-empty-sprf", func(t *transactions.Transaction) {
			online(t)
			t.StateProofPK = [64]byte{}
		}))
		add("keyreg_validity_too_long", kr("kr-long", func(t *transactions.Transaction) {
			online(t)
			t.VoteFirst = 1
			t.VoteLast = basics.Round(1 + p.MaxKeyregValidPeriod + 1)
		}))
		// the rewards-pool-style ordering: the fee-sink rule precedes the
		// coherency rules.
		add("keyreg_order_fee_sink_before_rounds", kr("kr-ord1", func(t *transactions.Transaction) {
			t.Sender = e.sink
			t.VoteFirst, t.VoteLast = 10, 5
		}))
		add("keyreg_order_rounds_before_coherence", kr("kr-ord2", func(t *transactions.Transaction) {
			t.VotePK = crypto.OneTimeSignatureVerifier(key32)
			t.VoteFirst, t.VoteLast = 10, 5
		}))
		add("keyreg_order_coherence_before_nonpart", kr("kr-ord3", func(t *transactions.Transaction) {
			t.Nonparticipation = true
			t.VotePK = crypto.OneTimeSignatureVerifier(key32)
		}))
	}

	// ---- asset config ----
	{
		ac := func(note string, f func(*basics.AssetParams)) transactions.Transaction {
			t := mk(note, protocol.AssetConfigTx)
			t.AssetParams = basics.AssetParams{Total: 1}
			f(&t.AssetParams)
			return t
		}
		add("acfg_name_too_big", ac("ac-name", func(a *basics.AssetParams) { a.AssetName = str(p.MaxAssetNameBytes + 1) }))
		add("acfg_unit_name_too_big", ac("ac-unit", func(a *basics.AssetParams) { a.UnitName = str(p.MaxAssetUnitNameBytes + 1) }))
		add("acfg_url_too_big", ac("ac-url", func(a *basics.AssetParams) { a.URL = str(p.MaxAssetURLBytes + 1) }))
		add("acfg_decimals_too_high", ac("ac-dec", func(a *basics.AssetParams) { a.Decimals = p.MaxAssetDecimals + 1 }))
		add("acfg_order_name_before_unit", ac("ac-ord", func(a *basics.AssetParams) {
			a.AssetName = str(p.MaxAssetNameBytes + 1)
			a.UnitName = str(p.MaxAssetUnitNameBytes + 1)
		}))
		add("acfg_order_unit_before_decimals", ac("ac-ord2", func(a *basics.AssetParams) {
			a.UnitName = str(p.MaxAssetUnitNameBytes + 1)
			a.Decimals = p.MaxAssetDecimals + 1
		}))
	}

	// ---- asset transfer / freeze ----
	{
		t := mk("ax-zero", protocol.AssetTransferTx)
		t.AssetAmount = 1
		add("axfer_asset_id_zero", t)
		t = mk("ax-claw", protocol.AssetTransferTx)
		t.XferAsset = 1
		t.AssetSender = other
		t.AssetCloseTo = e.pool
		add("axfer_close_by_clawback", t)
		t = mk("ax-ord", protocol.AssetTransferTx)
		t.AssetAmount = 1
		t.AssetSender = other
		t.AssetCloseTo = e.pool
		add("axfer_order_asset_id_before_clawback", t)
		t = mk("af-zero", protocol.AssetFreezeTx)
		t.FreezeAccount = other
		add("afrz_asset_id_zero", t)
		t = mk("af-acct", protocol.AssetFreezeTx)
		t.FreezeAsset = 1
		add("afrz_account_empty", t)
		t = mk("af-ord", protocol.AssetFreezeTx)
		add("afrz_order_asset_id_before_account", t)
	}

	// ---- application call ----
	{
		prog := func(version byte, n int) []byte {
			b := []byte{version, 0x81, 0x01}
			return append(b, filler(n)...)
		}
		ap := func(note string, id uint64, f func(*transactions.Transaction)) transactions.Transaction {
			t := mk(note, protocol.ApplicationCallTx)
			t.ApplicationID = basics.AppIndex(id)
			if id == 0 {
				t.ApprovalProgram = prog(8, 0)
				t.ClearStateProgram = prog(8, 0)
			}
			f(&t)
			return t
		}
		noop := func(*transactions.Transaction) {}
		_ = noop
		add("appl_invalid_on_completion", ap("ap-oc", 1, func(t *transactions.Transaction) { t.OnCompletion = 9 }))
		add("appl_reject_version_on_create", ap("ap-rv", 0, func(t *transactions.Transaction) { t.RejectVersion = 1 }))
		add("appl_programs_on_call", ap("ap-prog", 1, func(t *transactions.Transaction) { t.ApprovalProgram = prog(8, 0) }))
		add("appl_create_without_programs", ap("ap-noprog", 0, func(t *transactions.Transaction) {
			t.ApprovalProgram, t.ClearStateProgram = nil, nil
		}))
		add("appl_create_without_clear_program", ap("ap-noclear", 0, func(t *transactions.Transaction) { t.ClearStateProgram = nil }))
		add("appl_program_version_mismatch", ap("ap-ver", 0, func(t *transactions.Transaction) { t.ClearStateProgram = prog(7, 0) }))
		add("appl_extra_pages_over_max", ap("ap-epp", 0, func(t *transactions.Transaction) {
			t.ExtraProgramPages = uint32(p.MaxAbsoluteExtraProgramPages) + 1
		}))
		add("appl_local_schema_on_call", ap("ap-ls", 1, func(t *transactions.Transaction) {
			t.LocalStateSchema = basics.StateSchema{NumUint: 1, NumByteSlice: 2}
		}))
		add("appl_global_schema_on_call", ap("ap-gs", 1, func(t *transactions.Transaction) {
			t.GlobalStateSchema = basics.StateSchema{NumUint: 3, NumByteSlice: 4}
		}))
		add("appl_extra_pages_on_call", ap("ap-eppc", 1, func(t *transactions.Transaction) { t.ExtraProgramPages = 1 }))
		add("appl_approval_too_long", ap("ap-long", 0, func(t *transactions.Transaction) {
			t.ApprovalProgram = prog(8, p.MaxAppProgramLen)
		}))
		add("appl_clear_too_long", ap("ap-clong", 0, func(t *transactions.Transaction) {
			t.ClearStateProgram = prog(8, p.MaxAppProgramLen)
		}))
		add("appl_programs_total_too_long", ap("ap-tot", 0, func(t *transactions.Transaction) {
			n := p.MaxAppProgramLen - 3
			t.ApprovalProgram = prog(8, n)
			t.ClearStateProgram = prog(8, p.MaxAppTotalProgramLen-n-3+1)
		}))
		add("appl_too_many_args", ap("ap-args", 1, func(t *transactions.Transaction) {
			t.ApplicationArgs = make([][]byte, p.MaxAppArgs+1)
		}))
		add("appl_arg_too_long", ap("ap-arg", 1, func(t *transactions.Transaction) {
			t.ApplicationArgs = [][]byte{filler(config.MaxAVMBytesSize + 1)}
		}))
		add("appl_args_total_too_long", ap("ap-argt", 1, func(t *transactions.Transaction) {
			left := p.MaxAbsoluteTotalArgLen + 1
			for left > 0 {
				n := config.MaxAVMBytesSize
				if left < n {
					n = left
				}
				t.ApplicationArgs = append(t.ApplicationArgs, filler(n))
				left -= n
			}
			if len(t.ApplicationArgs) > p.MaxAppArgs {
				panic("wellformed oracle: args-total row needs more arguments than MaxAppArgs")
			}
		}))
		add("appl_too_many_accounts", ap("ap-acc", 1, func(t *transactions.Transaction) {
			t.Accounts = make([]basics.Address, p.MaxAppTxnAccounts+1)
		}))
		add("appl_too_many_foreign_apps", ap("ap-fapp", 1, func(t *transactions.Transaction) {
			t.ForeignApps = make([]basics.AppIndex, p.MaxAppTxnForeignApps+1)
		}))
		add("appl_too_many_foreign_assets", ap("ap-fasa", 1, func(t *transactions.Transaction) {
			t.ForeignAssets = make([]basics.AssetIndex, p.MaxAppTxnForeignAssets+1)
		}))
		add("appl_too_many_boxes", ap("ap-box", 1, func(t *transactions.Transaction) {
			t.Boxes = make([]transactions.BoxRef, p.MaxAppBoxReferences+1)
		}))
		add("appl_total_references_over_max", ap("ap-refs", 1, func(t *transactions.Transaction) {
			t.Accounts = make([]basics.Address, p.MaxAppTxnAccounts)
			n := p.MaxAppTotalTxnReferences - p.MaxAppTxnAccounts + 1
			if n > p.MaxAppTxnForeignApps {
				panic("wellformed oracle: total-references row needs more foreign apps than allowed")
			}
			t.ForeignApps = make([]basics.AppIndex, n)
		}))
		add("appl_box_index_over_foreign_apps", ap("ap-bidx", 1, func(t *transactions.Transaction) {
			t.Boxes = []transactions.BoxRef{{Index: 1, Name: []byte("k")}}
		}))
		add("appl_box_name_too_long", ap("ap-bname", 1, func(t *transactions.Transaction) {
			t.Boxes = []transactions.BoxRef{{Index: 0, Name: filler(p.MaxAppKeyLen + 1)}}
		}))
		add("appl_local_schema_too_large", ap("ap-lsl", 0, func(t *transactions.Transaction) {
			t.LocalStateSchema = basics.StateSchema{NumUint: uint64(p.MaxLocalSchemaEntries) + 1}
		}))
		add("appl_global_schema_too_large", ap("ap-gsl", 0, func(t *transactions.Transaction) {
			t.GlobalStateSchema = basics.StateSchema{NumUint: uint64(p.MaxGlobalSchemaEntries) + 1}
		}))
		// tx.Access
		someAddr := func() basics.Address { return other }
		add("appl_access_too_long", ap("ap-acl", 1, func(t *transactions.Transaction) {
			t.Access = make([]transactions.ResourceRef, p.MaxAppAccess+1)
		}))
		add("appl_access_with_accounts", ap("ap-aca", 1, func(t *transactions.Transaction) {
			t.Access = []transactions.ResourceRef{{Address: someAddr()}}
			t.Accounts = []basics.Address{someAddr()}
		}))
		add("appl_access_with_foreign_apps", ap("ap-acf", 1, func(t *transactions.Transaction) {
			t.Access = []transactions.ResourceRef{{Address: someAddr()}}
			t.ForeignApps = []basics.AppIndex{5}
		}))
		add("appl_access_with_foreign_assets", ap("ap-acs", 1, func(t *transactions.Transaction) {
			t.Access = []transactions.ResourceRef{{Address: someAddr()}}
			t.ForeignAssets = []basics.AssetIndex{5}
		}))
		add("appl_access_with_boxes", ap("ap-acb", 1, func(t *transactions.Transaction) {
			t.Access = []transactions.ResourceRef{{Address: someAddr()}}
			t.Boxes = []transactions.BoxRef{{Index: 0, Name: []byte("k")}}
		}))
		add("appl_access_multiple_types", ap("ap-acm", 1, func(t *transactions.Transaction) {
			t.Access = []transactions.ResourceRef{{Address: someAddr(), Asset: 7}}
		}))
		add("appl_access_holding_outside", ap("ap-ach", 1, func(t *transactions.Transaction) {
			t.Access = []transactions.ResourceRef{{Holding: transactions.HoldingRef{Address: 0, Asset: 5}}}
		}))
		add("appl_access_locals_zero_app_on_create", ap("ap-acz", 0, func(t *transactions.Transaction) {
			t.Access = []transactions.ResourceRef{{Locals: transactions.LocalsRef{Address: 1, App: 0}}, {Address: someAddr()}}
		}))
		add("appl_access_box_name_too_long", ap("ap-acn", 1, func(t *transactions.Transaction) {
			t.Access = []transactions.ResourceRef{{Box: transactions.BoxRef{Index: 0, Name: filler(p.MaxAppKeyLen + 1)}}}
		}))
		// the order of the application rules
		add("appl_order_on_completion_before_programs", ap("ap-o1", 1, func(t *transactions.Transaction) {
			t.OnCompletion = 9
			t.ApprovalProgram = prog(8, 0)
		}))
		add("appl_order_programs_before_extra_pages", ap("ap-o2", 1, func(t *transactions.Transaction) {
			t.ApprovalProgram = prog(8, 0)
			t.ExtraProgramPages = uint32(p.MaxAbsoluteExtraProgramPages) + 1
		}))
		add("appl_order_local_schema_before_global", ap("ap-o3", 1, func(t *transactions.Transaction) {
			t.LocalStateSchema = basics.StateSchema{NumUint: 1}
			t.GlobalStateSchema = basics.StateSchema{NumUint: 1}
		}))
		add("appl_order_args_before_references", ap("ap-o4", 1, func(t *transactions.Transaction) {
			t.ApplicationArgs = make([][]byte, p.MaxAppArgs+1)
			t.Accounts = make([]basics.Address, p.MaxAppTxnAccounts+1)
		}))
		add("appl_order_accounts_before_foreign_apps", ap("ap-o5", 1, func(t *transactions.Transaction) {
			t.Accounts = make([]basics.Address, p.MaxAppTxnAccounts+1)
			t.ForeignApps = make([]basics.AppIndex, p.MaxAppTxnForeignApps+1)
		}))
		add("appl_order_references_before_box_index", ap("ap-o6", 1, func(t *transactions.Transaction) {
			t.Accounts = make([]basics.Address, p.MaxAppTxnAccounts+1)
			t.Boxes = []transactions.BoxRef{{Index: 9, Name: []byte("k")}}
		}))
	}

	// ---- state proof ----
	{
		sp := func(note string, f func(*transactions.Transaction)) transactions.Transaction {
			t := mk(note, protocol.StateProofTx)
			t.Sender = transactions.StateProofSender
			t.Fee = basics.MicroAlgos{}
			t.Note = nil
			f(&t)
			return t
		}
		add("stpf_bad_sender", sp("sp-snd", func(t *transactions.Transaction) { t.Sender = e.sender }))
		add("stpf_fee_not_zero", sp("sp-fee", func(t *transactions.Transaction) { t.Fee = basics.MicroAlgos{Raw: 1} }))
		add("stpf_note_not_empty", sp("sp-note", func(t *transactions.Transaction) { t.Note = []byte("n") }))
		add("stpf_group_not_zero", sp("sp-grp", func(t *transactions.Transaction) { t.Group = crypto.Digest(key32) }))
		add("stpf_rekey_not_zero", sp("sp-rk", func(t *transactions.Transaction) { t.RekeyTo = other }))
		add("stpf_lease_not_zero", sp("sp-lease", func(t *transactions.Transaction) { t.Lease = key32 }))
		add("stpf_order_sender_before_fee", sp("sp-o1", func(t *transactions.Transaction) {
			t.Sender = e.sender
			t.Fee = basics.MicroAlgos{Raw: 1}
		}))
		add("stpf_order_fee_before_note", sp("sp-o2", func(t *transactions.Transaction) {
			t.Fee = basics.MicroAlgos{Raw: 1}
			t.Note = []byte("n")
		}))
		add("stpf_order_note_before_group", sp("sp-o3", func(t *transactions.Transaction) {
			t.Note = []byte("n")
			t.Group = crypto.Digest(key32)
		}))
	}

	// ---- heartbeat ----
	{
		hb := func(note string, f func(*transactions.Transaction, *transactions.HeartbeatTxnFields)) transactions.Transaction {
			t := mk(note, protocol.HeartbeatTx)
			h := &transactions.HeartbeatTxnFields{HbAddress: other}
			h.HbProof.Sig[0] = 1
			h.HbSeed[0] = 1
			h.HbVoteID[0] = 1
			h.HbKeyDilution = 1
			f(&t, h)
			t.HeartbeatTxnFields = h
			return t
		}
		add("hb_proof_empty", hb("hb-proof", func(t *transactions.Transaction, h *transactions.HeartbeatTxnFields) {
			h.HbProof = crypto.HeartbeatProof{}
		}))
		// a proof with only a later field set is not empty
		add("hb_proof_only_pk2", hb("hb-pk2", func(t *transactions.Transaction, h *transactions.HeartbeatTxnFields) {
			h.HbProof = crypto.HeartbeatProof{}
			h.HbProof.PK2[0] = 1
			h.HbSeed = [32]byte{}
		}))
		add("hb_seed_empty", hb("hb-seed", func(t *transactions.Transaction, h *transactions.HeartbeatTxnFields) {
			h.HbSeed = [32]byte{}
		}))
		add("hb_vote_id_empty", hb("hb-vid", func(t *transactions.Transaction, h *transactions.HeartbeatTxnFields) {
			h.HbVoteID = crypto.OneTimeSignatureVerifier{}
		}))
		add("hb_key_dilution_zero", hb("hb-kd", func(t *transactions.Transaction, h *transactions.HeartbeatTxnFields) {
			h.HbKeyDilution = 0
		}))
		add("hb_discounted_with_note", hb("hb-dnote", func(t *transactions.Transaction, h *transactions.HeartbeatTxnFields) {
			h.HbChallengeDiscount = true
		}))
		add("hb_discounted_with_lease", hb("hb-dlease", func(t *transactions.Transaction, h *transactions.HeartbeatTxnFields) {
			h.HbChallengeDiscount = true
			t.Note = nil
			t.Lease = key32
		}))
		add("hb_discounted_with_rekey", hb("hb-drekey", func(t *transactions.Transaction, h *transactions.HeartbeatTxnFields) {
			h.HbChallengeDiscount = true
			t.Note = nil
			t.RekeyTo = other
		}))
		add("hb_order_note_before_proof", hb("hb-o1", func(t *transactions.Transaction, h *transactions.HeartbeatTxnFields) {
			h.HbChallengeDiscount = true
			h.HbProof = crypto.HeartbeatProof{}
		}))
		add("hb_order_proof_before_seed", hb("hb-o2", func(t *transactions.Transaction, h *transactions.HeartbeatTxnFields) {
			h.HbProof = crypto.HeartbeatProof{}
			h.HbSeed = [32]byte{}
		}))
		t := mk("hb-nofields", protocol.HeartbeatTx)
		add("hb_no_heartbeat_fields", t)
	}

	// ---- the type switch ----
	add("unknown_tx_type", mk("unknown-type", protocol.TxType("xyz")))

	// ---- the order of the checks across stages ----
	{
		// per-type rules, then the field isolation rule, then the common rules.
		t := pay("o-close-window")
		t.CloseRemainderTo = e.sender
		t.FirstValid, t.LastValid = 1, 100_000
		add("order_type_rule_before_window", t)
		t = pay("o-iso-range")
		t.ConfigAsset = 1
		t.FirstValid, t.LastValid = 500, 400
		add("order_isolation_before_range", t)
		t = pay("o-type-iso")
		t.CloseRemainderTo = e.sender
		t.ConfigAsset = 1
		add("order_type_rule_before_isolation", t)
		t = pay("o-range-note")
		t.FirstValid, t.LastValid = 500, 400
		t.Note = filler(p.MaxAbsoluteTxnNoteBytes + 1)
		add("order_range_before_note", t)
		t = pay("o-window-note")
		t.FirstValid, t.LastValid = 1, 100_000
		t.Note = filler(p.MaxAbsoluteTxnNoteBytes + 1)
		add("order_window_before_note", t)
		t = pay("o-note-pool")
		t.Sender = e.pool
		t.Note = filler(p.MaxAbsoluteTxnNoteBytes + 1)
		add("order_note_before_pool_sender", t)
		t = mk("o-note-zero", protocol.AssetTransferTx)
		t.Sender = basics.Address{}
		t.XferAsset = 1
		t.Note = filler(p.MaxAbsoluteTxnNoteBytes + 1)
		add("order_note_before_zero_sender", t)
		t = mk("o-appl-window", protocol.ApplicationCallTx)
		t.ApplicationID = 1
		t.OnCompletion = 9
		t.FirstValid, t.LastValid = 1, 100_000
		add("order_application_rule_before_window", t)
		t = mk("o-sprf-window", protocol.StateProofTx)
		t.FirstValid, t.LastValid = 1, 100_000
		add("order_state_proof_rule_before_window", t)
		t = mk("o-hb-window", protocol.HeartbeatTx)
		t.FirstValid, t.LastValid = 1, 100_000
		add("order_missing_heartbeat_fields_before_window", t)
		t = mk("o-unknown-window", protocol.TxType("xyz"))
		t.FirstValid, t.LastValid = 1, 100_000
		add("order_unknown_type_before_window", t)
		t = mk("o-acfg-window", protocol.AssetConfigTx)
		t.AssetParams = basics.AssetParams{Total: 1, AssetName: str(p.MaxAssetNameBytes + 1)}
		t.FirstValid, t.LastValid = 1, 100_000
		add("order_asset_rule_before_window", t)
		t = mk("o-kr-window", protocol.KeyRegistrationTx)
		t.VotePK = crypto.OneTimeSignatureVerifier(key32)
		t.FirstValid, t.LastValid = 1, 100_000
		add("order_keyreg_rule_before_window", t)
	}

	seen := map[string]bool{}
	for _, r := range rows {
		if seen[r.name] {
			panic(fmt.Sprintf("wellformed oracle: duplicate row %s", r.name))
		}
		seen[r.name] = true
	}
	return rows
}
