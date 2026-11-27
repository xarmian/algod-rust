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

// Command checktxngroup-oracle is the go-algorand v5.1.1-stable oracle for the
// group-validity decisions of data/transactions.CheckTxnGroup and
// CheckPaysetGroup (issues #617, #2544). It builds crafted groups, runs them
// through the real functions under both values of allowGroupedHeartbeats, and
// prints one JSON row per (group, flag, function):
//
//	{"name":..., "allow_hb":bool, "func":"txn"|"payset", "group":[b64 msgpack...],
//	 "ok":bool, "error":"...", "reason":N, "group_index":N}
//
// crates/core/algo-validate/tests/check_txn_group_oracle_test.rs compares the
// Rust port to the committed output
// (crates/core/algo-validate/tests/fixtures/check_txn_group_oracle.jsonl).
//
// Regenerate (go checkout pinned to v5.1.1-stable at ../go-algorand):
//
//	make -C ../go-algorand libsodium
//	mkdir -p ../go-algorand/cmd/checktxngroup-oracle
//	cp tools/checktxngroup-oracle/main.go ../go-algorand/cmd/checktxngroup-oracle/
//	(cd ../go-algorand && go run ./cmd/checktxngroup-oracle) \
//	    > crates/core/algo-validate/tests/fixtures/check_txn_group_oracle.jsonl
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

type row struct {
	Name       string   `json:"name"`
	AllowHB    bool     `json:"allow_hb"`
	Func       string   `json:"func"`
	Group      []string `json:"group"`
	Ok         bool     `json:"ok"`
	Error      string   `json:"error,omitempty"`
	Reason     int      `json:"reason"`
	GroupIndex int      `json:"group_index"`
}

func regroup(g []transactions.SignedTxn) []transactions.SignedTxn {
	out := append([]transactions.SignedTxn(nil), g...)
	tg := transactions.TxGroup{}
	for i := range out {
		out[i].Txn.Group = crypto.Digest{}
		tg.TxGroupHashes = append(tg.TxGroupHashes, crypto.Digest(out[i].Txn.ID()))
	}
	id := crypto.HashObj(tg)
	for i := range out {
		out[i].Txn.Group = id
	}
	return out
}

func main() {
	enc := json.NewEncoder(os.Stdout)

	emit := func(name string, group []transactions.SignedTxn) {
		var b64 []string
		for i := range group {
			b64 = append(b64, base64.StdEncoding.EncodeToString(protocol.Encode(&group[i])))
		}
		for _, allow := range []bool{false, true} {
			var errs [2]error
			errs[0] = transactions.CheckTxnGroup(group, allow)
			ads := make([]transactions.SignedTxnWithAD, len(group))
			for i := range group {
				ads[i] = group[i].WithAD()
			}
			errs[1] = transactions.CheckPaysetGroup(ads, allow)
			for k, fn := range []string{"txn", "payset"} {
				r := row{Name: name, AllowHB: allow, Func: fn, Group: b64, Ok: errs[k] == nil, GroupIndex: -2}
				if errs[k] != nil {
					r.Error = errs[k].Error()
					var m *transactions.TxGroupMalformedError
					if errors.As(errs[k], &m) {
						r.Reason = int(m.Reason)
						r.GroupIndex = m.GroupIndex
					}
				}
				if err := enc.Encode(r); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
			}
		}
	}

	sender := basics.Address{1}
	mk := func(typ protocol.TxType, note byte) transactions.SignedTxn {
		return transactions.SignedTxn{Txn: transactions.Transaction{
			Type:   typ,
			Header: transactions.Header{Sender: sender, Note: []byte{note}},
		}}
	}
	hb := func(note byte) transactions.SignedTxn {
		t := mk(protocol.HeartbeatTx, note)
		t.Txn.HeartbeatTxnFields = &transactions.HeartbeatTxnFields{HbSeed: [32]byte{1}}
		return t
	}
	hbBare := func(note byte) transactions.SignedTxn { return mk(protocol.HeartbeatTx, note) }
	acfgCreate := func(note byte) transactions.SignedTxn { return mk(protocol.AssetConfigTx, note) }
	acfgChange := func(note byte) transactions.SignedTxn {
		t := mk(protocol.AssetConfigTx, note)
		t.Txn.ConfigAsset = 42
		return t
	}
	badStpf := mk(protocol.StateProofTx, 0)
	stpfType1 := mk(protocol.StateProofTx, 0)
	stpfType1.Txn.StateProofType = 1

	g := func(ts ...transactions.SignedTxn) []transactions.SignedTxn { return ts }
	pay := func(note byte) transactions.SignedTxn { return mk(protocol.PaymentTx, note) }

	// Heartbeat missing its body: no longer a group check (v5.1).
	emit("hb_missing_body_alone", g(hbBare(0)))
	emit("hb_with_body_alone", g(hb(0)))
	emit("hb_missing_body_grouped", regroup(g(pay(1), hbBare(2), pay(3))))

	// Grouped heartbeats; the flag is run both ways.
	emit("hb_then_appl", regroup(g(hb(0), mk(protocol.ApplicationCallTx, 1))))
	emit("appl_then_hb", regroup(g(mk(protocol.ApplicationCallTx, 1), hb(0))))
	emit("hb_then_asset_create", regroup(g(hb(0), acfgCreate(1))))
	emit("hb_then_asset_change", regroup(g(hb(0), acfgChange(1))))
	emit("hb_then_payment", regroup(g(hb(0), pay(1))))
	emit("hb_missing_body_then_appl", regroup(g(hbBare(0), mk(protocol.ApplicationCallTx, 1))))
	emit("hb_then_appl_ungrouped_ids", g(hb(0), mk(protocol.ApplicationCallTx, 1)))
	emit("hb_then_appl_wrong_group_id", func() []transactions.SignedTxn {
		x := regroup(g(hb(0), mk(protocol.ApplicationCallTx, 1)))
		x[0].Txn.Group[0] ^= 1
		x[1].Txn.Group[0] ^= 1
		return x
	}())

	// Unknown type: no longer a group check (v5.1).
	emit("unknown_type_alone", g(mk(protocol.TxType("bogus"), 0)))
	emit("unknown_type_after_appl", regroup(g(mk(protocol.ApplicationCallTx, 0), mk(protocol.TxType("bogus"), 1))))
	for _, tt := range []protocol.TxType{
		protocol.PaymentTx, protocol.KeyRegistrationTx, protocol.AssetConfigTx,
		protocol.AssetTransferTx, protocol.AssetFreezeTx, protocol.ApplicationCallTx,
	} {
		emit("known_type_"+string(tt), g(mk(tt, 0)))
	}

	// Application box index: no longer a group check (v5.1).
	box := mk(protocol.ApplicationCallTx, 0)
	box.Txn.Boxes = []transactions.BoxRef{{Index: 1}}
	emit("box_index_beyond_foreign_apps", g(box))
	boxOK := mk(protocol.ApplicationCallTx, 0)
	boxOK.Txn.ForeignApps = []basics.AppIndex{1}
	boxOK.Txn.Boxes = []transactions.BoxRef{{Index: 1}}
	emit("box_index_within_foreign_apps", g(boxOK))

	// State proofs: still a group check, before the group ID.
	emit("stpf_default_body", g(badStpf))
	emit("stpf_unsupported_type", g(stpfType1))
	emit("stpf_default_body_in_duplicate_group", regroup(g(badStpf, badStpf)))

	// Group ID rules.
	emit("single_zero_group", g(pay(0)))
	emit("empty_group", g())
	emit("zero_group_in_group_of_two", g(pay(0), pay(1)))
	emit("valid_group_of_two", regroup(g(pay(0), pay(1))))
	emit("valid_group_of_sixteen", func() []transactions.SignedTxn {
		var x []transactions.SignedTxn
		for i := 0; i < 16; i++ {
			x = append(x, pay(byte(i)))
		}
		return regroup(x)
	}())
	emit("valid_group_of_seventeen", func() []transactions.SignedTxn {
		var x []transactions.SignedTxn
		for i := 0; i < 17; i++ {
			x = append(x, pay(byte(i)))
		}
		return regroup(x)
	}())
	emit("single_member_nonzero_group", regroup(g(pay(0)))[:1])
	emit("two_of_three_members", regroup(g(pay(0), pay(1), pay(2)))[:2])
	emit("reordered_members", func() []transactions.SignedTxn {
		x := regroup(g(pay(0), pay(1), pay(2)))
		x[0], x[1] = x[1], x[0]
		return x
	}())
	emit("inconsistent_group_values", func() []transactions.SignedTxn {
		x := regroup(g(pay(0), pay(1), pay(2)))
		x[2].Txn.Group[0] ^= 1
		return x
	}())
	emit("first_zero_rest_nonzero", func() []transactions.SignedTxn {
		x := regroup(g(pay(0), pay(1)))
		x[0].Txn.Group = crypto.Digest{}
		return x
	}())

	// Duplicate transactions (v5.1, #6728): rejected even when the group ID
	// commits to both occurrences.
	a := pay(7)
	emit("duplicate_pair", regroup(g(a, a)))
	emit("duplicate_third_repeats_first", regroup(g(a, pay(8), a)))
	emit("duplicate_third_repeats_second", regroup(g(pay(8), a, a)))
	emit("duplicate_triple", regroup(g(a, a, a)))
	argsDup := regroup(g(a, a))
	argsDup[0].Lsig = transactions.LogicSig{Logic: []byte{1}, Args: [][]byte{{0}}}
	argsDup[1].Lsig = transactions.LogicSig{Logic: []byte{1}, Args: [][]byte{{1}}}
	emit("duplicate_differs_only_in_lsig_args", argsDup)
	sigDup := regroup(g(a, a))
	sigDup[0].Sig = crypto.Signature{1}
	sigDup[1].Sig = crypto.Signature{2}
	emit("duplicate_differs_only_in_signature", sigDup)
	emit("duplicate_pair_with_unrelated_group_id", func() []transactions.SignedTxn {
		x := g(a, a)
		x[0].Txn.Group = crypto.Digest{9}
		x[1].Txn.Group = crypto.Digest{9}
		return x
	}())
	emit("near_duplicate_distinct_notes", regroup(g(pay(1), pay(2))))
	emit("duplicate_heartbeat_pair", regroup(g(hb(1), hb(1))))
	emit("duplicate_heartbeat_with_appl", regroup(g(hb(1), mk(protocol.ApplicationCallTx, 1), hb(1))))
}
