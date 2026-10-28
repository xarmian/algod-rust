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

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

const (
	minFee  = 1000
	txnLife = 1000 // LastValid = FirstValid + txnLife (MaxTxnLife)

	appFunding   = 10_000_000_000     // 10k Algo into the main app account
	appAssetFund = 1_000_000_000_000  // asset-A units held by the main app
	assetATotal  = 10_000_000_000_000 // 1e13 units, held by the admin
	optInGrant   = 1_000_000          // asset-A units granted after an opt-in
)

// acct is the generator's model of one workload account. The model is
// updated at planning time, in exactly the order the transactions are
// submitted (and so appear in the block), so every planned transaction is
// valid when the pool evaluates it.
type acct struct {
	key
	idx      int
	auth     basics.Address // zero: signs with its own key
	optA     bool           // opted into asset A
	balA     uint64
	optApp   bool // opted into the main app
	online   bool
	reserved uint64 // round until which a lifecycle owns this account
}

// planned is one transaction group (a single txn is a group of one) before
// signing. signers[i] is the address whose key signs txns[i].
type planned struct {
	txns    []transactions.Transaction
	signers []basics.Address
	// onCommit runs after the block holding the group is recorded, with the
	// group's ApplyData (created asset/app ids).
	onCommit func(ads []transactions.ApplyData)
}

type throwApp struct {
	creator *acct
	id      basics.AppIndex
}

type throwAsset struct {
	creator *acct
	id      basics.AssetIndex
}

type params struct {
	rounds       uint64
	accounts     int
	txnsPerRound int
	tsOffset     uint64
	seed         string
}

type workload struct {
	p     params
	n     *network
	progs programs
	rng   *rand.Rand

	genesisID   string
	genesisHash crypto.Digest

	keys  map[basics.Address]*crypto.SignatureSecrets
	accts []*acct // accts[0] is the admin
	known []basics.Address

	assetA    basics.AssetIndex
	mainApp   basics.AppIndex
	calleeApp basics.AppIndex

	round uint64
	busy  map[basics.Address]bool
	sched map[uint64][]func() *planned

	boxes    [][]byte
	boxCtr   uint64
	ephCtr   uint64
	keyregN  uint64
	noteCtr  uint64
	throwAp  []*throwApp
	throwAs  []*throwAsset
	setupLen uint64
}

func newWorkload(p params, n *network, progs programs, genesisID string, genesisHash crypto.Digest) *workload {
	s := deriveSeed(p.seed, "workload-rng", 0)
	w := &workload{
		p:           p,
		n:           n,
		progs:       progs,
		rng:         rand.New(rand.NewPCG(binary.BigEndian.Uint64(s[0:8]), binary.BigEndian.Uint64(s[8:16]))),
		genesisID:   genesisID,
		genesisHash: genesisHash,
		keys:        map[basics.Address]*crypto.SignatureSecrets{},
		sched:       map[uint64][]func() *planned{},
	}
	for i, k := range n.accounts {
		w.accts = append(w.accts, &acct{key: k, idx: i})
		w.keys[k.addr] = k.secrets
	}
	w.known = append(w.known, n.rewardsPool.addr, n.feeSink.addr)
	for _, v := range n.validators {
		w.known = append(w.known, v.addr)
	}
	for _, a := range w.accts {
		w.known = append(w.known, a.addr)
	}
	return w
}

func (w *workload) admin() *acct { return w.accts[0] }

func (w *workload) header(sender basics.Address, fee uint64) transactions.Header {
	w.noteCtr++
	note := make([]byte, 10)
	copy(note, "bc")
	binary.BigEndian.PutUint64(note[2:], w.noteCtr)
	return transactions.Header{
		Sender:      sender,
		Fee:         basics.MicroAlgos{Raw: fee},
		FirstValid:  basics.Round(w.round),
		LastValid:   basics.Round(w.round + txnLife),
		Note:        note,
		GenesisID:   w.genesisID,
		GenesisHash: w.genesisHash,
	}
}

// authOf is the address whose key currently signs for a.
func authOf(a *acct) basics.Address {
	if a.auth.IsZero() {
		return a.addr
	}
	return a.auth
}

func single(tx transactions.Transaction, signer basics.Address) *planned {
	return &planned{txns: []transactions.Transaction{tx}, signers: []basics.Address{signer}}
}

// pick returns a random free (not busy this round, not reserved by a
// lifecycle, not the admin) account satisfying ok, and marks it busy.
func (w *workload) pick(ok func(*acct) bool) *acct {
	n := len(w.accts) - 1
	for try := 0; try < 24; try++ {
		a := w.accts[1+w.rng.IntN(n)]
		if w.busy[a.addr] || a.reserved >= w.round || (ok != nil && !ok(a)) {
			continue
		}
		w.busy[a.addr] = true
		return a
	}
	return nil
}

func (w *workload) at(r uint64, f func() *planned) { w.sched[r] = append(w.sched[r], f) }

// ---- transaction builders ----------------------------------------------

func (w *workload) pay(from *acct, to basics.Address, amt uint64) transactions.Transaction {
	return transactions.Transaction{
		Type:             protocol.PaymentTx,
		Header:           w.header(from.addr, minFee),
		PaymentTxnFields: transactions.PaymentTxnFields{Receiver: to, Amount: basics.MicroAlgos{Raw: amt}},
	}
}

func (w *workload) axfer(sender basics.Address, asset basics.AssetIndex, amt uint64, to basics.Address) transactions.Transaction {
	return transactions.Transaction{
		Type:   protocol.AssetTransferTx,
		Header: w.header(sender, minFee),
		AssetTransferTxnFields: transactions.AssetTransferTxnFields{
			XferAsset: asset, AssetAmount: amt, AssetReceiver: to,
		},
	}
}

func (w *workload) appCall(sender basics.Address, app basics.AppIndex, oc transactions.OnCompletion, fee uint64, args ...[]byte) transactions.Transaction {
	return transactions.Transaction{
		Type:   protocol.ApplicationCallTx,
		Header: w.header(sender, fee),
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID: app, OnCompletion: oc, ApplicationArgs: args,
		},
	}
}

// ---- setup: one step per round, each waiting for the previous one -------

func (w *workload) setupSteps() []func() *planned {
	ad := w.admin()
	return []func() *planned{
		func() *planned { // r1: asset A
			tx := transactions.Transaction{
				Type:   protocol.AssetConfigTx,
				Header: w.header(ad.addr, minFee),
				AssetConfigTxnFields: transactions.AssetConfigTxnFields{AssetParams: basics.AssetParams{
					Total: assetATotal, Decimals: 0, UnitName: "BENCH", AssetName: "bench corpus asset A",
					URL: "https://github.com/xarmian/algod-rust", Manager: ad.addr, Reserve: ad.addr,
					Freeze: ad.addr, Clawback: ad.addr,
				}},
			}
			p := single(tx, ad.addr)
			p.onCommit = func(ads []transactions.ApplyData) { w.assetA = ads[0].ConfigAsset }
			ad.optA, ad.balA = true, assetATotal
			return p
		},
		func() *planned { // r2: main app (global g, local l, boxes, inner txns)
			tx := w.appCall(ad.addr, 0, transactions.NoOpOC, minFee)
			tx.ApprovalProgram, tx.ClearStateProgram = w.progs.main, w.progs.clear
			tx.GlobalStateSchema = basics.StateSchema{NumUint: 1}
			tx.LocalStateSchema = basics.StateSchema{NumUint: 1}
			p := single(tx, ad.addr)
			p.onCommit = func(ads []transactions.ApplyData) {
				w.mainApp = ads[0].ApplicationID
				w.known = append(w.known, w.mainApp.Address())
			}
			return p
		},
		func() *planned { // r3: callee app (target of the inner appl)
			tx := w.appCall(ad.addr, 0, transactions.NoOpOC, minFee)
			tx.ApprovalProgram, tx.ClearStateProgram = w.progs.callee, w.progs.clear
			tx.GlobalStateSchema = basics.StateSchema{NumUint: 1}
			p := single(tx, ad.addr)
			p.onCommit = func(ads []transactions.ApplyData) {
				w.calleeApp = ads[0].ApplicationID
				w.known = append(w.known, w.calleeApp.Address())
			}
			return p
		},
		func() *planned { // r4: fund the main app account
			return single(w.pay(ad, w.mainApp.Address(), appFunding), ad.addr)
		},
		func() *planned { // r5: the main app opts into asset A (inner axfer)
			tx := w.appCall(ad.addr, w.mainApp, transactions.NoOpOC, 2*minFee, []byte("optasset"))
			tx.ForeignAssets = []basics.AssetIndex{w.assetA}
			return single(tx, ad.addr)
		},
		func() *planned { // r6: asset A units for the main app's inner axfers
			ad.balA -= appAssetFund
			return single(w.axfer(ad.addr, w.assetA, appAssetFund, w.mainApp.Address()), ad.addr)
		},
	}
}

// ---- regular actions ------------------------------------------------------

type action struct {
	name   string
	weight int
	plan   func() *planned
}

func (w *workload) actions() []action {
	return []action{
		{"pay", 30, w.actPay},
		{"axfer", 14, w.actAxfer},
		{"clawback", 2, w.actClawback},
		{"asset-optin", 4, w.actAssetOptIn},
		{"app-inc", 10, w.actInc},
		{"app-optin", 4, w.actAppOptIn},
		{"app-closeout", 1, w.actAppCloseOut},
		{"app-clear", 1, w.actAppClear},
		{"box-put", 6, w.actBoxPut},
		{"box-del", 3, w.actBoxDel},
		{"inner", 6, w.actInner},
		{"group", 8, w.actGroup},
		{"freeze", 1, w.actFreeze},
		{"rekey", 1, w.actRekey},
		{"close-out", 1, w.actCloseOut},
		{"keyreg", 1, w.actKeyreg},
		{"app-lifecycle", 1, w.actAppLifecycle},
		{"asset-lifecycle", 1, w.actAssetLifecycle},
	}
}

func (w *workload) actPay() *planned {
	a := w.pick(nil)
	b := w.pick(nil)
	if a == nil || b == nil {
		return nil
	}
	return single(w.pay(a, b.addr, 1000+uint64(w.rng.IntN(100_000))), authOf(a))
}

func (w *workload) actAxfer() *planned {
	a := w.pick(func(x *acct) bool { return x.optA && x.balA >= 10 })
	b := w.pick(func(x *acct) bool { return x.optA })
	if a == nil || b == nil {
		return nil
	}
	amt := 1 + uint64(w.rng.IntN(int(min(a.balA, 1000))))
	a.balA -= amt
	b.balA += amt
	return single(w.axfer(a.addr, w.assetA, amt, b.addr), authOf(a))
}

func (w *workload) actClawback() *planned {
	a := w.pick(func(x *acct) bool { return x.optA && x.balA >= 1 })
	b := w.pick(func(x *acct) bool { return x.optA })
	if a == nil || b == nil {
		return nil
	}
	ad := w.admin()
	tx := w.axfer(ad.addr, w.assetA, 1, b.addr)
	tx.AssetSender = a.addr
	a.balA--
	b.balA++
	return single(tx, ad.addr)
}

// actAssetOptIn: x opts into asset A; next round the admin grants it units.
func (w *workload) actAssetOptIn() *planned {
	x := w.pick(func(x *acct) bool { return !x.optA })
	if x == nil {
		return nil
	}
	x.optA = true
	x.reserved = w.round + 1
	w.at(w.round+1, func() *planned {
		ad := w.admin()
		ad.balA -= optInGrant
		x.balA += optInGrant
		return single(w.axfer(ad.addr, w.assetA, optInGrant, x.addr), ad.addr)
	})
	return single(w.axfer(x.addr, w.assetA, 0, x.addr), authOf(x))
}

func (w *workload) actInc() *planned {
	a := w.pick(func(x *acct) bool { return x.optApp })
	if a == nil {
		return nil
	}
	return single(w.appCall(a.addr, w.mainApp, transactions.NoOpOC, minFee, []byte("inc")), authOf(a))
}

func (w *workload) actAppOptIn() *planned {
	a := w.pick(func(x *acct) bool { return !x.optApp })
	if a == nil {
		return nil
	}
	a.optApp = true
	return single(w.appCall(a.addr, w.mainApp, transactions.OptInOC, minFee), authOf(a))
}

func (w *workload) actAppCloseOut() *planned {
	a := w.pick(func(x *acct) bool { return x.optApp })
	if a == nil {
		return nil
	}
	a.optApp = false
	return single(w.appCall(a.addr, w.mainApp, transactions.CloseOutOC, minFee), authOf(a))
}

func (w *workload) actAppClear() *planned {
	a := w.pick(func(x *acct) bool { return x.optApp })
	if a == nil {
		return nil
	}
	a.optApp = false
	return single(w.appCall(a.addr, w.mainApp, transactions.ClearStateOC, minFee), authOf(a))
}

func (w *workload) actBoxPut() *planned {
	a := w.pick(nil)
	if a == nil {
		return nil
	}
	w.boxCtr++
	name := make([]byte, 9)
	name[0] = 'b'
	binary.BigEndian.PutUint64(name[1:], w.boxCtr)
	val := make([]byte, 32)
	for i := range val {
		val[i] = byte(w.rng.Uint32())
	}
	w.boxes = append(w.boxes, name)
	tx := w.appCall(a.addr, w.mainApp, transactions.NoOpOC, minFee, []byte("box"), name, val)
	tx.Boxes = []transactions.BoxRef{{Index: 0, Name: name}}
	return single(tx, authOf(a))
}

func (w *workload) actBoxDel() *planned {
	if len(w.boxes) == 0 {
		return nil
	}
	a := w.pick(nil)
	if a == nil {
		return nil
	}
	i := w.rng.IntN(len(w.boxes))
	name := w.boxes[i]
	w.boxes[i] = w.boxes[len(w.boxes)-1]
	w.boxes = w.boxes[:len(w.boxes)-1]
	tx := w.appCall(a.addr, w.mainApp, transactions.NoOpOC, minFee, []byte("unbox"), name)
	tx.Boxes = []transactions.BoxRef{{Index: 0, Name: name}}
	return single(tx, authOf(a))
}

// actInner: the main app sends the caller 1000 uA and 1 unit of asset A and
// calls the callee app, all as inner transactions (fees pooled: 4x min).
func (w *workload) actInner() *planned {
	a := w.pick(func(x *acct) bool { return x.optA })
	if a == nil {
		return nil
	}
	a.balA++
	tx := w.appCall(a.addr, w.mainApp, transactions.NoOpOC, 4*minFee, []byte("inner"))
	tx.ForeignAssets = []basics.AssetIndex{w.assetA}
	tx.ForeignApps = []basics.AppIndex{w.calleeApp}
	return single(tx, authOf(a))
}

// actGroup: an atomic group of 2..5 transactions mixing pay, axfer and app
// calls, each from a different account.
func (w *workload) actGroup() *planned {
	size := 2 + w.rng.IntN(4)
	g := &planned{}
	for try := 0; len(g.txns) < size && try < 2*size; try++ {
		var p *planned
		switch w.rng.IntN(3) {
		case 0:
			p = w.actPay()
		case 1:
			p = w.actAxfer()
		default:
			p = w.actInc()
		}
		if p != nil {
			g.txns = append(g.txns, p.txns...)
			g.signers = append(g.signers, p.signers...)
		}
	}
	if len(g.txns) == 0 {
		return nil
	}
	return g
}

// actFreeze: the admin freezes a holder of asset A and unfreezes it two
// rounds later; the holder is reserved (no transfers) meanwhile.
func (w *workload) actFreeze() *planned {
	x := w.pick(func(x *acct) bool { return x.optA })
	if x == nil {
		return nil
	}
	x.reserved = w.round + 2
	freeze := func(frozen bool) *planned {
		ad := w.admin()
		return single(transactions.Transaction{
			Type:   protocol.AssetFreezeTx,
			Header: w.header(ad.addr, minFee),
			AssetFreezeTxnFields: transactions.AssetFreezeTxnFields{
				FreezeAccount: x.addr, FreezeAsset: w.assetA, AssetFrozen: frozen,
			},
		}, ad.addr)
	}
	w.at(w.round+2, func() *planned { w.busy[x.addr] = true; return freeze(false) })
	return freeze(true)
}

// actRekey: x rekeys to y, sends a payment authorised by y, then y rekeys x
// back to itself.
func (w *workload) actRekey() *planned {
	x := w.pick(func(a *acct) bool { return a.auth.IsZero() })
	y := w.pick(nil)
	if x == nil || y == nil {
		return nil
	}
	x.reserved = w.round + 3
	tx := w.pay(x, x.addr, 0)
	tx.RekeyTo = y.addr
	p := single(tx, authOf(x))
	x.auth = y.addr
	w.at(w.round+1, func() *planned {
		w.busy[x.addr] = true
		return single(w.pay(x, w.admin().addr, 1000), authOf(x))
	})
	w.at(w.round+3, func() *planned {
		w.busy[x.addr] = true
		back := w.pay(x, x.addr, 0)
		back.RekeyTo = x.addr
		p := single(back, authOf(x))
		x.auth = basics.Address{}
		return p
	})
	return p
}

// actCloseOut: a fresh ephemeral account is funded, opts into asset A,
// receives units, then closes its asset holding (axfer close) and the
// account itself (pay close) back to the funder.
func (w *workload) actCloseOut() *planned {
	f := w.pick(nil)
	if f == nil {
		return nil
	}
	e := deriveKey(w.p.seed, "ephemeral", w.ephCtr)
	w.ephCtr++
	w.keys[e.addr] = e.secrets
	w.known = append(w.known, e.addr)
	ea := &acct{key: e, idx: -1}
	w.at(w.round+1, func() *planned { return single(w.axfer(e.addr, w.assetA, 0, e.addr), e.addr) })
	w.at(w.round+2, func() *planned {
		ad := w.admin()
		ad.balA -= 3
		return single(w.axfer(ad.addr, w.assetA, 3, e.addr), ad.addr)
	})
	w.at(w.round+3, func() *planned {
		ad := w.admin()
		ad.balA += 3
		cl := w.axfer(e.addr, w.assetA, 0, ad.addr)
		cl.AssetCloseTo = ad.addr
		return single(cl, e.addr)
	})
	w.at(w.round+3, func() *planned {
		pc := w.pay(ea, f.addr, 0)
		pc.CloseRemainderTo = f.addr
		return single(pc, e.addr)
	})
	return single(w.pay(f, e.addr, 1_000_000), authOf(f))
}

// actKeyreg: x registers online with derived participation keys, and goes
// offline 20 rounds later.
func (w *workload) actKeyreg() *planned {
	x := w.pick(func(a *acct) bool { return !a.online })
	if x == nil {
		return nil
	}
	x.reserved = w.round + 20
	x.online = true
	pk := derivePartKeys(w.p.seed, "keyreg", w.keyregN)
	w.keyregN++
	tx := transactions.Transaction{
		Type:   protocol.KeyRegistrationTx,
		Header: w.header(x.addr, minFee),
		KeyregTxnFields: transactions.KeyregTxnFields{
			VotePK: pk.vote, SelectionPK: pk.selection, StateProofPK: pk.stateProf,
			VoteFirst: basics.Round(w.round), VoteLast: basics.Round(w.round + 1_000_000),
			VoteKeyDilution: 10_000,
		},
	}
	w.at(w.round+20, func() *planned {
		w.busy[x.addr] = true
		x.online = false
		return single(transactions.Transaction{
			Type: protocol.KeyRegistrationTx, Header: w.header(x.addr, minFee),
		}, authOf(x))
	})
	return single(tx, authOf(x))
}

// actAppLifecycle: x creates a throwaway app, calls it, updates it and
// deletes it.
func (w *workload) actAppLifecycle() *planned {
	x := w.pick(nil)
	if x == nil {
		return nil
	}
	ta := &throwApp{creator: x}
	tx := w.appCall(x.addr, 0, transactions.NoOpOC, minFee)
	tx.ApprovalProgram, tx.ClearStateProgram = w.progs.callee, w.progs.clear
	tx.GlobalStateSchema = basics.StateSchema{NumUint: 1}
	p := single(tx, authOf(x))
	p.onCommit = func(ads []transactions.ApplyData) { ta.id = ads[0].ApplicationID }
	step := func(oc transactions.OnCompletion) func() *planned {
		return func() *planned {
			w.busy[x.addr] = true
			c := w.appCall(x.addr, ta.id, oc, minFee)
			if oc == transactions.UpdateApplicationOC {
				c.ApprovalProgram, c.ClearStateProgram = w.progs.callee, w.progs.clear
			}
			return single(c, authOf(x))
		}
	}
	w.at(w.round+2, step(transactions.NoOpOC))
	w.at(w.round+4, step(transactions.UpdateApplicationOC))
	w.at(w.round+6, step(transactions.DeleteApplicationOC))
	return p
}

// actAssetLifecycle: x creates a throwaway asset, reconfigures it and
// destroys it.
func (w *workload) actAssetLifecycle() *planned {
	x := w.pick(nil)
	if x == nil {
		return nil
	}
	ta := &throwAsset{creator: x}
	params := basics.AssetParams{
		Total: 1000, UnitName: "TMP", AssetName: "throwaway",
		Manager: x.addr, Reserve: x.addr, Freeze: x.addr, Clawback: x.addr,
	}
	p := single(transactions.Transaction{
		Type:                 protocol.AssetConfigTx,
		Header:               w.header(x.addr, minFee),
		AssetConfigTxnFields: transactions.AssetConfigTxnFields{AssetParams: params},
	}, authOf(x))
	p.onCommit = func(ads []transactions.ApplyData) { ta.id = ads[0].ConfigAsset }
	w.at(w.round+3, func() *planned {
		w.busy[x.addr] = true
		re := basics.AssetParams{Manager: x.addr, Reserve: w.admin().addr, Freeze: x.addr, Clawback: x.addr}
		return single(transactions.Transaction{
			Type:                 protocol.AssetConfigTx,
			Header:               w.header(x.addr, minFee),
			AssetConfigTxnFields: transactions.AssetConfigTxnFields{ConfigAsset: ta.id, AssetParams: re},
		}, authOf(x))
	})
	w.at(w.round+6, func() *planned {
		w.busy[x.addr] = true
		return single(transactions.Transaction{
			Type:                 protocol.AssetConfigTx,
			Header:               w.header(x.addr, minFee),
			AssetConfigTxnFields: transactions.AssetConfigTxnFields{ConfigAsset: ta.id},
		}, authOf(x))
	})
	return p
}

// planRound returns the groups of block w.round, in submission order.
func (w *workload) planRound(setup []func() *planned) []*planned {
	w.busy = map[basics.Address]bool{}
	if w.round <= uint64(len(setup)) {
		return []*planned{setup[w.round-1]()}
	}
	var out []*planned
	count := 0
	for _, f := range w.sched[w.round] {
		p := f()
		out = append(out, p)
		count += len(p.txns)
	}
	delete(w.sched, w.round)
	acts := w.actions()
	total := 0
	for _, a := range acts {
		total += a.weight
	}
	for misses := 0; count < w.p.txnsPerRound && misses < 64; {
		r := w.rng.IntN(total)
		var act action
		for _, a := range acts {
			if r < a.weight {
				act = a
				break
			}
			r -= a.weight
		}
		p := act.plan()
		if p == nil {
			misses++
			continue
		}
		out = append(out, p)
		count += len(p.txns)
	}
	if len(out) == 0 {
		// Never leave a round empty: a DevMode block is only made by a submit.
		ad := w.admin()
		out = append(out, single(w.pay(ad, ad.addr, 0), ad.addr))
	}
	return out
}

// sign assigns the group id (for groups of 2+) and signs every txn with its
// signer's key, setting AuthAddr when the signer is not the sender.
func (w *workload) sign(p *planned) ([]transactions.SignedTxn, error) {
	if len(p.txns) > 1 {
		var tg transactions.TxGroup
		for _, tx := range p.txns {
			tg.TxGroupHashes = append(tg.TxGroupHashes, crypto.Digest(tx.ID()))
		}
		gid := crypto.HashObj(tg)
		for i := range p.txns {
			p.txns[i].Group = gid
		}
	}
	out := make([]transactions.SignedTxn, len(p.txns))
	for i, tx := range p.txns {
		sk := w.keys[p.signers[i]]
		if sk == nil {
			return nil, fmt.Errorf("no key for signer %s", p.signers[i])
		}
		out[i] = tx.Sign(sk)
		if p.signers[i] != tx.Sender {
			out[i].AuthAddr = p.signers[i]
		}
	}
	return out, nil
}
