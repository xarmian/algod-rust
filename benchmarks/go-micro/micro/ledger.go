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

package micro

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// appLedger is a minimal in-memory logic.LedgerForLogic for the
// avm/app-state-box pair: one application with global state and boxes,
// nothing else. go-algorand's own mock (logic.NewLedger) lives in a _test.go
// file of package logic and cannot be imported, so this is the equivalent of
// the Rust side's in-memory algo_ledger::LedgerState. Only the calls the
// benchmark program makes are functional; everything else reports
// "not available", exactly like an empty ledger.
type appLedger struct {
	appID   basics.AppIndex
	creator basics.Address
	globals map[string]basics.TealValue
	boxes   map[string][]byte
}

var _ logic.LedgerForLogic = (*appLedger)(nil)

func newAppLedger(appID basics.AppIndex, creator basics.Address) *appLedger {
	return &appLedger{
		appID:   appID,
		creator: creator,
		globals: make(map[string]basics.TealValue),
		boxes:   make(map[string][]byte),
	}
}

// reset restores the starting state of an evaluation: no global state and
// a zeroed box. Both sides' AVMs write globals and boxes straight into their
// ledger (go: SetGlobal/SetBox here; Rust: LedgerAvmContext writes into its
// LedgerState), so both reset at the start of every iteration.
func (l *appLedger) reset() {
	clear(l.globals)
	b := l.boxes[AppBoxName]
	if len(b) != AppBoxSize {
		b = make([]byte, AppBoxSize)
	}
	clear(b)
	l.boxes[AppBoxName] = b
}

// preState describes the state an evaluation starts from (part of the app
// pair's digest, so a missing reset changes the digest).
func (l *appLedger) preState() string {
	box := "none"
	if b, ok := l.boxes[AppBoxName]; ok {
		h := sha256.Sum256(b)
		box = hex.EncodeToString(h[:8])
	}
	return fmt.Sprintf("globals=%d,box=%s", len(l.globals), box)
}

var errNotHere = fmt.Errorf("not available in the micro-benchmark ledger")

func (l *appLedger) AccountData(addr basics.Address) (ledgercore.AccountData, error) {
	return ledgercore.AccountData{}, nil
}
func (l *appLedger) Authorizer(addr basics.Address) (basics.Address, error) { return addr, nil }
func (l *appLedger) Round() basics.Round                                    { return 1000 }
func (l *appLedger) PrevTimestamp() int64                                   { return 1_700_000_000 }
func (l *appLedger) AgreementData(addr basics.Address) (basics.OnlineAccountData, error) {
	return basics.OnlineAccountData{}, nil
}
func (l *appLedger) OnlineStake() (basics.MicroAlgos, error) { return basics.MicroAlgos{}, nil }
func (l *appLedger) AssetHolding(addr basics.Address, assetIdx basics.AssetIndex) (basics.AssetHolding, error) {
	return basics.AssetHolding{}, errNotHere
}
func (l *appLedger) AssetParams(aidx basics.AssetIndex) (basics.AssetParams, basics.Address, error) {
	return basics.AssetParams{}, basics.Address{}, errNotHere
}
func (l *appLedger) AppParams(aidx basics.AppIndex) (basics.AppParams, basics.Address, error) {
	if aidx != l.appID {
		return basics.AppParams{}, basics.Address{}, errNotHere
	}
	var p basics.AppParams
	p.GlobalStateSchema = basics.StateSchema{NumUint: 16, NumByteSlice: 16}
	return p, l.creator, nil
}
func (l *appLedger) OptedIn(addr basics.Address, appIdx basics.AppIndex) (bool, error) {
	return false, nil
}
func (l *appLedger) GetLocal(addr basics.Address, appIdx basics.AppIndex, key string, accountIdx uint64) (basics.TealValue, bool, error) {
	return basics.TealValue{}, false, errNotHere
}
func (l *appLedger) SetLocal(addr basics.Address, appIdx basics.AppIndex, key string, value basics.TealValue, accountIdx uint64) error {
	return errNotHere
}
func (l *appLedger) DelLocal(addr basics.Address, appIdx basics.AppIndex, key string, accountIdx uint64) error {
	return errNotHere
}
func (l *appLedger) GetGlobal(appIdx basics.AppIndex, key string) (basics.TealValue, bool, error) {
	if appIdx != l.appID {
		return basics.TealValue{}, false, errNotHere
	}
	v, ok := l.globals[key]
	return v, ok, nil
}
func (l *appLedger) SetGlobal(appIdx basics.AppIndex, key string, value basics.TealValue) error {
	if appIdx != l.appID {
		return errNotHere
	}
	l.globals[key] = value
	return nil
}
func (l *appLedger) DelGlobal(appIdx basics.AppIndex, key string) error {
	if appIdx != l.appID {
		return errNotHere
	}
	delete(l.globals, key)
	return nil
}
func (l *appLedger) NewBox(appIdx basics.AppIndex, key string, value []byte, appAddr basics.Address) error {
	if appIdx != l.appID {
		return errNotHere
	}
	if _, ok := l.boxes[key]; ok {
		return fmt.Errorf("box %q exists", key)
	}
	l.boxes[key] = append([]byte(nil), value...)
	return nil
}
func (l *appLedger) GetBox(appIdx basics.AppIndex, key string) ([]byte, bool, error) {
	if appIdx != l.appID {
		return nil, false, errNotHere
	}
	v, ok := l.boxes[key]
	return v, ok, nil
}
func (l *appLedger) SetBox(appIdx basics.AppIndex, key string, value []byte) error {
	if appIdx != l.appID {
		return errNotHere
	}
	if _, ok := l.boxes[key]; !ok {
		return fmt.Errorf("no box %q", key)
	}
	l.boxes[key] = append(l.boxes[key][:0], value...)
	return nil
}
func (l *appLedger) DelBox(appIdx basics.AppIndex, key string, appAddr basics.Address) (bool, error) {
	if appIdx != l.appID {
		return false, errNotHere
	}
	_, ok := l.boxes[key]
	delete(l.boxes, key)
	return ok, nil
}
func (l *appLedger) Perform(gi int, ep *logic.EvalParams) error { return errNotHere }
func (l *appLedger) Counter() uint64                            { return 2000 }
func (l *appLedger) SetForeignBoxReads(appID basics.AppIndex, enable bool) error {
	return errNotHere
}
func (l *appLedger) SetFamilyBoxAccess(appID basics.AppIndex, enable bool) error {
	return errNotHere
}
