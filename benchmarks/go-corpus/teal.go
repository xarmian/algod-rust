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
	"fmt"

	"github.com/algorand/go-algorand/data/transactions/logic"
)

// mainApproval is the workload's main application: a global counter "g", a
// per-account local counter "l", boxes, and an "inner" method that issues an
// inner pay + axfer + appl (call of the callee app) group.
//
//	args[0] = "inc"            g += 1, local l += 1 (sender must be opted in)
//	args[0] = "box"  name val  box_put(name, val)
//	args[0] = "unbox" name     box_del(name)
//	args[0] = "inner"          inner pay 1000 uA + axfer 1 unit of Assets[0]
//	                           to the sender, then appl call of Applications[1]
//	args[0] = "optasset"       the app opts into Assets[0]
//
// OptIn initialises l = 0; CloseOut is allowed; anything else fails.
const mainApproval = `#pragma version 10
txn ApplicationID
bz on_create
txn OnCompletion
int OptIn
==
bnz on_optin
txn OnCompletion
int CloseOut
==
bnz ok
txn OnCompletion
int NoOp
==
assert
txna ApplicationArgs 0
byte "inc"
==
bnz on_inc
txna ApplicationArgs 0
byte "box"
==
bnz on_box
txna ApplicationArgs 0
byte "unbox"
==
bnz on_unbox
txna ApplicationArgs 0
byte "inner"
==
bnz on_inner
txna ApplicationArgs 0
byte "optasset"
==
bnz on_optasset
err
on_create:
byte "g"
int 0
app_global_put
b ok
on_optin:
txn Sender
byte "l"
int 0
app_local_put
b ok
on_inc:
byte "g"
byte "g"
app_global_get
int 1
+
app_global_put
txn Sender
byte "l"
txn Sender
byte "l"
app_local_get
int 1
+
app_local_put
b ok
on_box:
txna ApplicationArgs 1
txna ApplicationArgs 2
box_put
b ok
on_unbox:
txna ApplicationArgs 1
box_del
assert
b ok
on_inner:
itxn_begin
int pay
itxn_field TypeEnum
txn Sender
itxn_field Receiver
int 1000
itxn_field Amount
int 0
itxn_field Fee
itxn_next
int axfer
itxn_field TypeEnum
txna Assets 0
itxn_field XferAsset
txn Sender
itxn_field AssetReceiver
int 1
itxn_field AssetAmount
int 0
itxn_field Fee
itxn_next
int appl
itxn_field TypeEnum
txna Applications 1
itxn_field ApplicationID
byte "ping"
itxn_field ApplicationArgs
int 0
itxn_field Fee
itxn_submit
b ok
on_optasset:
itxn_begin
int axfer
itxn_field TypeEnum
txna Assets 0
itxn_field XferAsset
global CurrentApplicationAddress
itxn_field AssetReceiver
int 0
itxn_field AssetAmount
int 0
itxn_field Fee
itxn_submit
b ok
ok:
int 1
return
`

// calleeApproval approves every call; any call other than the create bumps
// the global counter "p". It is the target of the main app's inner appl and
// the program of the throwaway apps that are created, updated and deleted.
const calleeApproval = `#pragma version 10
txn ApplicationID
bz ok
byte "p"
byte "p"
app_global_get
int 1
+
app_global_put
ok:
int 1
`

const clearApproval = `#pragma version 10
int 1
`

type programs struct {
	main, callee, clear []byte
}

func assemble(name, src string) ([]byte, error) {
	ops, err := logic.AssembleString(src)
	if err != nil {
		return nil, fmt.Errorf("assemble %s: %w", name, err)
	}
	return ops.Program, nil
}

func assemblePrograms() (programs, error) {
	var p programs
	var err error
	if p.main, err = assemble("main", mainApproval); err != nil {
		return p, err
	}
	if p.callee, err = assemble("callee", calleeApproval); err != nil {
		return p, err
	}
	if p.clear, err = assemble("clear", clearApproval); err != nil {
		return p, err
	}
	return p, nil
}
