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

// Signature-failure rows: go-algorand oracle for issue #2451.
//
// The signature classes of `verify.TxnGroup` the WellFormed table does not
// already hold (multisig, delegated LogicSig by key and by multisig, a
// rekeyed authorizer), each a single transaction run through the REST path
// (`verify.TxnGroup`) and simulate by blockdup.go. A member's failure is
// `transaction <%+v of the SignedTxn> invalid : <reason>`; the batch
// verifier's own failure is bare; a delegated LogicSig's signature is
// checked by its own batch inside `logicSigVerify`, so its failure is framed.
package main

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
)

type sigRow struct {
	name string
	tx   transactions.SignedTxn
}

func sigFailureRows(secrets *crypto.SignatureSecrets, payTxn func(string, [32]byte) transactions.Transaction) []sigRow {
	var seed crypto.Seed
	for i := range seed {
		seed[i] = 0xB2
	}
	other := crypto.GenerateSignatureSecrets(seed)
	pks := []crypto.PublicKey{secrets.SignatureVerifier, other.SignatureVerifier}
	msigAddr, err := crypto.MultisigAddrGen(1, 1, pks)
	must(err)

	pay := func(note string) transactions.Transaction { return payTxn(note, [32]byte{}) }
	msigTxn := func(note string) transactions.Transaction {
		t := pay(note)
		t.Sender = basics.Address(msigAddr)
		return t
	}
	msigSigned := func(note string) transactions.SignedTxn {
		t := msigTxn(note)
		sig, err := crypto.MultisigSign(t, msigAddr, 1, 1, pks, *secrets)
		must(err)
		return transactions.SignedTxn{Txn: t, Msig: sig}
	}
	ops, err := logic.AssembleString("#pragma version 8\nint 1")
	must(err)
	prog := ops.Program
	delegated := func(note string) transactions.SignedTxn {
		return transactions.SignedTxn{Txn: pay(note), Lsig: transactions.LogicSig{
			Logic: prog,
			Sig:   secrets.Sign(logic.Program(prog)),
		}}
	}
	lmsig := func(note string) transactions.SignedTxn {
		sig, err := crypto.MultisigSign(logic.MultisigProgram{Addr: msigAddr, Program: prog}, msigAddr, 1, 1, pks, *secrets)
		must(err)
		return transactions.SignedTxn{Txn: msigTxn(note), Lsig: transactions.LogicSig{Logic: prog, LMsig: sig}}
	}

	var rows []sigRow
	add := func(name string, tx transactions.SignedTxn) { rows = append(rows, sigRow{name, tx}) }

	add("verify_msig_valid", msigSigned("sig-msig-valid"))
	badVersion := msigSigned("sig-msig-bad-version")
	badVersion.Msig.Version = 2
	add("verify_msig_bad_version", badVersion)
	badSubsig := msigSigned("sig-msig-bad-subsig")
	badSubsig.Msig.Subsigs[0].Sig[0] ^= 1
	add("verify_msig_bad_subsig_signature", badSubsig)
	wrongAddr := msigSigned("sig-msig-wrong-address")
	wrongAddr.Txn.Sender = basics.Address(other.SignatureVerifier)
	add("verify_msig_wrong_address", wrongAddr)
	unsigned := msigSigned("sig-msig-no-subsig-signed")
	unsigned.Msig.Subsigs[0].Sig = crypto.Signature{}
	add("verify_msig_threshold_not_met", unsigned)

	add("verify_lsig_delegated_valid", delegated("sig-lsig-delegated-valid"))
	badDelegation := delegated("sig-lsig-delegated-bad-sig")
	badDelegation.Lsig.Sig[0] ^= 1
	add("verify_lsig_delegated_bad_signature", badDelegation)
	add("verify_lsig_not_logic_only_account", transactions.SignedTxn{
		Txn:  pay("sig-lsig-not-logic-only"),
		Lsig: transactions.LogicSig{Logic: prog},
	})
	twoDelegations := delegated("sig-lsig-two-delegations")
	twoDelegations.Lsig.LMsig = lmsig("sig-lsig-two-delegations-lmsig").Lsig.LMsig
	add("verify_lsig_two_delegation_signatures", twoDelegations)
	add("verify_lsig_lmsig_valid", lmsig("sig-lsig-lmsig-valid"))
	badLMsig := lmsig("sig-lsig-lmsig-bad-sig")
	badLMsig.Lsig.LMsig.Subsigs[0].Sig[0] ^= 1
	add("verify_lsig_lmsig_bad_signature", badLMsig)
	legacyMsig := lmsig("sig-lsig-legacy-msig")
	legacyMsig.Lsig.Msig, legacyMsig.Lsig.LMsig = legacyMsig.Lsig.LMsig, crypto.MultisigSig{}
	add("verify_lsig_legacy_msig_field", legacyMsig)
	add("verify_lsig_version_too_new", transactions.SignedTxn{
		Txn:  pay("sig-lsig-version-too-new"),
		Lsig: transactions.LogicSig{Logic: []byte{99, 0x81, 0x01}, Sig: secrets.Sign(logic.Program([]byte{99, 0x81, 0x01}))},
	})

	rekeyed := pay("sig-rekeyed-wrong-key").Sign(secrets)
	rekeyed.AuthAddr = basics.Address(other.SignatureVerifier)
	add("verify_rekeyed_signed_by_the_sender", rekeyed)
	return rows
}
