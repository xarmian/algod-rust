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

// Build a small set of Phase B fixtures for algokey-rust parity tests.
// Produces:
//   - sign:    unsigned + Go-signed pair
//   - multisig: unsigned-with-preimage + Go-signed pair (signer A of 2-of-3)
//   - keyreg offline: Go-emitted offline keyreg txn for testnet
//
// All txns use deterministic inputs (fixed seeds).

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

func seed(s string) crypto.Seed {
	h := sha256.Sum256([]byte(s))
	var out crypto.Seed
	copy(out[:], h[:])
	return out
}

func main() {
	outDir := os.Args[1]
	os.MkdirAll(outDir+"/sign", 0755)
	os.MkdirAll(outDir+"/multisig", 0755)
	os.MkdirAll(outDir+"/keyreg", 0755)

	// ── sign fixture: pay txn from sender to receiver, signed by sender ──
	sk := crypto.GenerateSignatureSecrets(seed("alpha"))
	sender := basics.Address(sk.SignatureVerifier)
	receiver := basics.Address([32]byte{0x11}) // arbitrary
	pay := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: 1000},
			FirstValid:  1,
			LastValid:   1000,
			GenesisHash: crypto.Digest{9, 9, 9},
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: 12345},
		},
	}
	unsigned := transactions.SignedTxn{Txn: pay}
	os.WriteFile(outDir+"/sign/unsigned.tx", protocol.Encode(&unsigned), 0644)

	signed := transactions.SignedTxn{Txn: pay}
	signed.Sig = sk.Sign(pay)
	os.WriteFile(outDir+"/sign/go-signed.tx", protocol.Encode(&signed), 0644)
	// Also write the keyfile (32 raw bytes of the seed).
	os.WriteFile(outDir+"/sign/keyfile", sk.SK[:32], 0600)

	// ── multisig fixture: 2-of-3, signer A partial ──
	skA := crypto.GenerateSignatureSecrets(seed("alpha"))
	skB := crypto.GenerateSignatureSecrets(seed("bravo"))
	skC := crypto.GenerateSignatureSecrets(seed("charlie"))
	pks := []crypto.PublicKey{
		skA.SignatureVerifier,
		skB.SignatureVerifier,
		skC.SignatureVerifier,
	}
	msigAddr, _ := crypto.MultisigAddrGen(1, 2, pks)
	msigPreimage := crypto.MultisigPreimageFromPKs(1, 2, pks)
	msigPay := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      basics.Address(msigAddr),
			Fee:         basics.MicroAlgos{Raw: 1000},
			FirstValid:  1,
			LastValid:   1000,
			GenesisHash: crypto.Digest{3, 3, 3},
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: 50000},
		},
	}
	unsignedMsig := transactions.SignedTxn{Txn: msigPay, Msig: msigPreimage}
	os.WriteFile(outDir+"/multisig/unsigned.tx", protocol.Encode(&unsignedMsig), 0644)

	signedByA, _ := crypto.MultisigSign(msigPay, msigAddr, 1, 2, pks, *skA)
	signedTxn := transactions.SignedTxn{Txn: msigPay, Msig: signedByA}
	os.WriteFile(outDir+"/multisig/go-signed-by-a.tx", protocol.Encode(&signedTxn), 0644)
	// Keyfile = seed of signer A.
	os.WriteFile(outDir+"/multisig/keyfile-a", skA.SK[:32], 0600)
	// Also write the 3 public-key addresses for the params string.
	addrA := basics.Address(skA.SignatureVerifier).String()
	addrB := basics.Address(skB.SignatureVerifier).String()
	addrC := basics.Address(skC.SignatureVerifier).String()
	params := fmt.Sprintf("2 %s %s %s", addrA, addrB, addrC)
	os.WriteFile(outDir+"/multisig/params.txt", []byte(params), 0644)

	// ── keyreg offline fixture ──
	offlineAddr := basics.Address(skA.SignatureVerifier)
	offlineTxn := transactions.Transaction{
		Type: protocol.KeyRegistrationTx,
		Header: transactions.Header{
			Sender:      offlineAddr,
			Fee:         basics.MicroAlgos{Raw: 1000},
			FirstValid:  1,
			LastValid:   1001,
			GenesisHash: mustB64("SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI="),
		},
	}
	offlineSigned, _ := transactions.AssembleSignedTxn(offlineTxn, crypto.Signature{}, crypto.MultisigSig{})
	os.WriteFile(outDir+"/keyreg/offline-testnet.tx", protocol.Encode(&offlineSigned), 0644)
	os.WriteFile(outDir+"/keyreg/offline-account.txt", []byte(addrA), 0644)
	fmt.Printf("offline addr: %s\n", addrA)
}

func mustB64(s string) crypto.Digest {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	var d crypto.Digest
	copy(d[:], b)
	return d
}
