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

// Parity oracle for algod-rust issue #2546: go-algorand v5.1.1-stable's
// SaltedKeySig for every signature scheme (f1, f5, ed, ls) under the `future`
// protocol, which enables them all. For each scheme and each variant of the
// envelope it builds a SignedTxn (top-level `pqsig`, and for the key schemes a
// delegated LogicSig), runs it through verify.TxnGroup (the pool path) and
// writes one JSON object per case: the go-encoded SignedTxn (hex), the
// protocol and the full error text ("" = accepted). The Rust test
// crates/core/algo-validate/tests/sig_scheme_texts_test.rs decodes go's bytes,
// re-encodes them byte for byte and compares the verdict and text.
//
// Staged into ledger/simulation of a go-algorand checkout at the pin
// (`make libsodium` first):
//
//	cp tools/sig-scheme-text-oracle/oracle_test.go \
//	   ../go-algorand/ledger/simulation/zz_algod_rust_sig_scheme_oracle_test.go
//	(cd ../go-algorand && ORACLE_OUT=$PWD/out.jsonl go test -count=1 \
//	   -run '^TestAlgodRustSigSchemeOracle$' ./ledger/simulation/)
//	cp ../go-algorand/out.jsonl crates/core/algo-validate/tests/fixtures/sig_scheme_texts.jsonl
package simulation_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	basics_testing "github.com/algorand/go-algorand/data/basics/testing"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/protocol"
)

// v6 `pushint 1`: a program go's static LogicSig check accepts.
var schemeOracleProgram = []byte{0x06, 0x81, 0x01}

// #pragma version 14; pushbytes "open sesame"; arg_0; ==
var openSesame = []byte{0x0e, 0x80, 0x0b, 'o', 'p', 'e', 'n', ' ', 's', 'e', 's', 'a', 'm', 'e', 0x2d, 0x12}

type schemeOracleLedger struct{ hdr bookkeeping.BlockHeader }

func (l schemeOracleLedger) BlockHdr(basics.Round) (bookkeeping.BlockHeader, error) {
	return l.hdr, nil
}
func (l schemeOracleLedger) GenesisHash() crypto.Digest { return l.hdr.GenesisHash }

type schemeCase struct {
	Path     string `json:"path"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Scheme   string `json:"scheme"`
	Protocol string `json:"protocol"`
	Stxn     string `json:"stxn"`
	Framed   bool   `json:"framed"`
	Want     string `json:"want"`
}

func schemeErrText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestAlgodRustSigSchemeOracle(t *testing.T) {
	outPath := os.Getenv("ORACLE_OUT")
	require.NotEmpty(t, outPath, "ORACLE_OUT must name the output file")
	out, err := os.Create(outPath)
	require.NoError(t, err)
	defer out.Close()
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)

	hdr := bookkeeping.BlockHeader{
		Round:        50,
		GenesisHash:  crypto.Hash([]byte("algod-rust #2546 sig scheme oracle")),
		UpgradeState: bookkeeping.UpgradeState{CurrentProtocol: protocol.ConsensusFuture},
	}
	ledger := schemeOracleLedger{hdr: hdr}

	baseTxn := func(sender basics.Address) transactions.Transaction {
		return transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      sender,
				Fee:         basics.MicroAlgos{Raw: 3000},
				FirstValid:  1,
				LastValid:   1000,
				GenesisHash: hdr.GenesisHash,
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: sender,
				Amount:   basics.MicroAlgos{Raw: 1},
			},
		}
	}
	emit := func(name, kind string, scheme protocol.SigScheme, stxn transactions.SignedTxn) {
		_, verr := verify.TxnGroup([]transactions.SignedTxn{stxn}, &hdr, nil, ledger)
		want := schemeErrText(verr)
		require.NoError(t, enc.Encode(schemeCase{
			Path:     "pool",
			Name:     name,
			Kind:     kind,
			Scheme:   string(scheme[:]),
			Protocol: string(hdr.CurrentProtocol),
			Stxn:     hex.EncodeToString(protocol.Encode(&stxn)),
			Framed:   strings.HasPrefix(want, "transaction ") && strings.Contains(want, " invalid : "),
			Want:     want,
		}))
	}

	// ---- the three key schemes: f1, f5, ed ------------------------------
	for _, st := range basics_testing.SigSchemeTests {
		acct := basics_testing.MakeSaltedKeySigTestAccount(t, 0x26, st.Scheme)
		other := basics_testing.MakeSaltedKeySigTestAccount(t, 0x27, st.Scheme)

		type variant struct {
			name   string
			mutate func(p *transactions.SaltedKeySig, sender *basics.Address)
			tamper func(p *transactions.SaltedKeySig)
		}
		variants := []variant{
			{name: "valid"},
			{name: "public key one byte short, authorizer derived from it", mutate: func(p *transactions.SaltedKeySig, sender *basics.Address) {
				p.PublicKey = slices.Clone(p.PublicKey[:len(p.PublicKey)-1])
				*sender = p.Address()
			}},
			{name: "public key empty, authorizer derived from it", mutate: func(p *transactions.SaltedKeySig, sender *basics.Address) {
				p.PublicKey = nil
				*sender = p.Address()
			}},
			{name: "wrong salt", mutate: func(p *transactions.SaltedKeySig, _ *basics.Address) { p.Salt ^= 1 }},
			{name: "another key envelope", mutate: func(p *transactions.SaltedKeySig, _ *basics.Address) {
				p.Salt, p.PublicKey = other.Salt, slices.Clone(other.PublicKey)
			}},
			{name: "unsupported scheme", mutate: func(p *transactions.SaltedKeySig, _ *basics.Address) { p.Scheme = protocol.SigScheme{'f', '2'} }},
			{name: "signature first byte flipped", tamper: func(p *transactions.SaltedKeySig) { p.Signature[0] ^= 1 }},
			{name: "signature middle byte flipped", tamper: func(p *transactions.SaltedKeySig) { p.Signature[len(p.Signature)/2] ^= 0xff }},
			{name: "signature last byte flipped", tamper: func(p *transactions.SaltedKeySig) { p.Signature[len(p.Signature)-1] ^= 0x55 }},
			{name: "signature truncated by one byte", tamper: func(p *transactions.SaltedKeySig) { p.Signature = p.Signature[:len(p.Signature)-1] }},
			{name: "signature one byte", tamper: func(p *transactions.SaltedKeySig) { p.Signature = p.Signature[:1] }},
			{name: "signature empty", tamper: func(p *transactions.SaltedKeySig) { p.Signature = nil }},
			{name: "signature of another message", tamper: func(p *transactions.SaltedKeySig) {
				sig, serr := acct.Signer.SignBytes([]byte("not the message"))
				require.NoError(t, serr)
				p.Signature = sig
			}},
			{name: "signature by another key", tamper: func(p *transactions.SaltedKeySig) {
				sig, serr := other.Signer.SignBytes([]byte("not the message"))
				require.NoError(t, serr)
				p.Signature = sig
			}},
		}
		for _, kind := range []string{"pqsig", "lsig"} {
			for _, v := range variants {
				sender := acct.Address
				sk := transactions.SaltedKeySig{Scheme: acct.Scheme, Salt: acct.Salt, PublicKey: slices.Clone(acct.PublicKey)}
				if v.mutate != nil {
					v.mutate(&sk, &sender)
				}
				txn := baseTxn(sender)
				var sig []byte
				if kind == "pqsig" {
					sig, err = acct.Signer.Sign(txn)
				} else {
					sig, err = acct.Signer.Sign(logic.SKsigDelegatedProgram{Addr: txn.Sender, Program: schemeOracleProgram})
				}
				require.NoError(t, err)
				sk.Signature = sig
				if v.tamper != nil {
					v.tamper(&sk)
				}
				stxn := transactions.SignedTxn{Txn: txn}
				if kind == "pqsig" {
					stxn.SKsig = sk
				} else {
					stxn.Lsig = transactions.LogicSig{Logic: schemeOracleProgram, SKsig: sk}
				}
				emit(v.name, kind, st.Scheme, stxn)
			}
		}
	}

	// ---- the ls scheme: the program is the key, its arguments the proof ---
	salt, addr, err := basics.CanonicalAddressSalt(protocol.SigSchemeLogicSig, openSesame)
	require.NoError(t, err)
	lsCases := []struct {
		name   string
		args   transactions.LogicSigArgs
		mutate func(p *transactions.SaltedKeySig, sender *basics.Address)
	}{
		{name: "valid", args: transactions.LogicSigArgs{[]byte("open sesame")}},
		{name: "program rejects the argument", args: transactions.LogicSigArgs{[]byte("close sesame")}},
		{name: "no arguments", args: nil},
		{name: "extra unread argument", args: transactions.LogicSigArgs{[]byte("open sesame"), []byte("x")}},
		{name: "wrong salt", args: transactions.LogicSigArgs{[]byte("open sesame")}, mutate: func(p *transactions.SaltedKeySig, _ *basics.Address) { p.Salt ^= 1 }},
		{name: "program tampered, authorizer derived from it", args: transactions.LogicSigArgs{[]byte("open sesame")}, mutate: func(p *transactions.SaltedKeySig, sender *basics.Address) {
			p.PublicKey = slices.Clone(p.PublicKey)
			p.PublicKey[len(p.PublicKey)-1] = 0x13
			*sender = p.Address()
		}},
	}
	for _, c := range lsCases {
		sender := addr
		sk := transactions.SaltedKeySig{
			Scheme:    protocol.SigSchemeLogicSig,
			Salt:      salt,
			PublicKey: slices.Clone(openSesame),
			Signature: transactions.EncodeLogicSigArgs(c.args),
		}
		if c.mutate != nil {
			c.mutate(&sk, &sender)
		}
		emit(c.name, "pqsig", protocol.SigSchemeLogicSig, transactions.SignedTxn{Txn: baseTxn(sender), SKsig: sk})
	}
}
