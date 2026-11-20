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

// Parity oracle for algod-rust issue #2438: the post-quantum (Falcon-1024)
// signature failure texts of go-algorand v5.0.5-stable's PQSig.Verify,
// VerifyFalcon1024 and the simulator, on the pool path (verify.TxnGroup,
// whose TxGroupError text is what BroadcastSignedTxGroup and the REST
// handler return) and in simulate (Simulator.Simulate).
//
// It is staged into ledger/simulation of a clean go-algorand clone by
// run-in-docker.sh (package simulation_test, so it can use the package's
// own test environment) and writes one JSON object per case to $ORACLE_OUT:
//
//   - "pool" cases carry the go-encoded SignedTxn (hex) and the text of
//     verify.TxnGroup's error ("" = accepted);
//   - "simulate" cases carry the PQ envelope, sender and request flags, and
//     go's Simulate outcome (request error, group FailureMessage, FailedAt).
//
// verify.TxnGroup frames a member's error as "transaction %+v invalid : <err>"
// (a Go struct dump of the whole SignedTxn, data/transactions/verify/txn.go);
// the texts are recorded in full (issue #2451) with "framed": true when they
// carry that frame. A simulate case also carries the SignedTxn go submitted.
package simulation_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/simulation"
	simulationtesting "github.com/algorand/go-algorand/ledger/simulation/testing"
	"github.com/algorand/go-algorand/protocol"
)

// v6 `pushint 1`: a program go's static LogicSig check accepts.
var oracleProgram = []byte{0x06, 0x81, 0x01}

type oracleLedger struct{ hdr bookkeeping.BlockHeader }

func (l oracleLedger) BlockHdr(basics.Round) (bookkeeping.BlockHeader, error) { return l.hdr, nil }
func (l oracleLedger) GenesisHash() crypto.Digest                             { return l.hdr.GenesisHash }

type poolCase struct {
	Path     string `json:"path"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Protocol string `json:"protocol"`
	Stxn     string `json:"stxn"`
	Framed   bool   `json:"framed"`
	Want     string `json:"want"`
}

type simulateCase struct {
	Path           string `json:"path"`
	Name           string `json:"name"`
	Kind           string `json:"kind"`
	Stxn           string `json:"stxn"`
	FixSigners     bool   `json:"fix_signers"`
	Sender         string `json:"sender"`
	Scheme         string `json:"scheme"`
	Salt           uint8  `json:"salt"`
	PublicKey      string `json:"pk"`
	Signature      string `json:"sig"`
	Program        string `json:"program,omitempty"`
	WantError      string `json:"want_error"`
	FailureFramed  bool   `json:"want_failure_framed"`
	FailureMessage string `json:"want_failure_message"`
	FailedAt       []int  `json:"want_failed_at"`
}

type oracleKey struct {
	signer crypto.FalconSigner
	pk     []byte
	salt   basics.PQAddressSalt
	addr   basics.Address
}

func makeOracleKey(t *testing.T, seedByte byte) oracleKey {
	var seed crypto.FalconSeed
	seed[0] = seedByte
	signer, err := crypto.GenerateFalconSigner(seed)
	require.NoError(t, err)
	pk := slices.Clone(signer.PublicKey[:])
	salt, addr, err := basics.CanonicalPQAddressSalt(protocol.PQSchemeFalcon1024, pk)
	require.NoError(t, err)
	return oracleKey{signer: signer, pk: pk, salt: salt, addr: addr}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// framed reports whether s carries verify.TxnGroup's "transaction %+v
// invalid : " frame.
func framed(s string) bool {
	return strings.HasPrefix(s, "transaction {") && strings.Contains(s, "} invalid : ")
}

func TestAlgodRustPQFailureTextOracle(t *testing.T) {
	outPath := os.Getenv("ORACLE_OUT")
	require.NotEmpty(t, outPath, "ORACLE_OUT must name the output file")
	out, err := os.Create(outPath)
	require.NoError(t, err)
	defer out.Close()
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)

	key := makeOracleKey(t, 0x26)
	other := makeOracleKey(t, 0x27)

	// ---- pool path: verify.TxnGroup -------------------------------------
	hdr := bookkeeping.BlockHeader{
		Round:        50,
		GenesisHash:  crypto.Hash([]byte("algod-rust #2438 pq oracle")),
		UpgradeState: bookkeeping.UpgradeState{CurrentProtocol: protocol.ConsensusCurrentVersion},
	}
	require.True(t, config.Consensus[hdr.CurrentProtocol].EnablePQSchemeFalcon1024)
	ledger := oracleLedger{hdr: hdr}

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

	// mutate edits the PQ envelope (and may re-point the sender) before
	// signing; tamper edits the finished envelope after signing.
	type variant struct {
		name   string
		mutate func(p *transactions.PQSig, sender *basics.Address)
		tamper func(p *transactions.PQSig)
	}
	shortKey := func(p *transactions.PQSig, sender *basics.Address) {
		p.PublicKey = slices.Clone(p.PublicKey[:len(p.PublicKey)-1])
		*sender = p.Address()
	}
	variants := []variant{
		{name: "valid"},
		{name: "public key one byte short, authorizer derived from it", mutate: shortKey},
		{name: "public key one byte short, authorizer from the full key", mutate: func(p *transactions.PQSig, _ *basics.Address) {
			p.PublicKey = slices.Clone(p.PublicKey[:len(p.PublicKey)-1])
		}},
		{name: "public key empty, authorizer derived from it", mutate: func(p *transactions.PQSig, sender *basics.Address) {
			p.PublicKey = nil
			*sender = p.Address()
		}},
		{name: "wrong salt", mutate: func(p *transactions.PQSig, _ *basics.Address) { p.Salt ^= 1 }},
		{name: "another key's envelope", mutate: func(p *transactions.PQSig, _ *basics.Address) {
			p.Salt, p.PublicKey = other.salt, slices.Clone(other.pk)
		}},
		{name: "unsupported scheme", mutate: func(p *transactions.PQSig, _ *basics.Address) { p.Scheme = protocol.PQScheme{'f', '2'} }},
		{name: "signature header byte flipped", tamper: func(p *transactions.PQSig) { p.Signature[0] ^= 1 }},
		{name: "signature body byte flipped", tamper: func(p *transactions.PQSig) { p.Signature[len(p.Signature)/2] ^= 0xff }},
		{name: "signature last byte flipped", tamper: func(p *transactions.PQSig) { p.Signature[len(p.Signature)-1] ^= 0x55 }},
		{name: "signature truncated to 41 bytes", tamper: func(p *transactions.PQSig) { p.Signature = p.Signature[:41] }},
		{name: "signature one byte", tamper: func(p *transactions.PQSig) { p.Signature = p.Signature[:1] }},
		{name: "signature empty", tamper: func(p *transactions.PQSig) { p.Signature = nil }},
		{name: "signature by another key", tamper: func(p *transactions.PQSig) {
			var sig crypto.FalconSignature
			var err error
			sig, err = other.signer.SignBytes([]byte("not the message"))
			require.NoError(t, err)
			p.Signature = sig
		}},
	}

	for _, kind := range []string{"pqsig", "lsig"} {
		for _, v := range variants {
			sender := key.addr
			pq := transactions.PQSig{Scheme: protocol.PQSchemeFalcon1024, Salt: key.salt, PublicKey: slices.Clone(key.pk)}
			if v.mutate != nil {
				v.mutate(&pq, &sender)
			}
			txn := baseTxn(sender)
			stxn := transactions.SignedTxn{Txn: txn}
			var sig crypto.FalconSignature
			if kind == "pqsig" {
				sig, err = key.signer.Sign(txn)
			} else {
				sig, err = key.signer.Sign(logic.PQDelegatedProgram{Addr: txn.Sender, Program: oracleProgram})
			}
			require.NoError(t, err)
			pq.Signature = sig
			if v.tamper != nil {
				v.tamper(&pq)
			}
			if kind == "pqsig" {
				stxn.PQsig = pq
			} else {
				stxn.Lsig = transactions.LogicSig{Logic: oracleProgram, PQsig: pq}
			}
			_, verr := verify.TxnGroup([]transactions.SignedTxn{stxn}, &hdr, nil, ledger)
			want := errText(verr)
			require.NoError(t, enc.Encode(poolCase{
				Path:     "pool",
				Name:     v.name,
				Kind:     kind,
				Protocol: string(hdr.CurrentProtocol),
				Stxn:     hex.EncodeToString(protocol.Encode(&stxn)),
				Framed:   framed(want),
				Want:     want,
			}))
		}
	}

	// ---- simulate: Simulator.Simulate -----------------------------------
	type simVariant struct {
		name       string
		fixSigners bool
		// placeholder leaves the signature empty; otherwise a real one is
		// made and tamper (if any) applied.
		placeholder bool
		mutate      func(p *transactions.PQSig, sender *basics.Address)
		tamper      func(p *transactions.PQSig)
	}
	simVariants := []simVariant{
		{name: "placeholder, wrong salt", placeholder: true, mutate: func(p *transactions.PQSig, _ *basics.Address) { p.Salt ^= 1 }},
		{name: "placeholder, wrong salt, fix signers", placeholder: true, fixSigners: true, mutate: func(p *transactions.PQSig, _ *basics.Address) { p.Salt ^= 1 }},
		{name: "placeholder, public key one byte short", placeholder: true, mutate: shortKey},
		{name: "placeholder, public key one byte short, fix signers", placeholder: true, fixSigners: true, mutate: shortKey},
		{name: "signature header byte flipped", tamper: func(p *transactions.PQSig) { p.Signature[0] ^= 1 }},
		{name: "public key one byte short, real signature", mutate: shortKey},
	}

	for _, kind := range []string{"pqsig", "lsig"} {
		for _, v := range simVariants {
			env := simulationtesting.PrepareSimulatorTest(t)
			sender := key.addr
			pq := transactions.PQSig{Scheme: protocol.PQSchemeFalcon1024, Salt: key.salt, PublicKey: slices.Clone(key.pk)}
			if v.mutate != nil {
				v.mutate(&pq, &sender)
			}
			// Fund the sender so that a group which gets past the
			// signature checks evaluates cleanly.
			env.TransferAlgos(env.Accounts[0].Addr, sender, 10_000_000)
			minFee := env.TxnInfo.CurrentProtocolParams().MinTxnFee
			txn := env.TxnInfo.NewTxn(txntest.Txn{
				Type:     protocol.PaymentTx,
				Sender:   sender,
				Receiver: sender,
				Fee:      minFee * 3,
			}).Txn()
			// NewTxn takes FirstValid from the environment's latest header,
			// which moves with the funding block's commit: pin the window so
			// the encoded transaction (and its signature) is reproducible.
			txn.FirstValid, txn.LastValid = 1, 1001
			if !v.placeholder {
				var sig crypto.FalconSignature
				if kind == "pqsig" {
					sig, err = key.signer.Sign(txn)
				} else {
					sig, err = key.signer.Sign(logic.PQDelegatedProgram{Addr: txn.Sender, Program: oracleProgram})
				}
				require.NoError(t, err)
				pq.Signature = sig
				if v.tamper != nil {
					v.tamper(&pq)
				}
			}
			stxn := transactions.SignedTxn{Txn: txn}
			c := simulateCase{
				Path:       "simulate",
				Name:       v.name,
				Kind:       kind,
				FixSigners: v.fixSigners,
				Sender:     sender.String(),
				Scheme:     string(pq.Scheme[:]),
				Salt:       uint8(pq.Salt),
				PublicKey:  hex.EncodeToString(pq.PublicKey),
				Signature:  hex.EncodeToString(pq.Signature),
				FailedAt:   []int{},
			}
			if kind == "pqsig" {
				stxn.PQsig = pq
			} else {
				stxn.Lsig = transactions.LogicSig{Logic: oracleProgram, PQsig: pq}
				c.Program = hex.EncodeToString(oracleProgram)
			}
			c.Stxn = hex.EncodeToString(protocol.Encode(&stxn))
			result, serr := simulation.MakeSimulator(env.Ledger, false).Simulate(simulation.Request{
				TxnGroups:            [][]transactions.SignedTxn{{stxn}},
				AllowEmptySignatures: true,
				FixSigners:           v.fixSigners,
			})
			c.WantError = errText(serr)
			if serr == nil {
				c.FailureMessage = result.TxnGroups[0].FailureMessage
				c.FailureFramed = framed(c.FailureMessage)
				for _, i := range result.TxnGroups[0].FailedAt {
					c.FailedAt = append(c.FailedAt, int(i))
				}
			}
			require.NoError(t, enc.Encode(c))
			env.Close()
		}
	}
}
