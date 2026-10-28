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

// Package micro is the go-algorand half of the paired Go/Rust
// micro-benchmark suite (issue #2103, epic #2101). Every pair id of
// benchmarks/pairs.toml has one Case here and one in the Rust crate
// crates/tools/algo-bench-pairs (src/lib.rs). Both read the same fixture
// file from benchmarks/fixtures/micro/ and run the same go-algorand /
// algod-rust production function on it.
//
// A Case has two halves that share one implementation of the operation:
//
//   - Op runs the operation once (the benchmarked body, setup excluded);
//   - Digest runs it once and returns a canonical description of the
//     output (re-encoded bytes hash, digest, verdict, AVM pass/cost/logs).
//     cmd/equiv prints every Digest; the micro tier compares them with the
//     Rust digests and fails on any difference.
package micro

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/algorand/sortition"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

// AppID is the application id of the avm/app-state-box pair (> 255, so
// AppForbidLowResources does not apply).
const AppID basics.AppIndex = 1001

// AppBoxName / AppBoxSize describe the box the app pair rewrites. It exists
// before every evaluation on both sides, so box_put replaces it in place.
const (
	AppBoxName = "box"
	AppBoxSize = 64
)

// Case is one side of a pair.
type Case struct {
	ID string
	// Op runs the measured operation once. It panics if the operation
	// fails, since a failing benchmark measures nothing.
	Op func()
	// Digest runs the operation once and describes its output.
	Digest func() (string, error)
}

type builder func(dir string) (*Case, error)

// Sinks keep the compiler from discarding results.
var (
	sinkBytes  []byte
	sinkDigest [32]byte
	sinkVrf    crypto.VrfOutput
	sinkU64    uint64
	sinkBool   bool
)

var builders = map[string]builder{
	"codec/decode-block-small": decodeBlock("block-small.msgpack"),
	"codec/decode-block-large": decodeBlock("block-large.msgpack"),
	"codec/encode-block-small": encodeBlock("block-small.msgpack"),
	"codec/encode-block-large": encodeBlock("block-large.msgpack"),
	"codec/decode-stxn":        decodeStxn,
	"codec/encode-stxn":        encodeStxn,
	"codec/txid":               txid,
	"codec/block-hash":         blockHash,

	"crypto/sha512_256-32B":     sha512256("bytes-32.bin"),
	"crypto/sha512_256-1KiB":    sha512256("bytes-1k.bin"),
	"crypto/sha512_256-64KiB":   sha512256("bytes-64k.bin"),
	"crypto/ed25519-verify":     ed25519Verify,
	"crypto/ed25519-batch-64":   ed25519Batch("stxns-64.msgpack"),
	"crypto/ed25519-batch-1024": ed25519Batch("stxns-1024.msgpack"),
	"crypto/vrf-verify":         vrfVerify,
	"crypto/falcon-verify":      falconVerify,

	"commit/txn-merkle-sha512_256": txnMerkle,
	"commit/txn-vc-sha256":         txnVectorCommitment,

	"avm/lsig-arith-loop": lsig("avm-arith.bin"),
	"avm/lsig-hash-loop":  lsig("avm-hash.bin"),
	"avm/lsig-bytes-ops":  lsig("avm-bytes.bin"),
	"avm/app-state-box":   app("avm-app.bin"),

	"agreement/sortition-select":      sortitionSelect(false),
	"agreement/sortition-select-f128": sortitionSelect(true),
	"agreement/credential-verify":     credentialVerify,
	"agreement/decode-cert":           decodeCert,
	"agreement/decode-proposal":       decodeProposal,
}

// IDs returns every pair id, sorted.
func IDs() []string {
	ids := make([]string, 0, len(builders))
	for id := range builders {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Build loads the fixture of pair id from dir and returns its Case.
func Build(dir, id string) (*Case, error) {
	b, ok := builders[id]
	if !ok {
		return nil, fmt.Errorf("unknown pair %q", id)
	}
	c, err := b(dir)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", id, err)
	}
	c.ID = id
	return c, nil
}

// --- helpers ---------------------------------------------------------------

func read(dir, name string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, name)) }

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Frames splits a framed fixture: a sequence of u32 little-endian length +
// that many bytes.
func Frames(b []byte) ([][]byte, error) {
	var out [][]byte
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, errors.New("truncated frame header")
		}
		n := binary.LittleEndian.Uint32(b)
		b = b[4:]
		if uint64(len(b)) < uint64(n) {
			return nil, errors.New("truncated frame")
		}
		out = append(out, b[:n])
		b = b[n:]
	}
	return out, nil
}

// EncodeFrames is the inverse of Frames.
func EncodeFrames(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = binary.LittleEndian.AppendUint32(out, uint32(len(p)))
		out = append(out, p...)
	}
	return out
}

// DecodeStxnStream decodes concatenated msgpack SignedTxn objects.
func DecodeStxnStream(data []byte) ([]transactions.SignedTxn, error) {
	dec := protocol.NewMsgpDecoderBytes(data)
	var out []transactions.SignedTxn
	for {
		var s transactions.SignedTxn
		err := dec.Decode(&s)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
}

// rawMsg is a crypto.Hashable whose HashRep is exactly its bytes (empty
// HashID), so a fixture can carry the precise VRF input.
type rawMsg []byte

func (m rawMsg) ToBeHashed() (protocol.HashID, []byte) { return "", m }

func mustNoErr(err error) {
	if err != nil {
		panic(err)
	}
}

// --- codec -----------------------------------------------------------------

func loadBlock(dir, file string) (bookkeeping.Block, []byte, error) {
	data, err := read(dir, file)
	if err != nil {
		return bookkeeping.Block{}, nil, err
	}
	var blk bookkeeping.Block
	err = protocol.Decode(data, &blk)
	return blk, data, err
}

func decodeBlock(file string) builder {
	return func(dir string) (*Case, error) {
		_, data, err := loadBlock(dir, file)
		if err != nil {
			return nil, err
		}
		return &Case{
			Op: func() {
				var blk bookkeeping.Block
				mustNoErr(protocol.Decode(data, &blk))
				sinkU64 = uint64(blk.Round())
			},
			Digest: func() (string, error) {
				var blk bookkeeping.Block
				if err := protocol.Decode(data, &blk); err != nil {
					return "", err
				}
				return sha256Hex(protocol.Encode(&blk)), nil
			},
		}, nil
	}
}

func encodeBlock(file string) builder {
	return func(dir string) (*Case, error) {
		blk, _, err := loadBlock(dir, file)
		if err != nil {
			return nil, err
		}
		return &Case{
			Op:     func() { sinkBytes = protocol.Encode(&blk) },
			Digest: func() (string, error) { return sha256Hex(protocol.Encode(&blk)), nil },
		}, nil
	}
}

func loadStxn(dir string) (transactions.SignedTxn, []byte, error) {
	data, err := read(dir, "stxn-appl.msgpack")
	if err != nil {
		return transactions.SignedTxn{}, nil, err
	}
	var s transactions.SignedTxn
	err = protocol.Decode(data, &s)
	return s, data, err
}

func decodeStxn(dir string) (*Case, error) {
	_, data, err := loadStxn(dir)
	if err != nil {
		return nil, err
	}
	return &Case{
		Op: func() {
			var s transactions.SignedTxn
			mustNoErr(protocol.Decode(data, &s))
			sinkU64 = s.Txn.Fee.Raw
		},
		Digest: func() (string, error) {
			var s transactions.SignedTxn
			if err := protocol.Decode(data, &s); err != nil {
				return "", err
			}
			return sha256Hex(protocol.Encode(&s)), nil
		},
	}, nil
}

func encodeStxn(dir string) (*Case, error) {
	s, _, err := loadStxn(dir)
	if err != nil {
		return nil, err
	}
	return &Case{
		Op:     func() { sinkBytes = protocol.Encode(&s) },
		Digest: func() (string, error) { return sha256Hex(protocol.Encode(&s)), nil },
	}, nil
}

func txid(dir string) (*Case, error) {
	s, _, err := loadStxn(dir)
	if err != nil {
		return nil, err
	}
	return &Case{
		Op: func() {
			id := s.Txn.ID()
			sinkDigest = id
		},
		Digest: func() (string, error) {
			id := s.Txn.ID()
			return "hex:" + hex.EncodeToString(id[:]), nil
		},
	}, nil
}

func blockHash(dir string) (*Case, error) {
	blk, _, err := loadBlock(dir, "block-large.msgpack")
	if err != nil {
		return nil, err
	}
	return &Case{
		Op: func() {
			h := blk.BlockHeader.Hash()
			sinkDigest = h
		},
		Digest: func() (string, error) {
			h := blk.BlockHeader.Hash()
			return "hex:" + hex.EncodeToString(h[:]), nil
		},
	}, nil
}

// --- crypto ----------------------------------------------------------------

func sha512256(file string) builder {
	return func(dir string) (*Case, error) {
		data, err := read(dir, file)
		if err != nil {
			return nil, err
		}
		return &Case{
			Op: func() {
				h := crypto.Hash(data)
				sinkDigest = h
			},
			Digest: func() (string, error) {
				h := crypto.Hash(data)
				return "hex:" + hex.EncodeToString(h[:]), nil
			},
		}, nil
	}
}

func ed25519Verify(dir string) (*Case, error) {
	s, _, err := loadStxn(dir)
	if err != nil {
		return nil, err
	}
	verify := func() bool { return crypto.SignatureVerifier(s.Txn.Sender).Verify(s.Txn, s.Sig) }
	return &Case{
		Op: func() {
			if !verify() {
				panic("signature does not verify")
			}
		},
		Digest: func() (string, error) { return fmt.Sprintf("valid:%t", verify()), nil },
	}, nil
}

func ed25519Batch(file string) builder {
	return func(dir string) (*Case, error) {
		data, err := read(dir, file)
		if err != nil {
			return nil, err
		}
		stxns, err := DecodeStxnStream(data)
		if err != nil {
			return nil, err
		}
		run := func() ([]bool, error) {
			bv := crypto.MakeBatchVerifierWithHint(len(stxns))
			for i := range stxns {
				bv.EnqueueSignature(crypto.SignatureVerifier(stxns[i].Txn.Sender), stxns[i].Txn, stxns[i].Sig)
			}
			return bv.VerifyWithFeedback()
		}
		return &Case{
			Op: func() {
				_, err := run()
				mustNoErr(err)
			},
			Digest: func() (string, error) {
				failed, err := run()
				if err != nil && !errors.Is(err, crypto.ErrBatchHasFailedSigs) {
					return "", err
				}
				valid := len(stxns)
				for _, f := range failed {
					if f {
						valid--
					}
				}
				return fmt.Sprintf("valid:%d/%d", valid, len(stxns)), nil
			},
		}, nil
	}
}

func vrfVerify(dir string) (*Case, error) {
	data, err := read(dir, "vrf.frames")
	if err != nil {
		return nil, err
	}
	f, err := Frames(data)
	if err != nil {
		return nil, err
	}
	if len(f) != 3 || len(f[0]) != 32 || len(f[1]) != 80 {
		return nil, errors.New("vrf.frames: want pk(32), proof(80), alpha")
	}
	var pk crypto.VrfPubkey
	var proof crypto.VrfProof
	copy(pk[:], f[0])
	copy(proof[:], f[1])
	alpha := rawMsg(f[2])
	return &Case{
		Op: func() {
			ok, out := pk.Verify(proof, alpha)
			if !ok {
				panic("vrf proof does not verify")
			}
			sinkVrf = out
		},
		Digest: func() (string, error) {
			ok, out := pk.Verify(proof, alpha)
			if !ok {
				return "vrf:invalid", nil
			}
			return "vrf:" + hex.EncodeToString(out[:]), nil
		},
	}, nil
}

func falconVerify(dir string) (*Case, error) {
	data, err := read(dir, "falcon.frames")
	if err != nil {
		return nil, err
	}
	f, err := Frames(data)
	if err != nil {
		return nil, err
	}
	if len(f) != 3 || len(f[0]) != crypto.FalconPublicKeySize {
		return nil, errors.New("falcon.frames: want pk, sig, msg")
	}
	var v crypto.FalconVerifier
	copy(v.PublicKey[:], f[0])
	sig := crypto.FalconSignature(f[1])
	msg := f[2]
	return &Case{
		Op:     func() { mustNoErr(v.VerifyBytes(msg, sig)) },
		Digest: func() (string, error) { return fmt.Sprintf("valid:%t", v.VerifyBytes(msg, sig) == nil), nil },
	}, nil
}

// --- commitments -----------------------------------------------------------

func txnMerkle(dir string) (*Case, error) {
	blk, _, err := loadBlock(dir, "block-large.msgpack")
	if err != nil {
		return nil, err
	}
	root := func() ([]byte, error) {
		t, err := blk.TxnMerkleTree()
		if err != nil {
			return nil, err
		}
		return []byte(t.Root()), nil
	}
	return &Case{
		Op: func() {
			r, err := root()
			mustNoErr(err)
			sinkBytes = r
		},
		Digest: func() (string, error) {
			r, err := root()
			return "hex:" + hex.EncodeToString(r), err
		},
	}, nil
}

func txnVectorCommitment(dir string) (*Case, error) {
	blk, _, err := loadBlock(dir, "block-large.msgpack")
	if err != nil {
		return nil, err
	}
	root := func() ([]byte, error) {
		t, err := blk.TxnMerkleTreeSHA256()
		if err != nil {
			return nil, err
		}
		return []byte(t.Root()), nil
	}
	return &Case{
		Op: func() {
			r, err := root()
			mustNoErr(err)
			sinkBytes = r
		},
		Digest: func() (string, error) {
			r, err := root()
			return "hex:" + hex.EncodeToString(r), err
		},
	}, nil
}

// --- AVM -------------------------------------------------------------------

// CurrentProto is the consensus version both sides evaluate under.
func CurrentProto() config.ConsensusParams {
	return config.Consensus[protocol.ConsensusCurrentVersion]
}

// Fixed addresses shared with the Rust side (src/lib.rs).
var (
	LsigSender = basics.Address{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	AppSender  = basics.Address{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22}
	AppCreator = basics.Address{0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33}
)

// LsigGroup is the one-transaction group whose logicsig is program.
func LsigGroup(program []byte) []transactions.SignedTxn {
	return []transactions.SignedTxn{{
		Lsig: transactions.LogicSig{Logic: program},
		Txn: transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:     LsigSender,
				Fee:        basics.MicroAlgos{Raw: 1000},
				FirstValid: 1000,
				LastValid:  2000,
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: AppSender,
				Amount:   basics.MicroAlgos{Raw: 1},
			},
		},
	}}
}

// EvalLsig evaluates program as the logicsig of LsigGroup.
func EvalLsig(group []transactions.SignedTxn, proto *config.ConsensusParams) (bool, int, error) {
	ep := logic.NewSigEvalParams(group, proto, logic.NoHeaderLedger{})
	pass, cx, err := logic.EvalSignatureFull(0, ep)
	cost := 0
	if cx != nil {
		cost = cx.Cost()
	}
	return pass, cost, err
}

func lsig(file string) builder {
	return func(dir string) (*Case, error) {
		program, err := read(dir, file)
		if err != nil {
			return nil, err
		}
		proto := CurrentProto()
		group := LsigGroup(program)
		return &Case{
			Op: func() {
				ep := logic.NewSigEvalParams(group, &proto, logic.NoHeaderLedger{})
				pass, err := logic.EvalSignature(0, ep)
				mustNoErr(err)
				if !pass {
					panic("logicsig rejected")
				}
				sinkBool = pass
			},
			Digest: func() (string, error) {
				pass, cost, err := EvalLsig(group, &proto)
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("pass:%t;cost:%d", pass, cost), nil
			},
		}, nil
	}
}

// AppGroup is the one-transaction app-call group of avm/app-state-box.
func AppGroup() []transactions.SignedTxnWithAD {
	return []transactions.SignedTxnWithAD{{SignedTxn: transactions.SignedTxn{
		Txn: transactions.Transaction{
			Type: protocol.ApplicationCallTx,
			Header: transactions.Header{
				Sender:     AppSender,
				Fee:        basics.MicroAlgos{Raw: 1000},
				FirstValid: 1000,
				LastValid:  2000,
			},
			ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
				ApplicationID: AppID,
				Boxes:         []transactions.BoxRef{{Index: 0, Name: []byte(AppBoxName)}},
			},
		},
	}}}
}

// AppRunner evaluates the app program against a fresh in-memory ledger
// state (the box exists, global state is empty).
type AppRunner struct {
	program []byte
	proto   config.ConsensusParams
	group   []transactions.SignedTxnWithAD
	ledger  *appLedger
}

// NewAppRunner prepares program for repeated evaluation.
func NewAppRunner(program []byte) *AppRunner {
	l := newAppLedger(AppID, AppCreator)
	l.boxes[AppBoxName] = make([]byte, AppBoxSize)
	return &AppRunner{program: program, proto: CurrentProto(), group: AppGroup(), ledger: l}
}

// Run evaluates the program once.
func (r *AppRunner) Run() (pass bool, cost int, logs []string, err error) {
	r.ledger.resetGlobals()
	ep := logic.NewAppEvalParams(r.group, &r.proto, &transactions.SpecialAddresses{})
	ep.Ledger = r.ledger
	ep.SigLedger = logic.NoHeaderLedger{}
	pass, cx, err := logic.EvalContract(r.program, 0, AppID, ep)
	if cx != nil {
		cost = cx.Cost()
	}
	for _, l := range ep.TxnGroup[0].EvalDelta.Logs {
		logs = append(logs, hex.EncodeToString([]byte(l)))
	}
	return pass, cost, logs, err
}

func app(file string) builder {
	return func(dir string) (*Case, error) {
		program, err := read(dir, file)
		if err != nil {
			return nil, err
		}
		r := NewAppRunner(program)
		return &Case{
			Op: func() {
				pass, _, _, err := r.Run()
				mustNoErr(err)
				if !pass {
					panic("app call rejected")
				}
				sinkBool = pass
			},
			Digest: func() (string, error) {
				pass, cost, logs, err := r.Run()
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("pass:%t;cost:%d;logs:%s", pass, cost, strings.Join(logs, ",")), nil
			},
		}, nil
	}
}

// --- agreement -------------------------------------------------------------

// SortitionInput is benchmarks/fixtures/micro/sortition.json.
type SortitionInput struct {
	Money        uint64 `json:"money"`
	TotalMoney   uint64 `json:"total_money"`
	ExpectedSize uint64 `json:"expected_size"`
	VrfOutput    string `json:"vrf_output"`
}

func sortitionSelect(f128 bool) builder {
	return func(dir string) (*Case, error) {
		data, err := read(dir, "sortition.json")
		if err != nil {
			return nil, err
		}
		var in SortitionInput
		if err := json.Unmarshal(data, &in); err != nil {
			return nil, err
		}
		raw, err := hex.DecodeString(in.VrfOutput)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("sortition.json: bad vrf_output")
		}
		var d sortition.Digest
		copy(d[:], raw)
		sel := func() uint64 {
			if f128 {
				return sortition.SelectF128(in.Money, in.TotalMoney, in.ExpectedSize, d)
			}
			return sortition.Select(in.Money, in.TotalMoney, float64(in.ExpectedSize), d)
		}
		return &Case{
			Op:     func() { sinkU64 = sel() },
			Digest: func() (string, error) { return fmt.Sprintf("weight:%d", sel()), nil },
		}, nil
	}
}

// CredentialInput is benchmarks/fixtures/micro/credential.json.
type CredentialInput struct {
	Address     string `json:"address"`
	SelectionPK string `json:"selection_pk"`
	Proof       string `json:"proof"`
	Balance     uint64 `json:"balance"`
	TotalMoney  uint64 `json:"total_money"`
	Seed        string `json:"seed"`
	Round       uint64 `json:"round"`
	Period      uint64 `json:"period"`
	Step        uint64 `json:"step"`
}

func unhex(dst []byte, s string) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(b) != len(dst) {
		return fmt.Errorf("hex field: want %d bytes, got %d", len(dst), len(b))
	}
	copy(dst, b)
	return nil
}

// CredentialFromInput builds the credential and membership of a fixture.
func CredentialFromInput(in CredentialInput) (committee.UnauthenticatedCredential, committee.Membership, error) {
	var cred committee.UnauthenticatedCredential
	var m committee.Membership
	var sel selector
	if err := unhex(cred.Proof[:], in.Proof); err != nil {
		return cred, m, err
	}
	if err := unhex(m.Record.Addr[:], in.Address); err != nil {
		return cred, m, err
	}
	if err := unhex(m.Record.SelectionID[:], in.SelectionPK); err != nil {
		return cred, m, err
	}
	if err := unhex(sel.Seed[:], in.Seed); err != nil {
		return cred, m, err
	}
	sel.Round, sel.Period, sel.Step = basics.Round(in.Round), in.Period, in.Step
	m.Record.MicroAlgosWithRewards = basics.MicroAlgos{Raw: in.Balance}
	m.TotalMoney = basics.MicroAlgos{Raw: in.TotalMoney}
	m.Selector = sel
	return cred, m, nil
}

// NewSelector returns the agreement selector mirror (for the generator).
func NewSelector(seed committee.Seed, rnd basics.Round, period, step uint64) committee.Selector {
	return selector{Seed: seed, Round: rnd, Period: period, Step: step}
}

func credentialVerify(dir string) (*Case, error) {
	data, err := read(dir, "credential.json")
	if err != nil {
		return nil, err
	}
	var in CredentialInput
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, err
	}
	cred, m, err := CredentialFromInput(in)
	if err != nil {
		return nil, err
	}
	proto := CurrentProto()
	return &Case{
		Op: func() {
			c, err := cred.Verify(proto, m)
			mustNoErr(err)
			sinkU64 = c.Weight
		},
		Digest: func() (string, error) {
			c, err := cred.Verify(proto, m)
			if err != nil {
				return "credential:invalid", nil
			}
			return fmt.Sprintf("weight:%d;vrfout:%s", c.Weight, hex.EncodeToString(c.VrfOut[:])), nil
		},
	}, nil
}

func decodeCert(dir string) (*Case, error) {
	data, err := read(dir, "cert-20.msgpack")
	if err != nil {
		return nil, err
	}
	return &Case{
		Op: func() {
			var c agreement.Certificate
			mustNoErr(protocol.Decode(data, &c))
			sinkU64 = uint64(c.Round)
		},
		Digest: func() (string, error) {
			var c agreement.Certificate
			if err := protocol.Decode(data, &c); err != nil {
				return "", err
			}
			return sha256Hex(protocol.Encode(&c)), nil
		},
	}, nil
}

func decodeProposal(dir string) (*Case, error) {
	data, err := read(dir, "proposal.msgpack")
	if err != nil {
		return nil, err
	}
	return &Case{
		Op: func() {
			var p agreement.TransmittedPayload
			mustNoErr(protocol.Decode(data, &p))
			sinkU64 = uint64(p.Round())
		},
		Digest: func() (string, error) {
			var p agreement.TransmittedPayload
			if err := protocol.Decode(data, &p); err != nil {
				return "", err
			}
			return sha256Hex(protocol.Encode(&p)), nil
		},
	}, nil
}

// Equal reports whether two encodings are byte-identical (generator helper).
func Equal(a, b []byte) bool { return bytes.Equal(a, b) }
