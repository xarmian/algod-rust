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

// avm-opcode-capture: generate AVM/TEAL opcode conformance vectors from
// go-algorand's authoritative logic evaluator (data/transactions/logic).
//
// Closes the gap that hid BT-294: the byte-level conformance harness was
// block-decode / state-compare oriented and had ZERO opcode coverage, so a
// consensus-critical `ed25519verify` divergence (the op SHA-512/256
// prehashed the ProgData payload that go does NOT prehash) shipped
// undetected. This tool captures go ground truth for TEAL programs —
// crucially including an `ed25519verify` program whose signature is produced
// by go over the raw `"ProgData" || H(Program(program)) || data` payload, so
// the pre-fix Rust op would have REJECTED it and the replay would have caught
// the bug.
//
// Each output line is one JSON object (JSONL):
//
//	{
//	  "name":         "<stable identifier>",
//	  "description":  "<human note>",
//	  "proto":        "<consensus version string>",  // e.g. ConsensusV41 URL
//	  "program":      "<hex of assembled program bytes>",
//	  "args":         ["<hex>", ...],                 // LogicSig args
//	  "pass":         true|false,                     // go EvalSignature result
//	  "error":        "" | "<go error string>",       // empty iff err==nil
//	  "final_stack":  [ {"t":"u","v":"<dec>"} | {"t":"b","v":"<hex>"} , ... ]
//	}
//
// `final_stack` is the EvalContext stack at program exit (only populated when
// there is no error), bottom-to-top. `t` is "u" for uint64, "b" for bytes.
//
// Ground truth: every record is produced by calling go-algorand's
// logic.EvalSignatureFull against a SignedTxn carrying the program as its
// LogicSig, exactly the path a relay/node takes when validating a LogicSig
// transaction. The crypto material (ed25519 keys + signatures, secp256k1 /
// secp256r1 keys + signatures) is generated inside this tool using
// go-algorand's own crypto so the captured "valid" cases are authentic go
// output, not hand-rolled constants. The VRF vectors are the spec anchors
// from go-algorand's own crypto_test.go (draft-irtf-cfrg-vrf-03).
//
// Determinism: all key material is derived from a fixed RNG seed and a stable
// iteration order, so two runs against the same go-algorand pin produce a
// byte-identical vectors.jsonl.
//
// go-algorand reference (v4.6.0-stable):
//
//	data/transactions/logic/eval.go:421   — NewSigEvalParams
//	data/transactions/logic/eval.go:1228  — EvalSignatureFull
//	data/transactions/logic/crypto.go:175 — opEd25519Verify (BT-294 site)
//	data/transactions/logic/crypto.go:162 — Msg.ToBeHashed ("ProgData" || H || data)
//	data/transactions/logic/crypto.go:237 — opEcdsaVerify
//	data/transactions/logic/crypto.go:401 — opVrfVerify
//	data/transactions/logic/crypto_test.go:316 — TestEd25519verify (signing pattern)
//	data/transactions/logic/crypto_test.go:482 — TestEcdsaWithSecp256k1
//	data/transactions/logic/crypto_test.go:638 — TestEcdsaWithSecp256r1
//	data/transactions/logic/crypto_test.go:225 — TestVrfVerify (vectors)
//
// Regeneration: see docs/DEV_WORKFLOW.md → "AVM Opcode Vector Regeneration".
package main

import (
	"bufio"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/secp256k1"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

// expectedGoAlgorandPin is the go-algorand tag this capture tool is pinned to.
// It matches the workspace-wide pin documented in CLAUDE.md. The tool refuses
// to run unless `../../../go-algorand` resolves to exactly this tag (or
// --allow-unpinned is set), so two developers regenerating the corpus get
// byte-identical output regardless of local go-algorand state.
const expectedGoAlgorandPin = "v5.0.5-stable"

// protoVersion is the consensus version every fixture is evaluated under.
// V41 is ConsensusCurrentVersion at the pin; its string value is recorded in
// each record's `proto` field so the Rust replay can map it to its own
// ConsensusParams via consensus_params_for_version.
const protoVersion = protocol.ConsensusV41

// stackEntry is one final-stack slot, recorded bottom-to-top.
type stackEntry struct {
	T string `json:"t"` // "u" = uint64, "b" = bytes
	V string `json:"v"` // decimal for uint64, hex for bytes
}

// Vector is one JSON line in the fixture file.
type Vector struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Proto       string       `json:"proto"`
	ProgramHex  string       `json:"program"`
	ArgsHex     []string     `json:"args"`
	Pass        bool         `json:"pass"`
	Error       string       `json:"error"`
	FinalStack  []stackEntry `json:"final_stack"`
	// CompareStack is false for programs that halt via an explicit `return`.
	// go's opReturn collapses the stack to the single return value, whereas a
	// conforming engine may instead consume it — the residual stack is an
	// implementation detail, not a consensus result, so the replay compares
	// only (errored, pass) for those. It is true for the common case where a
	// program halts by running off the end with its result on top.
	CompareStack bool `json:"compare_stack"`
	// CheckError is go's `logic.CheckSignature` verdict (the static pass every
	// LogicSig meets BEFORE evaluation: `verify.logicSigSanityCheck`), empty
	// when the program passes. Only the `check/` vectors are replayed against
	// it; every other vector is evaluated regardless.
	CheckError string `json:"check_error,omitempty"`
}

// detRand is a deterministic io.Reader for crypto key generation, so the
// captured corpus is reproducible. NOT for production use — fixtures only.
type detRand struct{ r *rand.Rand }

func (d detRand) Read(p []byte) (int, error) { return d.r.Read(p) }

func newDetRand(seed int64) detRand { return detRand{r: rand.New(rand.NewSource(seed))} }

// assemble compiles TEAL source at the given version and returns the program
// bytes, panicking on assembly error (a broken fixture program is a bug in
// this tool, not data). The source must NOT contain a `#pragma version` line;
// the version is supplied explicitly so it cannot drift from the assembler.
func assemble(source string, version uint64) []byte {
	ops, err := logic.AssembleStringWithVersion(source, version)
	if err != nil {
		panic(fmt.Sprintf("assemble failed (v%d) for source %q: %v", version, source, err))
	}
	return ops.Program
}

// evalSig runs `program` as a LogicSig with `args`, returning go's
// authoritative (pass, error, final-stack) triple. This is the exact path a
// node takes to validate a LogicSig transaction.
func evalSig(program []byte, args [][]byte) (bool, string, []stackEntry) {
	proto := config.Consensus[protoVersion]
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	txn.Lsig.Args = args
	ep := logic.NewSigEvalParams([]transactions.SignedTxn{txn}, &proto, &logic.NoHeaderLedger{})

	pass, cx, err := logic.EvalSignatureFull(0, ep)
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	var stack []stackEntry
	if err == nil && cx != nil {
		for _, sv := range cx.Stack {
			if sv.Bytes != nil {
				stack = append(stack, stackEntry{T: "b", V: hex.EncodeToString(sv.Bytes)})
			} else {
				stack = append(stack, stackEntry{T: "u", V: fmt.Sprintf("%d", sv.Uint)})
			}
		}
	}
	return pass, errStr, stack
}

// checkSig is go's static check of a LogicSig program (what a node runs before
// it evaluates the program): the error text, empty when the program passes.
func checkSig(program []byte) string {
	proto := config.Consensus[protoVersion]
	var txn transactions.SignedTxn
	txn.Lsig.Logic = program
	ep := logic.NewSigEvalParams([]transactions.SignedTxn{txn}, &proto, &logic.NoHeaderLedger{})
	if err := logic.CheckSignature(0, ep); err != nil {
		return err.Error()
	}
	return ""
}

// tailOf is the bytes of the single instruction `last` (assembled behind enough
// padding for the assembler's stack tracking to accept it), as in mkVectorTail.
func tailOf(last string, version uint64) []byte {
	for _, unit := range []string{"int 0; ", "byte 0x00; ", "byte 0x00; int 0; ", "int 0; byte 0x00; ", "byte 0x00; int 0; int 0; byte 0x00; "} {
		pad := strings.Repeat(unit, 4)
		ops, err := logic.AssembleStringWithVersion(pad+last, version)
		if err != nil {
			continue
		}
		padOnly := assemble(strings.TrimSuffix(pad, "; "), version)
		return ops.Program[len(padOnly):]
	}
	panic(fmt.Sprintf("tailOf: cannot assemble %q", last))
}

// mkVectorMalformed builds a program that goes' static check rejects: the
// program assembled from `prefix` (the version header alone when empty, at
// `version`) followed by the first `keep` bytes of the instruction `last`
// assembled at `lastVersion` (so a newer opcode can sit in an older program),
// or by `raw` when `last` is empty. The vector keeps go's check error AND its
// evaluation outcome.
func mkVectorMalformed(name, desc, prefix, last string, version, lastVersion uint64, keep int, raw []byte) Vector {
	head := []byte{byte(version)}
	if prefix != "" {
		head = assemble(prefix, version)
	}
	tail := raw
	if last != "" {
		tail = tailOf(last, lastVersion)
		if keep >= 0 && keep < len(tail) {
			tail = tail[:keep]
		}
	}
	program := append(append([]byte{}, head...), tail...)
	pass, errStr, stack := evalSig(program, nil)
	return Vector{
		Name:         name,
		Description:  desc,
		Proto:        string(protoVersion),
		ProgramHex:   hex.EncodeToString(program),
		ArgsHex:      []string{},
		Pass:         pass,
		Error:        errStr,
		FinalStack:   stack,
		CompareStack: true,
		CheckError:   checkSig(program),
	}
}

// mkVector assembles a TEAL source, evaluates it, and returns a fully
// populated Vector capturing go's ground truth.
func mkVector(name, desc, source string, version uint64, args [][]byte) Vector {
	program := assemble(source, version)
	pass, errStr, stack := evalSig(program, args)
	argsHex := make([]string, len(args))
	for i, a := range args {
		argsHex[i] = hex.EncodeToString(a)
	}
	// A program that halts via an explicit `return` leaves an
	// implementation-defined residual stack (go keeps the return value; a
	// conforming engine may consume it), so the replay should compare only
	// (errored, pass) for those, not the stack.
	compareStack := !sourceEndsWithReturn(source)
	return Vector{
		Name:         name,
		Description:  desc,
		Proto:        string(protoVersion),
		ProgramHex:   hex.EncodeToString(program),
		ArgsHex:      argsHex,
		Pass:         pass,
		Error:        errStr,
		FinalStack:   stack,
		CompareStack: compareStack,
	}
}

// mkVectorTail is mkVector for a program whose final instruction the assembler
// would refuse on its static stack-type check (an underflow, a wrong-typed
// argument): everything before the last `;`-separated instruction is
// assembled normally and the last instruction's bytes are appended raw, the
// technique go-algorand's own TestWrongStackTypeRuntime uses to reach the
// runtime gate. The tail bytes are taken from the same instruction assembled
// behind enough padding for the type tracker to accept it.
func mkVectorTail(name, desc, source string, version uint64, args [][]byte) Vector {
	prefix, last := "", source
	if i := strings.LastIndex(source, ";"); i >= 0 {
		prefix, last = source[:i], strings.TrimSpace(source[i+1:])
	}
	var tail []byte
	var lastErr error
	for _, unit := range []string{"int 0; ", "byte 0x00; ", "byte 0x00; int 0; int 0; ", "byte 0x00; int 0; byte 0x00; ", "int 0; byte 0x00; ", "byte 0x00; int 0; ", "int 0; byte 0x00; int 0; ", "byte 0x00; int 0; int 0; byte 0x00; ", "int 0; int 0; byte 0x00; ", "int 0; int 0; byte 0x00; int 0; ", "int 0; byte 0x00; byte 0x00; ", "byte 0x00; byte 0x00; byte 0x00; byte 0x00; byte 0x00; ", "int 1; bzero; int 0; int 1; bzero; int 1; bzero; ", "int 1; bzero; ", "int 1; bzero; int 1; bzero; int 1; bzero; int 1; bzero; int 1; bzero; "} {
		pad := strings.Repeat(unit, 4)
		ops, err := logic.AssembleStringWithVersion(pad+last, version)
		if err != nil {
			lastErr = err
			continue
		}
		padOnly := assemble(strings.TrimSuffix(pad, "; "), version)
		tail = ops.Program[len(padOnly):]
		break
	}
	if tail == nil {
		panic(fmt.Sprintf("mkVectorTail: cannot assemble %q behind int or byte padding: %v", last, lastErr))
	}
	head := []byte{byte(version)}
	if prefix != "" {
		head = assemble(prefix, version)
	}
	program := append(append([]byte{}, head...), tail...)
	pass, errStr, stack := evalSig(program, args)
	argsHex := make([]string, len(args))
	for i, a := range args {
		argsHex[i] = hex.EncodeToString(a)
	}
	return Vector{
		Name:         name,
		Description:  desc,
		Proto:        string(protoVersion),
		ProgramHex:   hex.EncodeToString(program),
		ArgsHex:      argsHex,
		Pass:         pass,
		Error:        errStr,
		FinalStack:   stack,
		CompareStack: !sourceEndsWithReturn(source),
	}
}

// mkVectorRawAppend assembles `source`, then appends `rawOpcode` directly to
// the compiled program bytes (bypassing the assembler's own static type
// tracker for the appended opcode), evaluates the result, and returns a
// fully populated Vector. This mirrors go-algorand's own technique for
// reaching the *runtime* type gate in `data/transactions/logic/eval_test.go`
// (e.g. `TestWrongStackTypeRuntime`/`TestWrongStackTypeRuntime2`, which do
// `ops.Program = append(ops.Program, 0x08)` after assembling a prefix) --
// used where the mismatch the vector exercises is one the assembler's static
// type tracker would itself refuse to assemble as source, so it can only be
// reached by a raw/malicious on-chain program.
func mkVectorRawAppend(name, desc, source string, version uint64, rawOpcode byte, args [][]byte) Vector {
	return mkVectorRawAppendBytes(name, desc, source, version, []byte{rawOpcode}, args)
}

// mkVectorRawAppendBytes is mkVectorRawAppend for an opcode with immediates:
// every byte of `raw` (opcode then immediates) is appended verbatim.
func mkVectorRawAppendBytes(name, desc, source string, version uint64, raw []byte, args [][]byte) Vector {
	program := append(assemble(source, version), raw...)
	pass, errStr, stack := evalSig(program, args)
	argsHex := make([]string, len(args))
	for i, a := range args {
		argsHex[i] = hex.EncodeToString(a)
	}
	return Vector{
		Name:        name,
		Description: desc,
		Proto:       string(protoVersion),
		ProgramHex:  hex.EncodeToString(program),
		ArgsHex:     argsHex,
		Pass:        pass,
		Error:       errStr,
		FinalStack:  stack,
		// The appended raw opcode always errors here (a runtime type-gate
		// rejection), so there is no successful final stack to compare.
		CompareStack: false,
	}
}

// sourceEndsWithReturn reports whether the final opcode token of a TEAL source
// is `return` (0x43). Tokens are separated by `;` and newlines.
func sourceEndsWithReturn(source string) bool {
	fields := strings.FieldsFunc(source, func(r rune) bool {
		return r == ';' || r == '\n'
	})
	for i := len(fields) - 1; i >= 0; i-- {
		tok := strings.TrimSpace(fields[i])
		if tok == "" {
			continue
		}
		return strings.HasPrefix(tok, "return")
	}
	return false
}

// ---------------------------------------------------------------------------
// Vector generation
// ---------------------------------------------------------------------------

func generate() []Vector {
	var out []Vector

	// =======================================================================
	// ed25519verify (0x04) — THE BT-294 regression guard.
	//
	// go signs Msg{ProgramHash: H(Program(program)), Data: data}, whose
	// ToBeHashed is "ProgData" || programHash || data with NO extra prehash
	// (crypto/util.go HashRep concatenates only). The pre-fix Rust op
	// SHA-512/256-prehashed that payload and therefore REJECTED this exact
	// go-produced signature. A passing replay of this fixture proves the fix.
	// =======================================================================
	{
		var seed crypto.Seed
		dr := newDetRand(0x6564323535313976) // "ed25519v"
		dr.Read(seed[:])
		c := crypto.GenerateSignatureSecrets(seed)
		data, _ := hex.DecodeString("62fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd")

		// arg 0 = data, arg 1 = sig, arg 2 = pubkey
		source := "arg 0; arg 1; arg 2; ed25519verify"
		program := assemble(source, 7)
		sig := c.Sign(logic.Msg{
			ProgramHash: crypto.HashObj(logic.Program(program)),
			Data:        data,
		})

		// Valid case: go-produced signature over the raw ProgData payload.
		out = append(out, mkVector(
			"ed25519verify/valid",
			"go-signed over \"ProgData\"||H(Program)||data; pre-fix Rust prehash would REJECT (BT-294)",
			source, 7,
			[][]byte{data, sig[:], c.SignatureVerifier[:]},
		))

		// Wrong case: flip the high nibble of the first data byte. The
		// signature no longer matches the message -> verify pushes 0 ->
		// program REJECTs (pass=false), but does NOT error.
		data1 := make([]byte, len(data))
		copy(data1, data)
		data1[0] ^= 0xf0
		out = append(out, mkVector(
			"ed25519verify/wrong_data",
			"tampered data; go-signed sig no longer matches -> verify=0 -> reject",
			source, 7,
			[][]byte{data1, sig[:], c.SignatureVerifier[:]},
		))

		// Prehashed-payload case (the SHAPE of the BT-294 bug): a signature
		// over SHA-512/256("ProgData"||H||data) instead of the raw payload.
		// go (and the fixed Rust) verify the RAW payload, so this signature
		// does NOT match -> reject. The PRE-fix Rust prehashed and so would
		// have ACCEPTED it: a direct divergence in opposite direction.
		var progHash crypto.Digest = crypto.HashObj(logic.Program(program))
		raw := append([]byte("ProgData"), progHash[:]...)
		raw = append(raw, data...)
		prehash := sha512.Sum512_256(raw)
		prehashSig := c.SignBytes(prehash[:]) // bare sign over the digest
		out = append(out, mkVector(
			"ed25519verify/prehashed_sig_rejected",
			"sig over SHA512_256(ProgData||H||data); go verifies RAW payload -> reject; pre-fix Rust prehashed -> would ACCEPT (BT-294 shape)",
			source, 7,
			[][]byte{data, prehashSig[:], c.SignatureVerifier[:]},
		))

		// Invalid signature length is a hard error in go (program errors).
		out = append(out, mkVector(
			"ed25519verify/short_sig_errors",
			"63-byte signature -> \"invalid signature\" hard error",
			source, 7,
			[][]byte{data, sig[1:], c.SignatureVerifier[:]},
		))
	}

	// =======================================================================
	// ed25519verify_bare (0x84, v7+) — no domain separation; sig over raw data.
	// =======================================================================
	{
		var seed crypto.Seed
		dr := newDetRand(0x6261726531323576) // "bare12v"
		dr.Read(seed[:])
		c := crypto.GenerateSignatureSecrets(seed)
		data, _ := hex.DecodeString("62fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd")
		sig := c.SignBytes(data)

		source := "arg 0; arg 1; arg 2; ed25519verify_bare"
		out = append(out, mkVector(
			"ed25519verify_bare/valid",
			"bare ed25519 over raw data (no ProgData prefix)",
			source, 7,
			[][]byte{data, sig[:], c.SignatureVerifier[:]},
		))

		data1 := make([]byte, len(data))
		copy(data1, data)
		data1[0] ^= 0x01
		out = append(out, mkVector(
			"ed25519verify_bare/wrong_data",
			"tampered data -> verify=0 -> reject",
			source, 7,
			[][]byte{data1, sig[:], c.SignatureVerifier[:]},
		))
	}

	// =======================================================================
	// ecdsa_verify Secp256k1 (0x05, curve 0). Stack: data, R, S, X, Y.
	// data must be sha512_256(message) (32 bytes). Mirrors crypto_test.go.
	// =======================================================================
	{
		// Fixed 32-byte private scalar -> deterministic key + RFC6979
		// signature. We do NOT use ecdsa.GenerateKey here: modern Go's
		// GenerateKey mixes in crypto/rand for blinding even when handed a
		// deterministic reader, so it is not reproducible. Deriving the
		// pubkey via ScalarBaseMult and signing via secp256k1.Sign (RFC6979,
		// deterministic) keeps the captured vector byte-stable run to run.
		var sk [32]byte
		copy(sk[:], []byte("avm-opcode-capture/secp256k1-key"))
		curve := secp256k1.S256()
		px, py := curve.ScalarBaseMult(sk[:])
		x := px.FillBytes(make([]byte, 32))
		y := py.FillBytes(make([]byte, 32))

		msg := sha512.Sum512_256([]byte("testdata"))
		sign, err := secp256k1.Sign(msg[:], sk[:])
		if err != nil {
			panic(fmt.Sprintf("secp256k1 sign: %v", err))
		}
		r := sign[:32]
		s := sign[32:64]

		source := func(dataStr, rHex, sHex string) string {
			return fmt.Sprintf("byte \"%s\"; sha512_256; byte 0x%s; byte 0x%s; byte 0x%s; byte 0x%s; ecdsa_verify Secp256k1",
				dataStr, rHex, sHex, hex.EncodeToString(x), hex.EncodeToString(y))
		}
		out = append(out, mkVector(
			"ecdsa_verify/secp256k1/valid",
			"go secp256k1.Sign over sha512_256(\"testdata\"); X,Y from key",
			source("testdata", hex.EncodeToString(r), hex.EncodeToString(s)), 7,
			nil,
		))

		rTampered := make([]byte, len(r))
		copy(rTampered, r)
		rTampered[0] += 1
		out = append(out, mkVector(
			"ecdsa_verify/secp256k1/tampered_r",
			"R[0]+1 -> verify=0 -> reject",
			source("testdata", hex.EncodeToString(rTampered), hex.EncodeToString(s)), 7,
			nil,
		))
		out = append(out, mkVector(
			"ecdsa_verify/secp256k1/wrong_msg",
			"signature is over \"testdata\", program hashes \"testdata1\" -> reject",
			source("testdata1", hex.EncodeToString(r), hex.EncodeToString(s)), 7,
			nil,
		))
	}

	// =======================================================================
	// ecdsa_pk_recover Secp256k1 (0x07, v5+). Stack: data, recovery id, R, S
	// (bottom to top; go `proto("b{32}ib{32}b{32}:b{32}b{32}")`, issue #2253).
	// Pushes X then Y (Y on top).
	// =======================================================================
	{
		var sk [32]byte
		copy(sk[:], []byte("avm-opcode-capture/secp256k1-key"))
		curve := secp256k1.S256()
		px, py := curve.ScalarBaseMult(sk[:])
		x := px.FillBytes(make([]byte, 32))
		y := py.FillBytes(make([]byte, 32))

		msg := sha512.Sum512_256([]byte("testdata"))
		sign, err := secp256k1.Sign(msg[:], sk[:])
		if err != nil {
			panic(fmt.Sprintf("secp256k1 sign: %v", err))
		}
		rHex := hex.EncodeToString(sign[:32])
		sHex := hex.EncodeToString(sign[32:64])
		recid := sign[64]

		// Compare the recovered key to the signer's public key.
		check := fmt.Sprintf("byte 0x%s; ==; swap; byte 0x%s; ==; &&", hex.EncodeToString(y), hex.EncodeToString(x))
		out = append(out, mkVector(
			"ecdsa_pk_recover/secp256k1/valid_go_order",
			"go order data, recid, R, S: recovers the signer's X,Y",
			fmt.Sprintf("byte \"testdata\"; sha512_256; int %d; byte 0x%s; byte 0x%s; ecdsa_pk_recover Secp256k1; %s", recid, rHex, sHex, check), 7,
			nil,
		))
		// The assembler's static type tracker refuses this order, so append
		// the opcode (0x07) and its curve immediate (0x00) raw.
		out = append(out, mkVectorRawAppendBytes(
			"ecdsa_pk_recover/secp256k1/old_rust_order_rejected",
			"data, R, S, recid (the pre-fix algod-rust order): go rejects with an argument-type error",
			fmt.Sprintf("byte \"testdata\"; sha512_256; byte 0x%s; byte 0x%s; int %d", rHex, sHex, recid), 7,
			[]byte{0x07, 0x00},
			nil,
		))
		out = append(out, mkVector(
			"ecdsa_pk_recover/secp256k1/invalid_recid",
			"recovery id 4 -> go errors 'invalid recovery id: 4'",
			fmt.Sprintf("byte \"testdata\"; sha512_256; int 4; byte 0x%s; byte 0x%s; ecdsa_pk_recover Secp256k1; pop; pop; int 1", rHex, sHex), 7,
			nil,
		))
		// Length handling (issue #2253 review): go concatenates R || S || recid
		// and requires the 64 signature bytes in total (secp256k1.checkSignature,
		// len(sig) == 65) and exactly 32 data bytes, so the split between R and
		// S is NOT enforced per argument.
		rb, sb := sign[:32], sign[32:64]
		cat := func(parts ...[]byte) string {
			var b []byte
			for _, p := range parts {
				b = append(b, p...)
			}
			return hex.EncodeToString(b)
		}
		msgB := msg[:]
		// The assembler tracks constant lengths (b{N}) statically, so build each
		// byte argument as the concat of two halves to keep it plain `bytes`.
		opaque := func(h string) string {
			m := (len(h) / 4) * 2
			return fmt.Sprintf("byte 0x%s; byte 0x%s; concat", h[:m], h[m:])
		}
		rec := func(name, desc, dataHex string, recidArg uint64, rHex, sHex string) {
			out = append(out, mkVector(
				"ecdsa_pk_recover/secp256k1/"+name, desc,
				fmt.Sprintf("%s; int %d; %s; %s; ecdsa_pk_recover Secp256k1; %s", opaque(dataHex), recidArg, opaque(rHex), opaque(sHex), check), 7,
				nil,
			))
		}
		rec("r31_s33_same_concat", "R 31 bytes, S 33 bytes, R||S unchanged: go recovers the key",
			hex.EncodeToString(msgB), uint64(recid), cat(rb[:31]), cat(rb[31:], sb))
		rec("r33_s31_same_concat", "R 33 bytes, S 31 bytes, R||S unchanged: go recovers the key",
			hex.EncodeToString(msgB), uint64(recid), cat(rb, sb[:1]), cat(sb[1:]))
		rec("r_empty_s64", "R empty, S = R||S (64 bytes): go recovers the key",
			hex.EncodeToString(msgB), uint64(recid), "", cat(rb, sb))
		rec("r64_s_empty", "R = R||S (64 bytes), S empty: go recovers the key",
			hex.EncodeToString(msgB), uint64(recid), cat(rb, sb), "")
		rec("r_empty_s_empty", "both empty: signature length 0",
			hex.EncodeToString(msgB), uint64(recid), "", "")
		rec("r31_s32", "R 31 + S 32 = 63 signature bytes",
			hex.EncodeToString(msgB), uint64(recid), cat(rb[:31]), cat(sb))
		rec("r33_s32", "R 33 + S 32 = 65 signature bytes",
			hex.EncodeToString(msgB), uint64(recid), cat(rb, []byte{0}), cat(sb))
		rec("data31", "31 data bytes: invalid message length",
			cat(msgB[:31]), uint64(recid), cat(rb), cat(sb))
		rec("data33", "33 data bytes: invalid message length",
			cat(msgB, []byte{0}), uint64(recid), cat(rb), cat(sb))
		rec("data_empty", "empty data: invalid message length",
			"", uint64(recid), cat(rb), cat(sb))
		// recovery id 4+ and a wrong-typed argument together (raw: the
		// assembler's type tracker refuses the wrong type).
		out = append(out, mkVectorRawAppendBytes(
			"ecdsa_pk_recover/secp256k1/recid4_and_wrong_typed_s",
			"recid 4 and S given as uint64: which error does go report",
			fmt.Sprintf("byte 0x%s; int 4; byte 0x%s; int 7", cat(msgB), cat(rb)), 7,
			[]byte{0x07, 0x00},
			nil,
		))
		out = append(out, mkVectorRawAppendBytes(
			"ecdsa_pk_recover/secp256k1/recid4_and_wrong_typed_data",
			"recid 4 and data given as uint64",
			fmt.Sprintf("int 9; int 4; byte 0x%s; byte 0x%s", cat(rb), cat(sb)), 7,
			[]byte{0x07, 0x00},
			nil,
		))
		out = append(out, mkVectorRawAppendBytes(
			"ecdsa_pk_recover/secp256k1/recid4_and_bytes_recid",
			"recid slot holds bytes (and would be >3 as a number)",
			fmt.Sprintf("byte 0x%s; byte 0x04; byte 0x%s; byte 0x%s", cat(msgB), cat(rb), cat(sb)), 7,
			[]byte{0x07, 0x00},
			nil,
		))
		rec("recid4_with_short_data", "recid 4 and 31 data bytes: which error first",
			cat(msgB[:31]), 4, cat(rb), cat(sb))
		// libsecp256k1 edge cases (issue #2253 review): go parses R || S || recid
		// with libsecp256k1 (RecoverPubkey), algod-rust with k256. For every case
		// the recovered key (when go recovers one) is compared to the key
		// secp256k1.RecoverPubkey itself returns, so the vector pins pass/fail,
		// the error text AND the recovered X||Y.
		curveN, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
		fieldP, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
		max256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
		b32 := func(v *big.Int) []byte { return v.FillBytes(make([]byte, 32)) }
		edge := func(name, desc string, recidArg byte, r, sv []byte) {
			sig := append(append(append([]byte{}, r...), sv...), recidArg)
			prefix := fmt.Sprintf("%s; int %d; %s; %s; ecdsa_pk_recover Secp256k1",
				opaque(hex.EncodeToString(msgB)), recidArg, opaque(hex.EncodeToString(r)), opaque(hex.EncodeToString(sv)))
			program := prefix + "; pop; pop; int 1"
			if pk, err := secp256k1.RecoverPubkey(msgB, sig); err == nil {
				program = prefix + fmt.Sprintf("; concat; byte 0x%s; ==", hex.EncodeToString(pk[1:65]))
			}
			out = append(out, mkVector("ecdsa_pk_recover/secp256k1/edge_"+name, desc, program, 7, nil))
		}
		sMinus := new(big.Int).Sub(curveN, new(big.Int).SetBytes(sb))
		for rid := byte(0); rid < 4; rid++ {
			edge(fmt.Sprintf("real_sig_recid%d", rid), "valid signature with each recovery id", rid, rb, sb)
		}
		edge("high_s_same_recid", "s replaced by n-s, same recovery id", recid, rb, b32(sMinus))
		edge("high_s_flipped_recid", "s replaced by n-s, recovery id flipped (recovers the signer's key)", recid^1, rb, b32(sMinus))
		rBig := new(big.Int).SetBytes(rb)
		edge("r_eq_n", "r = n", recid, b32(curveN), sb)
		edge("r_eq_n_plus_1", "r = n+1", recid, b32(new(big.Int).Add(curveN, big.NewInt(1))), sb)
		edge("r_max256", "r = 2^256-1", recid, b32(max256), sb)
		edge("r_eq_n_minus_1", "r = n-1", recid, b32(new(big.Int).Sub(curveN, big.NewInt(1))), sb)
		edge("s_eq_n", "s = n", recid, rb, b32(curveN))
		edge("s_eq_n_plus_1", "s = n+1", recid, rb, b32(new(big.Int).Add(curveN, big.NewInt(1))))
		edge("s_max256", "s = 2^256-1", recid, rb, b32(max256))
		edge("s_eq_n_minus_1", "s = n-1", recid, rb, b32(new(big.Int).Sub(curveN, big.NewInt(1))))
		edge("r_zero", "r = 0", recid, b32(big.NewInt(0)), sb)
		edge("s_zero", "s = 0", recid, rb, b32(big.NewInt(0)))
		edge("r_zero_s_zero", "r = 0, s = 0", recid, b32(big.NewInt(0)), b32(big.NewInt(0)))
		_ = rBig
		for rv := int64(1); rv <= 6; rv++ {
			for rid := byte(0); rid < 4; rid++ {
				edge(fmt.Sprintf("small_r%d_s1_recid%d", rv, rid), "small r, s = 1: recid 2/3 use x = r+n", rid, b32(big.NewInt(rv)), b32(big.NewInt(1)))
			}
		}
		pMinusN := new(big.Int).Sub(fieldP, curveN)
		for _, d := range []int64{-1, 0, 1} {
			for rid := byte(2); rid < 4; rid++ {
				rv := new(big.Int).Add(pMinusN, big.NewInt(d))
				edge(fmt.Sprintf("r_p_minus_n_%+d_recid%d", d, rid), "recid 2/3 with r+n around the field prime p", rid, b32(rv), b32(big.NewInt(1)))
			}
		}
		// go's own TestEcdsaEthAddress program (crypto_test.go:841-851).
		out = append(out, mkVector(
			"ecdsa_pk_recover/secp256k1/eth_address_go_test_program",
			"go TestEcdsaEthAddress program verbatim (keccak256, recid 0, r, s, concat, keccak256, substring 12 32)",
			`byte "hello from ethereum"; keccak256; int 0; byte 0x745e8f55ac6189ee89ed707c36694868e3903988fbf776c8096c45da2e60c638; byte 0x30c8e4a9b5d2eb53ddc6294587dd00bed8afe2c45dd72f6b4cf752e46d5ba681; ecdsa_pk_recover Secp256k1; concat; keccak256; substring 12 32; byte 0x5ce9454909639d2d17a3f753ce7d93fa0b9ab12e; ==`, 7,
			nil,
		))
	}

	// =======================================================================
	// ecdsa_verify Secp256r1 (0x05, curve 1, v7+). Stack: data, R, S, X, Y.
	// =======================================================================
	{
		// Modern Go's ecdsa.GenerateKey/Sign are intentionally
		// non-deterministic (they mix in crypto/rand for blinding even with a
		// deterministic reader), so we cannot regenerate a P-256 key+signature
		// reproducibly at runtime. Instead we embed an authentic,
		// go-produced (X, Y, R, S) over sha512_256("testdata"), captured once
		// from `crypto/ecdsa` using a fixed private scalar
		// ("avm-opcode-capture/secp256r1-key" reduced mod N). The runtime
		// eval below RE-VERIFIES this signature through go's opEcdsaVerify, so
		// a stale/incorrect constant would surface as pass=false here and a
		// replay mismatch — i.e. the constants are checked, not trusted.
		xHex := "4862227ae813aba1b5eb1481b08fa0b3f8d3fec9a35e31f997397d4f87dd45df"
		yHex := "a2681e878625fa1e9375f7a90ea70171939ff4660a56426c6401319fd5df28e5"
		rHexC := "af68083e4d09ed721b67db3c2823942559c1a29b1178dbbcf148f3647408915a"
		sHexC := "b6463ea21b152286c5dcaec9672f2a747efadb911289038aeb18e0a4451c9bd2"
		xb, _ := hex.DecodeString(xHex)
		yb, _ := hex.DecodeString(yHex)
		rb, _ := hex.DecodeString(rHexC)
		sb, _ := hex.DecodeString(sHexC)
		x := xb
		y := yb
		r := rb
		s := sb

		source := func(dataStr, rHex string) string {
			return fmt.Sprintf("byte \"%s\"; sha512_256; byte 0x%s; byte 0x%s; byte 0x%s; byte 0x%s; ecdsa_verify Secp256r1",
				dataStr, rHex, hex.EncodeToString(s), hex.EncodeToString(x), hex.EncodeToString(y))
		}
		out = append(out, mkVector(
			"ecdsa_verify/secp256r1/valid",
			"go ecdsa.Sign(P256) over sha512_256(\"testdata\")",
			source("testdata", hex.EncodeToString(r)), 7,
			nil,
		))

		rTampered := make([]byte, len(r))
		copy(rTampered, r)
		rTampered[0] += 1
		out = append(out, mkVector(
			"ecdsa_verify/secp256r1/tampered_r",
			"R[0]+1 -> verify=0 -> reject",
			source("testdata", hex.EncodeToString(rTampered)), 7,
			nil,
		))
	}

	// =======================================================================
	// vrf_verify VrfAlgorand (0xd0, v7+). Stack: data, proof(80), pubkey(32).
	// Pushes output(64 bytes) then verified flag. Spec anchors from
	// go-algorand crypto_test.go TestVrfVerify (draft-irtf-cfrg-vrf-03).
	// =======================================================================
	{
		// TV with empty alpha.
		pk, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
		proof, _ := hex.DecodeString("b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe701677c0f602900")
		output, _ := hex.DecodeString("5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a603f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc")
		// Program: verify, assert verified flag, then check output == expected.
		source := fmt.Sprintf("byte 0x%s\nbyte 0x%s\nbyte 0x%s\nvrf_verify VrfAlgorand\nassert\nbyte 0x%s\n==",
			"", hex.EncodeToString(proof), hex.EncodeToString(pk), hex.EncodeToString(output))
		out = append(out, mkVector(
			"vrf_verify/valid_empty_alpha",
			"draft-irtf-cfrg-vrf-03 anchor; empty alpha; verified=1 and output matches",
			source, 7,
			nil,
		))

		// TV with alpha = 0x72.
		pk2, _ := hex.DecodeString("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
		proof2, _ := hex.DecodeString("ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717e895fd15f99f07")
		output2, _ := hex.DecodeString("94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82eb1cfa97d84991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8")
		source2 := fmt.Sprintf("byte 0x%s\nbyte 0x%s\nbyte 0x%s\nvrf_verify VrfAlgorand\nassert\nbyte 0x%s\n==",
			"72", hex.EncodeToString(proof2), hex.EncodeToString(pk2), hex.EncodeToString(output2))
		out = append(out, mkVector(
			"vrf_verify/valid_alpha_72",
			"draft-irtf-cfrg-vrf-03 anchor; alpha=0x72; verified=1 and output matches",
			source2, 7,
			nil,
		))

		// Failing verify: a 0x33-prefixed 32-byte pubkey with an all-zero
		// 80-byte proof does not verify. Program pushes output(zeros) and
		// verified=0; we negate-assert and check the output is 64 zero bytes
		// (mirrors crypto_test.go line 242).
		failSource := "byte 0x3344; int 80; bzero; int 32; bzero; vrf_verify VrfAlgorand; !; assert; int 64; bzero; =="
		out = append(out, mkVector(
			"vrf_verify/fails_verify",
			"junk proof -> verified=0, output=64 zero bytes",
			failSource, 7,
			nil,
		))
	}

	// =======================================================================
	// A few cheap non-crypto opcodes (sanity coverage; final-stack compared).
	// =======================================================================
	out = append(out, mkVector(
		"arith/add",
		"100 + 200 == 300",
		"int 100; int 200; +; int 300; ==", 7,
		nil,
	))
	out = append(out, mkVector(
		"arith/div_by_zero_errors",
		"10 / 0 -> divide by zero error",
		"int 10; int 0; /", 7,
		nil,
	))
	out = append(out, mkVector(
		"crypto/sha256",
		"sha256(\"hello\") matches expected; leaves 1 on stack",
		"byte \"hello\"; sha256; byte 0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824; ==", 7,
		nil,
	))
	out = append(out, mkVector(
		"bytes/concat_len",
		"len(\"foo\"+\"bar\") == 6",
		"byte \"foo\"; byte \"bar\"; concat; len; int 6; ==", 7,
		nil,
	))
	out = append(out, mkVector(
		"flow/return_zero_rejects",
		"int 0; return -> pass=false (no error)",
		"int 0; return", 7,
		nil,
	))

	// =======================================================================
	// Regression (issue #1255): a bytes-typed stack value -- even a non-nil,
	// zero-length one -- in a uint64 arg position must be rejected by the
	// runtime type gate (`avmType()`/`opCompat()` in
	// data/transactions/logic/eval.go), exactly like a non-empty bytes value.
	// The assembler's own static type tracker would refuse to assemble `byte
	// ""; int 1; +` as source, so the mismatching `+` opcode is appended raw
	// post-assembly -- the same technique go-algorand's own
	// TestWrongStackTypeRuntime2 uses to reach this runtime-only path.
	// =======================================================================
	out = append(out, mkVectorRawAppend(
		"arith/plus_rejects_empty_bytes_arg",
		"byte \"\"; int 1; <raw 0x08 (+)> -> runtime type-gate error, not coercion to 0",
		"byte \"\"; int 1", 7, 0x08,
		nil,
	))

	// =======================================================================
	// Error text and pc parity (issues #2200 / #2225): runtime errors across the
	// opcode families, replayed with go's text and pc compared.
	// =======================================================================
	out = append(out, mkVectorTail(
		"errtext/mod_by_zero",
		"go EvalError text and pc for: int 10; int 0; %",
		"int 10; int 0; %", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/divmodw_by_zero",
		"go EvalError text and pc for: int 1; int 2; int 0; int 0; divmodw",
		"int 1; int 2; int 0; int 0; divmodw", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/divw_by_zero",
		"go EvalError text and pc for: int 1; int 2; int 0; divw",
		"int 1; int 2; int 0; divw", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/divw_overflow",
		"go EvalError text and pc for: int 5; int 2; int 1; divw",
		"int 5; int 2; int 1; divw", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/add_overflow",
		"go EvalError text and pc for: int 18446744073709551615; int 1; +",
		"int 18446744073709551615; int 1; +", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/sub_underflow",
		"go EvalError text and pc for: int 1; int 2; -",
		"int 1; int 2; -", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mul_overflow",
		"go EvalError text and pc for: int 18446744073709551615; int 2; *",
		"int 18446744073709551615; int 2; *", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/exp_zero_zero",
		"go EvalError text and pc for: int 0; int 0; exp",
		"int 0; int 0; exp", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/exp_overflow",
		"go EvalError text and pc for: int 2; int 64; exp",
		"int 2; int 64; exp", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/shl_over_63",
		"go EvalError text and pc for: int 1; int 64; shl",
		"int 1; int 64; shl", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/shr_over_63",
		"go EvalError text and pc for: int 1; int 64; shr",
		"int 1; int 64; shr", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/err_opcode",
		"go EvalError text and pc for: err",
		"err", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/assert_zero",
		"go EvalError text and pc for: int 0; assert",
		"int 0; assert", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/dig_too_deep",
		"go EvalError text and pc for: int 1; dig 1",
		"int 1; dig 1", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/cover_too_deep",
		"go EvalError text and pc for: int 1; cover 1",
		"int 1; cover 1", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/uncover_too_deep",
		"go EvalError text and pc for: int 1; uncover 1",
		"int 1; uncover 1", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/bury_too_deep",
		"go EvalError text and pc for: int 1; bury 1",
		"int 1; bury 1", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/popn_too_many",
		"go EvalError text and pc for: int 1; popn 2",
		"int 1; popn 2", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/dupn_empty",
		"go EvalError text and pc for: dupn 1",
		"dupn 1", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/pop_empty",
		"go EvalError text and pc for: pop",
		"pop", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/dup_empty",
		"go EvalError text and pc for: dup",
		"dup", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/swap_one",
		"go EvalError text and pc for: int 1; swap",
		"int 1; swap", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/select_empty",
		"go EvalError text and pc for: select",
		"select", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/loads_oob",
		"go EvalError text and pc for: int 256; loads",
		"int 256; loads", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/load_unset_ok",
		"go EvalError text and pc for: load 0; pop; int 1",
		"load 0; pop; int 1", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/stores_oob",
		"go EvalError text and pc for: int 256; int 1; stores",
		"int 256; int 1; stores", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/substring_oob",
		"go EvalError text and pc for: byte 0x010203; substring 0 4",
		"byte 0x010203; substring 0 4", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/substring3_oob",
		"go EvalError text and pc for: byte 0x010203; int 0; int 4; substring3",
		"byte 0x010203; int 0; int 4; substring3", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/extract_oob",
		"go EvalError text and pc for: byte 0x010203; extract 1 5",
		"byte 0x010203; extract 1 5", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/extract3_oob",
		"go EvalError text and pc for: byte 0x010203; int 1; int 5; extract3",
		"byte 0x010203; int 1; int 5; extract3", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/extract_uint16_oob",
		"go EvalError text and pc for: byte 0x01; int 0; extract_uint16",
		"byte 0x01; int 0; extract_uint16", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/extract_uint32_oob",
		"go EvalError text and pc for: byte 0x010203; int 0; extract_uint32",
		"byte 0x010203; int 0; extract_uint32", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/extract_uint64_oob",
		"go EvalError text and pc for: byte 0x01020304; int 0; extract_uint64",
		"byte 0x01020304; int 0; extract_uint64", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/replace2_oob",
		"go EvalError text and pc for: byte 0x010203; byte 0x0405; replace2 2",
		"byte 0x010203; byte 0x0405; replace2 2", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/replace3_oob",
		"go EvalError text and pc for: byte 0x010203; int 2; byte 0x0405; replace3",
		"byte 0x010203; int 2; byte 0x0405; replace3", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/getbit_oob_bytes",
		"go EvalError text and pc for: byte 0x01; int 8; getbit",
		"byte 0x01; int 8; getbit", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/getbyte_oob",
		"go EvalError text and pc for: byte 0x01; int 1; getbyte",
		"byte 0x01; int 1; getbyte", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/setbit_oob_bytes",
		"go EvalError text and pc for: byte 0x01; int 8; int 1; setbit",
		"byte 0x01; int 8; int 1; setbit", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/setbit_bad_value",
		"go EvalError text and pc for: int 1; int 0; int 2; setbit",
		"int 1; int 0; int 2; setbit", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/setbyte_oob",
		"go EvalError text and pc for: byte 0x01; int 1; int 1; setbyte",
		"byte 0x01; int 1; int 1; setbyte", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/bzero_too_big",
		"go EvalError text and pc for: int 4097; bzero",
		"int 4097; bzero", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/concat_too_long",
		"go EvalError text and pc for: byte 0x00; int 4096; bzero; concat",
		"byte 0x00; int 4096; bzero; concat", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/b_plus_too_long",
		"go EvalError text and pc for: byte 0x00; int 65; bzero; byte 0x01; b+",
		"byte 0x00; int 65; bzero; byte 0x01; b+", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/b_minus_negative",
		"go EvalError text and pc for: byte 0x01; byte 0x02; b-",
		"byte 0x01; byte 0x02; b-", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/b_div_by_zero",
		"go EvalError text and pc for: byte 0x01; byte 0x00; b/",
		"byte 0x01; byte 0x00; b/", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/b_mod_by_zero",
		"go EvalError text and pc for: byte 0x01; byte 0x00; b%",
		"byte 0x01; byte 0x00; b%", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/btoi_too_long",
		"go EvalError text and pc for: byte 0x010203040506070809; btoi",
		"byte 0x010203040506070809; btoi", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/bsqrt_too_long",
		"go EvalError text and pc for: byte 0x00; int 65; bzero; bsqrt",
		"byte 0x00; int 65; bzero; bsqrt", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/itxn_field_no_begin",
		"go EvalError text and pc for: int 1; itxn_field Amount",
		"int 1; itxn_field Amount", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/callsub_stack_underflow_retsub",
		"go EvalError text and pc for: retsub",
		"retsub", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/pushbytes_len_cmp_type",
		"go EvalError text and pc for: int 1; byte 0x01; ==",
		"int 1; byte 0x01; ==", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/log_in_logicsig",
		"go EvalError text and pc for: byte 0x01; log",
		"byte 0x01; log", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/global_group_size_ok",
		"go EvalError text and pc for: global GroupSize; int 1; ==",
		"global GroupSize; int 1; ==", 8,
		nil,
	))

	// =======================================================================
	// Error text parity, slice 2 (issue #2225): the mode gates of the
	// application-only opcodes and fields, and the array/group index errors.
	// =======================================================================
	out = append(out, mkVectorTail(
		"errtext/mode_balance",
		"go EvalError text and pc for: balance",
		"balance", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_min_balance",
		"go EvalError text and pc for: min_balance",
		"min_balance", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_app_opted_in",
		"go EvalError text and pc for: app_opted_in",
		"app_opted_in", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_app_local_get",
		"go EvalError text and pc for: app_local_get",
		"app_local_get", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_app_local_get_ex",
		"go EvalError text and pc for: app_local_get_ex",
		"app_local_get_ex", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_app_global_get",
		"go EvalError text and pc for: app_global_get",
		"app_global_get", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_app_global_get_ex",
		"go EvalError text and pc for: app_global_get_ex",
		"app_global_get_ex", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_app_local_put",
		"go EvalError text and pc for: app_local_put",
		"app_local_put", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_app_global_put",
		"go EvalError text and pc for: app_global_put",
		"app_global_put", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_app_local_del",
		"go EvalError text and pc for: app_local_del",
		"app_local_del", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_app_global_del",
		"go EvalError text and pc for: app_global_del",
		"app_global_del", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_asset_holding_get",
		"go EvalError text and pc for: asset_holding_get AssetBalance",
		"asset_holding_get AssetBalance", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_asset_params_get",
		"go EvalError text and pc for: asset_params_get AssetTotal",
		"asset_params_get AssetTotal", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_app_params_get",
		"go EvalError text and pc for: app_params_get AppCreator",
		"app_params_get AppCreator", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_acct_params_get",
		"go EvalError text and pc for: acct_params_get AcctBalance",
		"acct_params_get AcctBalance", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_box_create",
		"go EvalError text and pc for: box_create",
		"box_create", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_box_extract",
		"go EvalError text and pc for: box_extract",
		"box_extract", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_box_replace",
		"go EvalError text and pc for: box_replace",
		"box_replace", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_box_del",
		"go EvalError text and pc for: box_del",
		"box_del", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_box_len",
		"go EvalError text and pc for: box_len",
		"box_len", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_box_get",
		"go EvalError text and pc for: box_get",
		"box_get", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_box_put",
		"go EvalError text and pc for: box_put",
		"box_put", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_box_splice",
		"go EvalError text and pc for: box_splice",
		"box_splice", 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_box_resize",
		"go EvalError text and pc for: box_resize",
		"box_resize", 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_itxn_begin",
		"go EvalError text and pc for: itxn_begin",
		"itxn_begin", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_itxn_next",
		"go EvalError text and pc for: itxn_next",
		"itxn_next", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_itxn_submit",
		"go EvalError text and pc for: itxn_submit",
		"itxn_submit", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_itxn",
		"go EvalError text and pc for: itxn Fee",
		"itxn Fee", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_itxna",
		"go EvalError text and pc for: itxna ApplicationArgs 0",
		"itxna ApplicationArgs 0", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_itxnas",
		"go EvalError text and pc for: itxnas ApplicationArgs",
		"itxnas ApplicationArgs", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_gitxn",
		"go EvalError text and pc for: gitxn 0 Fee",
		"gitxn 0 Fee", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_gitxna",
		"go EvalError text and pc for: gitxna 0 ApplicationArgs 0",
		"gitxna 0 ApplicationArgs 0", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_gitxnas",
		"go EvalError text and pc for: gitxnas 0 ApplicationArgs",
		"gitxnas 0 ApplicationArgs", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_gload",
		"go EvalError text and pc for: gload 0 0",
		"gload 0 0", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_gloads",
		"go EvalError text and pc for: gloads 0",
		"gloads 0", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_gloadss",
		"go EvalError text and pc for: gloadss",
		"gloadss", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_gaid",
		"go EvalError text and pc for: gaid 0",
		"gaid 0", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_gaids",
		"go EvalError text and pc for: gaids",
		"gaids", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/mode_block",
		"go EvalError text and pc for: block BlkTimestamp",
		"block BlkTimestamp", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/global_round",
		"go EvalError text and pc for: global Round",
		"global Round", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/global_latest_timestamp",
		"go EvalError text and pc for: global LatestTimestamp",
		"global LatestTimestamp", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/global_current_application_id",
		"go EvalError text and pc for: global CurrentApplicationID",
		"global CurrentApplicationID", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/global_creator_address",
		"go EvalError text and pc for: global CreatorAddress",
		"global CreatorAddress", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/global_current_application_address",
		"go EvalError text and pc for: global CurrentApplicationAddress",
		"global CurrentApplicationAddress", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/global_caller_application_id",
		"go EvalError text and pc for: global CallerApplicationID",
		"global CallerApplicationID", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/global_caller_application_address",
		"go EvalError text and pc for: global CallerApplicationAddress",
		"global CallerApplicationAddress", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/txn_num_logs",
		"go EvalError text and pc for: txn NumLogs",
		"txn NumLogs", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/txn_created_asset_id",
		"go EvalError text and pc for: txn CreatedAssetID",
		"txn CreatedAssetID", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/txn_created_application_id",
		"go EvalError text and pc for: txn CreatedApplicationID",
		"txn CreatedApplicationID", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/txn_last_log",
		"go EvalError text and pc for: txn LastLog",
		"txn LastLog", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/txna_logs",
		"go EvalError text and pc for: txna Logs 0",
		"txna Logs 0", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/txnas_logs",
		"go EvalError text and pc for: int 0; txnas Logs",
		"int 0; txnas Logs", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/gtxn_num_logs",
		"go EvalError text and pc for: gtxn 0 NumLogs",
		"gtxn 0 NumLogs", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/gtxna_logs",
		"go EvalError text and pc for: gtxna 0 Logs 0",
		"gtxna 0 Logs 0", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/gtxns_num_logs",
		"go EvalError text and pc for: int 0; gtxns NumLogs",
		"int 0; gtxns NumLogs", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/txna_args_oob",
		"go EvalError text and pc for: txna ApplicationArgs 5",
		"txna ApplicationArgs 5", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/txna_accounts_oob",
		"go EvalError text and pc for: txna Accounts 3",
		"txna Accounts 3", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/txna_assets_oob",
		"go EvalError text and pc for: txna Assets 0",
		"txna Assets 0", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/txna_applications_oob",
		"go EvalError text and pc for: txna Applications 2",
		"txna Applications 2", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/txna_approval_pages_oob",
		"go EvalError text and pc for: txna ApprovalProgramPages 0",
		"txna ApprovalProgramPages 0", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/txna_clear_pages_oob",
		"go EvalError text and pc for: txna ClearStateProgramPages 0",
		"txna ClearStateProgramPages 0", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/txnas_args_oob",
		"go EvalError text and pc for: int 9; txnas ApplicationArgs",
		"int 9; txnas ApplicationArgs", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/txnas_accounts_oob",
		"go EvalError text and pc for: int 9; txnas Accounts",
		"int 9; txnas Accounts", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/gtxn_group_oob",
		"go EvalError text and pc for: gtxn 3 TxID",
		"gtxn 3 TxID", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/gtxn_sender_group_oob",
		"go EvalError text and pc for: gtxn 2 Sender",
		"gtxn 2 Sender", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/gtxns_group_oob",
		"go EvalError text and pc for: int 4; gtxns Sender",
		"int 4; gtxns Sender", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/gtxna_args_oob",
		"go EvalError text and pc for: gtxna 0 ApplicationArgs 3",
		"gtxna 0 ApplicationArgs 3", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/gtxnas_args_oob",
		"go EvalError text and pc for: int 3; gtxnas 0 ApplicationArgs",
		"int 3; gtxnas 0 ApplicationArgs", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/gtxnsa_args_oob",
		"go EvalError text and pc for: int 0; gtxnsa ApplicationArgs 2",
		"int 0; gtxnsa ApplicationArgs 2", 8,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/gtxnsas_args_oob",
		"go EvalError text and pc for: int 0; int 2; gtxnsas ApplicationArgs",
		"int 0; int 2; gtxnsas ApplicationArgs", 8,
		nil,
	))

	// =======================================================================
	// Error text parity, slice 3 (issue #2225): the crypto opcodes' argument
	// and length errors (ec_*, ecdsa_*, vrf_verify, ed25519verify*, falcon_verify).
	// =======================================================================
	out = append(out, mkVectorTail(
		"errtext/ec_add_bn254g1_short",
		`go EvalError text and pc for: byte 0x01; byte 0x02; ec_add BN254g1`,
		`byte 0x01; byte 0x02; ec_add BN254g1`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_scalar_mul_bn254g1_short",
		`go EvalError text and pc for: byte 0x01; byte 0x02; ec_scalar_mul BN254g1`,
		`byte 0x01; byte 0x02; ec_scalar_mul BN254g1`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_multi_scalar_mul_bn254g1_short",
		`go EvalError text and pc for: byte 0x01; byte 0x02; ec_multi_scalar_mul BN254g1`,
		`byte 0x01; byte 0x02; ec_multi_scalar_mul BN254g1`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_subgroup_check_bn254g1_short",
		`go EvalError text and pc for: byte 0x01; ec_subgroup_check BN254g1`,
		`byte 0x01; ec_subgroup_check BN254g1`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_map_to_bn254g1_short",
		`go EvalError text and pc for: byte 0x01; ec_map_to BN254g1`,
		`byte 0x01; ec_map_to BN254g1`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_add_bn254g2_short",
		`go EvalError text and pc for: byte 0x01; byte 0x02; ec_add BN254g2`,
		`byte 0x01; byte 0x02; ec_add BN254g2`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_scalar_mul_bn254g2_short",
		`go EvalError text and pc for: byte 0x01; byte 0x02; ec_scalar_mul BN254g2`,
		`byte 0x01; byte 0x02; ec_scalar_mul BN254g2`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_multi_scalar_mul_bn254g2_short",
		`go EvalError text and pc for: byte 0x01; byte 0x02; ec_multi_scalar_mul BN254g2`,
		`byte 0x01; byte 0x02; ec_multi_scalar_mul BN254g2`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_subgroup_check_bn254g2_short",
		`go EvalError text and pc for: byte 0x01; ec_subgroup_check BN254g2`,
		`byte 0x01; ec_subgroup_check BN254g2`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_map_to_bn254g2_short",
		`go EvalError text and pc for: byte 0x01; ec_map_to BN254g2`,
		`byte 0x01; ec_map_to BN254g2`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_add_bls12_381g1_short",
		`go EvalError text and pc for: byte 0x01; byte 0x02; ec_add BLS12_381g1`,
		`byte 0x01; byte 0x02; ec_add BLS12_381g1`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_scalar_mul_bls12_381g1_short",
		`go EvalError text and pc for: byte 0x01; byte 0x02; ec_scalar_mul BLS12_381g1`,
		`byte 0x01; byte 0x02; ec_scalar_mul BLS12_381g1`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_multi_scalar_mul_bls12_381g1_short",
		`go EvalError text and pc for: byte 0x01; byte 0x02; ec_multi_scalar_mul BLS12_381g1`,
		`byte 0x01; byte 0x02; ec_multi_scalar_mul BLS12_381g1`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_subgroup_check_bls12_381g1_short",
		`go EvalError text and pc for: byte 0x01; ec_subgroup_check BLS12_381g1`,
		`byte 0x01; ec_subgroup_check BLS12_381g1`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_map_to_bls12_381g1_short",
		`go EvalError text and pc for: byte 0x01; ec_map_to BLS12_381g1`,
		`byte 0x01; ec_map_to BLS12_381g1`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_add_bls12_381g2_short",
		`go EvalError text and pc for: byte 0x01; byte 0x02; ec_add BLS12_381g2`,
		`byte 0x01; byte 0x02; ec_add BLS12_381g2`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_scalar_mul_bls12_381g2_short",
		`go EvalError text and pc for: byte 0x01; byte 0x02; ec_scalar_mul BLS12_381g2`,
		`byte 0x01; byte 0x02; ec_scalar_mul BLS12_381g2`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_multi_scalar_mul_bls12_381g2_short",
		`go EvalError text and pc for: byte 0x01; byte 0x02; ec_multi_scalar_mul BLS12_381g2`,
		`byte 0x01; byte 0x02; ec_multi_scalar_mul BLS12_381g2`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_subgroup_check_bls12_381g2_short",
		`go EvalError text and pc for: byte 0x01; ec_subgroup_check BLS12_381g2`,
		`byte 0x01; ec_subgroup_check BLS12_381g2`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_map_to_bls12_381g2_short",
		`go EvalError text and pc for: byte 0x01; ec_map_to BLS12_381g2`,
		`byte 0x01; ec_map_to BLS12_381g2`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_pairing_check_bn254g1_short",
		`go EvalError text and pc for: byte 0x01; byte 0x02; ec_pairing_check BN254g1`,
		`byte 0x01; byte 0x02; ec_pairing_check BN254g1`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_pairing_check_bn254g2_short",
		`go EvalError text and pc for: byte 0x01; byte 0x02; ec_pairing_check BN254g2`,
		`byte 0x01; byte 0x02; ec_pairing_check BN254g2`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_pairing_check_bls12_381g1_short",
		`go EvalError text and pc for: byte 0x01; byte 0x02; ec_pairing_check BLS12_381g1`,
		`byte 0x01; byte 0x02; ec_pairing_check BLS12_381g1`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ec_pairing_check_bls12_381g2_short",
		`go EvalError text and pc for: byte 0x01; byte 0x02; ec_pairing_check BLS12_381g2`,
		`byte 0x01; byte 0x02; ec_pairing_check BLS12_381g2`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ecdsa_verify_secp256r1_short",
		`go EvalError text and pc for: byte "d"; byte 0x01; byte 0x02; byte 0x03; byte 0x04; ecdsa_verify Secp256r1`,
		`byte "d"; byte 0x01; byte 0x02; byte 0x03; byte 0x04; ecdsa_verify Secp256r1`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ecdsa_verify_secp256k1_short",
		`go EvalError text and pc for: byte "d"; byte 0x01; byte 0x02; byte 0x03; byte 0x04; ecdsa_verify Secp256k1`,
		`byte "d"; byte 0x01; byte 0x02; byte 0x03; byte 0x04; ecdsa_verify Secp256k1`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ecdsa_pk_decompress_k1_short",
		`go EvalError text and pc for: byte 0x01; ecdsa_pk_decompress Secp256k1`,
		`byte 0x01; ecdsa_pk_decompress Secp256k1`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ecdsa_pk_decompress_r1_short",
		`go EvalError text and pc for: byte 0x01; ecdsa_pk_decompress Secp256r1`,
		`byte 0x01; ecdsa_pk_decompress Secp256r1`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ecdsa_pk_recover_r1_not_supported",
		`go EvalError text and pc for: byte "d"; int 0; byte 0x01; byte 0x02; ecdsa_pk_recover Secp256r1`,
		`byte "d"; int 0; byte 0x01; byte 0x02; ecdsa_pk_recover Secp256r1`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/vrf_verify_short",
		`go EvalError text and pc for: byte 0x01; byte 0x02; byte 0x03; vrf_verify VrfAlgorand`,
		`byte 0x01; byte 0x02; byte 0x03; vrf_verify VrfAlgorand`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ed25519verify_short_key",
		`go EvalError text and pc for: byte "m"; int 64; bzero; byte 0x01; ed25519verify`,
		`byte "m"; int 64; bzero; byte 0x01; ed25519verify`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ed25519verify_bare_short_key",
		`go EvalError text and pc for: byte "m"; int 64; bzero; byte 0x01; ed25519verify_bare`,
		`byte "m"; int 64; bzero; byte 0x01; ed25519verify_bare`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/ed25519verify_short_sig_and_key",
		`go EvalError text and pc for: byte "m"; byte 0x01; byte 0x02; ed25519verify`,
		`byte "m"; byte 0x01; byte 0x02; ed25519verify`, 10,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/falcon_verify_short",
		`go EvalError text and pc for: byte 0x01; byte 0x02; byte 0x03; falcon_verify`,
		`byte 0x01; byte 0x02; byte 0x03; falcon_verify`, 12,
		nil,
	))
	out = append(out, mkVectorTail(
		"errtext/sha3_256_empty_ok",
		`go EvalError text and pc for: byte ""; sha3_256; pop; int 1`,
		`byte ""; sha3_256; pop; int 1`, 10,
		nil,
	))

	// =======================================================================
	// Static check parity (issue #2225): go runs logic.CheckSignature before it
	// evaluates a LogicSig, so a malformed program never reaches the runtime
	// `step` texts ("program ends without immediate value(s)"); the node reports
	// the check's `pc=%3d <err>`. Replayed against go's check error.
	// =======================================================================
	out = append(out, mkVectorMalformed(
		"check/txn_no_immediate",
		`go static check of a malformed program: txn_no_immediate`,
		`int 1`, `txn Fee`, 8, 8, 1, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/gtxn_one_immediate",
		`go static check of a malformed program: gtxn_one_immediate`,
		`int 1`, `gtxn 0 Fee`, 8, 8, 2, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/gtxn_no_immediate",
		`go static check of a malformed program: gtxn_no_immediate`,
		`int 1`, `gtxn 0 Fee`, 8, 8, 1, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/global_no_immediate",
		`go static check of a malformed program: global_no_immediate`,
		`int 1`, `global GroupSize`, 8, 8, 1, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/load_no_immediate",
		`go static check of a malformed program: load_no_immediate`,
		`int 1`, `load 0`, 8, 8, 1, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/store_no_immediate",
		`go static check of a malformed program: store_no_immediate`,
		`int 1`, `store 0`, 8, 8, 1, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/substring_one_immediate",
		`go static check of a malformed program: substring_one_immediate`,
		`byte 0x01`, `substring 0 1`, 8, 8, 2, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/extract_no_immediate",
		`go static check of a malformed program: extract_no_immediate`,
		`byte 0x01`, `extract 0 1`, 8, 8, 1, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/intc_no_immediate",
		`go static check of a malformed program: intc_no_immediate`,
		`int 1`, `intc 0`, 8, 8, 1, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/bnz_no_offset",
		`go static check of a malformed program: bnz_no_offset`,
		`int 1`, ``, 8, 8, -1, []byte{0x40},
	))
	out = append(out, mkVectorMalformed(
		"check/bnz_half_offset",
		`go static check of a malformed program: bnz_half_offset`,
		`int 1`, ``, 8, 8, -1, []byte{0x40, 0x00},
	))
	out = append(out, mkVectorMalformed(
		"check/bz_no_offset",
		`go static check of a malformed program: bz_no_offset`,
		`int 1`, ``, 8, 8, -1, []byte{0x41},
	))
	out = append(out, mkVectorMalformed(
		"check/b_no_offset",
		`go static check of a malformed program: b_no_offset`,
		`int 1`, ``, 8, 8, -1, []byte{0x42},
	))
	out = append(out, mkVectorMalformed(
		"check/pushint_no_value",
		`go static check of a malformed program: pushint_no_value`,
		`int 1`, `pushint 300`, 8, 8, 1, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/pushint_truncated_varuint",
		`go static check of a malformed program: pushint_truncated_varuint`,
		`int 1`, `pushint 300`, 8, 8, 2, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/pushbytes_no_length",
		`go static check of a malformed program: pushbytes_no_length`,
		`int 1`, `pushbytes 0x0102`, 8, 8, 1, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/pushbytes_short_data",
		`go static check of a malformed program: pushbytes_short_data`,
		`int 1`, `pushbytes 0x0102`, 8, 8, 2, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/pushbytes_half_data",
		`go static check of a malformed program: pushbytes_half_data`,
		`int 1`, `pushbytes 0x010203`, 8, 8, 3, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/intcblock_no_count",
		`go static check of a malformed program: intcblock_no_count`,
		`int 1`, `intcblock 1 2`, 8, 8, 1, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/intcblock_short",
		`go static check of a malformed program: intcblock_short`,
		`int 1`, `intcblock 1 2`, 8, 8, 3, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/bytecblock_no_count",
		`go static check of a malformed program: bytecblock_no_count`,
		`int 1`, `bytecblock 0x01`, 8, 8, 1, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/bytecblock_short",
		`go static check of a malformed program: bytecblock_short`,
		`int 1`, `bytecblock 0x01 0x0203`, 8, 8, 3, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/invalid_opcode_ff",
		`go static check of a malformed program: invalid_opcode_ff`,
		`int 1`, ``, 8, 8, -1, []byte{0xff},
	))
	out = append(out, mkVectorMalformed(
		"check/opcode_newer_than_program",
		`go static check of a malformed program: opcode_newer_than_program`,
		`int 1`, `box_splice`, 8, 10, -1, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/app_only_opcode_in_logicsig",
		`go static check of a malformed program: app_only_opcode_in_logicsig`,
		`int 1`, `balance`, 8, 8, -1, nil,
	))
	out = append(out, mkVectorMalformed(
		"check/version_too_new",
		`go static check of a malformed program: version_too_new`,
		``, ``, 99, 99, -1, []byte{},
	))
	out = append(out, mkVectorMalformed(
		"check/empty_program_after_header",
		`go static check of a malformed program: empty_program_after_header`,
		``, ``, 8, 8, -1, []byte{},
	))

	return out
}

// ---------------------------------------------------------------------------
// Pin enforcement (mirrors the other capture tools)
// ---------------------------------------------------------------------------

func goAlgorandDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// tools/avm-opcode-capture -> repo root -> sibling go-algorand
	return filepath.Clean(filepath.Join(wd, "..", "..", "..", "go-algorand")), nil
}

func enforcePin(allowUnpinned bool) error {
	if allowUnpinned {
		fmt.Fprintln(os.Stderr, "WARNING: --allow-unpinned set; not enforcing go-algorand pin")
		return nil
	}
	dir, err := goAlgorandDir()
	if err != nil {
		return err
	}
	// 1. Tag pin.
	cmd := exec.Command("git", "-C", dir, "describe", "--tags", "--exact-match")
	tagOut, tagErr := cmd.Output()
	if tagErr != nil {
		return fmt.Errorf("go-algorand at %s is not on tag %q (git describe --exact-match failed: %v); use --allow-unpinned to override", dir, expectedGoAlgorandPin, tagErr)
	}
	if tag := strings.TrimSpace(string(tagOut)); tag != expectedGoAlgorandPin {
		return fmt.Errorf("go-algorand at %s is on tag %q, expected %q (use --allow-unpinned to override)", dir, tag, expectedGoAlgorandPin)
	}

	// 2. Clean working tree under the paths whose contents determine the
	//    captured vectors. Local edits to logic eval / crypto / consensus
	//    params would change generated output while still passing the tag
	//    pin, silently breaking the deterministic ground-truth guarantee.
	statusOut, err := exec.Command("git", "-C", dir, "status", "--porcelain").Output()
	if err != nil {
		return fmt.Errorf("checking %s working tree: %w", dir, err)
	}
	guarded := []string{
		"data/transactions/logic/",
		"crypto/",
		"config/",
		"protocol/",
	}
	if dirty := dirtyGuardedPaths(string(statusOut), guarded); len(dirty) > 0 {
		return fmt.Errorf(
			"go-algorand at %s has uncommitted changes touching paths that determine "+
				"captured vectors:\n%s\nClean the tree or pass --allow-unpinned.",
			dir, strings.Join(dirty, "\n"),
		)
	}
	return nil
}

// dirtyGuardedPaths returns the `git status --porcelain` lines whose source
// or destination path lies under any guarded prefix. Renames/copies are
// emitted as `XY <old> -> <new>`, so both sides are inspected: a file moved
// into a guarded directory changes that tree just as an in-place edit does.
// The leading two status columns are stripped (offset 3) without trimming the
// whole line first — porcelain v1 can begin with a literal space.
func dirtyGuardedPaths(porcelain string, prefixes []string) []string {
	var dirty []string
	for _, line := range strings.Split(strings.TrimRight(porcelain, "\n"), "\n") {
		if len(line) < 4 {
			continue
		}
		body := strings.TrimSpace(line[3:])
		candidates := []string{body}
		if idx := strings.Index(body, " -> "); idx >= 0 {
			candidates = []string{strings.TrimSpace(body[:idx]), strings.TrimSpace(body[idx+4:])}
		}
	candidateLoop:
		for _, c := range candidates {
			p := strings.Trim(c, "\"")
			for _, pre := range prefixes {
				if strings.HasPrefix(p, pre) {
					dirty = append(dirty, line)
					break candidateLoop
				}
			}
		}
	}
	return dirty
}

func main() {
	var (
		outPath       = flag.String("out", "../../crates/tools/algo-conformance/tests/fixtures/avm/vectors.jsonl", "output JSONL path")
		allowUnpinned = flag.Bool("allow-unpinned", false, "skip go-algorand pin enforcement")
	)
	flag.Parse()

	if err := enforcePin(*allowUnpinned); err != nil {
		fmt.Fprintf(os.Stderr, "pin check: %v\n", err)
		os.Exit(1)
	}

	vectors := generate()
	for i := range vectors {
		if vectors[i].CheckError != "" {
			continue
		}
		program, err := hex.DecodeString(vectors[i].ProgramHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "decode %s: %v\n", vectors[i].Name, err)
			os.Exit(1)
		}
		vectors[i].CheckError = checkSig(program)
	}

	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}
	if err := writeCheckCorpus(filepath.Join(filepath.Dir(*outPath), "check_corpus.jsonl")); err != nil {
		fmt.Fprintf(os.Stderr, "check corpus: %v\n", err)
		os.Exit(1)
	}
	f, err := os.Create(*outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create %s: %v\n", *outPath, err)
		os.Exit(1)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, v := range vectors {
		if err := enc.Encode(&v); err != nil {
			fmt.Fprintf(os.Stderr, "encode %s: %v\n", v.Name, err)
			os.Exit(1)
		}
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "flush: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "avm-opcode-capture: wrote %d vectors to %s\n", len(vectors), *outPath)
}
