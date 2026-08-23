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
const expectedGoAlgorandPin = "v4.6.0-stable"

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

	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
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
