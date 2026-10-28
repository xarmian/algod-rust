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

// Command genfixtures writes benchmarks/fixtures/micro/ (issue #2103): the
// shared inputs of the paired Go/Rust micro-benchmarks. Everything is
// deterministic (fixed seeds, no clock, no RNG), so a re-run at the same
// go-algorand pin reproduces the committed bytes exactly; the sha256 of
// every file is recorded in benchmarks/pairs.toml and checked by
// scripts/bench/test_pairs.py.
//
// Go produces every fixture that must be go-produced (msgpack encodings,
// signatures, VRF proofs, Falcon signatures, assembled TEAL). The block,
// certificate and proposal fixtures are re-encodings of fixtures already in
// the repository (go-captured), named in sources below.
//
// Run from benchmarks/go-micro (needs go-algorand's libsodium, `make
// libsodium` in the go-algorand checkout):
//
//	go run ./cmd/genfixtures -repo ../.. -out ../fixtures/micro
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/msgp/msgp"

	"github.com/xarmian/algod-rust/benchmarks/go-micro/micro"
)

var genesisHash = crypto.Digest(sha256.Sum256([]byte("algod-rust/micro/genesis")))

const genesisID = "micro-v1"

func seed(tag string, i int) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("algod-rust/micro/%s/%d", tag, i)))
}

// stream returns n deterministic bytes: sha256("algod-rust/micro/bytes" || u64le(i)) blocks.
func stream(n int) []byte {
	out := make([]byte, 0, n+32)
	for i := uint64(0); len(out) < n; i++ {
		var ctr [8]byte
		binary.LittleEndian.PutUint64(ctr[:], i)
		h := sha256.Sum256(append([]byte("algod-rust/micro/bytes"), ctr[:]...))
		out = append(out, h[:]...)
	}
	return out[:n]
}

func signer(tag string, i int) *crypto.SignatureSecrets {
	return crypto.GenerateSignatureSecrets(crypto.Seed(seed(tag, i)))
}

func payTxn(s *crypto.SignatureSecrets, i int) transactions.SignedTxn {
	txn := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      basics.Address(s.SignatureVerifier),
			Fee:         basics.MicroAlgos{Raw: 1000},
			FirstValid:  1000,
			LastValid:   2000,
			Note:        stream(8 + i%8),
			GenesisID:   genesisID,
			GenesisHash: genesisHash,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: basics.Address(seed("receiver", i)),
			Amount:   basics.MicroAlgos{Raw: uint64(1_000_000 + i)},
		},
	}
	return transactions.SignedTxn{Txn: txn, Sig: s.Sign(txn)}
}

func applTxn() transactions.SignedTxn {
	s := signer("appl", 0)
	txn := transactions.Transaction{
		Type: protocol.ApplicationCallTx,
		Header: transactions.Header{
			Sender:      basics.Address(s.SignatureVerifier),
			Fee:         basics.MicroAlgos{Raw: 2000},
			FirstValid:  1000,
			LastValid:   2000,
			Note:        stream(32),
			Lease:       seed("lease", 0),
			GenesisID:   genesisID,
			GenesisHash: genesisHash,
		},
		ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
			ApplicationID:   micro.AppID,
			OnCompletion:    transactions.NoOpOC,
			ApplicationArgs: [][]byte{[]byte("swap"), stream(8), stream(32)},
			Accounts:        []basics.Address{basics.Address(seed("acct", 0)), basics.Address(seed("acct", 1))},
			ForeignApps:     []basics.AppIndex{2001, 2002},
			ForeignAssets:   []basics.AssetIndex{3001},
			Boxes:           []transactions.BoxRef{{Index: 0, Name: []byte("box")}, {Index: 1, Name: stream(16)}},
		},
	}
	return transactions.SignedTxn{Txn: txn, Sig: s.Sign(txn)}
}

// largeBlock is a current-protocol block whose payset is the 1024 signed
// payments of stxns-1024.msgpack plus the signed app call of
// stxn-appl.msgpack (1025 transactions), encoded in-block form with go's
// own Block.EncodeSignedTxn and committed with Block.PaysetCommit, so the
// header's txn / txn256 / txn512 commitments are go's.
func largeBlock() []byte {
	blk := bookkeeping.Block{BlockHeader: bookkeeping.BlockHeader{
		Round:       1000,
		Branch:      bookkeeping.BlockHash(seed("branch", 0)),
		Seed:        committee.Seed(seed("block-seed", 0)),
		TimeStamp:   1_700_000_000,
		GenesisID:   genesisID,
		GenesisHash: genesisHash,
		RewardsState: bookkeeping.RewardsState{
			FeeSink:     basics.Address(seed("fee-sink", 0)),
			RewardsPool: basics.Address(seed("rewards-pool", 0)),
		},
		UpgradeState: bookkeeping.UpgradeState{CurrentProtocol: protocol.ConsensusCurrentVersion},
		TxnCounter:   5000,
	}}
	stxns := make([]transactions.SignedTxn, 0, 1025)
	for i := 0; i < 1024; i++ {
		stxns = append(stxns, payTxn(signer("batch", i), i))
	}
	stxns = append(stxns, applTxn())
	for _, s := range stxns {
		stib, err := blk.EncodeSignedTxn(s, transactions.ApplyData{})
		if err != nil {
			log.Fatal(err)
		}
		blk.Payset = append(blk.Payset, stib)
	}
	var err error
	if blk.TxnCommitments, err = blk.PaysetCommit(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  block-large: round %d, %d txns\n", blk.Round(), len(blk.Payset))
	return protocol.Encode(&blk)
}

type writer struct {
	dir     string
	written []string
}

func (w *writer) put(name string, data []byte) {
	if err := os.WriteFile(filepath.Join(w.dir, name), data, 0o644); err != nil {
		log.Fatal(err)
	}
	w.written = append(w.written, name)
	h := sha256.Sum256(data)
	fmt.Printf("%-22s %7d bytes  sha256 %s\n", name, len(data), hex.EncodeToString(h[:]))
}

func (w *writer) putJSON(name string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	w.put(name, append(b, '\n'))
}

func mustRead(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

// reencodeBlock takes a go `GET /v2/blocks/R?format=msgpack` response
// ({block, cert}) and returns protocol.Encode(&block).
func reencodeBlock(path string) []byte {
	var bc rpcs.EncodedBlockCert
	if err := protocol.Decode(mustRead(path), &bc); err != nil {
		log.Fatalf("%s: %v", path, err)
	}
	fmt.Printf("  %s: round %d, %d txns\n", filepath.Base(path), bc.Block.Round(), len(bc.Block.Payset))
	return protocol.Encode(&bc.Block)
}

// roundTrip checks that a go-captured agreement fixture still decodes and
// re-encodes byte-identically at this pin, then returns it.
func roundTrip(path string, obj msgpObj) []byte {
	b := mustRead(path)
	if err := protocol.Decode(b, obj); err != nil {
		log.Fatalf("%s: %v", path, err)
	}
	if !micro.Equal(protocol.Encode(obj), b) {
		log.Fatalf("%s: does not re-encode byte-identically at this pin", path)
	}
	return b
}

type msgpObj interface {
	msgp.Marshaler
	msgp.Unmarshaler
}

// TEAL templates. CHECK is replaced by the final result check: the
// generator first evaluates the program with CHECK = "int 1", reads the
// result from scratch slot 0, and then embeds it, so the committed program
// only approves when the evaluator computes exactly go-algorand's value.
const tealArith = `#pragma version 10
int 1
store 0
int 0
store 2
int 0
store 1
loop:
load 0
pushint 6364136223846793005
mulw
swap
pop
pushint 1442695040888963407
addw
swap
pop
dup
store 0
pushint 7
%
load 2
+
store 2
load 1
int 1
+
dup
store 1
pushint 500
<
bnz loop
load 0
load 2
^
store 0
CHECK
`

const tealHash = `#pragma version 10
pushbytes 0x` + "SEED32" + `
store 0
int 0
store 1
loop:
load 0
sha256
sha512_256
keccak256
store 0
load 1
int 1
+
dup
store 1
pushint 60
<
bnz loop
CHECK
`

const tealBytes = `#pragma version 10
pushbytes 0x` + "SEED32" + `
store 0
int 0
store 1
loop:
load 0
pushbytes 0x` + "MASK32" + `
b^
dup
extract 16 16
swap
extract 0 16
concat
load 1
itob
b+
pushint 32
bzero
b|
dup
len
pushint 32
-
pushint 32
extract3
load 1
itob
replace2 8
store 0
load 1
int 1
+
dup
store 1
pushint 250
<
bnz loop
CHECK
`

const tealApp = `#pragma version 10
int 0
store 0
int 0
store 1
loop:
pushbytes "k"
load 1
itob
concat
load 1
pushint 1000
+
app_global_put
pushbytes "k"
load 1
itob
concat
app_global_get
load 0
+
store 0
load 1
int 1
+
dup
store 1
pushint 8
<
bnz loop
pushbytes "box"
load 0
itob
pushint 56
bzero
concat
box_put
pushbytes "box"
box_get
assert
sha256
log
load 0
itob
log
int 1
`

func assemble(src string) []byte {
	ops, err := logic.AssembleString(src)
	if err != nil {
		log.Fatalf("assemble: %v\n%s", err, src)
	}
	return ops.Program
}

// lsigProgram assembles a self-checking logicsig (see CHECK above).
func lsigProgram(w *writer, name, tmpl string) {
	proto := micro.CurrentProto()
	probe := assemble(strings.Replace(tmpl, "CHECK", "int 1", 1))
	ep := logic.NewSigEvalParams(micro.LsigGroup(probe), &proto, logic.NoHeaderLedger{})
	pass, cx, err := logic.EvalSignatureFull(0, ep)
	if err != nil || !pass {
		log.Fatalf("%s probe: pass=%v err=%v", name, pass, err)
	}
	var check string
	if v := cx.Scratch[0]; v.Bytes != nil {
		check = "load 0\npushbytes 0x" + hex.EncodeToString(v.Bytes) + "\n=="
	} else {
		check = fmt.Sprintf("load 0\npushint %d\n==", v.Uint)
	}
	src := strings.Replace(tmpl, "CHECK", check, 1)
	prog := assemble(src)
	pass, cost, err := micro.EvalLsig(micro.LsigGroup(prog), &proto)
	if err != nil || !pass {
		log.Fatalf("%s final: pass=%v err=%v", name, pass, err)
	}
	fmt.Printf("  %s: cost %d of %d\n", name, cost, proto.LogicSigMaxCost)
	w.put(name+".teal", []byte(src))
	w.put(name+".bin", prog)
}

func main() {
	repo := flag.String("repo", "../..", "algod-rust repository root")
	out := flag.String("out", "../fixtures/micro", "output directory")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}
	w := &writer{dir: *out}
	src := func(p string) string { return filepath.Join(*repo, filepath.FromSlash(p)) }

	// codec
	w.put("block-small.msgpack", reencodeBlock(src("crates/core/algo-codec/tests/fixtures/block_6.msgpack")))
	w.put("block-large.msgpack", largeBlock())
	w.put("stxn-appl.msgpack", protocol.Encode(func() *transactions.SignedTxn { s := applTxn(); return &s }()))

	// crypto
	w.put("bytes-32.bin", stream(32))
	w.put("bytes-1k.bin", stream(1024))
	w.put("bytes-64k.bin", stream(64*1024))
	for _, n := range []int{64, 1024} {
		var buf []byte
		for i := 0; i < n; i++ {
			s := payTxn(signer("batch", i), i)
			buf = append(buf, protocol.Encode(&s)...)
		}
		w.put(fmt.Sprintf("stxns-%d.msgpack", n), buf)
	}

	// agreement inputs: a soft-vote selector, its VRF proof and credential.
	proto := micro.CurrentProto()
	vrfPK, vrfSK := crypto.VrfKeygenFromSeed(seed("vrf", 0))
	var cseed committee.Seed = committee.Seed(seed("committee-seed", 0))
	sel := micro.NewSelector(cseed, 1000, 0, 1)
	alpha := crypto.HashRep(sel)
	proof, ok := vrfSK.Prove(sel)
	if !ok {
		log.Fatal("vrf prove failed")
	}
	w.put("vrf.frames", micro.EncodeFrames(vrfPK[:], proof[:], alpha))

	falconSigner, err := crypto.GenerateFalconSigner(crypto.FalconSeed(stream(crypto.FalconSeedSize)))
	if err != nil {
		log.Fatal(err)
	}
	fmsg := stream(64)
	fsig, err := falconSigner.SignBytes(fmsg)
	if err != nil {
		log.Fatal(err)
	}
	w.put("falcon.frames", micro.EncodeFrames(falconSigner.PublicKey[:], fsig, fmsg))

	vrfOut := sha256.Sum256([]byte("algod-rust/micro/sortition"))
	w.putJSON("sortition.json", micro.SortitionInput{
		Money: 10_000_000_000_000, TotalMoney: 2_000_000_000_000_000,
		ExpectedSize: proto.SoftCommitteeSize, VrfOutput: hex.EncodeToString(vrfOut[:]),
	})

	addr := basics.Address(seed("voter", 0))
	cin := micro.CredentialInput{
		Address: hex.EncodeToString(addr[:]), SelectionPK: hex.EncodeToString(vrfPK[:]),
		Proof: hex.EncodeToString(proof[:]), Balance: 10_000_000_000_000,
		TotalMoney: 2_000_000_000_000_000, Seed: hex.EncodeToString(cseed[:]),
		Round: 1000, Period: 0, Step: 1,
	}
	cred, m, err := micro.CredentialFromInput(cin)
	if err != nil {
		log.Fatal(err)
	}
	c, err := cred.Verify(proto, m)
	if err != nil || c.Weight == 0 {
		log.Fatalf("credential does not verify: %v", err)
	}
	fmt.Printf("  credential weight %d\n", c.Weight)
	w.putJSON("credential.json", cin)

	w.put("cert-20.msgpack", roundTrip(src("crates/core/algo-agreement/tests/fixtures/wire/cert/twenty_votes.msgpack"), &agreement.Certificate{}))
	w.put("proposal.msgpack", roundTrip(src("crates/core/algo-agreement/tests/fixtures/wire/tpayload/distinct_all.msgpack"), &agreement.TransmittedPayload{}))

	// AVM
	seed32 := hex.EncodeToString(stream(32))
	mask := sha256.Sum256([]byte("algod-rust/micro/mask"))
	lsigProgram(w, "avm-arith", tealArith)
	lsigProgram(w, "avm-hash", strings.Replace(tealHash, "SEED32", seed32, 1))
	lsigProgram(w, "avm-bytes", strings.NewReplacer("SEED32", seed32, "MASK32", hex.EncodeToString(mask[:])).Replace(tealBytes))
	appProg := assemble(tealApp)
	o, err := micro.NewAppRunner(appProg).Run()
	if err != nil || !o.Pass {
		log.Fatalf("avm-app: pass=%v err=%v", o.Pass, err)
	}
	fmt.Printf("  avm-app: cost %d, logs %v\n", o.Cost, o.Logs)
	w.put("avm-app.teal", []byte(tealApp))
	w.put("avm-app.bin", appProg)
}
