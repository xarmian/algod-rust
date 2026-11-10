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

// Static-check corpus (issue #2286): a seeded, deterministic set of small
// programs -- hand-built malformed ones plus randomly assembled instruction
// streams (branches, switch/match, varlen immediates, random bytes) -- with
// go's verdict of BOTH static checks:
//
//   - logic.CheckSignature (a LogicSig, `verify.logicSigSanityCheck`), and
//   - logic.CheckContract (an application program, `checkPrograms`).
//
// The Rust replay (crates/tools/algo-conformance/tests/avm_check_corpus.rs)
// requires algo_avm::check to be CONSERVATIVE against it: a program go accepts
// is never rejected, and a rejection carries go's exact text. Programs the
// port does not cover (pre-v4 static cost, prefix-family immediates, ...)
// may pass in Rust where go rejects.

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

// checkCorpusProto is the consensus version of the corpus: its LogicSigVersion
// (13) is the newest the Rust check ports (varint branches).
const checkCorpusProto = protocol.ConsensusV42

type checkRecord struct {
	Name          string `json:"name"`
	Proto         string `json:"proto"`
	ProgramHex    string `json:"program"`
	CheckError    string `json:"check_error"`
	CheckAppError string `json:"check_app_error"`
}

func checkProgram(program []byte, app bool) string {
	proto := config.Consensus[checkCorpusProto]
	var err error
	if app {
		var txn transactions.SignedTxnWithAD
		txn.Txn.Type = protocol.ApplicationCallTx
		ep := logic.NewAppEvalParams([]transactions.SignedTxnWithAD{txn}, &proto, &transactions.SpecialAddresses{})
		err = logic.CheckContract(program, 0, ep)
	} else {
		var txn transactions.SignedTxn
		txn.Lsig.Logic = program
		ep := logic.NewSigEvalParams([]transactions.SignedTxn{txn}, &proto, &logic.NoHeaderLedger{})
		err = logic.CheckSignature(0, ep)
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

func appendUvarint(b []byte, x uint64) []byte {
	return binary.AppendUvarint(b, x)
}

func appendVarint(b []byte, x int64) []byte {
	return binary.AppendVarint(b, x)
}

// instructions the generator picks from, besides raw random bytes.
var checkSimpleOps = []byte{
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x50, 0x51, 0x52, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
	0x67, 0x68, 0x69, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x7f, 0x89, 0x95, 0xa0,
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xc0, 0xc1, 0xc2,
}

var checkOffsets = []int16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 20, 100, -1, -2, -3, -4, -5, -6, -7, -8, -10, -20, 0x7fff, -0x8000}

func randInstruction(r *rand.Rand, version byte, n int) []byte {
	var b []byte
	switch r.Intn(14) {
	case 0, 1, 2:
		// an Int16 branch (b / bz / bnz / callsub), or its varint form from v13.
		op := []byte{0x40, 0x41, 0x42, 0x88}[r.Intn(4)]
		b = append(b, op)
		if version >= 13 && r.Intn(4) != 0 {
			vals := []int64{0, 1, 2, 3, 4, 5, 6, 8, 10, -1, -2, -3, -4, -5, -6, -8, 300, -300}
			b = appendVarint(b, vals[r.Intn(len(vals))])
		} else {
			o := checkOffsets[r.Intn(len(checkOffsets))]
			b = append(b, byte(uint16(o)>>8), byte(uint16(o)))
		}
	case 3:
		// switch / match
		op := []byte{0x8d, 0x8e}[r.Intn(2)]
		b = append(b, op)
		count := r.Intn(4)
		b = append(b, byte(count))
		for i := 0; i < count; i++ {
			o := checkOffsets[r.Intn(len(checkOffsets))]
			b = append(b, byte(uint16(o)>>8), byte(uint16(o)))
		}
	case 4:
		b = append(b, 0x81) // pushint
		b = appendUvarint(b, uint64(r.Intn(400)))
	case 5:
		b = append(b, 0x80) // pushbytes
		l := r.Intn(4)
		b = appendUvarint(b, uint64(l))
		for i := 0; i < l; i++ {
			b = append(b, byte(r.Intn(256)))
		}
	case 6:
		b = append(b, 0x20) // intcblock
		c := r.Intn(3)
		b = appendUvarint(b, uint64(c))
		for i := 0; i < c; i++ {
			b = appendUvarint(b, uint64(r.Intn(300)))
		}
	case 7:
		b = append(b, 0x26) // bytecblock
		c := r.Intn(3)
		b = appendUvarint(b, uint64(c))
		for i := 0; i < c; i++ {
			l := r.Intn(3)
			b = appendUvarint(b, uint64(l))
			for j := 0; j < l; j++ {
				b = append(b, byte(r.Intn(256)))
			}
		}
	case 8:
		b = append(b, []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x21, 0x22, 0x23, 0x24, 0x25, 0x27, 0x2e, 0x2f}[r.Intn(14)])
		b = append(b, byte(r.Intn(6)))
	case 9:
		b = append(b, byte(r.Intn(256))) // any opcode, immediates follow by chance
	default:
		b = append(b, checkSimpleOps[r.Intn(len(checkSimpleOps))])
	}
	return b
}

// checkCorpus builds the corpus records (without go verdicts filled by hand:
// both checks run here).
func checkCorpus() []checkRecord {
	r := rand.New(rand.NewSource(2286))
	seen := map[string]bool{}
	var out []checkRecord
	add := func(name string, program []byte) {
		key := hex.EncodeToString(program)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, checkRecord{
			Name:          fmt.Sprintf("checkcorpus/%s", name),
			Proto:         string(checkCorpusProto),
			ProgramHex:    key,
			CheckError:    checkProgram(program, false),
			CheckAppError: checkProgram(program, true),
		})
	}
	for i := 0; i < 1500; i++ {
		version := byte(1 + r.Intn(13))
		prog := []byte{version}
		n := 1 + r.Intn(6)
		for j := 0; j < n; j++ {
			prog = append(prog, randInstruction(r, version, j)...)
		}
		// Sometimes cut the program short, to hit "ends without ..." paths.
		if r.Intn(6) == 0 && len(prog) > 2 {
			prog = prog[:1+r.Intn(len(prog)-1)]
		}
		add(fmt.Sprintf("random-%04d", i), prog)
	}
	// Every single opcode byte alone, and followed by two zero bytes, at a few
	// versions: opcode lookup, version gating and the mode gate of both modes.
	for _, version := range []byte{1, 2, 4, 8, 13} {
		for op := 0; op < 256; op++ {
			add(fmt.Sprintf("op-v%d-%02x", version, op), []byte{version, byte(op)})
		}
	}
	for _, version := range []byte{3, 8, 13} {
		for op := 0; op < 256; op++ {
			add(fmt.Sprintf("op0-v%d-%02x", version, op), []byte{version, byte(op), 0, 0})
		}
	}
	return out
}

func writeCheckCorpus(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, rec := range checkCorpus() {
		if err := enc.Encode(&rec); err != nil {
			return err
		}
	}
	return w.Flush()
}
