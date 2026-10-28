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
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/algorand/go-algorand/protocol"
)

// Same seed, same genesis bytes; different seed, different genesis.
func TestGenesisDeterministic(t *testing.T) {
	a := protocol.EncodeJSON(newNetwork("s1", 16).genesis())
	b := protocol.EncodeJSON(newNetwork("s1", 16).genesis())
	c := protocol.EncodeJSON(newNetwork("s2", 16).genesis())
	if !bytes.Equal(a, b) {
		t.Fatal("same seed produced different genesis bytes")
	}
	if bytes.Equal(a, c) {
		t.Fatal("different seeds produced the same genesis")
	}
	g := newNetwork("s1", 16).genesis()
	if !g.DevMode || g.Timestamp != genesisTimestamp || g.Proto != protocol.ConsensusCurrentVersion {
		t.Fatalf("unexpected genesis header: %+v", g)
	}
	if len(g.Allocation) != 2+numValidators+16 {
		t.Fatalf("allocation has %d entries", len(g.Allocation))
	}
}

// writeDataDir must produce byte-identical files run after run.
func TestDataDirDeterministic(t *testing.T) {
	d1, d2 := t.TempDir(), t.TempDir()
	for _, d := range []string{d1, d2} {
		if err := writeDataDir(newNetwork("seed", 8), d); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"genesis.json", "config.json"} {
		a, _ := os.ReadFile(filepath.Join(d1, f))
		b, _ := os.ReadFile(filepath.Join(d2, f))
		if len(a) == 0 || !bytes.Equal(a, b) {
			t.Fatalf("%s differs between two writes", f)
		}
	}
}

// Derived keys are stable: pin one address so a change to the derivation
// (which would silently change every corpus) fails here first.
func TestKeyDerivationPinned(t *testing.T) {
	got := deriveKey("pin", "account", 0).addr.String()
	const want = "RC27XM5YYK6MC6UR5NSQPCYWUTA2IYMZEUU762ZO4J7SF3O7FWA42GYBLA"
	if got != want {
		t.Fatalf("derived address %s, pinned %s: bump generatorVersion if this is intended", got, want)
	}
}

func TestProgramsAssemble(t *testing.T) {
	if _, err := assemblePrograms(); err != nil {
		t.Fatal(err)
	}
}

func TestBlockStreamRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.bin")
	bw, err := createBlockWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	payloads := [][]byte{[]byte("zero"), {}, []byte("two")}
	for i, p := range payloads {
		if err := bw.write(uint64(i), p); err != nil {
			t.Fatal(err)
		}
	}
	if err := bw.close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := 0
	err = readBlocks(f, func(r uint64, p []byte) error {
		if r != uint64(n) || !bytes.Equal(p, payloads[n]) {
			t.Fatalf("record %d: round %d payload %q", n, r, p)
		}
		n++
		return nil
	})
	if err != nil || n != len(payloads) {
		t.Fatalf("read %d records, err %v", n, err)
	}
}
