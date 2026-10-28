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

// Go half of the paired Go/Rust micro-benchmarks (issue #2103). One
// Benchmark function per benchmarks/pairs.toml entry (its `go_bench`);
// scripts/bench/test_pairs.py checks the mapping both ways.
//
//	go test -run '^$' -bench . -benchmem
package gomicro_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/xarmian/algod-rust/benchmarks/go-micro/micro"
)

const fixtureDir = "../fixtures/micro"

func run(b *testing.B, id string) {
	c, err := micro.Build(fixtureDir, id)
	if err != nil {
		b.Fatal(err)
	}
	c.BenchIteration() // fail fast (it panics) before timing
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.BenchIteration() // Reset (stateful pairs only) + Op, as on the Rust side
	}
}

func BenchmarkCodecDecodeBlockSmall(b *testing.B)  { run(b, "codec/decode-block-small") }
func BenchmarkCodecDecodeBlockLarge(b *testing.B)  { run(b, "codec/decode-block-large") }
func BenchmarkCodecEncodeBlockSmall(b *testing.B)  { run(b, "codec/encode-block-small") }
func BenchmarkCodecEncodeBlockLarge(b *testing.B)  { run(b, "codec/encode-block-large") }
func BenchmarkCodecDecodeStxn(b *testing.B)        { run(b, "codec/decode-stxn") }
func BenchmarkCodecEncodeStxn(b *testing.B)        { run(b, "codec/encode-stxn") }
func BenchmarkCodecTxid(b *testing.B)              { run(b, "codec/txid") }
func BenchmarkCodecBlockHash(b *testing.B)         { run(b, "codec/block-hash") }
func BenchmarkCryptoSha512_256_32B(b *testing.B)   { run(b, "crypto/sha512_256-32B") }
func BenchmarkCryptoSha512_256_1KiB(b *testing.B)  { run(b, "crypto/sha512_256-1KiB") }
func BenchmarkCryptoSha512_256_64KiB(b *testing.B) { run(b, "crypto/sha512_256-64KiB") }
func BenchmarkCryptoEd25519Verify(b *testing.B)    { run(b, "crypto/ed25519-verify") }
func BenchmarkCryptoEd25519Batch64(b *testing.B)   { run(b, "crypto/ed25519-batch-64") }
func BenchmarkCryptoEd25519Batch1024(b *testing.B) { run(b, "crypto/ed25519-batch-1024") }
func BenchmarkCryptoVrfVerify(b *testing.B)        { run(b, "crypto/vrf-verify") }
func BenchmarkCryptoFalconVerify(b *testing.B)     { run(b, "crypto/falcon-verify") }
func BenchmarkCommitTxnMerkle(b *testing.B)        { run(b, "commit/txn-merkle-sha512_256") }
func BenchmarkCommitTxnVcSha256(b *testing.B)      { run(b, "commit/txn-vc-sha256") }
func BenchmarkAvmLsigArithLoop(b *testing.B)       { run(b, "avm/lsig-arith-loop") }
func BenchmarkAvmLsigHashLoop(b *testing.B)        { run(b, "avm/lsig-hash-loop") }
func BenchmarkAvmLsigBytesOps(b *testing.B)        { run(b, "avm/lsig-bytes-ops") }
func BenchmarkAvmAppStateBox(b *testing.B)         { run(b, "avm/app-state-box") }
func BenchmarkAgreementSortitionSelect(b *testing.B) {
	run(b, "agreement/sortition-select")
}
func BenchmarkAgreementSortitionSelectF128(b *testing.B) {
	run(b, "agreement/sortition-select-f128")
}
func BenchmarkAgreementCredentialVerify(b *testing.B) { run(b, "agreement/credential-verify") }
func BenchmarkAgreementDecodeCert(b *testing.B)       { run(b, "agreement/decode-cert") }
func BenchmarkAgreementDecodeProposal(b *testing.B)   { run(b, "agreement/decode-proposal") }

// TestDigestsMatchRecorded keeps the committed go-digests.json in step with
// the Go side: a fixture or go-algorand change that alters an output must
// regenerate it (go run ./cmd/equiv -write ../fixtures/micro/go-digests.json).
func TestDigestsMatchRecorded(t *testing.T) {
	raw, err := os.ReadFile(fixtureDir + "/go-digests.json")
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	ids := micro.IDs()
	if len(want) != len(ids) {
		t.Errorf("go-digests.json has %d entries, the Go side has %d pairs", len(want), len(ids))
	}
	for _, id := range ids {
		c, err := micro.Build(fixtureDir, id)
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.Digest()
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if got != want[id] {
			t.Errorf("%s: digest %q, recorded %q", id, got, want[id])
		}
		// Every benchmark iteration must do the same work: after N
		// iterations exactly as the benchmark runs them, the digest must
		// still be the fresh one (catches state leaking between iterations).
		for i := 0; i < 3; i++ {
			c.BenchIteration()
		}
		again, err := c.Digest()
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if again != got {
			t.Errorf("%s: digest drifts after repeated iterations: %q, fresh %q", id, again, got)
		}
	}
}
