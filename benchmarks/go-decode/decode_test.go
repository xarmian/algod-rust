// Package decode_test benchmarks go-algorand's msgpack block decoding using
// the same fixture files as the Rust criterion benchmarks in
// crates/core/algo-codec/benches/codec_bench.rs.
//
// Run:
//
//	go test -bench=. -benchmem -count=5
package decode_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
)

const fixtureDir = "../../crates/core/algo-codec/tests/fixtures"

// loadFixture reads a msgpack fixture file and panics on error.
func loadFixture(b *testing.B, name string) []byte {
	b.Helper()
	p := filepath.Join(fixtureDir, name)
	data, err := os.ReadFile(p)
	if err != nil {
		b.Fatalf("failed to read fixture %s: %v", p, err)
	}
	return data
}

// BenchmarkDecodeBlockResponse decodes the full REST response (block+cert)
// into rpcs.EncodedBlockCert, which mirrors the Rust
// decode_block_response benchmark.
func BenchmarkDecodeBlockResponse(b *testing.B) {
	fixtures := []struct {
		name  string
		label string
	}{
		{"block_1.msgpack", "block_1_pay"},
		{"block_6.msgpack", "block_6_appl"},
	}

	for _, f := range fixtures {
		data := loadFixture(b, f.name)
		b.Run(f.label, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var bc rpcs.EncodedBlockCert
				if err := protocol.Decode(data, &bc); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDecodeBlock decodes only the block portion (not the cert wrapper).
// We first extract the raw block bytes from the fixture, then benchmark
// decoding just the block.
func BenchmarkDecodeBlock(b *testing.B) {
	fixtures := []struct {
		name  string
		label string
	}{
		{"block_1.msgpack", "block_1_pay"},
		{"block_6.msgpack", "block_6_appl"},
	}

	for _, f := range fixtures {
		data := loadFixture(b, f.name)

		// Decode once to extract the raw block bytes via PreEncodedBlockCert.
		var pre rpcs.PreEncodedBlockCert
		if err := protocol.DecodeReflect(data, &pre); err != nil {
			b.Fatalf("failed to pre-decode %s: %v", f.name, err)
		}
		blockBytes := []byte(pre.Block)

		b.Run(f.label, func(b *testing.B) {
			b.SetBytes(int64(len(blockBytes)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var blk bookkeeping.Block
				if err := protocol.Decode(blockBytes, &blk); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
