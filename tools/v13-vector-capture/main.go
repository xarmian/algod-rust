// v13-vector-capture: generate sha512 + sumhash512 opcode parity vectors.
//
// Produces JSON fixture files consumed by the Rust AVM parity tests:
//   crates/core/algo-avm/tests/fixtures/v13/sha512/vectors.json
//   crates/core/algo-avm/tests/fixtures/v13/sumhash512/vectors.json
//
// Each fixture is an array of {name, input_hex, output_hex} entries covering:
//   - empty input
//   - 1, 63, 64 (chunk boundary), 65 bytes
//   - 128, 1KB, 4KB, 1MB
//   - several random inputs of varied sizes (seeded RNG for reproducibility)
//
// This uses the same primitives as go-algorand's opSHA512 / opSumhash512:
//   - crypto/sha512.Sum512
//   - github.com/algorand/go-sumhash.New512(nil)
//
// References (go-algorand v4.5.1-stable):
//   data/transactions/logic/crypto.go:120 — opSumhash512
//   data/transactions/logic/crypto.go:128 — opSHA512
//
// Regeneration: see docs/DEV_WORKFLOW.md, "V13 vector regeneration".
package main

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"

	sumhash "github.com/algorand/go-sumhash"
)

type Vector struct {
	Name      string `json:"name"`
	InputHex  string `json:"input_hex"`
	OutputHex string `json:"output_hex"`
}

// deterministicBytes returns n pseudo-random bytes seeded by `seed`.
// Using a fixed-seed math/rand source ensures the fixture is reproducible.
func deterministicBytes(seed int64, n int) []byte {
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	_, _ = r.Read(b)
	return b
}

// inputs returns the canonical set of test inputs, shared between sha512 and
// sumhash512. Names are stable identifiers; do not rename without regenerating.
func inputs() []struct {
	Name string
	Data []byte
} {
	return []struct {
		Name string
		Data []byte
	}{
		{"empty", []byte{}},
		{"one_byte_00", []byte{0x00}},
		{"one_byte_ff", []byte{0xff}},
		{"bytes_63", deterministicBytes(1, 63)},
		{"bytes_64_chunk_boundary", deterministicBytes(2, 64)},
		{"bytes_65", deterministicBytes(3, 65)},
		{"bytes_127", deterministicBytes(4, 127)},
		{"bytes_128_chunk_boundary", deterministicBytes(5, 128)},
		{"bytes_129", deterministicBytes(6, 129)},
		{"bytes_256", deterministicBytes(7, 256)},
		{"bytes_512", deterministicBytes(8, 512)},
		{"bytes_1023", deterministicBytes(9, 1023)},
		{"bytes_1024_1kb", deterministicBytes(10, 1024)},
		{"bytes_1025", deterministicBytes(11, 1025)},
		{"bytes_4096_4kb", deterministicBytes(12, 4096)},
		{"bytes_16384_16kb", deterministicBytes(13, 16384)},
		{"bytes_65536_64kb", deterministicBytes(14, 65536)},
		{"bytes_262144_256kb", deterministicBytes(15, 262144)},
		{"bytes_1048576_1mb", deterministicBytes(16, 1024*1024)},
		// All-zero input of a few sizes — simple boundary for sumhash.
		{"zeros_64", make([]byte, 64)},
		{"zeros_128", make([]byte, 128)},
		{"ascii_short", []byte("the quick brown fox jumps over the lazy dog")},
		{"ascii_empty_string_padding", []byte("")},
	}
}

func sha512Vectors() []Vector {
	out := make([]Vector, 0, 32)
	for _, in := range inputs() {
		h := sha512.Sum512(in.Data)
		out = append(out, Vector{
			Name:      in.Name,
			InputHex:  hex.EncodeToString(in.Data),
			OutputHex: hex.EncodeToString(h[:]),
		})
	}
	return out
}

func sumhash512Vectors() []Vector {
	out := make([]Vector, 0, 32)
	for _, in := range inputs() {
		h := sumhash.New512(nil)
		h.Write(in.Data)
		sum := h.Sum(nil)
		out = append(out, Vector{
			Name:      in.Name,
			InputHex:  hex.EncodeToString(in.Data),
			OutputHex: hex.EncodeToString(sum),
		})
	}
	return out
}

func writeVectors(path string, vectors []Vector) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	data, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	// Trailing newline for POSIX friendliness.
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func main() {
	outDir := flag.String("out", "crates/core/algo-avm/tests/fixtures/v13", "output base directory")
	flag.Parse()

	sha512Path := filepath.Join(*outDir, "sha512", "vectors.json")
	sumhashPath := filepath.Join(*outDir, "sumhash512", "vectors.json")

	if err := writeVectors(sha512Path, sha512Vectors()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s\n", sha512Path)

	if err := writeVectors(sumhashPath, sumhash512Vectors()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s\n", sumhashPath)
}
