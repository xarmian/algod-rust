// vrf-vector-capture: generate byte-exact VRF parity vectors from
// go-algorand's libsodium-fork (crypto/vrf.go).
//
// Produces a JSONL fixture consumed by the Rust VRF parity harness
// (TASK-52, blocked on this). Each line is:
//
//	{
//	  "name":   "<stable identifier>",
//	  "seed":   "<hex32>",   // 32-byte VRF seed -> VrfKeygenFromSeed
//	  "alpha":  "<hex>",     // raw VRF input (no HashID prefix)
//	  "pk":     "<hex32>",   // VrfPubkey derived from seed
//	  "sk":     "<hex64>",   // VrfPrivkey (ed25519 sk||pk)
//	  "proof":  "<hex80>",   // VRF proof from Go/libsodium-fork
//	  "output": "<hex64>"    // VRF output (proof.Hash())
//	}
//
// The corpus is composed of:
//   - Fixed edge-case seeds (zero, 0xff, 0x55, 0xaa, increasing, decreasing, …)
//     crossed with fixed alphas (empty, 1-byte 0x00/0xff, 8-byte, 32-byte,
//     64-byte, 128-byte, 512-byte, 1024-byte; zero / all-ones / patterned
//     content; IETF draft-03 TV1 and TV2 seeds as anchor points).
//   - 10,000 (seed, alpha) pairs drawn from a deterministic RNG, with alpha
//     size sampled from a realistic consensus-weighted distribution
//     (empty .. 1 KB).
//
// Determinism: math/rand.New(rand.NewSource(…)) + stable iteration order
// (named edge cases first, then random[0..N-1]). Two runs against the same
// go-algorand checkout produce identical bytes.
//
// go-algorand reference (v4.5.1-stable):
//
//	crypto/vrf.go:73-142  — VrfProof [80]byte, VrfOutput [64]byte, VrfPrivkey [64]byte
//	crypto/vrf.go:82      — VrfKeygenFromSeed
//	crypto/vrf.go:111     — VrfPrivkey.Prove(Hashable)
//	crypto/vrf.go:117     — VrfProof.Hash
//	crypto/vrf.go:122     — VrfPubkey.verifyBytes (internal)
//	crypto/util.go:38     — HashRep[H Hashable] (empty HashID => identity)
//
// Regeneration: see docs/DEV_WORKFLOW.md, "VRF vector regeneration".
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

// rawAlpha is a crypto.Hashable whose HashRep is identity: ToBeHashed returns
// an empty HashID and the raw bytes, so HashRep(rawAlpha{b}) = b. This lets
// us drive VrfPrivkey.Prove without any domain-separation prefix, mirroring
// the raw `proveBytes` path that libsodium-fork's crypto_vrf_prove takes.
type rawAlpha struct{ b []byte }

func (r rawAlpha) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.HashID(""), r.b
}

// Vector is one JSON line in the fixture file.
type Vector struct {
	Name      string `json:"name"`
	SeedHex   string `json:"seed"`
	AlphaHex  string `json:"alpha"`
	PubkeyHex string `json:"pk"`
	PrivHex   string `json:"sk"`
	ProofHex  string `json:"proof"`
	OutputHex string `json:"output"`
}

// produce runs Go/libsodium-fork's VRF for a given (seed, alpha) and returns
// the full Vector. Asserts invariants:
//   - Prove must succeed
//   - Hash(proof) must succeed
//   - Verify(proof, alpha) against the derived pk must succeed and agree with
//     the output hash (sanity check that our capture is self-consistent)
func produce(name string, seed [32]byte, alpha []byte) Vector {
	pk, sk := crypto.VrfKeygenFromSeed(seed)

	proof, ok := sk.Prove(rawAlpha{alpha})
	if !ok {
		panic(fmt.Sprintf("prove failed for %q (seed=%x alpha_len=%d)", name, seed[:], len(alpha)))
	}

	output, ok := proof.Hash()
	if !ok {
		panic(fmt.Sprintf("proof.Hash failed for %q", name))
	}

	verified, verOut := pk.Verify(proof, rawAlpha{alpha})
	if !verified {
		panic(fmt.Sprintf("self-verify failed for %q", name))
	}
	if verOut != output {
		panic(fmt.Sprintf("self-verify output mismatch for %q", name))
	}

	return Vector{
		Name:      name,
		SeedHex:   hex.EncodeToString(seed[:]),
		AlphaHex:  hex.EncodeToString(alpha),
		PubkeyHex: hex.EncodeToString(pk[:]),
		PrivHex:   hex.EncodeToString(sk[:]),
		ProofHex:  hex.EncodeToString(proof[:]),
		OutputHex: hex.EncodeToString(output[:]),
	}
}

// fixedSeeds returns a stable, deterministic set of edge-case seeds. Adding
// entries below invalidates the fixture's name-based identity; do NOT rename
// existing entries without regenerating all downstream consumers.
func fixedSeeds() []struct {
	Name string
	Seed [32]byte
} {
	out := []struct {
		Name string
		Seed [32]byte
	}{
		{Name: "seed_zero"},
		{Name: "seed_one_lsb"},
		{Name: "seed_all_ff"},
		{Name: "seed_all_55"},
		{Name: "seed_all_aa"},
		{Name: "seed_inc"},
		{Name: "seed_dec"},
		{Name: "seed_msb_only"},
		{Name: "seed_lsb_only"},
		// IETF draft-irtf-cfrg-vrf-03 test vectors — anchor points that Rust's
		// unit tests already pin against. Including them here ensures the
		// fixture corpus itself agrees with the public spec vectors.
		{Name: "seed_ietf_draft03_tv1"},
		{Name: "seed_ietf_draft03_tv2"},
	}
	out[1].Seed[0] = 0x01
	for i := range out[2].Seed {
		out[2].Seed[i] = 0xff
	}
	for i := range out[3].Seed {
		out[3].Seed[i] = 0x55
	}
	for i := range out[4].Seed {
		out[4].Seed[i] = 0xaa
	}
	for i := range out[5].Seed {
		out[5].Seed[i] = byte(i)
	}
	for i := range out[6].Seed {
		out[6].Seed[i] = byte(31 - i)
	}
	out[7].Seed[31] = 0x80
	out[8].Seed[0] = 0x80

	// TV1 / TV2 seeds, copied from Rust's unit tests (crates/core/algo-
	// consensus-crypto/src/vrf.rs test vectors).
	tv1, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	tv2, _ := hex.DecodeString("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
	copy(out[9].Seed[:], tv1)
	copy(out[10].Seed[:], tv2)

	return out
}

// fixedAlphas returns a stable set of alpha byte strings spanning empty, tiny,
// chunk-boundary, and KB-scale inputs with content patterns expected to
// exercise Elligator2 inputs (hash inputs leading to +/−1 chi branch, small-
// order points rejected, etc.) where reachable from SHA-512 outputs.
func fixedAlphas() []struct {
	Name string
	Data []byte
} {
	return []struct {
		Name string
		Data []byte
	}{
		{"alpha_empty", []byte{}},
		{"alpha_one_00", []byte{0x00}},
		{"alpha_one_ff", []byte{0xff}},
		{"alpha_one_72", []byte{0x72}}, // matches IETF draft-03 TV2 alpha
		{"alpha_8_zero", make([]byte, 8)},
		{"alpha_8_ff", bytes(0xff, 8)},
		{"alpha_32_zero", make([]byte, 32)},
		{"alpha_32_ff", bytes(0xff, 32)},
		{"alpha_32_count", increasing(32)},
		{"alpha_64_zero", make([]byte, 64)},
		{"alpha_64_ff", bytes(0xff, 64)},
		{"alpha_64_count", increasing(64)},
		{"alpha_128_zero", make([]byte, 128)},
		{"alpha_128_ff", bytes(0xff, 128)},
		{"alpha_256_count", increasing(256)},
		{"alpha_512_count", increasing(512)},
		{"alpha_1024_count", increasing(1024)},
		{"alpha_1024_alt", alternating(1024)},
	}
}

func bytes(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func increasing(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i & 0xff)
	}
	return out
}

func alternating(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		if i%2 == 0 {
			out[i] = 0x55
		} else {
			out[i] = 0xaa
		}
	}
	return out
}

// randomAlphaSizes distributes random alpha sizes roughly like Algorand's
// real consensus inputs (most small, a long tail out to 1 KB). Weights are
// integers; the cumulative sum drives a uniform draw.
var randomAlphaSizes = []struct {
	Size   int
	Weight int
}{
	{0, 2},     // 2%  empty
	{1, 5},     // 5%  one byte
	{8, 10},    // 10% short
	{32, 20},   // 20% hash-sized
	{64, 20},   // 20% 2x hash
	{128, 20},  // 20% typical consensus input
	{256, 15},  // 15%
	{512, 5},   // 5%
	{1024, 3},  // 3%  long-tail 1 KB
}

// sampleAlphaSize picks a size from randomAlphaSizes using the supplied RNG.
func sampleAlphaSize(r *rand.Rand) int {
	total := 0
	for _, s := range randomAlphaSizes {
		total += s.Weight
	}
	pick := r.Intn(total)
	for _, s := range randomAlphaSizes {
		if pick < s.Weight {
			return s.Size
		}
		pick -= s.Weight
	}
	return randomAlphaSizes[len(randomAlphaSizes)-1].Size
}

// writeJSONL streams vectors to the fixture file, one JSON object per line.
// Uses a buffered writer with a fixed line terminator to keep output
// reproducible across Go versions.
func writeJSONL(path string, vecs []Vector) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, v := range vecs {
		if err := enc.Encode(v); err != nil {
			return fmt.Errorf("encode %s: %w", v.Name, err)
		}
	}
	return w.Flush()
}

// defaultOutPath resolves the fixture file relative to this source file so
// `go run .` writes to the checked-in location regardless of CWD.
func defaultOutPath() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("..", "..", "crates", "core", "algo-consensus-crypto", "tests", "fixtures", "vrf", "vectors.jsonl")
	}
	toolDir := filepath.Dir(thisFile)
	repoRoot := filepath.Clean(filepath.Join(toolDir, "..", ".."))
	return filepath.Join(repoRoot, "crates", "core", "algo-consensus-crypto", "tests", "fixtures", "vrf", "vectors.jsonl")
}

func main() {
	out := flag.String("out", defaultOutPath(), "output JSONL path")
	randN := flag.Int("random", 10_000, "number of random (seed, alpha) vectors")
	rngSeed := flag.Int64("rng-seed", 0x5152_5354_5556_5758, "RNG seed for random-vector generation")
	flag.Parse()

	var vecs []Vector

	// Fixed edge-case vectors: every seed × every alpha (≈ 11*18 = 198).
	seeds := fixedSeeds()
	alphas := fixedAlphas()
	for _, s := range seeds {
		for _, a := range alphas {
			name := fmt.Sprintf("fixed/%s/%s", s.Name, a.Name)
			vecs = append(vecs, produce(name, s.Seed, a.Data))
		}
	}

	// Random vectors from a seeded RNG.
	r := rand.New(rand.NewSource(*rngSeed))
	for i := 0; i < *randN; i++ {
		var seed [32]byte
		if _, err := r.Read(seed[:]); err != nil {
			panic(err)
		}
		alpha := make([]byte, sampleAlphaSize(r))
		if len(alpha) > 0 {
			if _, err := r.Read(alpha); err != nil {
				panic(err)
			}
		}
		name := fmt.Sprintf("random/%06d", i)
		vecs = append(vecs, produce(name, seed, alpha))
	}

	if err := writeJSONL(*out, vecs); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d vectors to %s\n", len(vecs), *out)
}
