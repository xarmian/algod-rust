// merkle-trie-root-capture: emit Go-computed merkletrie root hashes for
// deterministic input element sets, as JSON fixtures consumed by the Rust
// trie conformance test in
// `crates/core/algo-ledger/tests/merkle_trie_conformance_test.rs`.
//
// Output schema:
//
//	[
//	  {
//	    "name": "5-account-trie",
//	    "element_count": 5,
//	    "element_size": 36,
//	    "elements_hex": ["...", "..."],
//	    "root_hex": "..."
//	  },
//	  ...
//	]
//
// References (go-algorand v4.5.1-stable):
//
//	crypto/merkletrie/trie.go:62-170     — Trie, MakeTrie, Add, RootHash
//	crypto/merkletrie/node.go:227-252    — node.calculateHash (hash accumulator)
//	crypto/merkletrie/cache.go           — merkleTrieCache (in-memory committer)
//	ledger/store/trackerdb/hashing.go:64 — AccountHashBuilderV6 (36-byte format)
//
// Reproducible setup:
//
// The `replace` directive in `go.mod` resolves to `../../../go-algorand`
// relative to this tool's directory, which is the parent of the
// `algod-rust` repo root. From a fresh `git clone` of `algod-rust`:
//
//  1. Check out go-algorand as a sibling of `algod-rust`:
//
//         # from $REPO_PARENT (the directory that contains algod-rust/)
//         git clone --depth 1 --branch v4.5.1-stable \
//             https://github.com/algorand/go-algorand.git
//
//  2. Build and run from this tool's directory:
//
//         cd algod-rust/tools/merkle-trie-root-capture
//         go run . > \
//             ../../crates/core/algo-ledger/tests/fixtures/merkle_trie_roots/roots.json
//
// Determinism: each element is derived from a fixed-seed SHA512/256 with a
// 4-byte affinity prefix (BE u32 counter) and a 1-byte HashKind = 0, mirroring
// the layout of `AccountHashBuilderV6`. The byte content is reproducible.
//
// Scenarios captured:
//
//   - "single-element": exercises the single-leaf-root invariant
//     (RootHash = SHA512/256(0x00 || full_element)).
//   - "two-element-split": exercises the leaf-split path with a chain-of-one
//     ancestor (shared prefix = 0 byte → no ancestors; differs only in byte 0).
//   - "two-element-shared-byte": shared prefix = 1 byte → forces one chain
//     ancestor between the root and the branch node.
//   - "5-account-trie": the TASK-134 deliverable. Five 36-byte elements with
//     mixed shared prefixes, exercising both leaf-remainder storage and
//     ancestor-chain construction.
//   - "100-account-trie": TASK-138 deliverable. 100 elements (fits on one
//     production page since NODES_PER_PAGE = 116) but with non-trivial
//     internal-node depth and fanout.
//   - "1000-account-trie": TASK-138 deliverable. 1000 elements, exercises
//     commit splitting across multiple pages and the full hash-accumulator
//     + recompute path on a deep tree. This is the consensus-critical
//     close-out gate for PLAN-130.
//
// Each scenario emits the input element list (so the Rust test can replay
// the inserts) and the Go-computed root hash (the ground truth).
package main

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/algorand/go-algorand/crypto/merkletrie"
)

const (
	elementSize       = 36
	nodesCountPerPage = 116 // ledger/store/trackerdb/catchpoint.go:42
)

type fixture struct {
	Name         string   `json:"name"`
	ElementCount int      `json:"element_count"`
	ElementSize  int      `json:"element_size"`
	ElementsHex  []string `json:"elements_hex"`
	RootHex      string   `json:"root_hex"`
}

// makeElement constructs a deterministic 36-byte trie element in the
// AccountHashBuilderV6 layout (affinity[4] || kind[1] || hash[1..32]),
// using SHA512/256 over the supplied seed bytes.
//
// `affinity` populates bytes 0..4 (BE u32); `seed` is fed into SHA512/256
// to fill bytes 5..36. `kind` byte is fixed at 0 (Account).
func makeElement(affinity uint32, seed []byte) [elementSize]byte {
	// SHA512/256 of seed; take bytes [1..32] to mirror finishV6 in
	// hashing.go:130-135 (`copy(v6hash[5:], entryHash[1:])`).
	h := sha512.Sum512_256(seed)

	var e [elementSize]byte
	binary.BigEndian.PutUint32(e[0:4], affinity)
	e[4] = 0 // HashKind::Account
	copy(e[5:36], h[1:32])
	return e
}

// makeElementSeq builds N deterministic elements with `affinity = i` and
// seed = [byte(i), byte(i>>8), byte(i>>16), byte(i>>24)] for i in [0, N).
// This is the same pattern merkle-page-capture uses, just framed into the
// 36-byte AccountHashBuilderV6 layout.
func makeElementSeq(n int) [][elementSize]byte {
	out := make([][elementSize]byte, n)
	for i := 0; i < n; i++ {
		seed := []byte{byte(i & 0xff), byte((i >> 8) & 0xff), byte((i >> 16) & 0xff), byte((i >> 24) & 0xff)}
		out[i] = makeElement(uint32(i), seed)
	}
	return out
}

// computeRoot builds a Go merkletrie from the supplied elements and returns
// its 32-byte root hash. Uses the InMemoryCommitter (default when no
// committer is passed to MakeTrie — see trie.go:86-87).
func computeRoot(elements [][elementSize]byte) ([32]byte, error) {
	memoryConfig := merkletrie.MemoryConfig{
		NodesCountPerPage:         nodesCountPerPage,
		CachedNodesCount:          9000,
		PageFillFactor:            0.95,
		MaxChildrenPagesThreshold: 64,
	}
	trie, err := merkletrie.MakeTrie(nil, memoryConfig)
	if err != nil {
		return [32]byte{}, fmt.Errorf("MakeTrie: %w", err)
	}
	for i, e := range elements {
		added, err := trie.Add(e[:])
		if err != nil {
			return [32]byte{}, fmt.Errorf("trie.Add[%d]: %w", i, err)
		}
		if !added {
			return [32]byte{}, fmt.Errorf("trie.Add[%d]: unexpected duplicate", i)
		}
	}
	root, err := trie.RootHash()
	if err != nil {
		return [32]byte{}, fmt.Errorf("trie.RootHash: %w", err)
	}
	return root, nil
}

// hexElements maps a slice of fixed-size elements to their hex strings.
func hexElements(elements [][elementSize]byte) []string {
	out := make([]string, len(elements))
	for i, e := range elements {
		out[i] = hex.EncodeToString(e[:])
	}
	return out
}

// twoElementsSharingFirstByte forces a shared prefix of exactly one byte
// (one chain ancestor between the root and the branch node).
//
// We pin both elements to identical bytes 0..N (affinity prefix included)
// and force them to diverge at a specific later byte by overwriting byte 5
// (the first byte of the hash region).
func twoElementsSharingFirstByte() [][elementSize]byte {
	a := makeElement(0xAABBCCDD, []byte{1})
	b := a // copy
	// Differ at byte 5 only — element A keeps its computed byte 5, element
	// B gets a different one. Bytes 0..5 are identical.
	if a[5] == 0xFF {
		b[5] = 0x00
	} else {
		b[5] = 0xFF
	}
	return [][elementSize]byte{a, b}
}

// twoElementsDifferingFirstByte produces two elements that diverge at byte 0
// (no shared prefix → root is the branch node directly, no chain ancestor).
func twoElementsDifferingFirstByte() [][elementSize]byte {
	a := makeElement(0x00000000, []byte{1})
	b := makeElement(0xFFFFFFFF, []byte{2})
	// Bytes 0..3 will differ (affinity differs), so the first divergence is
	// at byte 0. That's exactly what we want.
	return [][elementSize]byte{a, b}
}

func main() {
	scenarios := []struct {
		name        string
		elements    [][elementSize]byte
		description string
	}{
		{
			name:        "single-element",
			elements:    makeElementSeq(1),
			description: "single-leaf root invariant: RootHash = SHA512/256(0x00 || element)",
		},
		{
			name:        "two-element-split-byte-0",
			elements:    twoElementsDifferingFirstByte(),
			description: "no shared prefix → root is branch node directly, no chain ancestor",
		},
		{
			name:        "two-element-shared-byte-0..4",
			elements:    twoElementsSharingFirstByte(),
			description: "shared prefix = 5 bytes (affinity+kind) → five chain ancestors above the branch node",
		},
		{
			name:        "5-account-trie",
			elements:    makeElementSeq(5),
			description: "TASK-134 deliverable: 5 elements with mixed prefixes, exercises leaf-remainder + ancestor chain",
		},
		{
			name:        "100-account-trie",
			elements:    makeElementSeq(100),
			description: "TASK-138 deliverable: 100 elements — exercises tree depth, multiple internal-node fanouts, persistence packing across more than one page (NODES_PER_PAGE = 116, so 100 elements fits on one page but produces tree shape with depth > 2)",
		},
		{
			name:        "1000-account-trie",
			elements:    makeElementSeq(1000),
			description: "TASK-138 deliverable: 1000 elements — full large-N scenario. Exercises commit splitting across multiple pages, deep ancestor chains, and the hash-accumulator + recompute path on a non-trivial tree. This is the consensus-critical close-out gate for PLAN-130",
		},
	}

	var out []fixture
	for _, sc := range scenarios {
		root, err := computeRoot(sc.elements)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scenario %q: %v\n", sc.name, err)
			os.Exit(1)
		}
		out = append(out, fixture{
			Name:         sc.name,
			ElementCount: len(sc.elements),
			ElementSize:  elementSize,
			ElementsHex:  hexElements(sc.elements),
			RootHex:      hex.EncodeToString(root[:]),
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "JSON encode failed: %v\n", err)
		os.Exit(1)
	}
}
