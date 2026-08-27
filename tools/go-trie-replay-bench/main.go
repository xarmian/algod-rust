// go-trie-replay-bench: Go counterpart to the Rust `trie_replay` perf bench
// (TASK-145 / PLAN-144). Drives go-algorand's `crypto/merkletrie` through
// the same three measured phases on the same input set as the Rust side,
// and emits a structurally-identical JSON file under
// `bench-results/trie_replay-go.json`.
//
// The `trie_bench_compare` binary (Rust, in `crates/tools/algo-bench`)
// reads both JSON files and emits a Rust↔Go ratio table to stdout +
// `docs/PERF_TRIE.md`.
//
// Phases (identical to the Rust harness):
//
//  1. apply     — N sequential trie.Add() calls on a fresh trie.
//  2. commit    — one trie.Commit() on a trie pre-populated with N elements.
//  3. cold-load — one MakeTrie() against a populated InMemoryCommitter
//     (Go's analogue of MerkleTrie::load — see trie.go:79-100,
//     the load path reads page 0 and lazy-fetches the rest).
//
// Determinism: each element is derived from a fixed-seed SHA512/256 with a
// 4-byte affinity prefix (BE u32 counter) and a 1-byte HashKind = 0,
// mirroring the layout of `AccountHashBuilderV6`. Identical bytes to the
// Rust side; the JSON `input_hash_hex` field lets the compare tool verify.
//
// Env vars:
//
//	TRIE_BENCH_N        — element count       (default 1000)
//	TRIE_BENCH_SAMPLES  — per-phase samples   (default 20)
//	TRIE_BENCH_OUT      — output JSON path    (default bench-results/trie_replay-go.json)
//
// Reproducible setup:
//
// The `replace` directive in `go.mod` resolves to `../../../go-algorand`
// relative to this tool's directory, which is the parent of the
// `algod-rust` repo root. From a fresh clone of `algod-rust`:
//
//  1. Check out go-algorand v4.7.3-stable as a sibling of `algod-rust`.
//  2. From this tool's directory: `go run .`
package main

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/algorand/go-algorand/crypto/merkletrie"
)

const (
	elementSize       = 36
	nodesCountPerPage = 116 // matches ledger/store/trackerdb/catchpoint.go:42
)

// memoryConfig is the production-flavoured cache config — same shape used
// by `merkle-trie-root-capture`.
var memoryConfig = merkletrie.MemoryConfig{
	NodesCountPerPage:         nodesCountPerPage,
	CachedNodesCount:          9000,
	PageFillFactor:            0.95,
	MaxChildrenPagesThreshold: 64,
}

func envInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %s=%q is not an int, using default %d\n", name, v, def)
		return def
	}
	return n
}

func envStr(name, def string) string {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	return v
}

// makeElement is byte-for-byte identical to
// `tools/merkle-trie-root-capture/main.go::makeElement` and to the Rust
// `algo_bench::trie_replay::make_element`.
func makeElement(affinity uint32, seed []byte) [elementSize]byte {
	h := sha512.Sum512_256(seed)
	var e [elementSize]byte
	binary.BigEndian.PutUint32(e[0:4], affinity)
	e[4] = 0
	copy(e[5:36], h[1:32])
	return e
}

// makeElementSeq builds the same N-element sequence as the Rust harness.
func makeElementSeq(n int) [][elementSize]byte {
	out := make([][elementSize]byte, n)
	for i := 0; i < n; i++ {
		seed := []byte{byte(i & 0xff), byte((i >> 8) & 0xff), byte((i >> 16) & 0xff), byte((i >> 24) & 0xff)}
		out[i] = makeElement(uint32(i), seed)
	}
	return out
}

// hashInputSet returns the SHA512/256 of the concatenated element bytes.
// Matches `algo_bench::trie_replay::hash_input_set`.
func hashInputSet(elements [][elementSize]byte) string {
	h := sha512.New512_256()
	for i := range elements {
		h.Write(elements[i][:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// runApplyPhase: time only the Add() loop. Fresh trie per sample.
func runApplyPhase(elements [][elementSize]byte, samples int) []time.Duration {
	out := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		var committer merkletrie.InMemoryCommitter
		trie, err := merkletrie.MakeTrie(&committer, memoryConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "MakeTrie: %v\n", err)
			os.Exit(1)
		}
		start := time.Now()
		for j := range elements {
			added, err := trie.Add(elements[j][:])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Add[%d]: %v\n", j, err)
				os.Exit(1)
			}
			if !added {
				fmt.Fprintf(os.Stderr, "Add[%d]: unexpected duplicate\n", j)
				os.Exit(1)
			}
		}
		out = append(out, time.Since(start))
	}
	return out
}

// runCommitPhase: populate trie out of the measured region, then time
// exactly the Commit() call.
func runCommitPhase(elements [][elementSize]byte, samples int) []time.Duration {
	out := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		var committer merkletrie.InMemoryCommitter
		trie, err := merkletrie.MakeTrie(&committer, memoryConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "MakeTrie: %v\n", err)
			os.Exit(1)
		}
		for j := range elements {
			if _, err := trie.Add(elements[j][:]); err != nil {
				fmt.Fprintf(os.Stderr, "Add[%d]: %v\n", j, err)
				os.Exit(1)
			}
		}
		start := time.Now()
		if _, err := trie.Commit(); err != nil {
			fmt.Fprintf(os.Stderr, "Commit: %v\n", err)
			os.Exit(1)
		}
		out = append(out, time.Since(start))
	}
	return out
}

// runColdLoadPhase: build a populated committer (out of the measured
// region), then time exactly the MakeTrie(committer, ...) "load" path.
//
// Go's `MakeTrie` is the load entry point — see trie.go:79-100; it reads
// page 0 (the metadata) and reconstructs trie state from the committer.
// This is the analog of Rust's `MerkleTrie::load`.
func runColdLoadPhase(elements [][elementSize]byte, samples int) []time.Duration {
	out := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		var committer merkletrie.InMemoryCommitter
		{
			trie, err := merkletrie.MakeTrie(&committer, memoryConfig)
			if err != nil {
				fmt.Fprintf(os.Stderr, "MakeTrie: %v\n", err)
				os.Exit(1)
			}
			for j := range elements {
				if _, err := trie.Add(elements[j][:]); err != nil {
					fmt.Fprintf(os.Stderr, "Add[%d]: %v\n", j, err)
					os.Exit(1)
				}
			}
			if _, err := trie.Commit(); err != nil {
				fmt.Fprintf(os.Stderr, "Commit: %v\n", err)
				os.Exit(1)
			}
		}
		start := time.Now()
		restored, err := merkletrie.MakeTrie(&committer, memoryConfig)
		elapsed := time.Since(start)
		if err != nil {
			fmt.Fprintf(os.Stderr, "MakeTrie (load): %v\n", err)
			os.Exit(1)
		}
		// Touch a load-time observable so the optimizer doesn't dead-code it.
		_ = restored
		out = append(out, elapsed)
	}
	return out
}

// phaseStats — JSON shape MUST match the Rust `PhaseStats`.
type phaseStats struct {
	Phase     string  `json:"phase"`
	MedianNs  uint64  `json:"median_ns"`
	P99Ns     uint64  `json:"p99_ns"`
	MeanNs    uint64  `json:"mean_ns"`
	TotalMs   float64 `json:"total_ms"`
	NSamples  int     `json:"n_samples"`
	NElements int     `json:"n_elements"`
}

// trieReplayResult — JSON shape MUST match the Rust `TrieReplayResult`.
type trieReplayResult struct {
	Implementation string       `json:"implementation"`
	NElements      int          `json:"n_elements"`
	InputHashHex   string       `json:"input_hash_hex"`
	Phases         []phaseStats `json:"phases"`
}

// percentileNs is linear-interpolation percentile on a sorted slice of
// nanosecond values. Matches the Rust implementation byte-for-byte
// (algorithmically); reductions on identical inputs produce identical
// outputs.
func percentileNs(sorted []uint64, p float64) uint64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	rank := p * float64(len(sorted)-1)
	lo := int(rank)
	hi := lo
	if float64(lo) < rank {
		hi = lo + 1
	}
	if lo == hi {
		return sorted[lo]
	}
	loV := float64(sorted[lo])
	hiV := float64(sorted[hi])
	frac := rank - float64(lo)
	return uint64(loV + frac*(hiV-loV) + 0.5)
}

func statsFromDurations(phase string, nElements int, samples []time.Duration) phaseStats {
	if len(samples) == 0 {
		return phaseStats{Phase: phase, NElements: nElements}
	}
	ns := make([]uint64, len(samples))
	var total uint64
	for i, d := range samples {
		ns[i] = uint64(d.Nanoseconds())
		total += ns[i]
	}
	sort.Slice(ns, func(i, j int) bool { return ns[i] < ns[j] })
	mean := total / uint64(len(samples))
	median := percentileNs(ns, 0.50)
	p99 := percentileNs(ns, 0.99)
	totalMs := float64(total) / 1_000_000.0
	return phaseStats{
		Phase:     phase,
		MedianNs:  median,
		P99Ns:     p99,
		MeanNs:    mean,
		TotalMs:   totalMs,
		NSamples:  len(samples),
		NElements: nElements,
	}
}

func main() {
	n := envInt("TRIE_BENCH_N", 1000)
	samples := envInt("TRIE_BENCH_SAMPLES", 20)
	outPath := envStr("TRIE_BENCH_OUT", "bench-results/trie_replay-go.json")

	elements := makeElementSeq(n)
	inputHash := hashInputSet(elements)

	// Warm-up — one full apply pass — primes the allocator and L2/L3.
	{
		var committer merkletrie.InMemoryCommitter
		trie, err := merkletrie.MakeTrie(&committer, memoryConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warm-up MakeTrie: %v\n", err)
			os.Exit(1)
		}
		for j := range elements {
			if _, err := trie.Add(elements[j][:]); err != nil {
				fmt.Fprintf(os.Stderr, "warm-up Add: %v\n", err)
				os.Exit(1)
			}
		}
	}

	applyDurs := runApplyPhase(elements, samples)
	commitDurs := runCommitPhase(elements, samples)
	loadDurs := runColdLoadPhase(elements, samples)

	result := trieReplayResult{
		Implementation: "go",
		NElements:      n,
		InputHashHex:   inputHash,
		Phases: []phaseStats{
			statsFromDurations("apply", n, applyDurs),
			statsFromDurations("commit", n, commitDurs),
			statsFromDurations("cold-load", n, loadDurs),
		},
	}

	if dir := filepath.Dir(outPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "mkdir %s: %v\n", dir, err)
			os.Exit(1)
		}
	}
	f, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create %s: %v\n", outPath, err)
		os.Exit(1)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "encode JSON: %v\n", err)
		os.Exit(1)
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close %s: %v\n", outPath, err)
		os.Exit(1)
	}

	// Summary to stderr (so > redirect of stdout stays clean if anyone
	// pipes the JSON to another tool).
	fmt.Fprintf(os.Stderr, "trie_replay (go): n_elements=%d input_hash=%s\n", n, inputHash)
	for _, p := range result.Phases {
		fmt.Fprintf(os.Stderr,
			"  phase=%-10s samples=%3d  median=%10d ns  p99=%10d ns  mean=%10d ns  total=%9.2f ms\n",
			p.Phase, p.NSamples, p.MedianNs, p.P99Ns, p.MeanNs, p.TotalMs)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", outPath)
}
