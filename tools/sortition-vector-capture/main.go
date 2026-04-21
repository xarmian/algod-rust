// sortition-vector-capture: generate Algorand sortition parity vectors by
// driving the external `github.com/algorand/sortition` module (a CGo
// wrapper over Boost 1.65.1's binomial distribution CDF).
//
// The vectors are consumed by the Rust parity harness at
// `crates/core/algo-consensus-crypto/tests/sortition_parity.rs`. Any
// divergence between Rust's `statrs::Binomial`-based CDF walk and Go's
// Boost-backed walk at precision-boundary money values means committee-
// selection disagreement and a fork risk — so parity is byte-exact and
// the corpus deliberately stresses the boundaries rather than the common
// case.
//
// JSONL schema (one record per line):
//
//	{
//	  "name":            "fixed/<seed_name>/<params_name>",
//	  "money":           1234,        // uint64 as JSON number (fits in f64 < 2^53 or encoded as string when larger)
//	  "money_hex":       "0x…",       // 16-hex-char big-endian u64 — unambiguous across JSON encodings
//	  "total_money":     1_000_000,
//	  "total_money_hex": "0x…",
//	  "expected_size":   20.0,
//	  "digest":          "<hex64>",   // 32-byte VRF-output stand-in
//	  "weight":          42
//	}
//
// We emit both the decimal and hex forms of the u64 fields because some
// JSON parsers silently truncate integers above 2^53 to the nearest f64.
// The Rust consumer should use the `_hex` variant to be safe.
//
// Pinning: `go.sum` pins `github.com/algorand/sortition` to exactly
// v1.0.0; a version mismatch breaks module resolution at build time, so
// there's no runtime pin check here (unlike the VRF tool, which links
// against a locally-vendored libsodium-fork through a `replace`
// directive).
//
// Regeneration: see docs/DEV_WORKFLOW.md → "Sortition Vector Regeneration".
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"

	"github.com/algorand/sortition"
)

// Vector is one JSONL record.
type Vector struct {
	Name          string  `json:"name"`
	Money         uint64  `json:"money"`
	MoneyHex      string  `json:"money_hex"`
	TotalMoney    uint64  `json:"total_money"`
	TotalMoneyHex string  `json:"total_money_hex"`
	ExpectedSize  float64 `json:"expected_size"`
	Digest        string  `json:"digest"`
	Weight        uint64  `json:"weight"`
}

// produce drives a single sortition.Select call and returns the vector.
// Never panics on degenerate inputs — a zero-money or zero-total-money
// call just returns weight 0, same as Go's production path. (Rust's
// `select` matches this and returns 0 for the same cases.)
func produce(name string, money, totalMoney uint64, expected float64, digest [32]byte) Vector {
	weight := sortition.Select(money, totalMoney, expected, sortition.Digest(digest))
	return Vector{
		Name:          name,
		Money:         money,
		MoneyHex:      fmt.Sprintf("0x%016x", money),
		TotalMoney:    totalMoney,
		TotalMoneyHex: fmt.Sprintf("0x%016x", totalMoney),
		ExpectedSize:  expected,
		Digest:        hex.EncodeToString(digest[:]),
		Weight:        weight,
	}
}

// digestAt builds a 32-byte digest where the first byte is `first` and the
// rest is `fill` — a compact way to target precise ratio values (a digest
// of {0x80, 0x00…} gives ratio ≈ 0.5, {0xC0, 0x00…} ≈ 0.75, etc.).
func digestAt(first, fill byte) [32]byte {
	var d [32]byte
	d[0] = first
	for i := 1; i < len(d); i++ {
		d[i] = fill
	}
	return d
}

// fixedDigests returns a stable set of digest patterns chosen to hit
// specific ratio thresholds along the CDF. Naming is stable; reorder only
// by appending.
func fixedDigests() []struct {
	Name   string
	Digest [32]byte
} {
	return []struct {
		Name   string
		Digest [32]byte
	}{
		{"digest_zero", digestAt(0x00, 0x00)},       // ratio = 0
		{"digest_half", digestAt(0x80, 0x00)},       // ratio ≈ 0.5
		{"digest_quarter", digestAt(0x40, 0x00)},    // ratio ≈ 0.25
		{"digest_three_quarters", digestAt(0xC0, 0x00)}, // ratio ≈ 0.75
		{"digest_near_one", digestAt(0xFF, 0xFE)},   // ratio ≈ 1 - 2^-255
		{"digest_max", digestAt(0xFF, 0xFF)},        // ratio = 1
		{"digest_low", digestAt(0x00, 0x01)},        // ratio ≈ 2^-248
		{"digest_count_up", digestCountUp()},
		{"digest_count_down", digestCountDown()},
	}
}

func digestCountUp() [32]byte {
	var d [32]byte
	for i := range d {
		d[i] = byte(i)
	}
	return d
}

func digestCountDown() [32]byte {
	var d [32]byte
	for i := range d {
		d[i] = byte(31 - i)
	}
	return d
}

// fixedParams enumerates (money, total_money, expected_size) triples
// covering the precision-boundary cases the task calls out:
//
//   - boundary money values: 0, 1, small (<100), 2^32, 2^48, 2^60, 2^62
//   - degenerate cases: money == 0, money == total_money, money == total_money - 1
//   - expected sizes: 1, 20 (soft), 1500 (cert-like), 2990 (agreement soft),
//     10000 (stress)
//
// Names are stable identifiers.
func fixedParams() []struct {
	Name         string
	Money        uint64
	TotalMoney   uint64
	ExpectedSize float64
} {
	const (
		p32 = uint64(1) << 32
		p48 = uint64(1) << 48
		p60 = uint64(1) << 60
		p62 = uint64(1) << 62
	)
	return []struct {
		Name         string
		Money        uint64
		TotalMoney   uint64
		ExpectedSize float64
	}{
		// Zero-money (weight must always be 0). Rust and Go both
		// short-circuit before touching the CDF.
		{"money_zero_total_1e6_exp20", 0, 1_000_000, 20},

		// NOTE: total_money == 0 is intentionally excluded from the
		// corpus. Boost's binomial constructor aborts the process with
		// "Success fraction argument is inf" when `expected_size/0`
		// feeds in, whereas Rust's `select` guards zero-denom and
		// returns 0. The go-algorand code path never invokes sortition
		// with a zero total (credential verification rejects zero-stake
		// upstream), so the divergence isn't reachable in practice and
		// capturing a fixture against an abort path has no meaning.

		// Tiny money values at realistic consensus sizes.
		{"money_1_total_1e6_exp1", 1, 1_000_000, 1},
		{"money_1_total_1e6_exp20", 1, 1_000_000, 20},
		{"money_1_total_1e9_exp20", 1, 1_000_000_000, 20},
		{"money_99_total_1e6_exp20", 99, 1_000_000, 20},

		// Power-of-two money boundaries at a fixed large-total baseline.
		{"money_p32_total_p62_exp20", p32, p62, 20},
		{"money_p48_total_p62_exp20", p48, p62, 20},
		{"money_p60_total_p62_exp20", p60, p62, 20},
		{"money_p62_total_p62_exp20", p62, p62, 20},

		// User owns everything (money == total_money).
		{"money_eq_total_1e6_exp20", 1_000_000, 1_000_000, 20},
		{"money_eq_total_p60_exp20", p60, p60, 20},

		// User owns (total - 1) — the "one else exists" case.
		{"money_tminus1_1e6_exp20", 999_999, 1_000_000, 20},

		// Expected-size scan at a moderate money/total.
		{"money_1e5_total_1e6_exp1", 100_000, 1_000_000, 1},
		{"money_1e5_total_1e6_exp20", 100_000, 1_000_000, 20},
		{"money_1e5_total_1e6_exp1500", 100_000, 1_000_000, 1500},
		{"money_1e5_total_1e6_exp2990", 100_000, 1_000_000, 2990},
		{"money_1e5_total_1e6_exp10000", 100_000, 1_000_000, 10000},

		// Precision-stress ≥200 vectors generated below — not fixed here;
		// we contribute a few explicit anchors:
		{"money_p59_total_p62_exp20", uint64(1) << 59, p62, 20},
		{"money_p60_plus_1_total_p62_exp20", (uint64(1) << 60) + 1, p62, 20},
		{"money_p61_total_p62_exp20", uint64(1) << 61, p62, 20},
		{"money_p61_minus_1_total_p62_exp20", (uint64(1) << 61) - 1, p62, 20},
	}
}

// precisionStressVectors emits `n` (money, total_money, expected_size,
// digest) tuples with `money ∈ [2^59, 2^61]` and `total_money` in the
// neighborhood of 2^62 — the region where Boost's multiprecision path
// and Rust's BigUint→f64 conversion are most likely to diverge. Each
// tuple is named `precision/%06d`.
func precisionStressVectors(n int, rng *rand.Rand) []Vector {
	out := make([]Vector, 0, n)
	for i := 0; i < n; i++ {
		// Draw money uniformly in [2^59, 2^61].
		const (
			lo = uint64(1) << 59
			hi = uint64(1) << 61
		)
		money := lo + rng.Uint64()%(hi-lo+1)
		// Total money slightly above money, capped at 2^62.
		total := money + rng.Uint64()%(uint64(1)<<60)
		if total < money {
			total = money
		}
		const p62 = uint64(1) << 62
		if total > p62 {
			total = p62
		}
		expected := float64(1 + rng.Intn(2000)) // 1..2000
		var d [32]byte
		_, _ = rng.Read(d[:])
		name := fmt.Sprintf("precision/%06d", i)
		out = append(out, produce(name, money, total, expected, d))
	}
	return out
}

// randomVectors emits `n` plausible-but-unbiased sortition calls from a
// seeded RNG. Unlike precisionStressVectors these don't cluster near the
// precision boundary; they just fill out the space.
func randomVectors(n int, rng *rand.Rand) []Vector {
	out := make([]Vector, 0, n)
	for i := 0; i < n; i++ {
		// total_money in [1e6, 1e12] with a log-uniform flavor so we
		// sample realistic Algorand mainnet magnitudes as well as small
		// local-net-style stakes.
		totalLog := 6.0 + rng.Float64()*6.0
		total := uint64(math.Pow(10, totalLog))
		if total == 0 {
			total = 1
		}
		// money is a random fraction of total.
		money := uint64(float64(total) * rng.Float64())
		// expected_size drawn in [1, 3000].
		expected := float64(1 + rng.Intn(3000))
		var d [32]byte
		_, _ = rng.Read(d[:])
		name := fmt.Sprintf("random/%06d", i)
		out = append(out, produce(name, money, total, expected, d))
	}
	return out
}

// writeJSONL writes vectors one per line, no HTML escaping (so "<>&" stay
// literal in any future digest strings).
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

func defaultOutPath() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("..", "..", "crates", "core", "algo-consensus-crypto", "tests", "fixtures", "sortition", "vectors.jsonl")
	}
	toolDir := filepath.Dir(thisFile)
	repoRoot := filepath.Clean(filepath.Join(toolDir, "..", ".."))
	return filepath.Join(repoRoot, "crates", "core", "algo-consensus-crypto", "tests", "fixtures", "sortition", "vectors.jsonl")
}

func main() {
	out := flag.String("out", defaultOutPath(), "output JSONL path")
	randN := flag.Int("random", 4_500, "number of unbiased random vectors")
	precN := flag.Int("precision", 500, "number of precision-stress vectors (money ∈ [2^59, 2^61])")
	rngSeed := flag.Int64("rng-seed", 0x536f_7274_6974_696e, "RNG seed for random-vector generation")
	flag.Parse()

	var vecs []Vector

	// Fixed matrix: digests × params.
	digests := fixedDigests()
	params := fixedParams()
	for _, p := range params {
		for _, d := range digests {
			name := fmt.Sprintf("fixed/%s/%s", p.Name, d.Name)
			vecs = append(vecs, produce(name, p.Money, p.TotalMoney, p.ExpectedSize, d.Digest))
		}
	}

	r := rand.New(rand.NewSource(*rngSeed))
	vecs = append(vecs, precisionStressVectors(*precN, r)...)
	vecs = append(vecs, randomVectors(*randN, r)...)

	if err := writeJSONL(*out, vecs); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d sortition vectors to %s\n", len(vecs), *out)
}
