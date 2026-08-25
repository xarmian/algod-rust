// lookback-vector-capture: produce (version, round, params_round,
// balance_round, seed_round) parity vectors from go-algorand so the
// Rust integration test in
// `crates/core/algo-agreement/tests/lookback_boundary.rs` anchors
// against Go as the source of truth rather than re-deriving the
// expected values from our own consensus-params table.
//
// The three lookback primitives under test are trivially short
// formulas individually — but they're called at every vote-
// verification, so any silent drift between Rust's and Go's
// implementation (or between Rust's ConsensusParams table and Go's)
// causes committee-selection divergence during upgrades. This tool
// captures the exact Go output at every consensus version and every
// boundary round, so the Rust test's pass/fail signal is "Rust
// agrees with the captured Go bytes" — not "Rust agrees with what we
// thought Go would say".
//
// go-algorand references (v4.6.0-stable):
//
//	agreement/params.go:25    — func ParamsRound(r basics.Round) basics.Round
//	agreement/selector.go:53  — func BalanceRound(r basics.Round, cparams config.ConsensusParams) basics.Round
//	agreement/selector.go:59  — func BalanceLookback(cparams config.ConsensusParams) basics.Round
//	                              (= 2 * SeedRefreshInterval * SeedLookback)
//	agreement/selector.go:63  — func seedRound(r basics.Round, cparams config.ConsensusParams) basics.Round
//	                              (= r.SubSaturate(basics.Round(cparams.SeedLookback)))
//	                              unexported — replicated verbatim below
//	data/basics/units.go:150  — func (round Round) SubSaturate(x Round) Round
//	config/consensus.go:870   — only historical change: v8.SeedRefreshInterval = 80 (v7 default: 100)
//
// Output: a single pretty-printed JSON file
// `crates/core/algo-agreement/tests/fixtures/lookback/lookback_boundaries.json`
// with schema:
//
//	{
//	  "source":           "algod-rust/tools/lookback-vector-capture (TASK-57)",
//	  "go_algorand_pin":  "v4.6.0-stable",
//	  "vectors": [
//	    {
//	      "version":               "v7",
//	      "seed_lookback":         2,
//	      "seed_refresh_interval": 100,
//	      "round":                 0,
//	      "params_round":          0,
//	      "balance_round":         0,
//	      "seed_round":            0
//	    },
//	    ...
//	  ]
//	}
//
// Regeneration: see docs/DEV_WORKFLOW.md → "Lookback Vector Regeneration".
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

// expectedGoAlgorandPin matches the workspace-wide pin documented in
// the repo's CLAUDE.md. Two developers regenerating the same corpus
// are guaranteed byte-identical output regardless of what branch or
// dirty state happens to be checked out in their local go-algorand
// clone.
const expectedGoAlgorandPin = "v4.7.0-stable"

// allVersions returns every non-deprecated consensus version in order.
// V7 is included (beyond the task's V18..V41 range) because the V7→V8
// upgrade is the only historical protocol transition where
// SeedRefreshInterval actually changes (100 → 80 at V8). Capturing
// both sides of that boundary gives the parity test a real "lookback
// values differ" case; everything V8..V41 happens to be a no-op on
// the lookback math, but we still capture every version to guard
// against future protocol changes reintroducing a shift.
func allVersions() []protocol.ConsensusVersion {
	return []protocol.ConsensusVersion{
		protocol.ConsensusV7, protocol.ConsensusV8, protocol.ConsensusV9,
		protocol.ConsensusV10, protocol.ConsensusV11, protocol.ConsensusV12,
		protocol.ConsensusV13, protocol.ConsensusV14, protocol.ConsensusV15,
		protocol.ConsensusV16, protocol.ConsensusV17, protocol.ConsensusV18,
		protocol.ConsensusV19, protocol.ConsensusV20, protocol.ConsensusV21,
		protocol.ConsensusV22, protocol.ConsensusV23, protocol.ConsensusV24,
		protocol.ConsensusV25, protocol.ConsensusV26, protocol.ConsensusV27,
		protocol.ConsensusV28, protocol.ConsensusV29, protocol.ConsensusV30,
		protocol.ConsensusV31, protocol.ConsensusV32, protocol.ConsensusV33,
		protocol.ConsensusV34, protocol.ConsensusV35, protocol.ConsensusV36,
		protocol.ConsensusV37, protocol.ConsensusV38, protocol.ConsensusV39,
		protocol.ConsensusV40, protocol.ConsensusV41,
	}
}

// seedRound replicates go-algorand/agreement/selector.go:63 verbatim.
// The Go function is unexported; its body is a single
// `r.SubSaturate(basics.Round(cparams.SeedLookback))` — mirrored here
// so the capture can emit it for parity testing.
func seedRound(r basics.Round, cparams config.ConsensusParams) basics.Round {
	return r.SubSaturate(basics.Round(cparams.SeedLookback))
}

// roundMatrix returns the test-round values for a given
// (seed_lookback, seed_refresh_interval) pair. Deliberately covers:
//   - 0, 1                         — saturation floor
//   - sl-1, sl, sl+1               — seed-lookback boundary
//   - bl-1, bl, bl+1               — balance-lookback boundary
//   - 10_000_000                   — "large" round well past every
//                                    historical mainnet height at the
//                                    time of writing, but still safely
//                                    inside u64
//
// Duplicates (e.g. when sl-1 == 0) are dropped and the result is
// sorted ascending so fixture ordering is deterministic.
func roundMatrix(sl, sri uint64) []uint64 {
	bl := 2 * sri * sl
	candidates := []uint64{0, 1, 10_000_000}
	if sl > 0 {
		candidates = append(candidates, sl, sl+1)
		if sl >= 1 {
			candidates = append(candidates, sl-1)
		}
	}
	if bl > 0 {
		candidates = append(candidates, bl, bl+1)
		if bl >= 1 {
			candidates = append(candidates, bl-1)
		}
	}
	seen := map[uint64]struct{}{}
	out := candidates[:0]
	for _, r := range candidates {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Vector is one parity tuple.
type Vector struct {
	Version             string `json:"version"`
	SeedLookback        uint64 `json:"seed_lookback"`
	SeedRefreshInterval uint64 `json:"seed_refresh_interval"`
	Round               uint64 `json:"round"`
	ParamsRound         uint64 `json:"params_round"`
	BalanceRound        uint64 `json:"balance_round"`
	SeedRound           uint64 `json:"seed_round"`
}

// Corpus is the on-disk envelope.
type Corpus struct {
	Source        string   `json:"source"`
	GoAlgorandPin string   `json:"go_algorand_pin"`
	Vectors       []Vector `json:"vectors"`
}

// goAlgorandDir resolves the sibling go-algorand checkout relative to
// this tool's source location (so the pin check works regardless of
// the CWD the tool is invoked from).
func goAlgorandDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Clean(filepath.Join("..", "..", "..", "go-algorand"))
	}
	toolDir := filepath.Dir(thisFile)
	repoRoot := filepath.Clean(filepath.Join(toolDir, "..", ".."))
	return filepath.Clean(filepath.Join(repoRoot, "..", "go-algorand"))
}

// defaultOutputPath is the committed fixture location.
func defaultOutputPath() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("crates", "core", "algo-agreement", "tests", "fixtures", "lookback", "lookback_boundaries.json")
	}
	toolDir := filepath.Dir(thisFile)
	repoRoot := filepath.Clean(filepath.Join(toolDir, "..", ".."))
	return filepath.Join(repoRoot, "crates", "core", "algo-agreement", "tests", "fixtures", "lookback", "lookback_boundaries.json")
}

// verifyGoAlgorandPin refuses to run unless ../go-algorand is exactly
// at expectedGoAlgorandPin with a clean tree for the two directories
// this capture depends on (agreement/ for the lookback functions,
// config/ for the per-version ConsensusParams table). Modelled on
// tools/vrf-vector-capture.
func verifyGoAlgorandPin(path string) error {
	cmd := exec.Command("git", "-C", path, "describe", "--tags", "--exact-match", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		rev, _ := exec.Command("git", "-C", path, "rev-parse", "HEAD").Output()
		return fmt.Errorf(
			"go-algorand at %q is not pinned to %s (HEAD=%s). "+
				"Fix: cd %s && git fetch --tags && git checkout %s  (or pass --allow-unpinned)",
			path, expectedGoAlgorandPin, strings.TrimSpace(string(rev)), path, expectedGoAlgorandPin,
		)
	}
	if got := strings.TrimSpace(string(out)); got != expectedGoAlgorandPin {
		return fmt.Errorf(
			"go-algorand at %q is on tag %q, expected %q. "+
				"Fix: cd %s && git checkout %s  (or pass --allow-unpinned)",
			path, got, expectedGoAlgorandPin, path, expectedGoAlgorandPin,
		)
	}

	cmd = exec.Command("git", "-C", path, "status", "--porcelain")
	out, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("checking %s working tree: %w", path, err)
	}
	// protocol/ is guarded because the tool builds its version list
	// from `protocol.ConsensusV*` constants; a local edit there
	// could add, rename, or drop a version without the capture
	// reflecting that, breaking reproducibility against the pinned
	// release.
	dirty := filterDirtyPaths(string(out), []string{
		"agreement/",
		"config/",
		"data/basics/",
		"protocol/",
	})
	if len(dirty) > 0 {
		return fmt.Errorf(
			"go-algorand at %q has uncommitted changes in agreement/, config/, data/basics/, or protocol/ "+
				"that could change the captured vectors:\n%s\nClean the tree or pass --allow-unpinned.",
			path, strings.Join(dirty, "\n"),
		)
	}
	return nil
}

// filterDirtyPaths returns porcelain v1 entries whose source or
// destination path starts with any of `prefixes` and is not a pure
// test-file move. Rename entries (`R  <old> -> <new>`) are
// expanded and both sides are inspected, so a rename *into* a
// guarded directory is flagged just like an in-place modification —
// a non-rename-aware filter could silently accept a dirty checkout
// whose build-affecting files had been renamed under agreement/
// and emit non-reproducible vectors.
//
// Files ending in `_test.go` are excluded because `go build` /
// `go run` of this external consumer never imports them, so their
// state cannot change the captured vectors; in practice the
// workspace ships at least one pre-existing untracked test file
// under agreement/ (see agreement-wire-capture for context). The
// skip applies only when EVERY path in the entry is a test file —
// a rename that converts a non-test file into a test file (or vice
// versa) still gets prefix-checked because the build-tree change
// is real.
func filterDirtyPaths(porcelain string, prefixes []string) []string {
	var dirty []string
	for _, line := range strings.Split(strings.TrimRight(porcelain, "\n"), "\n") {
		if len(line) < 4 {
			continue
		}
		body := strings.TrimSpace(line[3:])
		paths := []string{body}
		if idx := strings.Index(body, " -> "); idx >= 0 {
			paths = []string{
				strings.TrimSpace(body[:idx]),
				strings.TrimSpace(body[idx+len(" -> "):]),
			}
		}
		allTest := true
		for _, p := range paths {
			if !strings.HasSuffix(p, "_test.go") {
				allTest = false
				break
			}
		}
		if allTest {
			continue
		}
		for _, p := range paths {
			matched := false
			for _, prefix := range prefixes {
				if strings.HasPrefix(p, prefix) {
					matched = true
					break
				}
			}
			if matched {
				dirty = append(dirty, line)
				break
			}
		}
	}
	return dirty
}

// resolveGoAlgorandPin returns the string written to the fixture's
// `go_algorand_pin` metadata. When the pin was verified it's the
// expected tag (honestly describing a reproducible capture). Under
// `--allow-unpinned` we instead emit whatever `git describe` reports
// for the actual HEAD, plus a `(unpinned)` suffix — so a fixture
// captured against a different commit carries metadata that tells
// reviewers "this did not come from the workspace-wide pin".
func resolveGoAlgorandPin(path string, pinVerified bool) string {
	if pinVerified {
		return expectedGoAlgorandPin
	}
	out, err := exec.Command("git", "-C", path, "describe", "--tags", "--always", "--dirty=+dirty").Output()
	if err != nil {
		// Fall back to raw HEAD so we always emit *something*
		// identifiable instead of silently misreporting the tag.
		if rev, rerr := exec.Command("git", "-C", path, "rev-parse", "HEAD").Output(); rerr == nil {
			return strings.TrimSpace(string(rev)) + " (unpinned)"
		}
		return "unknown (unpinned)"
	}
	return strings.TrimSpace(string(out)) + " (unpinned)"
}

func main() {
	var (
		outPath        = flag.String("out", defaultOutputPath(), "path to write the JSON corpus")
		allowUnpinned  = flag.Bool("allow-unpinned", false, "skip the go-algorand tag/cleanliness check (captures will not be reproducible across developers)")
	)
	flag.Parse()

	pinVerified := !*allowUnpinned
	if pinVerified {
		if err := verifyGoAlgorandPin(goAlgorandDir()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}

	versions := allVersions()
	corpus := Corpus{
		Source:        "algod-rust/tools/lookback-vector-capture (TASK-57)",
		GoAlgorandPin: resolveGoAlgorandPin(goAlgorandDir(), pinVerified),
	}

	for _, v := range versions {
		cparams, ok := config.Consensus[v]
		if !ok {
			fmt.Fprintf(os.Stderr, "consensus version %q not present in go-algorand's Consensus map\n", v)
			os.Exit(3)
		}
		sl := cparams.SeedLookback
		sri := cparams.SeedRefreshInterval
		for _, r := range roundMatrix(sl, sri) {
			round := basics.Round(r)
			corpus.Vectors = append(corpus.Vectors, Vector{
				Version:             string(v),
				SeedLookback:        sl,
				SeedRefreshInterval: sri,
				Round:               r,
				ParamsRound:         uint64(agreement.ParamsRound(round)),
				BalanceRound:        uint64(agreement.BalanceRound(round, cparams)),
				SeedRound:           uint64(seedRound(round, cparams)),
			})
		}
	}

	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(4)
	}
	buf, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(5)
	}
	buf = append(buf, '\n') // trailing newline for POSIX text-file conventions
	if err := os.WriteFile(*outPath, buf, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(6)
	}
	fmt.Fprintf(os.Stderr, "wrote %d vectors across %d consensus versions to %s\n",
		len(corpus.Vectors), len(versions), *outPath)
}
