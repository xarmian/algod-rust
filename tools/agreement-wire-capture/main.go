// agreement-wire-capture: dump canonical msgpack fixtures for every
// go-algorand agreement wire type (vote / unauthenticated vote / bundle /
// certificate / unauthenticated proposal / transmitted payload).
//
// Driven by TASK-54 under PLAN-30. Consumed by TASK-55 (codec roundtrip
// parity) and TASK-56 (msgpack fuzz seed corpus).
//
// Constraint: every interesting agreement type
// (rawVote, unauthenticatedVote, vote, unauthenticatedBundle, bundle,
// voteAuthenticator, equivocationVoteAuthenticator, unauthenticatedProposal,
// transmittedPayload) is *unexported* in the `agreement` package. An
// external Go program can't touch them. The capture therefore runs as a
// real Go test inside go-algorand's `agreement` package — but since we
// never modify the pinned go-algorand checkout, we stage the test file
// from our own repo into `../go-algorand/agreement/` on each run and
// remove it afterwards. The file has a distinctive prefix
// (`algod_rust_`) so collisions with go-algorand's own tests are
// impossible.
//
// Flow:
//
//   1. Verify `../go-algorand` HEAD is exactly the pinned tag (same
//      enforcement as `tools/vrf-vector-capture`).
//   2. Copy `fixtures_test.go.tmpl` into
//      `../go-algorand/agreement/algod_rust_wire_fixtures_test.go`.
//   3. Run `go test -run TestAlgodRustGenerateWireFixtures -count=1` in
//      that directory, passing the target fixture directory via the
//      env var `ALGOD_RUST_WIRE_FIXTURE_DIR`.
//   4. Remove the staged file, regardless of test outcome.
//   5. If any of the above failed, exit non-zero.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	expectedGoAlgorandPin = "v4.5.1-stable"
	// Name chosen to (a) be obviously ours in go-algorand's directory
	// listing and (b) end in `_test.go` so `go test` picks it up.
	stagedFileName = "algod_rust_wire_fixtures_test.go"
	testFuncName   = "TestAlgodRustGenerateWireFixtures"
)

// repoRoot is the root of the algod-rust workspace (two levels above this
// source file). goAlgorandDir is the sibling go-algorand checkout.
func repoRoot() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		// Fall back to CWD-relative — works only when invoked from
		// `tools/agreement-wire-capture/`.
		return filepath.Clean(filepath.Join("..", ".."))
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}

func goAlgorandDir() string { return filepath.Clean(filepath.Join(repoRoot(), "..", "go-algorand")) }

// defaultFixtureDir is where the test writes .msgpack / .json output.
func defaultFixtureDir() string {
	return filepath.Join(repoRoot(), "crates", "core", "algo-agreement", "tests", "fixtures", "wire")
}

// templatePath is the source-of-truth Go test file in our repo.
func templatePath() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("fixtures_test.go.tmpl")
	}
	return filepath.Join(filepath.Dir(thisFile), "fixtures_test.go.tmpl")
}

// stagedPath is where we copy the template inside go-algorand's agreement package.
func stagedPath() string { return filepath.Join(goAlgorandDir(), "agreement", stagedFileName) }

// verifyGoAlgorandPin is lifted in spirit from tools/vrf-vector-capture:
// hard-require the pinned tag with a clean `agreement/` tree before we
// stage anything. The fixture output is a function of the pinned
// msgp_gen.go encoder; any mismatch silently changes the corpus.
func verifyGoAlgorandPin(allowUnpinned bool) error {
	if allowUnpinned {
		return nil
	}
	gaDir := goAlgorandDir()
	tagOut, err := exec.Command("git", "-C", gaDir, "describe", "--tags", "--exact-match", "HEAD").Output()
	if err != nil {
		rev, _ := exec.Command("git", "-C", gaDir, "rev-parse", "HEAD").Output()
		return fmt.Errorf(
			"go-algorand at %q is not pinned to %s (HEAD=%s). "+
				"Fix:\n  cd %s && git fetch --tags && git checkout %s\n"+
				"or pass --allow-unpinned if intentionally regenerating against a different pin.",
			gaDir, expectedGoAlgorandPin, strings.TrimSpace(string(rev)), gaDir, expectedGoAlgorandPin,
		)
	}
	if got := strings.TrimSpace(string(tagOut)); got != expectedGoAlgorandPin {
		return fmt.Errorf("go-algorand at %q is on tag %q, expected %q (pass --allow-unpinned to override)",
			gaDir, got, expectedGoAlgorandPin)
	}
	// Dirty-tree check limited to agreement/ — that's the only directory
	// whose contents influence the staged test's encoding output.
	statusOut, err := exec.Command("git", "-C", gaDir, "status", "--porcelain").Output()
	if err != nil {
		return fmt.Errorf("checking %s working tree: %w", gaDir, err)
	}
	var dirty []string
	for _, line := range strings.Split(strings.TrimRight(string(statusOut), "\n"), "\n") {
		if len(line) < 4 {
			continue
		}
		body := strings.TrimSpace(line[3:])
		// Consider both rename sides.
		paths := []string{body}
		if idx := strings.Index(body, " -> "); idx >= 0 {
			paths = []string{strings.TrimSpace(body[:idx]), strings.TrimSpace(body[idx+4:])}
		}
		for _, p := range paths {
			p = strings.TrimPrefix(strings.TrimSuffix(p, `"`), `"`)
			// Ignore our own staged file if a previous run crashed
			// mid-flight; we'll clean it up below. Also ignore
			// golden_vectors_test.go which existed before this work.
			if p == "agreement/"+stagedFileName || p == "agreement/golden_vectors_test.go" {
				continue
			}
			if strings.HasPrefix(p, "agreement/") {
				dirty = append(dirty, line)
				break
			}
		}
	}
	if len(dirty) > 0 {
		return fmt.Errorf(
			"go-algorand at %q has uncommitted changes under agreement/ "+
				"that could change wire encodings:\n%s\nClean the tree or pass --allow-unpinned.",
			gaDir, strings.Join(dirty, "\n"),
		)
	}
	return nil
}

// clearFixtureSubdirs removes every immediate subdirectory of `dir`
// (each holds one wire type's fixtures) so a regeneration starts from
// a known-empty state. Top-level files are preserved — specifically
// the committed `README.md`.
//
// Factored out of `main` to keep that function linear and so tests
// (future) can exercise the clearing logic independently.
func clearFixtureSubdirs(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub := filepath.Join(dir, e.Name())
		if err := os.RemoveAll(sub); err != nil {
			return fmt.Errorf("clear %s: %w", sub, err)
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy %s -> %s: %w", src, dst, err)
	}
	return nil
}

func main() {
	out := flag.String("out", defaultFixtureDir(), "output directory for fixtures")
	allowUnpinned := flag.Bool("allow-unpinned", false, "skip the go-algorand pin check")
	keepStaged := flag.Bool("keep-staged", false,
		"debug: don't remove the staged test file from go-algorand after running")
	flag.Parse()

	if err := verifyGoAlgorandPin(*allowUnpinned); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	tmpl := templatePath()
	staged := stagedPath()
	if err := copyFile(tmpl, staged); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Defer cleanup unless the user asked to keep it (for debugging).
	cleanup := func() {
		if *keepStaged {
			fmt.Fprintf(os.Stderr, "staged file left in place for debugging: %s\n", staged)
			return
		}
		if err := os.Remove(staged); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "cleanup: failed to remove %s: %v\n", staged, err)
		}
	}
	defer cleanup()

	// Ensure the fixture output dir exists before go test runs.
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Clear stale fixtures before regenerating. Without this, a
	// renamed/removed case in the template (e.g. `zero` → `empty`)
	// leaves its prior `.msgpack` + `.json` files on disk; since the
	// staged test's coverage floor is only a `>= 40 files` lower
	// bound per subdirectory, the check silently passes and obsolete
	// vectors re-commit as if the tool had generated them. That
	// would weaken downstream roundtrip and fuzz coverage and break
	// the tool's "deterministic regeneration" guarantee (Codex P2 on
	// PR #228).
	//
	// Approach: remove every immediate subdirectory of `out` (each
	// corresponds to one wire type and is rebuilt by the test).
	// Files at the top level — specifically the committed `README.md`
	// — are preserved.
	if err := clearFixtureSubdirs(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	cmd := exec.Command("go", "test",
		"-run", "^"+testFuncName+"$",
		"-count=1",
		"-v",
		"./agreement",
	)
	cmd.Dir = goAlgorandDir()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"ALGOD_RUST_WIRE_FIXTURE_DIR="+*out,
	)
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "go test failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("agreement wire fixtures written to %s\n", *out)
}
