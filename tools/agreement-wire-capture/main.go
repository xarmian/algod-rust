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
	expectedGoAlgorandPin = "v5.0.0-stable"
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
	// Dirty-tree check: every package the staged test
	// (`fixtures_test.go.tmpl`) transitively references in the
	// encoded struct values can influence the fixture output's
	// byte pattern. A local edit under any of these directories
	// makes the output no longer canonical for the pinned tag.
	// Ignoring the rest (CLAUDE.md, README, docker/, etc.) so
	// unrelated workspace state doesn't block regeneration.
	// Codex P2 (PR #228, r4) flagged that an earlier version
	// scoped this to agreement/ only.
	statusOut, err := exec.Command("git", "-C", gaDir, "status", "--porcelain").Output()
	if err != nil {
		return fmt.Errorf("checking %s working tree: %w", gaDir, err)
	}
	dirty := filterDirtyAgreementPaths(string(statusOut))
	if len(dirty) > 0 {
		return fmt.Errorf(
			"go-algorand at %q has uncommitted changes under directories whose "+
				"contents feed into the agreement wire fixture output:\n%s\n"+
				"Clean the tree or pass --allow-unpinned.",
			gaDir, strings.Join(dirty, "\n"),
		)
	}
	return nil
}

// guardedPrefixes enumerates go-algorand subdirectories whose contents
// can change the wire-fixture output. Any of these being dirty means a
// regeneration is no longer canonical for the pinned tag.
//
//   - `agreement/`           — types + msgp_gen.go encoders under test.
//   - `crypto/`              — OneTimeSignature, VrfProof, Digest, Hashable.
//   - `data/basics/`         — basics.Address, basics.Round.
//   - `data/bookkeeping/`    — bookkeeping.Block / BlockHeader (proposal).
//   - `data/committee/`      — UnauthenticatedCredential, Credential.
//   - `protocol/`            — protocol.Encode + HashID identifiers.
var guardedPrefixes = []string{
	"agreement/",
	"crypto/",
	"data/basics/",
	"data/bookkeeping/",
	"data/committee/",
	"protocol/",
}

// ignoredPaths carries files the regen tool is known to create or that
// are legitimately present in a fresh checkout. Listed as exact paths
// (not prefixes) to keep the allowlist tight.
func ignoredPaths() map[string]bool {
	return map[string]bool{
		"agreement/" + stagedFileName:              true,
		"agreement/golden_vectors_test.go":         true,
		"data/committee/golden_vectors_test.go":    true,
	}
}

// filterDirtyAgreementPaths returns porcelain lines whose (any) path
// is under a guarded prefix AND not in the ignored-paths set.
//
// Factored out for unit testing — this is identical in spirit to the
// helper in tools/vrf-vector-capture/main.go but with a different
// prefix list.
func filterDirtyAgreementPaths(porcelain string) []string {
	ignored := ignoredPaths()
	var dirty []string
	for _, line := range strings.Split(strings.TrimRight(porcelain, "\n"), "\n") {
		if len(line) < 4 {
			continue
		}
		body := strings.TrimSpace(line[3:])
		paths := []string{body}
		// Rename/copy: `XY old -> new` → inspect both sides.
		if idx := strings.Index(body, " -> "); idx >= 0 {
			paths = []string{strings.TrimSpace(body[:idx]), strings.TrimSpace(body[idx+4:])}
		}
		matched := false
		for _, p := range paths {
			p = strings.TrimPrefix(strings.TrimSuffix(p, `"`), `"`)
			if ignored[p] {
				continue
			}
			for _, pref := range guardedPrefixes {
				if strings.HasPrefix(p, pref) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if matched {
			dirty = append(dirty, line)
		}
	}
	return dirty
}

// fixtureSubdirs lists every subdirectory this tool owns under the
// output directory. clearFixtureSubdirs only removes entries whose
// name matches this list — any unknown subdirectory (perhaps a
// sibling fixture set, or user scratch data if `--out` was pointed
// at a shared path like `/tmp`) is left untouched. The staged test
// inside go-algorand writes exactly these names; extending this
// slice requires a corresponding change in the test template.
var fixtureSubdirs = []string{
	"rawvote",
	"uvote",
	"vote",
	"ubundle",
	"cert",
	"bundle",
	"uproposal",
	"proposal",
	"tpayload",
	"proposalvalue",
}

// (Legacy `clearFixtureSubdirs` was removed in the stage-and-swap
// refactor for Codex P2 r5. The "only touch allowlisted subdirs"
// invariant is now enforced inside `swapFixtureSubdirs`: that
// function iterates `fixtureSubdirs` and is the sole deleter of
// destination subdirectories.)

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
	// All fallible logic lives in `run`. `os.Exit` does not execute
	// deferred functions, so running the whole flow inside a
	// returning helper is the only way to guarantee that the
	// staged-file cleanup (a deferred closure set up once the copy
	// succeeds) actually fires on every error path — including the
	// `go test` failure path that previously leaked the file into
	// `../go-algorand/agreement/` and left the checkout dirty
	// (Codex P1 on PR #228, r4).
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	out := flag.String("out", defaultFixtureDir(), "output directory for fixtures")
	allowUnpinned := flag.Bool("allow-unpinned", false, "skip the go-algorand pin check")
	keepStaged := flag.Bool("keep-staged", false,
		"debug: don't remove the staged test file from go-algorand after running")
	flag.Parse()

	// Normalize --out to an absolute path BEFORE anything else uses
	// it. The wrapper runs in the user's CWD, but we launch `go test`
	// with `cmd.Dir = ../go-algorand`; a relative `--out` would
	// resolve to different directories in the two contexts, causing
	// the cleanup step to clear one path and the fixture writes to
	// land elsewhere — stale vectors on disk, deterministic regen
	// broken (Codex P2 on PR #228, r3).
	absOut, err := filepath.Abs(*out)
	if err != nil {
		return fmt.Errorf("resolving --out=%q: %w", *out, err)
	}
	*out = absOut

	if err := verifyGoAlgorandPin(*allowUnpinned); err != nil {
		return err
	}

	tmpl := templatePath()
	staged := stagedPath()
	if err := copyFile(tmpl, staged); err != nil {
		return err
	}

	// Defer cleanup unless the user asked to keep it (for debugging).
	// Safe now that `run` returns — `os.Exit` is only called from
	// `main` after `run` has already returned and its defers fired.
	defer func() {
		if *keepStaged {
			fmt.Fprintf(os.Stderr, "staged file left in place for debugging: %s\n", staged)
			return
		}
		if err := os.Remove(staged); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "cleanup: failed to remove %s: %v\n", staged, err)
		}
	}()

	// Ensure the fixture output dir exists before go test runs.
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}

	// Stage-and-swap: generate fixtures into a sibling temp
	// directory first; only clear the committed subdirs and move
	// the new fixtures into place after `go test` succeeds. Without
	// this, a transient test/build/runtime failure leaves the
	// committed corpus partially or fully wiped on disk (the user's
	// working tree would show thousands of deleted files that
	// correspond to nothing and would propagate the deletion to
	// the next commit unless spotted). Codex P2 on PR #228 r5
	// called this out as "regeneration non-atomic."
	//
	// The temp dir is a sibling of `*out` so `os.Rename` across
	// subdirectories stays on the same filesystem. It's removed
	// unconditionally at function exit — whether we succeed or
	// fail — so there's no scratch left behind.
	tmpDir, err := os.MkdirTemp(filepath.Dir(*out), ".wire-staging-")
	if err != nil {
		return fmt.Errorf("create staging dir next to %s: %w", *out, err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			fmt.Fprintf(os.Stderr, "cleanup: failed to remove staging %s: %v\n", tmpDir, err)
		}
	}()

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
		"ALGOD_RUST_WIRE_FIXTURE_DIR="+tmpDir,
	)
	if err := cmd.Run(); err != nil {
		// Failure BEFORE the swap: the committed corpus at `*out`
		// is untouched. The tmpDir cleanup fires via defer.
		return fmt.Errorf("go test failed: %w", err)
	}

	// Success path — swap the newly-generated subdirs into place.
	// Only the allowlisted subdirectories (those the staged test
	// writes) are touched at the target. Top-level files like the
	// committed `README.md` remain untouched.
	if err := swapFixtureSubdirs(tmpDir, *out); err != nil {
		return fmt.Errorf("swapping regenerated fixtures into %s: %w", *out, err)
	}

	fmt.Printf("agreement wire fixtures written to %s\n", *out)
	return nil
}

// swapFixtureSubdirs is the "commit" half of the stage-and-swap
// regeneration pattern. For every allowlisted fixture subdirectory
// found under `src`, it atomically replaces the corresponding
// subdirectory at `dst` via `os.Rename`. If a subdirectory doesn't
// exist in the freshly-generated staging dir (the template was
// edited to drop it), the old one at `dst` is still removed — so
// obsolete subdirectories don't linger.
//
// This runs only AFTER `go test` succeeds; any failure before that
// point leaves `dst` fully intact. Rename is atomic per-subdirectory
// on POSIX when source and target are on the same filesystem — we
// ensure that by creating the staging dir as a sibling of `dst`.
//
// Factored out for unit testing.
func swapFixtureSubdirs(src, dst string) error {
	for _, name := range fixtureSubdirs {
		srcSub := filepath.Join(src, name)
		dstSub := filepath.Join(dst, name)

		// Remove the old destination subdir (if any). Safe to do
		// unconditionally: we're about to replace it with the
		// staged version, and if the staged version is missing,
		// the removal still matches the test's intent (a deleted
		// subdir should disappear from the corpus).
		if err := os.RemoveAll(dstSub); err != nil {
			return fmt.Errorf("clearing old %s: %w", dstSub, err)
		}

		// If the staging dir has no corresponding subdir, nothing
		// to move — the subdir was genuinely removed in this regen.
		if _, err := os.Stat(srcSub); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return fmt.Errorf("stat %s: %w", srcSub, err)
		}

		if err := os.Rename(srcSub, dstSub); err != nil {
			return fmt.Errorf("moving %s → %s: %w", srcSub, dstSub, err)
		}
	}
	return nil
}
