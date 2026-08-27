// vfuture-consensus-override: emit a go-algorand `consensus.json`
// (config.ConfigurableConsensusProtocolsFilename) that overrides only
// `MaxTxnBytesPerBlock` for the `vFuture`/"future" consensus version.
//
// Why this exists (issue #548): the default `MaxTxnBytesPerBlock` for
// "future" is 5 MiB (inherited from V41 — config/consensus.go), so
// driving on-chain block `Load`/`CongestionTax` (the "ld"/"ct" header
// fields added in #534/PR #547) above the 50%-full threshold that makes
// `CongestionTax` non-zero (`NextCongestionTax` in
// data/bookkeeping/block.go) would require flooding megabytes of
// transactions through a private network — slow and flaky to automate.
// Shrinking the block-size ceiling to a few KiB lets a handful of
// payment transactions cross that threshold instead.
//
// go-algorand only accepts a *full* ConsensusParams replacement per
// version in `consensus.json` (config.ConsensusProtocols.Merge fully
// replaces the entry rather than merging field-by-field — see
// config/consensus.go's `Merge`), so this tool starts from the real
// pinned "future" params (`config.Consensus[protocol.ConsensusFuture]`)
// and only mutates the one field, then serializes the whole struct.
//
// Usage:
//
//	go run . -out /path/to/consensus.json [-max-txn-bytes-per-block 4096]
//
// Regeneration: see docs/DEV_WORKFLOW.md → "vFuture Fixture Capture".
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/protocol"
)

// expectedGoAlgorandPin matches the workspace-wide pin documented in
// the repo's CLAUDE.md, so two developers regenerating the override
// against the same go-algorand pin get byte-identical output.
const expectedGoAlgorandPin = "v4.7.3-stable"

// goAlgorandDir resolves the sibling go-algorand checkout relative to
// this tool's own source location, so the pin check works regardless
// of the working directory the tool is invoked from.
func goAlgorandDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Clean(filepath.Join("..", "..", "..", "go-algorand"))
	}
	toolDir := filepath.Dir(thisFile)
	repoRoot := filepath.Clean(filepath.Join(toolDir, "..", ".."))
	return filepath.Clean(filepath.Join(repoRoot, "..", "go-algorand"))
}

func checkPin(dir string, allowUnpinned bool) error {
	cmd := exec.Command("git", "-C", dir, "describe", "--tags", "--exact-match")
	out, err := cmd.Output()
	tag := strings.TrimSpace(string(out))
	if err != nil || tag != expectedGoAlgorandPin {
		msg := fmt.Sprintf(
			"go-algorand checkout at %s is not pinned to %s (got %q); "+
				"regenerating against an unpinned checkout produces output "+
				"out of sync with the rest of the workspace",
			dir, expectedGoAlgorandPin, tag,
		)
		if allowUnpinned {
			fmt.Fprintln(os.Stderr, "WARNING (--allow-unpinned): "+msg)
			return nil
		}
		return fmt.Errorf("%s (pass --allow-unpinned to override)", msg)
	}

	statusCmd := exec.Command("git", "-C", dir, "status", "--porcelain",
		"--", "config", "protocol")
	statusOut, err := statusCmd.Output()
	if err != nil {
		return fmt.Errorf("checking git status of %s: %w", dir, err)
	}
	if dirty := strings.TrimSpace(string(statusOut)); dirty != "" {
		msg := fmt.Sprintf("go-algorand checkout at %s has a dirty config/ or "+
			"protocol/ tree:\n%s", dir, dirty)
		if allowUnpinned {
			fmt.Fprintln(os.Stderr, "WARNING (--allow-unpinned): "+msg)
			return nil
		}
		return fmt.Errorf("%s (pass --allow-unpinned to override)", msg)
	}
	return nil
}

func main() {
	out := flag.String("out", "vfuture-consensus.json", "output path for the consensus.json override")
	maxTxnBytesPerBlock := flag.Int("max-txn-bytes-per-block", 4096,
		"override value for the future protocol's MaxTxnBytesPerBlock")
	allowUnpinned := flag.Bool("allow-unpinned", false,
		"skip the go-algorand pin/dirty-tree check (for intentional regeneration against a different tag)")
	flag.Parse()

	dir := goAlgorandDir()
	if err := checkPin(dir, *allowUnpinned); err != nil {
		fmt.Fprintln(os.Stderr, "vfuture-consensus-override:", err)
		os.Exit(1)
	}

	base, ok := config.Consensus[protocol.ConsensusFuture]
	if !ok {
		fmt.Fprintln(os.Stderr, "vfuture-consensus-override: protocol.ConsensusFuture not present in config.Consensus")
		os.Exit(1)
	}
	if !base.LoadTracking {
		fmt.Fprintln(os.Stderr, "vfuture-consensus-override: expected LoadTracking=true on the future protocol (see #534) — go-algorand pin may have changed this")
		os.Exit(1)
	}

	// Full-struct copy: config.ConsensusProtocols.Merge replaces the
	// entire ConsensusParams for a version rather than merging
	// field-by-field, so a partial override would zero every other
	// field (MinTxnFee, ApprovedUpgrades, etc.) and break the network.
	override := base
	override.MaxTxnBytesPerBlock = *maxTxnBytesPerBlock

	payload := config.ConsensusProtocols{
		protocol.ConsensusFuture: override,
	}

	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "vfuture-consensus-override: marshal:", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil && filepath.Dir(*out) != "." {
		fmt.Fprintln(os.Stderr, "vfuture-consensus-override: mkdir:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, encoded, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "vfuture-consensus-override: write:", err)
		os.Exit(1)
	}

	fmt.Printf("vfuture-consensus-override: wrote %s (future.MaxTxnBytesPerBlock=%d, pin=%s)\n",
		*out, *maxTxnBytesPerBlock, expectedGoAlgorandPin)
}
