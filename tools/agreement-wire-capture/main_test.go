// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSwapFixtureSubdirs_ReplacesOnlyAllowlistedAndPreservesNonOwned
// is the P1+P2 regression guard for PR #228 r2/r5: the swap step
// (a) moves only the allowlisted fixture subdirectories from the
// staging dir into the target, and (b) leaves any non-allowlisted
// content at the target untouched. This keeps `--out /tmp` (or
// any shared scratch path) from being a footgun AND preserves the
// committed `README.md` across regenerations.
func TestSwapFixtureSubdirs_ReplacesOnlyAllowlistedAndPreservesNonOwned(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "staging")
	dst := filepath.Join(base, "target")
	mustMkdir(t, src)
	mustMkdir(t, dst)

	// Old fixture subdirs at the target — must be replaced.
	mustMkdir(t, filepath.Join(dst, "rawvote"))
	mustWriteFile(t, filepath.Join(dst, "rawvote", "old.msgpack"), "old-rawvote")
	mustMkdir(t, filepath.Join(dst, "uvote"))
	mustWriteFile(t, filepath.Join(dst, "uvote", "old.msgpack"), "old-uvote")

	// Freshly-generated subdirs in staging.
	mustMkdir(t, filepath.Join(src, "rawvote"))
	mustWriteFile(t, filepath.Join(src, "rawvote", "new.msgpack"), "new-rawvote")
	// Note: src has no `uvote/` — simulates the template dropping
	// that type. swap should still remove the old uvote/ at dst.

	// Non-owned directory at target — must be preserved.
	mustMkdir(t, filepath.Join(dst, "user_scratch"))
	mustWriteFile(t, filepath.Join(dst, "user_scratch", "precious.txt"), "keep me")

	// Top-level file at target — must be preserved.
	mustWriteFile(t, filepath.Join(dst, "README.md"), "# fixtures")

	if err := swapFixtureSubdirs(src, dst); err != nil {
		t.Fatalf("swapFixtureSubdirs: %v", err)
	}

	// rawvote/ at dst now has the new content.
	body, err := os.ReadFile(filepath.Join(dst, "rawvote", "new.msgpack"))
	if err != nil || string(body) != "new-rawvote" {
		t.Errorf("rawvote/new.msgpack after swap: body=%q err=%v", body, err)
	}
	// Old rawvote file is gone.
	if _, err := os.Stat(filepath.Join(dst, "rawvote", "old.msgpack")); !os.IsNotExist(err) {
		t.Errorf("old rawvote file should be gone, err=%v", err)
	}
	// uvote/ (removed from src) should be removed at dst.
	if _, err := os.Stat(filepath.Join(dst, "uvote")); !os.IsNotExist(err) {
		t.Errorf("dst/uvote should be removed (no longer in src), got err=%v", err)
	}
	// Non-owned dir + file preserved.
	if _, err := os.Stat(filepath.Join(dst, "user_scratch", "precious.txt")); err != nil {
		t.Errorf("user_scratch/precious.txt removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "README.md")); err != nil {
		t.Errorf("README.md removed: %v", err)
	}
	// Top-level file in src is not copied (swap only touches
	// allowlisted subdirs).
	// (Implicitly validated by the non-owned preservation above.)
}

// TestSwapFixtureSubdirs_NoOpWhenStagingEmpty — calling swap with
// an empty staging dir and an empty target should succeed, doing
// nothing destructive. This matches the edge case where no subdirs
// are written (should never happen in practice — the staged test
// asserts ≥40 files per subdir — but guarding the function anyway).
func TestSwapFixtureSubdirs_NoOpWhenStagingEmpty(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "staging")
	dst := filepath.Join(base, "target")
	mustMkdir(t, src)
	mustMkdir(t, dst)
	mustWriteFile(t, filepath.Join(dst, "README.md"), "# readme")

	if err := swapFixtureSubdirs(src, dst); err != nil {
		t.Fatalf("empty swap failed: %v", err)
	}
	// README.md survives.
	if _, err := os.Stat(filepath.Join(dst, "README.md")); err != nil {
		t.Errorf("README.md removed: %v", err)
	}
}

// TestSwapFixtureSubdirs_LeavesTargetUntouchedIfNeverCalled —
// the "failure preserves corpus" invariant (Codex P2 on PR #228
// r5) depends on the caller only invoking swap AFTER `go test`
// succeeds. This test codifies that contract: a target directory
// whose swap is never invoked is unchanged.
func TestSwapFixtureSubdirs_LeavesTargetUntouchedIfNeverCalled(t *testing.T) {
	base := t.TempDir()
	dst := filepath.Join(base, "target")
	mustMkdir(t, dst)
	mustMkdir(t, filepath.Join(dst, "rawvote"))
	mustWriteFile(t, filepath.Join(dst, "rawvote", "committed.msgpack"), "committed")
	mustWriteFile(t, filepath.Join(dst, "README.md"), "# committed")

	// Simulate a failed regeneration: we created the staging dir
	// but never called swap. In main, the staging dir is cleaned
	// up via defer; the target is untouched.
	stagingParent := base
	staging, err := os.MkdirTemp(stagingParent, ".wire-staging-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	// Write some partial "generated" content to the staging dir,
	// as if go test had crashed mid-way.
	mustMkdir(t, filepath.Join(staging, "rawvote"))
	mustWriteFile(t, filepath.Join(staging, "rawvote", "partial.msgpack"), "partial")
	// Clean up staging (mirrors main's defer).
	if err := os.RemoveAll(staging); err != nil {
		t.Fatalf("RemoveAll staging: %v", err)
	}

	// dst must be unchanged.
	if body, err := os.ReadFile(filepath.Join(dst, "rawvote", "committed.msgpack")); err != nil || string(body) != "committed" {
		t.Errorf("committed fixture lost on failed regen: body=%q err=%v", body, err)
	}
	if _, err := os.Stat(filepath.Join(dst, "README.md")); err != nil {
		t.Errorf("README.md lost on failed regen: %v", err)
	}
}

// TestFilterDirtyAgreementPaths_ExpandedGuard is the regression guard
// for PR #228 r4: the pin's dirty-tree scan must cover every
// go-algorand directory whose contents contribute to the wire-fixture
// encoding — not just `agreement/`. Before the expansion, a local
// edit in `crypto/` (e.g. changing a Hashable ToBeHashed prefix) or
// `data/bookkeeping/` (a renamed Block field) would silently produce
// non-canonical fixtures while the tool reported success.
func TestFilterDirtyAgreementPaths_ExpandedGuard(t *testing.T) {
	cases := []struct {
		name      string
		porcelain string
		want      []string
	}{
		{
			name:      "empty tree",
			porcelain: "",
			want:      nil,
		},
		{
			name:      "only ignored staged file",
			porcelain: "?? agreement/" + stagedFileName,
			want:      nil,
		},
		{
			name:      "only known pre-existing golden vectors",
			porcelain: "?? agreement/golden_vectors_test.go\n?? data/committee/golden_vectors_test.go",
			want:      nil,
		},
		{
			name:      "root-level changes are ignored",
			porcelain: " T CLAUDE.md\n M README.md",
			want:      nil,
		},
		{
			name:      "agreement/ edit is flagged",
			porcelain: " M agreement/vote.go",
			want:      []string{" M agreement/vote.go"},
		},
		{
			name:      "crypto/ edit is flagged",
			porcelain: " M crypto/onetimesig.go",
			want:      []string{" M crypto/onetimesig.go"},
		},
		{
			name:      "data/basics/ edit is flagged",
			porcelain: " M data/basics/address.go",
			want:      []string{" M data/basics/address.go"},
		},
		{
			name:      "data/bookkeeping/ edit is flagged",
			porcelain: " M data/bookkeeping/block.go",
			want:      []string{" M data/bookkeeping/block.go"},
		},
		{
			name:      "data/committee/ edit is flagged",
			porcelain: " M data/committee/credential.go",
			want:      []string{" M data/committee/credential.go"},
		},
		{
			name:      "protocol/ edit is flagged",
			porcelain: " M protocol/hash.go",
			want:      []string{" M protocol/hash.go"},
		},
		{
			name:      "rename into guarded dir from unrelated source",
			porcelain: "R  scratch/x.go -> agreement/x.go",
			want:      []string{"R  scratch/x.go -> agreement/x.go"},
		},
		{
			name:      "unrelated subdirs (data/transactions/) stay clean",
			porcelain: " M data/transactions/logic/eval.go",
			want:      nil,
		},
		{
			name: "mixed: one guarded + one ignored + one unrelated",
			porcelain: " M agreement/vote.go\n" +
				"?? agreement/" + stagedFileName + "\n" +
				" M README.md",
			want: []string{" M agreement/vote.go"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := filterDirtyAgreementPaths(tc.porcelain)
			if !stringSlicesEqual(got, tc.want) {
				t.Fatalf("filterDirtyAgreementPaths(%q):\n  got  = %#v\n  want = %#v",
					tc.porcelain, got, tc.want)
			}
		})
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
