package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestClearFixtureSubdirs_OnlyTouchesAllowlistedDirs is the P1
// regression guard for PR #228 r2: `clearFixtureSubdirs` must remove
// only the allowlisted fixture subdirectories and leave everything
// else alone. Otherwise, a user who passed `--out /tmp` (or worse)
// could have unrelated data wiped before generation even runs.
func TestClearFixtureSubdirs_OnlyTouchesAllowlistedDirs(t *testing.T) {
	tmp := t.TempDir()

	// Fixture subdirs we own — must be removed.
	ownedSubdirs := []string{"rawvote", "uvote", "vote", "ubundle"}
	for _, s := range ownedSubdirs {
		mustMkdir(t, filepath.Join(tmp, s))
		mustWriteFile(t, filepath.Join(tmp, s, "stale.msgpack"), "stale")
	}

	// Non-owned directory — must be preserved.
	mustMkdir(t, filepath.Join(tmp, "user_scratch"))
	mustWriteFile(t, filepath.Join(tmp, "user_scratch", "precious.txt"), "keep me")

	// Top-level file — must be preserved.
	mustWriteFile(t, filepath.Join(tmp, "README.md"), "# fixtures")

	if err := clearFixtureSubdirs(tmp); err != nil {
		t.Fatalf("clearFixtureSubdirs: %v", err)
	}

	for _, s := range ownedSubdirs {
		if _, err := os.Stat(filepath.Join(tmp, s)); !os.IsNotExist(err) {
			t.Errorf("owned subdir %q should be removed, got err=%v", s, err)
		}
	}
	if _, err := os.Stat(filepath.Join(tmp, "user_scratch")); err != nil {
		t.Errorf("non-owned subdir %q was removed (err=%v), expected preserved", "user_scratch", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "user_scratch", "precious.txt")); err != nil {
		t.Errorf("non-owned file was removed (err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "README.md")); err != nil {
		t.Errorf("top-level README.md was removed (err=%v)", err)
	}
}

// TestClearFixtureSubdirs_NoOpWhenEmpty — clearing a directory that
// has none of the allowlisted subdirs must succeed silently. This
// matches the first-time-after-fresh-checkout case.
func TestClearFixtureSubdirs_NoOpWhenEmpty(t *testing.T) {
	tmp := t.TempDir()
	// A completely empty dir.
	if err := clearFixtureSubdirs(tmp); err != nil {
		t.Fatalf("empty dir clear failed: %v", err)
	}
	// And a dir with only non-owned contents.
	mustMkdir(t, filepath.Join(tmp, "other"))
	mustWriteFile(t, filepath.Join(tmp, "README.md"), "# fixtures")
	if err := clearFixtureSubdirs(tmp); err != nil {
		t.Fatalf("non-owned-only clear failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "other")); err != nil {
		t.Errorf("non-owned dir removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "README.md")); err != nil {
		t.Errorf("README.md removed: %v", err)
	}
}

// TestClearFixtureSubdirs_RefusesToRemoveFileAtSubdirPath — if
// somebody (or a buggy `mkdir` race) left a regular file at what
// should be a fixture subdirectory path, we refuse to remove it and
// surface the surprise rather than silently deleting the user's file.
func TestClearFixtureSubdirs_RefusesToRemoveFileAtSubdirPath(t *testing.T) {
	tmp := t.TempDir()
	mustWriteFile(t, filepath.Join(tmp, "rawvote"), "oops: this is a file, not a dir")

	err := clearFixtureSubdirs(tmp)
	if err == nil {
		t.Fatalf("expected error when subdir path is a regular file, got nil")
	}
	// The file must still be there; error must have been returned
	// BEFORE any removal attempt.
	if _, statErr := os.Stat(filepath.Join(tmp, "rawvote")); statErr != nil {
		t.Errorf("file at subdir path was removed despite error: %v", statErr)
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
