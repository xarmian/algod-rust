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
