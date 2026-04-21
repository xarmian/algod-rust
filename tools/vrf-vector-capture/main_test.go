package main

import (
	"reflect"
	"testing"
)

// TestFilterDirtyPaths_RenamesBothSides specifically guards the PR-#225 /
// Codex P2 regression: a rename INTO crypto/ from an unrelated directory must
// be flagged, not silently dropped as "not in crypto/".
func TestFilterDirtyPaths_RenamesBothSides(t *testing.T) {
	cases := []struct {
		name       string
		porcelain  string
		prefixes   []string
		wantDirty  []string
	}{
		{
			name:      "empty tree",
			porcelain: "",
			prefixes:  []string{"crypto/", "protocol/"},
			wantDirty: nil,
		},
		{
			name:      "unrelated modification",
			porcelain: " M README.md\n?? tmp.log",
			prefixes:  []string{"crypto/", "protocol/"},
			wantDirty: nil,
		},
		{
			name:      "in-place crypto modification",
			porcelain: " M crypto/vrf.go",
			prefixes:  []string{"crypto/", "protocol/"},
			wantDirty: []string{" M crypto/vrf.go"},
		},
		{
			name:      "in-place protocol modification",
			porcelain: "M  protocol/hash.go",
			prefixes:  []string{"crypto/", "protocol/"},
			wantDirty: []string{"M  protocol/hash.go"},
		},
		{
			// The exact bypass Codex flagged: file renamed FROM an
			// unrelated directory INTO crypto/. Naive prefix match on the
			// raw "other/x -> crypto/x" body would miss it because the body
			// starts with "other/".
			name:      "rename INTO crypto/ from unrelated dir",
			porcelain: "R  other/x.go -> crypto/x.go",
			prefixes:  []string{"crypto/", "protocol/"},
			wantDirty: []string{"R  other/x.go -> crypto/x.go"},
		},
		{
			// Symmetric: rename OUT OF crypto/ also changes the tree under
			// crypto/ (a file disappeared from it), so it must be flagged.
			name:      "rename OUT OF crypto/ to unrelated dir",
			porcelain: "R  crypto/x.go -> other/x.go",
			prefixes:  []string{"crypto/", "protocol/"},
			wantDirty: []string{"R  crypto/x.go -> other/x.go"},
		},
		{
			name:      "copy INTO protocol/",
			porcelain: "C  shared/h.go -> protocol/h.go",
			prefixes:  []string{"crypto/", "protocol/"},
			wantDirty: []string{"C  shared/h.go -> protocol/h.go"},
		},
		{
			name:      "quoted path with space renamed into crypto/",
			porcelain: `R  "other/with space.go" -> "crypto/with space.go"`,
			prefixes:  []string{"crypto/", "protocol/"},
			wantDirty: []string{`R  "other/with space.go" -> "crypto/with space.go"`},
		},
		{
			name:      "untracked file under crypto/",
			porcelain: "?? crypto/new.go",
			prefixes:  []string{"crypto/", "protocol/"},
			wantDirty: []string{"?? crypto/new.go"},
		},
		{
			name:      "mixed entries keeps only flagged ones",
			porcelain: " M README.md\n?? agreement/notes.txt\n M crypto/vrf.go\nR  other/y.go -> crypto/y.go",
			prefixes:  []string{"crypto/", "protocol/"},
			wantDirty: []string{" M crypto/vrf.go", "R  other/y.go -> crypto/y.go"},
		},
		{
			// PR-#225 round-3 Codex P2: a source filename literally
			// containing " -> " is quoted by git, and a naive
			// strings.Index(body, " -> ") would split inside the quoted
			// name — producing a "destination" that doesn't start with
			// crypto/ and bypassing the guard. splitRename must ignore
			// separators inside quoted tokens.
			name:      "rename with literal ' -> ' in quoted source",
			porcelain: `R  "other/a -> b.go" -> crypto/c.go`,
			prefixes:  []string{"crypto/", "protocol/"},
			wantDirty: []string{`R  "other/a -> b.go" -> crypto/c.go`},
		},
		{
			// Symmetric: both tokens quoted, destination under protocol/.
			name:      "rename with literal ' -> ' in quoted source, quoted dst",
			porcelain: `R  "other/a -> b.go" -> "protocol/c d.go"`,
			prefixes:  []string{"crypto/", "protocol/"},
			wantDirty: []string{`R  "other/a -> b.go" -> "protocol/c d.go"`},
		},
		{
			// Escaped double-quote inside a quoted path must NOT close the
			// quoted region prematurely (would otherwise surface a bogus
			// " -> " split right after the escaped quote).
			name:      "rename with escaped quote in quoted source",
			porcelain: `R  "weird\"name -> notreally.go" -> crypto/real.go`,
			prefixes:  []string{"crypto/", "protocol/"},
			wantDirty: []string{`R  "weird\"name -> notreally.go" -> crypto/real.go`},
		},
		{
			// Benign quoted paths with neither side touching guarded dirs
			// must NOT be flagged — guards against an over-eager fix that
			// loses selectivity.
			name:      "rename with literal ' -> ' but neither side under guarded dir",
			porcelain: `R  "a -> b.go" -> "c -> d.go"`,
			prefixes:  []string{"crypto/", "protocol/"},
			wantDirty: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := filterDirtyPaths(tc.porcelain, tc.prefixes)
			if !reflect.DeepEqual(got, tc.wantDirty) {
				t.Fatalf("filterDirtyPaths(%q):\n  got  = %#v\n  want = %#v", tc.porcelain, got, tc.wantDirty)
			}
		})
	}
}

// TestSplitRename verifies the quote-aware rename splitter directly, so a
// regression in splitRename is localized even if filterDirtyPaths itself is
// refactored later.
func TestSplitRename(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantSrc  string
		wantDst  string
		wantOK   bool
	}{
		{"bare", "a -> b", "a", "b", true},
		{"no separator", "a b c", "", "", false},
		{"empty", "", "", "", false},
		{"quoted src+dst", `"a" -> "b"`, `"a"`, `"b"`, true},
		{
			"arrow in quoted src",
			`"a -> b.go" -> c.go`,
			`"a -> b.go"`, `c.go`, true,
		},
		{
			"arrow in quoted dst",
			`a.go -> "c -> d.go"`,
			`a.go`, `"c -> d.go"`, true,
		},
		{
			"escaped quote in quoted src",
			`"a\"x -> y.go" -> b.go`,
			`"a\"x -> y.go"`, `b.go`, true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src, dst, ok := splitRename(tc.body)
			if ok != tc.wantOK || src != tc.wantSrc || dst != tc.wantDst {
				t.Fatalf("splitRename(%q):\n  got  = (%q, %q, %v)\n  want = (%q, %q, %v)",
					tc.body, src, dst, ok, tc.wantSrc, tc.wantDst, tc.wantOK)
			}
		})
	}
}
