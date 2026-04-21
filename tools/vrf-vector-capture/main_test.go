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
