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

// merkle-page-capture: emit Go-encoded `accounthashes`-style trie pages
// as JSON fixtures consumed by the Rust merkle-page round-trip tests in
// `crates/core/algo-ledger/tests/merkle_page_fixture_test.rs`.
//
// Output schema:
//   [
//     {
//       "name": "small-leaves",
//       "page_id": 1,
//       "bytes_hex": "0a0b...",
//       "node_count": 5,
//       "description": "five 32-byte leaves, no internal nodes"
//     },
//     ...
//   ]
//
// References (go-algorand v4.6.0-stable, commit a8c16ecc):
//   crypto/merkletrie/cache.go:660-704 — decodePage / encodePage
//   crypto/merkletrie/node.go:312-373  — node.serialize / deserializeNode
//   crypto/merkletrie/trie.go:32       — nodePageVersion
//   ledger/store/trackerdb/catchpoint.go:42 — MerkleCommitterNodesPerPage = 116
//
// Reproducible setup:
//
// The `replace` directive in `go.mod` resolves to `../../../go-algorand`
// relative to this tool's directory, which is the parent of the
// `algod-rust` repo root. From a fresh `git clone` of `algod-rust`:
//
//  1. Check out go-algorand as a sibling of `algod-rust`:
//
//         # from $REPO_PARENT (the directory that contains algod-rust/)
//         git clone --depth 1 --branch v4.6.0-stable \
//             https://github.com/algorand/go-algorand.git
//         # resulting layout:
//         #   $REPO_PARENT/algod-rust/
//         #   $REPO_PARENT/go-algorand/
//
//  2. Build and run from this tool's directory:
//
//         cd algod-rust/tools/merkle-page-capture
//         go run . > \
//             ../../crates/core/algo-ledger/tests/fixtures/merkle_pages/pages.json
//
// `go.mod` carries a `replace` directive pointing at that sibling
// checkout, mirroring `tools/lookback-vector-capture` and the other
// vector-capture tools in this repo. Without the sibling checkout the
// build fails fast at `go run` time — that's intentional, because the
// alternative (publishing a forked module) would unpin the version we
// claim to cross-reference: v4.6.0-stable, commit
// a8c16ecc2324cc10acb75de367c0b5dad4b0a5a3, dated 2026-02-09.
//
// Determinism: the fixture is generated from a fixed sequence of
// hashes (the same i-byte triples Go's own committer_test.go uses) so
// the byte output is reproducible. The actual page-byte layout still
// reflects go-algorand's runtime map iteration order — pages can come
// out in different node orderings, but the Rust decoder is
// order-insensitive, so round-trip equality is asserted at the page
// level, not at the byte level.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merkletrie"
)

// pageCapturer is a merkletrie.Committer that captures the raw page
// bytes written during Commit(). It also satisfies LoadPage so the trie
// can re-read pages while it commits.
type pageCapturer struct {
	pages map[uint64][]byte
}

func newPageCapturer() *pageCapturer { return &pageCapturer{pages: map[uint64][]byte{}} }

func (p *pageCapturer) StorePage(page uint64, content []byte) error {
	if content == nil {
		delete(p.pages, page)
		return nil
	}
	// Copy: the trie may reuse its serialization buffer.
	buf := make([]byte, len(content))
	copy(buf, content)
	p.pages[page] = buf
	return nil
}

func (p *pageCapturer) LoadPage(page uint64) ([]byte, error) {
	return p.pages[page], nil
}

type fixture struct {
	Name        string `json:"name"`
	PageID      uint64 `json:"page_id"`
	BytesHex    string `json:"bytes_hex"`
	NodeCount   int    `json:"node_count"`
	Description string `json:"description"`
}

func main() {
	memoryConfig := merkletrie.MemoryConfig{
		NodesCountPerPage:         116, // production page size — trackerdb.MerkleCommitterNodesPerPage
		CachedNodesCount:          9000,
		PageFillFactor:            0.95,
		MaxChildrenPagesThreshold: 64,
	}

	// Three scenarios that exercise:
	//   1. A small tree producing one page with a few leaves.
	//   2. A medium tree that splits across multiple pages with
	//      internal nodes (the interesting per-node format).
	//   3. A full-page case to verify large-buffer handling.
	scenarios := []struct {
		name        string
		description string
		count       int
	}{
		{"small-leaves", "8 fixed-seed 32-byte hashes, one page", 8},
		{"split-pages", "200 hashes, splits across ~2 pages of leaves + branches", 200},
		{"full-page", "1024 hashes, exercises multi-page commits", 1024},
	}

	var out []fixture
	for _, sc := range scenarios {
		hashes := make([]crypto.Digest, sc.count)
		for i := range hashes {
			hashes[i] = crypto.Hash([]byte{byte(i & 0xff), byte((i >> 8) & 0xff), byte((i >> 16) & 0xff)})
		}

		committer := newPageCapturer()
		trie, err := merkletrie.MakeTrie(committer, memoryConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "MakeTrie failed: %v\n", err)
			os.Exit(1)
		}
		for _, h := range hashes {
			if _, err := trie.Add(h[:]); err != nil {
				fmt.Fprintf(os.Stderr, "trie.Add failed: %v\n", err)
				os.Exit(1)
			}
		}
		if _, err := trie.Commit(); err != nil {
			fmt.Fprintf(os.Stderr, "trie.Commit failed: %v\n", err)
			os.Exit(1)
		}

		// Sort page IDs for stable output. Skip page 0 — that page is
		// the root-meta page and uses the (separate) trie-level
		// serialization, not encodePage; covered by trie.go's
		// `serialize` / `deserialize` rather than this fixture set.
		ids := make([]uint64, 0, len(committer.pages))
		for id := range committer.pages {
			if id == 0 {
				continue
			}
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

		for _, id := range ids {
			bytes := committer.pages[id]
			// Per scenario, emit at most 3 pages to keep fixture size
			// bounded; the Rust test iterates all of them.
			out = append(out, fixture{
				Name:        fmt.Sprintf("%s-page-%d", sc.name, id),
				PageID:      id,
				BytesHex:    hex.EncodeToString(bytes),
				NodeCount:   countNodesInPage(bytes),
				Description: sc.description,
			})
		}
	}

	if len(out) < 3 {
		fmt.Fprintf(os.Stderr, "captured %d pages, expected at least 3 — fixture would be too small\n", len(out))
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "JSON encode failed: %v\n", err)
		os.Exit(1)
	}
}

// countNodesInPage reads only the page header (version + node count)
// to populate fixture.NodeCount as a sanity signal for the Rust test.
// Mirrors the inline logic in committer_test.go's decodePageHeaderSize.
func countNodesInPage(buf []byte) int {
	var version uint64
	var shift uint
	i := 0
	for {
		if i >= len(buf) {
			return -1
		}
		b := buf[i]
		i++
		if b < 0x80 {
			version |= uint64(b) << shift
			break
		}
		version |= uint64(b&0x7f) << shift
		shift += 7
	}
	// Versions sanity: must match nodePageVersion.
	const nodePageVersion = uint64(0x1000000010000000)
	if version != nodePageVersion {
		return -1
	}
	// Read signed varint for node count (zigzag).
	var ux uint64
	shift = 0
	for {
		if i >= len(buf) {
			return -1
		}
		b := buf[i]
		i++
		if b < 0x80 {
			ux |= uint64(b) << shift
			break
		}
		ux |= uint64(b&0x7f) << shift
		shift += 7
	}
	x := int64(ux >> 1)
	if ux&1 == 1 {
		x = -(x + 1)
	}
	return int(x)
}
