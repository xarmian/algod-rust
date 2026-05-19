// trie-element-capture: emit Go-computed 36-byte Merkle trie element bytes
// for fixed (affinity, kind, prehash) inputs by invoking the authoritative
// go-algorand builders directly, as JSON fixtures consumed by the Rust
// trie-element layout test in `crates/core/algo-ledger/src/trie_hash.rs`
// (under `#[cfg(test)]`).
//
// Output schema:
//
//	[
//	  {
//	    "name": "account-defaults",
//	    "affinity": 0,
//	    "kind": 0,
//	    "prehash_hex": "...",
//	    "element_hex": "..."
//	  },
//	  ...
//	]
//
// References (go-algorand v4.5.1-stable):
//
//	ledger/store/trackerdb/hashing.go:64-78   — AccountHashBuilderV6
//	ledger/store/trackerdb/hashing.go:81-95   — ResourcesHashBuilderV6
//	ledger/store/trackerdb/hashing.go:107-115 — KvHashBuilderV6
//	ledger/store/trackerdb/hashing.go:117-128 — hashBufV6 (affinity+kind prefix)
//	ledger/store/trackerdb/hashing.go:130-135 — finishV6 (SHA tail)
//
// Reproducible setup:
//
// The `replace` directive in `go.mod` resolves to `../../../go-algorand`
// relative to this tool's directory, which is the parent of the
// `algod-rust` repo root. From a fresh `git clone` of `algod-rust`:
//
//  1. Check out go-algorand as a sibling of `algod-rust`:
//
//         git clone --depth 1 --branch v4.5.1-stable \
//             https://github.com/algorand/go-algorand.git
//
//  2. Build and run:
//
//         cd algod-rust/tools/trie-element-capture
//         go run . > \
//             ../../crates/core/algo-ledger/tests/fixtures/merkle_trie_elements/elements.json
//
// Layout test scope (PLAN-130 TASK-135):
//
// Each scenario records the logical inputs (the address, creatable index,
// resource blob, key/value, etc.) AND the prehash bytes that those inputs
// would be composed into by the matching Go builder. The Rust test feeds
// the prehash bytes into Rust's `finish_v6` helper and asserts byte-exact
// equality against the element_hex field, which itself was produced by
// invoking the authoritative go-algorand `AccountHashBuilderV6` /
// `ResourcesHashBuilderV6` / `KvHashBuilderV6` (whose finishV6 sub-call
// is the byte-exact target).
//
// This isolates the (affinity, kind, prehash) → 36-byte element step from
// any encoder concerns. Encoder correctness (Rust `encode_account_data`
// vs Go `protocol.Encode` for non-trivial AccountData) is out of scope
// here and is verified by other fixture-driven tests in the workspace.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
)

// HashKind constants — must match
// `ledger/store/trackerdb/hashing.go:39-43` AccountHK/AssetHK/AppHK/KvHK.
const (
	hashKindAccount = 0
	hashKindAsset   = 1
	hashKindApp     = 2
	hashKindKv      = 3
)

type fixture struct {
	Name       string `json:"name"`
	Affinity   uint32 `json:"affinity"`
	Kind       int    `json:"kind"`
	PrehashHex string `json:"prehash_hex"`
	ElementHex string `json:"element_hex"`
}

func main() {
	var out []fixture

	// -----------------------------------------------------------------------
	// account-defaults
	//
	// Inputs:
	//   addr = [32]byte{} (all zeros)
	//   accountData = &trackerdb.BaseAccountData{} (default zero-value)
	//   encodedAccountData = []byte{0x80} (msgpack empty map, the
	//     canonical encoding for an all-omitempty default struct)
	//
	// AccountHashBuilderV6 composes prehash = addr || encodedAccountData
	// internally (hashing.go:73-75), then calls finishV6 with affinity=0
	// (both UpdateRound and RewardsBase are zero in defaults).
	// -----------------------------------------------------------------------
	{
		var addr basics.Address // all zeros
		// Force the canonical empty-map encoding directly. Using a
		// pre-known msgpack literal here avoids the test depending on
		// protocol.Encode's exact output for &BaseAccountData{} (which
		// is verified separately by the encoder fixture tests).
		encoded := []byte{0x80}

		element := trackerdb.AccountHashBuilderV6(addr, &trackerdb.BaseAccountData{}, encoded)
		if len(element) != 36 {
			fmt.Fprintf(os.Stderr, "account-defaults: unexpected element len %d\n", len(element))
			os.Exit(1)
		}
		prehash := append(addr[:], encoded...)
		out = append(out, fixture{
			Name:       "account-defaults",
			Affinity:   0,
			Kind:       hashKindAccount,
			PrehashHex: hex.EncodeToString(prehash),
			ElementHex: hex.EncodeToString(element),
		})
	}

	// -----------------------------------------------------------------------
	// resource-asset
	//
	// Inputs:
	//   addr = [32]byte{0x03, 0x03, ...}
	//   cidx = 42
	//   updateRound = 200 (becomes the affinity prefix)
	//   encodedResourceData = []byte("fake_asset_resource_blob")
	//   rd is configured as an asset so HashKind = AssetHK (1).
	//
	// ResourcesHashBuilderV6 composes prehash = addr || cidx_LE ||
	// encodedResourceData (hashing.go:89-92), then calls finishV6 with
	// affinity = updateRound truncated to u32.
	// -----------------------------------------------------------------------
	{
		var addr basics.Address
		for i := range addr {
			addr[i] = 0x03
		}
		cidx := basics.CreatableIndex(42)
		updateRound := uint64(200)
		encoded := []byte("fake_asset_resource_blob")

		// Build a minimal ResourcesData that classifies as an asset.
		// rdGetCreatableHashKind dispatches on rd.IsAsset()/IsApp()
		// (hashing.go:97-104). Setting AssetParams Total > 0 (or
		// equivalently any field that makes IsAsset() return true) is
		// sufficient. We use SetAssetParams with non-empty params.
		rd := trackerdb.MakeResourcesData(updateRound)
		rd.SetAssetParams(basics.AssetParams{Total: 1, UnitName: "x"}, true)

		element, err := trackerdb.ResourcesHashBuilderV6(&rd, addr, cidx, updateRound, encoded)
		if err != nil {
			fmt.Fprintf(os.Stderr, "resource-asset: %v\n", err)
			os.Exit(1)
		}
		if len(element) != 36 {
			fmt.Fprintf(os.Stderr, "resource-asset: unexpected element len %d\n", len(element))
			os.Exit(1)
		}

		prehash := make([]byte, 0, 32+8+len(encoded))
		prehash = append(prehash, addr[:]...)
		var cidxLE [8]byte
		binary.LittleEndian.PutUint64(cidxLE[:], uint64(cidx))
		prehash = append(prehash, cidxLE[:]...)
		prehash = append(prehash, encoded...)
		out = append(out, fixture{
			Name:       "resource-asset",
			Affinity:   uint32(updateRound),
			Kind:       hashKindAsset,
			PrehashHex: hex.EncodeToString(prehash),
			ElementHex: hex.EncodeToString(element),
		})
	}

	// -----------------------------------------------------------------------
	// resource-app
	//
	// Same shape as resource-asset but with IsApp() = true so HashKind
	// = AppHK (2).
	// -----------------------------------------------------------------------
	{
		var addr basics.Address
		for i := range addr {
			addr[i] = 0x05
		}
		cidx := basics.CreatableIndex(99)
		updateRound := uint64(10)
		encoded := []byte("fake_app_blob")

		rd := trackerdb.MakeResourcesData(updateRound)
		rd.SetAppParams(basics.AppParams{
			ApprovalProgram:   []byte{0x01},
			ClearStateProgram: []byte{0x01},
		}, true)

		element, err := trackerdb.ResourcesHashBuilderV6(&rd, addr, cidx, updateRound, encoded)
		if err != nil {
			fmt.Fprintf(os.Stderr, "resource-app: %v\n", err)
			os.Exit(1)
		}

		prehash := make([]byte, 0, 32+8+len(encoded))
		prehash = append(prehash, addr[:]...)
		var cidxLE [8]byte
		binary.LittleEndian.PutUint64(cidxLE[:], uint64(cidx))
		prehash = append(prehash, cidxLE[:]...)
		prehash = append(prehash, encoded...)
		out = append(out, fixture{
			Name:       "resource-app",
			Affinity:   uint32(updateRound),
			Kind:       hashKindApp,
			PrehashHex: hex.EncodeToString(prehash),
			ElementHex: hex.EncodeToString(element),
		})
	}

	// -----------------------------------------------------------------------
	// kv-simple
	//
	// KvHashBuilderV6: affinity = 0, kind = KvHK, prehash = key || value.
	// -----------------------------------------------------------------------
	{
		key := "bx:\x00\x00\x00\x00\x00\x00\x00\x2amybox"
		value := []byte("hello world")

		element := trackerdb.KvHashBuilderV6(key, value)

		prehash := append([]byte(key), value...)
		out = append(out, fixture{
			Name:       "kv-simple",
			Affinity:   0,
			Kind:       hashKindKv,
			PrehashHex: hex.EncodeToString(prehash),
			ElementHex: hex.EncodeToString(element),
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "JSON encode failed: %v\n", err)
		os.Exit(1)
	}
}
