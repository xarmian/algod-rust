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

//! Conformance tests: Rust `MerkleTrie` root hash matches go-algorand
//! `crypto/merkletrie` byte-for-byte.
//!
//! Fixtures are produced by `tools/merkle-trie-root-capture` running against
//! go-algorand v4.6.0-stable's actual `crypto/merkletrie.MakeTrie` +
//! `Add` + `RootHash`. Each fixture records:
//!
//! - the input element bytes (in insertion order)
//! - the Go-computed 32-byte root hash
//!
//! We replay the inserts on a Rust `MerkleTrie` and assert the root matches.
//! This is the consensus-critical gate for PLAN-130: when this test passes,
//! the Rust trie's node structure, leaf-remainder storage, ancestor-chain
//! construction, and hash accumulator are all known to match Go.
//!
//! Scenarios covered by the fixture file:
//!
//! - `single-element`               — single-leaf-root invariant
//! - `two-element-split-byte-0`     — no shared prefix (no chain ancestors)
//! - `two-element-shared-byte-0..4` — 5-byte shared prefix (5 chain ancestors)
//! - `5-account-trie`               — TASK-134 deliverable: 5 mixed-prefix elements
//! - `100-account-trie`             — TASK-138 deliverable: 100 elements
//! - `1000-account-trie`            — TASK-138 deliverable: 1000 elements
//!   (the consensus-critical close-out gate for PLAN-130)
//!
//! Capture re-run: see the `merkle-trie-root-capture` package comment for
//! the sibling-checkout setup required to regenerate the fixture.
//!
//! Persistence: the `large_n_fixtures_round_trip_through_paged_committer`
//! test additionally drives the TASK-136 paged-persistence path with the
//! same fixtures — adding all elements, committing through an in-memory
//! [`InMemoryPageCommitter`], reloading via [`MerkleTrie::load`], and
//! asserting both the contents and the root hash match. This validates
//! that the cache + page format survive scale.

use std::path::PathBuf;

use algo_ledger::merkle_cache::InMemoryPageCommitter;
use algo_ledger::merkle_trie::MerkleTrie;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Fixture {
    name: String,
    element_count: usize,
    element_size: usize,
    elements_hex: Vec<String>,
    root_hex: String,
    /// Node-page count (page id ≥ 1) recorded by go-algorand's
    /// `merkleTrieCache::commit` for this scenario. Captured by
    /// `tools/merkle-trie-root-capture` with the production
    /// `MemoryConfig` (`PageFillFactor=0.95`,
    /// `MaxChildrenPagesThreshold=64`). PLAN-144 TASK-148: Rust must
    /// match within ±10%.
    page_count_after_commit: usize,
}

fn load_fixtures() -> Vec<Fixture> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("merkle_trie_roots")
        .join("roots.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read fixture file {}: {e}", path.display()));
    let fixtures: Vec<Fixture> = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("parse fixture file {}: {e}", path.display()));
    assert!(
        !fixtures.is_empty(),
        "expected at least one captured Go trie root in {}",
        path.display()
    );
    fixtures
}

/// Decode a hex string into a 32-byte root hash. Panics with `name` context
/// on malformed input.
fn decode_root(name: &str, hex_str: &str) -> [u8; 32] {
    let bytes =
        hex::decode(hex_str).unwrap_or_else(|e| panic!("scenario {name}: hex decode root: {e}"));
    let len = bytes.len();
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("scenario {name}: root must be 32 bytes, got {len}"))
}

#[test]
fn every_go_captured_root_matches_rust_trie() {
    let fixtures = load_fixtures();

    // Track each scenario we've checked, so the test output gives a complete
    // pass/fail picture rather than bailing on the first mismatch.
    let mut report: Vec<(String, bool, [u8; 32], [u8; 32])> = Vec::new();

    for fx in &fixtures {
        assert_eq!(
            fx.elements_hex.len(),
            fx.element_count,
            "scenario {}: elements_hex.len ({}) != element_count ({})",
            fx.name,
            fx.elements_hex.len(),
            fx.element_count
        );

        let mut trie = MerkleTrie::new(fx.element_size);
        for (i, hex_str) in fx.elements_hex.iter().enumerate() {
            let bytes = hex::decode(hex_str)
                .unwrap_or_else(|e| panic!("scenario {}: hex decode element[{i}]: {e}", fx.name));
            assert_eq!(
                bytes.len(),
                fx.element_size,
                "scenario {}: element[{i}] length {} != element_size {}",
                fx.name,
                bytes.len(),
                fx.element_size
            );
            let added = trie
                .add(&bytes)
                .unwrap_or_else(|e| panic!("scenario {}: add element[{i}]: {e}", fx.name));
            assert!(
                added,
                "scenario {}: element[{i}] reported as duplicate — fixture inputs must be unique",
                fx.name
            );
        }

        let expected = decode_root(&fx.name, &fx.root_hex);
        let actual = trie
            .root_hash()
            .unwrap_or_else(|e| panic!("scenario {}: root_hash: {e}", fx.name));
        let matched = actual == expected;
        report.push((fx.name.clone(), matched, expected, actual));
    }

    let failures: Vec<&(String, bool, [u8; 32], [u8; 32])> =
        report.iter().filter(|(_, ok, _, _)| !ok).collect();

    if !failures.is_empty() {
        let mut msg = String::from("\nMerkle trie root hash mismatch vs. go-algorand:\n");
        for (name, _, expected, actual) in &failures {
            msg.push_str(&format!(
                "  scenario {name}:\n    go-algorand expected: {}\n    rust actual:         {}\n",
                hex::encode(expected),
                hex::encode(actual),
            ));
        }
        msg.push_str(&format!(
            "\n{} of {} scenarios matched.\n",
            report.len() - failures.len(),
            report.len(),
        ));
        panic!("{msg}");
    }
}

/// Sanity check: a single-leaf trie's root must equal
/// `SHA512_256(0x00 || element)` per Go's `RootHash` at `trie.go:130`. This
/// duplicates the unit test in `merkle_trie::tests` but uses the actual Go-
/// captured fixture element, which proves the fixture loader is wiring up
/// the test correctly (i.e. a green `every_go_captured_root_matches_rust_trie`
/// can't trivially pass via empty inputs).
#[test]
fn single_element_fixture_matches_manual_hash() {
    use sha2::{Digest, Sha512_256};

    let fixtures = load_fixtures();
    let single = fixtures
        .iter()
        .find(|f| f.name == "single-element")
        .expect("fixture must contain a `single-element` scenario");
    assert_eq!(single.element_count, 1, "single-element must have 1 entry");

    let elem = hex::decode(&single.elements_hex[0]).expect("decode element");
    let mut hasher = Sha512_256::new();
    hasher.update([0x00]);
    hasher.update(&elem);
    let manual = hasher.finalize();

    let expected = decode_root(&single.name, &single.root_hex);
    assert_eq!(
        manual[..],
        expected[..],
        "go-algorand fixture root must equal SHA512_256(0x00 || element)"
    );

    // And of course the Rust trie must agree.
    let mut trie = MerkleTrie::new(single.element_size);
    trie.add(&elem).unwrap();
    assert_eq!(trie.root_hash().unwrap(), expected);
}

/// PLAN-144 TASK-148: post-commit node-page count must match Go's
/// recorded count within ±10%, proving the `reallocatePendingPages`
/// page-packing heuristic is correctly ported. Without the heuristic
/// Rust packs less tightly than Go (lower fill factor → more pages);
/// with it, the page count should agree across implementations.
#[test]
fn page_packing_matches_go_within_tolerance() {
    use algo_ledger::merkle_cache::InMemoryPageCommitter;

    let fixtures = load_fixtures();
    let mut report: Vec<(String, usize, usize, bool)> = Vec::new();

    for fx in &fixtures {
        let mut trie = MerkleTrie::new(fx.element_size);
        for (i, h) in fx.elements_hex.iter().enumerate() {
            let bytes = hex::decode(h)
                .unwrap_or_else(|e| panic!("scenario {}: hex decode[{i}]: {e}", fx.name));
            trie.add(&bytes)
                .unwrap_or_else(|e| panic!("scenario {}: add[{i}]: {e}", fx.name));
        }
        let committer = InMemoryPageCommitter::new();
        trie.commit(&committer)
            .unwrap_or_else(|e| panic!("scenario {}: commit: {e}", fx.name));
        // page_count() includes the metadata page (page 0); subtract
        // to align with the Go fixture's node-page-only count.
        let rust_node_pages = committer.page_count().saturating_sub(1);
        let go_node_pages = fx.page_count_after_commit;

        // ±10% tolerance, with a floor of 1 so the tiny scenarios
        // (1–5 elements) don't fail on a single-page rounding gap.
        let tolerance = ((go_node_pages as f64 * 0.10).ceil() as usize).max(1);
        let lo = go_node_pages.saturating_sub(tolerance);
        let hi = go_node_pages + tolerance;
        let ok = (lo..=hi).contains(&rust_node_pages);
        report.push((fx.name.clone(), go_node_pages, rust_node_pages, ok));
    }

    let failures: Vec<&(String, usize, usize, bool)> =
        report.iter().filter(|(_, _, _, ok)| !ok).collect();
    if !failures.is_empty() {
        let mut msg =
            String::from("\nMerkle trie page-count divergence vs. go-algorand (>10% tolerance):\n");
        for (name, go, rust, _) in &failures {
            msg.push_str(&format!(
                "  scenario {name}: go={go} rust={rust} (diff={diff})\n",
                diff = (*rust as i64 - *go as i64).abs(),
            ));
        }
        msg.push_str(&format!(
            "\n{}/{} scenarios within ±10% of Go.\n",
            report.len() - failures.len(),
            report.len(),
        ));
        panic!("{msg}");
    }
}

/// TASK-138 close-out: drive every fixture through the
/// commit-then-load round trip via the paged persistence layer added
/// by TASK-136. This validates that:
///
/// 1. The trie can be built up to ≥ 1000 elements without errors.
/// 2. The page format survives scale — committing 1000 elements
///    produces pages that re-load into a structurally-identical trie.
/// 3. The root hash matches the Go reference both before commit
///    (in-memory) and after a load (from the persisted bytes).
/// 4. `contains` returns true for every input element after the
///    round trip.
#[test]
fn large_n_fixtures_round_trip_through_paged_committer() {
    let fixtures = load_fixtures();

    let mut report: Vec<(String, bool, [u8; 32], [u8; 32])> = Vec::new();

    for fx in &fixtures {
        let committer = InMemoryPageCommitter::new();

        // Build trie, commit, then reload from the committer.
        let mut trie = MerkleTrie::new(fx.element_size);
        let elements: Vec<Vec<u8>> = fx
            .elements_hex
            .iter()
            .map(|h| hex::decode(h).expect("hex"))
            .collect();
        for (i, e) in elements.iter().enumerate() {
            let added = trie
                .add(e)
                .unwrap_or_else(|err| panic!("scenario {}: add[{i}]: {err}", fx.name));
            assert!(
                added,
                "scenario {}: element[{i}] unexpectedly duplicate",
                fx.name
            );
        }
        let in_memory_root = trie
            .root_hash()
            .unwrap_or_else(|e| panic!("scenario {}: root_hash: {e}", fx.name));
        trie.commit(&committer)
            .unwrap_or_else(|e| panic!("scenario {}: commit: {e}", fx.name));

        // Reload from disk via lazy loader (PLAN-144 TASK-146).
        let mut restored = MerkleTrie::load(Box::new(committer.clone()))
            .unwrap_or_else(|e| panic!("scenario {}: load: {e}", fx.name))
            .unwrap_or_else(|| panic!("scenario {}: load returned None after commit", fx.name));

        for (i, e) in elements.iter().enumerate() {
            assert!(
                restored
                    .contains(e)
                    .unwrap_or_else(|err| panic!("scenario {}: contains[{i}]: {err}", fx.name)),
                "scenario {}: reloaded trie missing element[{i}]",
                fx.name
            );
        }

        // After walking every element via `contains`, every leaf page is
        // lazy-loaded; the leaf-count assertion is then meaningful.
        assert_eq!(
            restored.len(),
            elements.len(),
            "scenario {}: reload len mismatch ({} vs {}) after lazy walk",
            fx.name,
            restored.len(),
            elements.len()
        );

        let restored_root = restored
            .root_hash()
            .unwrap_or_else(|e| panic!("scenario {}: restored root_hash: {e}", fx.name));
        assert_eq!(
            in_memory_root, restored_root,
            "scenario {}: in-memory root does not match reloaded root",
            fx.name
        );

        let expected = decode_root(&fx.name, &fx.root_hex);
        report.push((
            fx.name.clone(),
            restored_root == expected,
            expected,
            restored_root,
        ));
    }

    let failures: Vec<&(String, bool, [u8; 32], [u8; 32])> =
        report.iter().filter(|(_, ok, _, _)| !ok).collect();

    if !failures.is_empty() {
        let mut msg = String::from(
            "\nreloaded-trie root hash mismatch vs. go-algorand (TASK-138 close-out):\n",
        );
        for (name, _, expected, actual) in &failures {
            msg.push_str(&format!(
                "  scenario {name}:\n    go-algorand expected: {}\n    rust after reload:   {}\n",
                hex::encode(expected),
                hex::encode(actual),
            ));
        }
        msg.push_str(&format!(
            "\n{} of {} scenarios matched.\n",
            report.len() - failures.len(),
            report.len(),
        ));
        panic!("{msg}");
    }
}
