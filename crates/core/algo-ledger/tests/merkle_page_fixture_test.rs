//! Fixture-driven round-trip tests for the merkle-page (de)serializer.
//!
//! Bytes are produced by `tools/merkle-page-capture` running against
//! go-algorand v4.6.0-stable's actual `crypto/merkletrie` package
//! (`MakeTrie` + `InMemoryCommitter` + `Commit`). We capture the
//! exact byte payloads `StorePage` saw and assert that:
//!
//! 1. `Page::deserialize` accepts every Go-produced page.
//! 2. The decoded `Page` re-serializes to a byte string that
//!    `Page::deserialize` accepts and that round-trips back to the
//!    same Page (i.e. encoder ↔ decoder are inverses).
//!
//! We do NOT assert byte-for-byte equality between Go's bytes and
//! Rust's bytes: Go iterates the node map in unspecified order, so a
//! page with N>1 nodes is encoded under whatever order Go's map
//! iterator chose. Both encodings are valid per the format spec, and
//! both decode to the same Page; that's what we verify.

use std::collections::BTreeMap;
use std::path::PathBuf;

use algo_ledger::merkle_page::{Page, NODE_PAGE_VERSION};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Fixture {
    name: String,
    page_id: u64,
    bytes_hex: String,
    node_count: i64,
    description: String,
}

fn load_fixtures() -> Vec<Fixture> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("merkle_pages")
        .join("pages.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read fixture file {}: {e}", path.display()));
    let fixtures: Vec<Fixture> = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("parse fixture file {}: {e}", path.display()));
    assert!(
        fixtures.len() >= 3,
        "expected at least 3 captured Go pages in {}, got {}",
        path.display(),
        fixtures.len()
    );
    fixtures
}

#[test]
fn every_go_captured_page_decodes_and_round_trips() {
    let fixtures = load_fixtures();
    let mut decoded_pages: BTreeMap<String, Page> = BTreeMap::new();

    for fx in &fixtures {
        let bytes =
            hex::decode(&fx.bytes_hex).unwrap_or_else(|e| panic!("hex decode {}: {e}", fx.name));
        let page = Page::deserialize(&bytes).unwrap_or_else(|e| {
            panic!(
                "decode Go-produced page {} (page_id={}, {} bytes, {}): {e}",
                fx.name,
                fx.page_id,
                bytes.len(),
                fx.description,
            );
        });
        assert_eq!(
            page.nodes.len(),
            fx.node_count as usize,
            "node count mismatch on {}: header claimed {}, decoded {}",
            fx.name,
            fx.node_count,
            page.nodes.len(),
        );

        // Re-encode via the Rust path and decode again: the result must
        // equal the first decode. This is the round-trip property we
        // promise — same Page in, same Page out, regardless of which
        // node-order the Go side happened to write.
        let rust_bytes = page.serialize();
        let again = Page::deserialize(&rust_bytes).unwrap_or_else(|e| {
            panic!(
                "Rust-encoded page {} failed to round-trip through Rust decoder: {e}",
                fx.name
            );
        });
        assert_eq!(
            again, page,
            "re-encode/decode produced a different Page for {}",
            fx.name,
        );

        decoded_pages.insert(fx.name.clone(), page);
    }

    // Sanity: every fixture made it through.
    assert_eq!(decoded_pages.len(), fixtures.len());
}

#[test]
fn rust_encoding_is_stable_across_repeated_calls() {
    // Property: serialize() is deterministic — calling it twice on the
    // same Page must produce identical bytes. We rely on this for SQL
    // page rewrites to be a no-op when nothing changed (otherwise the
    // page would be marked dirty every commit).
    let fixtures = load_fixtures();
    for fx in &fixtures {
        let bytes = hex::decode(&fx.bytes_hex).unwrap();
        let page = Page::deserialize(&bytes).unwrap();
        let a = page.serialize();
        let b = page.serialize();
        assert_eq!(
            a, b,
            "serialize() output drifted across calls for fixture {}",
            fx.name
        );
    }
}

#[test]
fn rust_encoded_pages_carry_the_documented_version_word() {
    // Property: every page Rust produces starts with the Go
    // nodePageVersion uvarint. Documenting the constant once in
    // merkle_page.rs is not enough; we lock it down at the byte level
    // here so a future "version bump" can't silently slip out.
    let fixtures = load_fixtures();
    for fx in &fixtures {
        let bytes = hex::decode(&fx.bytes_hex).unwrap();
        let page = Page::deserialize(&bytes).unwrap();
        let rust_bytes = page.serialize();
        // Read the leading uvarint by hand (mirrors Go's binary.Uvarint).
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        for &b in &rust_bytes {
            if b < 0x80 {
                value |= (b as u64) << shift;
                break;
            }
            value |= ((b & 0x7f) as u64) << shift;
            shift += 7;
        }
        assert_eq!(
            value, NODE_PAGE_VERSION,
            "Rust-encoded fixture {} did not begin with NODE_PAGE_VERSION (got 0x{value:016x})",
            fx.name,
        );
    }
}
