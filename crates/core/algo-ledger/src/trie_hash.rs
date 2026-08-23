//! V6 hash builders for Merkle trie elements.
//!
//! Each trie element is 36 bytes:
//!
//! ```text
//!   bytes 0..4:   affinity (big-endian u32)
//!   byte  4:      HashKind (Account=0, Asset=1, App=2, Kv=3)
//!   bytes 5..36:  SHA512/256(prehash)[1..32]  (bytes 1 through 31, dropping byte 0)
//! ```
//!
//! This layout mirrors go-algorand v4.6.0-stable's three sibling builders in
//! `ledger/store/trackerdb/hashing.go` byte-for-byte:
//!
//! - `AccountHashBuilderV6` (`hashing.go:64-78`)
//! - `ResourcesHashBuilderV6` (`hashing.go:81-95`)
//! - `KvHashBuilderV6` (`hashing.go:107-115`)
//!
//! All three delegate to `hashBufV6(affinity, kind)` (`hashing.go:117-128`)
//! which writes the affinity + kind prefix, and `finishV6(hash, prehash)`
//! (`hashing.go:130-135`) which composes the SHA512/256 tail. The Rust
//! `finish_v6` helper below performs the identical composition; the three
//! `*_hash_v6` builders mirror the prehash construction of their Go
//! counterparts.
//!
//! Verdict: **MATCH** per PLAN-130 TASK-131 (see DOC-129 §5 Findings). The
//! 36-byte layout is correct; no alignment work is needed. The
//! `test_finish_v6_matches_go_captured_elements` test below (PLAN-130
//! TASK-135) locks this in by asserting byte-exact equality against
//! Go-captured element bytes for one fixture per HashKind. Capture tool:
//! `tools/trie-element-capture`.

use algo_types::{AccountData, Address};
use sha2::{Digest, Sha512_256};

use crate::sqlite::encode_account_data;

/// Element size for the Merkle trie (36 bytes).
///
/// Matches `4 + crypto.DigestSize` in go-algorand
/// `ledger/store/trackerdb/hashing.go:51, 73, 89, 110` (where
/// `crypto.DigestSize = 32`).
pub const ELEMENT_SIZE: usize = 36;

/// Compose the final 36-byte element from `(affinity, kind, prehash)`.
///
/// Layout:
///
/// ```text
///   element[0..4] = affinity.to_be_bytes()
///   element[4]    = kind as u8
///   element[5..36]= SHA512/256(prehash)[1..32]
/// ```
///
/// This mirrors Go's two-step composition: `hashBufV6(affinity, kind)`
/// produces the 36-byte buffer with bytes 0..5 populated and bytes 5..36
/// zeroed, then `finishV6(buf, prehash)` overwrites bytes 5..36 with
/// `crypto.Hash(prehash)[1:]`. The Rust implementation fuses both steps
/// into a single function because the intermediate "partial buffer" has
/// no other callers in this codebase.
///
/// Centralizing the assembly here also gives the TASK-135 fixture test a
/// stable entry point for byte-exact comparison against Go.
pub(crate) fn finish_v6(affinity: u32, kind: HashKind, prehash: &[u8]) -> [u8; ELEMENT_SIZE] {
    let mut hasher = Sha512_256::new();
    hasher.update(prehash);
    let hash = hasher.finalize();

    let mut element = [0u8; ELEMENT_SIZE];
    element[0..4].copy_from_slice(&affinity.to_be_bytes());
    element[4] = kind as u8;
    element[5..36].copy_from_slice(&hash[1..32]);
    element
}

/// Discriminant byte indicating the type of resource in the trie element.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    Account = 0,
    Asset = 1,
    App = 2,
    Kv = 3,
}

/// Compute the affinity value for an account.
///
/// Uses `update_round` if non-zero, otherwise falls back to `rewards_base`.
/// The result is truncated to u32.
pub fn compute_affinity(account_data: &AccountData) -> u32 {
    let val = if account_data.update_round != 0 {
        account_data.update_round
    } else {
        account_data.rewards_base
    };
    val as u32
}

/// Compute the 36-byte trie element for an account.
///
/// Prehash layout: `address_bytes(32) || canonical_msgpack(account_data)`.
/// Mirrors `AccountHashBuilderV6` (`hashing.go:64-78`); see module docs.
pub fn account_hash_v6(address: &Address, account_data: &AccountData) -> [u8; ELEMENT_SIZE] {
    let encoded = encode_account_data(account_data);
    let mut prehash = Vec::with_capacity(32 + encoded.len());
    prehash.extend_from_slice(&address.0);
    prehash.extend_from_slice(&encoded);
    finish_v6(compute_affinity(account_data), HashKind::Account, &prehash)
}

/// Extract the affinity value from a raw msgpack-encoded data blob.
///
/// Scans the msgpack map for keys `"z"` (update_round) and `"c"` (rewards_base).
/// Returns `update_round` if non-zero, otherwise `rewards_base`, truncated to u32.
/// This works for both account data (which has both `"z"` and `"c"`) and resource
/// data (which has `"z"` but not `"c"`).
///
/// Matches Go's `AccountHashBuilderV6` (for accounts) and
/// `ResourcesHashBuilderV6` (for resources, which passes `resData.UpdateRound`).
pub fn extract_raw_affinity(data: &[u8]) -> u32 {
    let val = match rmpv::decode::read_value(&mut &data[..]) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let map = match &val {
        rmpv::Value::Map(m) => m,
        _ => return 0,
    };

    let mut update_round: u64 = 0;
    let mut rewards_base: u64 = 0;

    for (k, v) in map {
        let key_str = match k {
            rmpv::Value::String(s) => match s.as_str() {
                Some(s) => s,
                None => continue,
            },
            _ => continue,
        };
        match key_str {
            "z" => update_round = v.as_u64().unwrap_or(0),
            "c" => rewards_base = v.as_u64().unwrap_or(0),
            _ => {}
        }
    }

    let val = if update_round != 0 {
        update_round
    } else {
        rewards_base
    };
    val as u32
}

/// Compute the 36-byte trie element for a resource with an explicit HashKind.
///
/// Prehash layout: `address_bytes(32) || creatable_index(8 bytes LE) || resource_blob`.
/// Mirrors `ResourcesHashBuilderV6` (`hashing.go:81-95`); see module docs.
///
/// The `resource_data` is the already-encoded msgpack blob (possibly merged
/// holding + params). The `affinity` should come from the resource's own
/// `UpdateRound` (codec key `"z"`).
pub fn resource_hash_v6_with_kind(
    address: &Address,
    creatable_index: u64,
    resource_data: &[u8],
    affinity: u32,
    kind: HashKind,
) -> [u8; ELEMENT_SIZE] {
    let mut prehash = Vec::with_capacity(32 + 8 + resource_data.len());
    prehash.extend_from_slice(&address.0);
    prehash.extend_from_slice(&creatable_index.to_le_bytes());
    prehash.extend_from_slice(resource_data);
    finish_v6(affinity, kind, &prehash)
}

/// Compute the 36-byte trie element for a KV (box) entry.
///
/// Mirrors `KvHashBuilderV6` (`hashing.go:107-115`): affinity = 0, HashKind
/// = `Kv` (3), prehash is `key_bytes || value_bytes`. See module docs.
///
/// The `key` is the full kvstore key (e.g. `"bx:" + big-endian app_id + box_name`).
pub fn kv_hash_v6(key: &[u8], value: &[u8]) -> [u8; ELEMENT_SIZE] {
    let mut prehash = Vec::with_capacity(key.len() + value.len());
    prehash.extend_from_slice(key);
    prehash.extend_from_slice(value);
    finish_v6(0, HashKind::Kv, &prehash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::AccountStatus;

    /// Helper: compute SHA512/256 of data and return full 32-byte hash.
    fn sha512_256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha512_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Regression test: assert basic layout invariants.
    ///
    /// `ELEMENT_SIZE` is part of the consensus-critical contract with
    /// go-algorand's `AccountHashBuilderV6` / `ResourcesHashBuilderV6` /
    /// `KvHashBuilderV6`. The byte at index 4 is the `HashKindEncodingIndex`
    /// (see `ledger/store/trackerdb/hashing.go:47`), and that's where
    /// `catchupaccessor.go:904` reads the kind to disambiguate hashed
    /// resources. Pin these two invariants here so they can't drift
    /// silently — alongside the byte-exact fixture test below which locks
    /// the entire layout.
    #[test]
    fn test_element_layout_invariants() {
        assert_eq!(
            ELEMENT_SIZE, 36,
            "ELEMENT_SIZE must remain 36 (4-byte affinity + 1-byte kind + 31-byte hash tail)"
        );
        assert_eq!(HashKind::Account as u8, 0);
        assert_eq!(HashKind::Asset as u8, 1);
        assert_eq!(HashKind::App as u8, 2);
        assert_eq!(HashKind::Kv as u8, 3);
    }

    // -----------------------------------------------------------------------
    // Byte-exact fixture test (PLAN-130 TASK-135).
    //
    // Locks in the TASK-131 MATCH verdict (DOC-129 §5 Findings): given the
    // same (affinity, kind, prehash), Rust's `finish_v6` produces exactly
    // the same 36 bytes that go-algorand v4.6.0-stable's `finishV6` does
    // (as invoked through the authoritative public builders
    // `AccountHashBuilderV6` / `ResourcesHashBuilderV6` / `KvHashBuilderV6`).
    //
    // Fixtures are produced by `tools/trie-element-capture` — see that
    // package's comment for the sibling-checkout setup required to
    // regenerate.
    // -----------------------------------------------------------------------

    #[derive(serde::Deserialize)]
    struct ElementFixture {
        name: String,
        affinity: u32,
        kind: u8,
        prehash_hex: String,
        element_hex: String,
    }

    fn load_element_fixtures() -> Vec<ElementFixture> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("merkle_trie_elements")
            .join("elements.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read fixture file {}: {e}", path.display()));
        let fixtures: Vec<ElementFixture> = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("parse fixture file {}: {e}", path.display()));
        assert!(
            !fixtures.is_empty(),
            "expected at least one captured Go element in {}",
            path.display()
        );
        fixtures
    }

    fn hashkind_from_u8(name: &str, k: u8) -> HashKind {
        match k {
            0 => HashKind::Account,
            1 => HashKind::Asset,
            2 => HashKind::App,
            3 => HashKind::Kv,
            other => panic!("fixture {name}: unknown HashKind discriminant {other}"),
        }
    }

    #[test]
    fn test_finish_v6_matches_go_captured_elements() {
        let fixtures = load_element_fixtures();

        // Track results across all scenarios so the test report shows the
        // full pass/fail picture rather than bailing at the first mismatch.
        let mut report: Vec<(String, bool, [u8; ELEMENT_SIZE], [u8; ELEMENT_SIZE])> = Vec::new();

        for fx in &fixtures {
            let prehash = hex::decode(&fx.prehash_hex)
                .unwrap_or_else(|e| panic!("fixture {}: decode prehash: {e}", fx.name));
            let expected_vec = hex::decode(&fx.element_hex)
                .unwrap_or_else(|e| panic!("fixture {}: decode element: {e}", fx.name));
            assert_eq!(
                expected_vec.len(),
                ELEMENT_SIZE,
                "fixture {}: expected element must be 36 bytes",
                fx.name
            );
            let mut expected = [0u8; ELEMENT_SIZE];
            expected.copy_from_slice(&expected_vec);

            let kind = hashkind_from_u8(&fx.name, fx.kind);
            let actual = finish_v6(fx.affinity, kind, &prehash);
            report.push((fx.name.clone(), actual == expected, expected, actual));
        }

        let failures: Vec<&(String, bool, [u8; ELEMENT_SIZE], [u8; ELEMENT_SIZE])> =
            report.iter().filter(|(_, ok, _, _)| !ok).collect();

        if !failures.is_empty() {
            let mut msg = String::from("\ntrie element bytes mismatch vs. go-algorand finishV6:\n");
            for (name, _, expected, actual) in &failures {
                msg.push_str(&format!(
                    "  fixture {name}:\n    go-algorand expected: {}\n    rust actual:         {}\n",
                    hex::encode(expected),
                    hex::encode(actual),
                ));
            }
            msg.push_str(&format!(
                "\n{} of {} fixtures matched.\n",
                report.len() - failures.len(),
                report.len(),
            ));
            panic!("{msg}");
        }
    }

    /// Independent layout cross-check: for one of the captured fixtures,
    /// recompute the expected element via `sha512_256` + manual byte
    /// assembly, and assert that BOTH `finish_v6` and the fixture agree.
    /// This guards against the (unlikely but possible) scenario where
    /// `finish_v6` and the fixture were both regenerated from a broken
    /// algorithm — a manual recomputation here grounds the test in the
    /// arithmetic of the spec rather than just the two implementations
    /// agreeing with each other.
    #[test]
    fn test_finish_v6_layout_via_manual_recomputation() {
        let fixtures = load_element_fixtures();
        let kv = fixtures
            .iter()
            .find(|f| f.name == "kv-simple")
            .expect("kv-simple fixture must be present");

        let prehash = hex::decode(&kv.prehash_hex).unwrap();
        let expected_full = hex::decode(&kv.element_hex).unwrap();

        // Manual recomputation: affinity(0u32) || kind(0x03) || hash[1..32].
        let hash = sha512_256(&prehash);
        let mut manual = [0u8; ELEMENT_SIZE];
        manual[0..4].copy_from_slice(&0u32.to_be_bytes());
        manual[4] = HashKind::Kv as u8;
        manual[5..36].copy_from_slice(&hash[1..32]);

        assert_eq!(&manual[..], &expected_full[..], "manual layout mismatch");
        assert_eq!(
            finish_v6(0, HashKind::Kv, &prehash),
            manual,
            "finish_v6 output must equal manual layout recomputation"
        );
    }

    #[test]
    fn test_affinity_uses_update_round_when_nonzero() {
        let acct = AccountData {
            update_round: 42,
            rewards_base: 99,
            ..Default::default()
        };
        assert_eq!(compute_affinity(&acct), 42);
    }

    #[test]
    fn test_affinity_falls_back_to_rewards_base_when_update_round_zero() {
        let acct = AccountData {
            update_round: 0,
            rewards_base: 123,
            ..Default::default()
        };
        assert_eq!(compute_affinity(&acct), 123);
    }

    #[test]
    fn test_affinity_truncates_to_u32() {
        let acct = AccountData {
            update_round: 0x1_0000_0042, // larger than u32
            ..Default::default()
        };
        assert_eq!(compute_affinity(&acct), 0x42);
    }

    #[test]
    fn test_account_hash_v6_format() {
        let addr = Address([7u8; 32]);
        let acct = AccountData {
            micro_algos: 1_000_000,
            update_round: 100,
            ..Default::default()
        };

        let element = account_hash_v6(&addr, &acct);

        // Verify total size
        assert_eq!(element.len(), 36);

        // Verify affinity (bytes 0..4)
        let affinity = u32::from_be_bytes([element[0], element[1], element[2], element[3]]);
        assert_eq!(affinity, 100);

        // Verify HashKind (byte 4)
        assert_eq!(element[4], HashKind::Account as u8);

        // Verify hash portion: reconstruct the prehash and check bytes [1..32]
        let encoded = encode_account_data(&acct);
        let mut prehash = Vec::new();
        prehash.extend_from_slice(&addr.0);
        prehash.extend_from_slice(&encoded);
        let full_hash = sha512_256(&prehash);
        assert_eq!(&element[5..36], &full_hash[1..32]);
    }

    #[test]
    fn test_account_hash_v6_default_account() {
        // Default (all zeros) account should still produce a valid element.
        let addr = Address([0u8; 32]);
        let acct = AccountData::default();
        let element = account_hash_v6(&addr, &acct);

        assert_eq!(element.len(), 36);
        // Affinity should be 0 (both update_round and rewards_base are 0)
        assert_eq!(
            u32::from_be_bytes([element[0], element[1], element[2], element[3]]),
            0
        );
        assert_eq!(element[4], HashKind::Account as u8);
    }

    #[test]
    fn test_account_hash_v6_with_status() {
        let addr = Address([1u8; 32]);
        let acct = AccountData {
            status: AccountStatus::Online,
            micro_algos: 500_000,
            rewards_base: 50,
            update_round: 0, // will use rewards_base
            ..Default::default()
        };

        let element = account_hash_v6(&addr, &acct);
        let affinity = u32::from_be_bytes([element[0], element[1], element[2], element[3]]);
        assert_eq!(affinity, 50); // rewards_base used as fallback
    }

    #[test]
    fn test_resource_hash_v6_with_kind_asset_format() {
        let addr = Address([3u8; 32]);
        let creatable_index: u64 = 42;
        let resource_data = b"fake_msgpack_blob";
        let affinity: u32 = 200;

        let element = resource_hash_v6_with_kind(
            &addr,
            creatable_index,
            resource_data,
            affinity,
            HashKind::Asset,
        );

        // Verify total size
        assert_eq!(element.len(), 36);

        // Verify affinity (bytes 0..4)
        let aff = u32::from_be_bytes([element[0], element[1], element[2], element[3]]);
        assert_eq!(aff, 200);

        // Verify HashKind (byte 4)
        assert_eq!(element[4], HashKind::Asset as u8);

        // Verify hash portion: reconstruct the prehash and check bytes [1..32]
        let mut prehash = Vec::new();
        prehash.extend_from_slice(&addr.0);
        prehash.extend_from_slice(&creatable_index.to_le_bytes());
        prehash.extend_from_slice(resource_data);
        let full_hash = sha512_256(&prehash);
        assert_eq!(&element[5..36], &full_hash[1..32]);
    }

    #[test]
    fn test_resource_hash_v6_with_kind() {
        let addr = Address([5u8; 32]);
        let creatable_index: u64 = 99;
        let resource_data = b"app_blob";
        let affinity: u32 = 10;

        let element = resource_hash_v6_with_kind(
            &addr,
            creatable_index,
            resource_data,
            affinity,
            HashKind::App,
        );

        assert_eq!(element[4], HashKind::App as u8);

        // Hash portion should match
        let mut prehash = Vec::new();
        prehash.extend_from_slice(&addr.0);
        prehash.extend_from_slice(&creatable_index.to_le_bytes());
        prehash.extend_from_slice(resource_data);
        let full_hash = sha512_256(&prehash);
        assert_eq!(&element[5..36], &full_hash[1..32]);
    }

    #[test]
    fn test_prehash_layout_account() {
        // Verify that account prehash is exactly address || encoded_data
        let addr = Address([0xAB; 32]);
        let acct = AccountData {
            micro_algos: 42,
            ..Default::default()
        };
        let encoded = encode_account_data(&acct);

        let mut expected_prehash = Vec::with_capacity(32 + encoded.len());
        expected_prehash.extend_from_slice(&[0xAB; 32]);
        expected_prehash.extend_from_slice(&encoded);

        let full_hash = sha512_256(&expected_prehash);

        let element = account_hash_v6(&addr, &acct);
        assert_eq!(&element[5..36], &full_hash[1..32]);
    }

    #[test]
    fn test_prehash_layout_resource() {
        // Verify that resource prehash is exactly address || index(8 LE) || data
        let addr = Address([0xCD; 32]);
        let index: u64 = 0x0000_0000_0000_002A; // 42
        let data = vec![0x80]; // empty msgpack map

        let mut expected_prehash = Vec::new();
        expected_prehash.extend_from_slice(&[0xCD; 32]);
        expected_prehash.extend_from_slice(&index.to_le_bytes());
        expected_prehash.extend_from_slice(&data);

        let full_hash = sha512_256(&expected_prehash);

        let element = resource_hash_v6_with_kind(&addr, index, &data, 0, HashKind::Asset);
        assert_eq!(&element[5..36], &full_hash[1..32]);
    }

    #[test]
    fn test_sha512_256_truncation_drops_byte_zero() {
        // Verify we use bytes [1..32], NOT [0..31]
        let addr = Address([0xFF; 32]);
        let acct = AccountData {
            micro_algos: 999,
            update_round: 1,
            ..Default::default()
        };
        let encoded = encode_account_data(&acct);

        let mut prehash = Vec::new();
        prehash.extend_from_slice(&addr.0);
        prehash.extend_from_slice(&encoded);

        let full_hash = sha512_256(&prehash);

        let element = account_hash_v6(&addr, &acct);
        // bytes [5..36] should be hash[1..32], NOT hash[0..31]
        assert_eq!(&element[5..36], &full_hash[1..32]);
        // Specifically verify byte 0 of hash is NOT at element[5]
        // (unless by coincidence hash[0] == hash[1])
        // We verify the slice matches the expected range.
        assert_ne!(&element[5..36], &full_hash[0..31],
            "element should use hash[1..32], not hash[0..31] (unless hash[0]==hash[1] by coincidence)");
    }

    #[test]
    fn test_different_addresses_produce_different_hashes() {
        let acct = AccountData {
            micro_algos: 100,
            ..Default::default()
        };
        let e1 = account_hash_v6(&Address([1u8; 32]), &acct);
        let e2 = account_hash_v6(&Address([2u8; 32]), &acct);
        assert_ne!(e1[5..36], e2[5..36]);
    }

    #[test]
    fn test_different_balances_produce_different_hashes() {
        let addr = Address([1u8; 32]);
        let a1 = AccountData {
            micro_algos: 100,
            ..Default::default()
        };
        let a2 = AccountData {
            micro_algos: 200,
            ..Default::default()
        };
        let e1 = account_hash_v6(&addr, &a1);
        let e2 = account_hash_v6(&addr, &a2);
        assert_ne!(e1[5..36], e2[5..36]);
    }

    #[test]
    fn test_kv_hash_v6_format() {
        let key = b"bx:\x00\x00\x00\x00\x00\x00\x00\x2amybox";
        let value = b"hello world";

        let element = kv_hash_v6(key, value);

        // Verify total size
        assert_eq!(element.len(), 36);

        // Verify affinity is 0 (bytes 0..4)
        assert_eq!(&element[0..4], &[0, 0, 0, 0]);

        // Verify HashKind is Kv = 3 (byte 4)
        assert_eq!(element[4], HashKind::Kv as u8);
        assert_eq!(element[4], 3);

        // Verify hash portion: reconstruct the prehash and check bytes [1..32]
        let mut prehash = Vec::new();
        prehash.extend_from_slice(key);
        prehash.extend_from_slice(value);
        let full_hash = sha512_256(&prehash);
        assert_eq!(&element[5..36], &full_hash[1..32]);
    }

    #[test]
    fn test_kv_hash_v6_different_keys_produce_different_hashes() {
        let value = b"same_value";
        let e1 = kv_hash_v6(b"bx:\x00\x00\x00\x00\x00\x00\x00\x01key1", value);
        let e2 = kv_hash_v6(b"bx:\x00\x00\x00\x00\x00\x00\x00\x01key2", value);
        assert_ne!(e1[5..36], e2[5..36]);
    }

    #[test]
    fn test_kv_hash_v6_different_values_produce_different_hashes() {
        let key = b"bx:\x00\x00\x00\x00\x00\x00\x00\x01mybox";
        let e1 = kv_hash_v6(key, b"value_a");
        let e2 = kv_hash_v6(key, b"value_b");
        assert_ne!(e1[5..36], e2[5..36]);
    }
}
