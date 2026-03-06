//! V6 hash builders for Merkle trie elements.
//!
//! Each trie element is 36 bytes:
//!   bytes 0..4:   affinity (big-endian u32)
//!   byte  4:      HashKind
//!   bytes 5..36:  SHA512/256(prehash)[1..32]  (bytes 1 through 31, dropping byte 0)

use algo_types::{AccountData, Address};
use sha2::{Digest, Sha512_256};

use crate::sqlite::encode_account_data;

/// Element size for the Merkle trie (36 bytes).
pub const ELEMENT_SIZE: usize = 36;

/// Discriminant byte indicating the type of resource in the trie element.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    Account = 0,
    Asset = 1,
    App = 2,
    // Kv = 3,  // not needed for Phase 2
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
/// Prehash layout: `address_bytes(32) || canonical_msgpack(account_data)`
pub fn account_hash_v6(address: &Address, account_data: &AccountData) -> [u8; ELEMENT_SIZE] {
    let encoded = encode_account_data(account_data);

    let mut hasher = Sha512_256::new();
    hasher.update(address.0);
    hasher.update(&encoded);
    let hash = hasher.finalize();

    let affinity = compute_affinity(account_data);
    let mut element = [0u8; ELEMENT_SIZE];
    element[0..4].copy_from_slice(&affinity.to_be_bytes());
    element[4] = HashKind::Account as u8;
    // Take bytes [1..32] of the hash (31 bytes), skipping byte 0.
    element[5..36].copy_from_slice(&hash[1..32]);
    element
}

/// Compute the 36-byte trie element for a resource with an explicit HashKind.
///
/// Prehash layout: `address_bytes(32) || creatable_index(8 bytes BE) || resource_blob`
///
/// The `resource_data` is the already-encoded msgpack blob (possibly merged holding + params).
/// The `affinity` should come from the owning account's `compute_affinity()`.
pub fn resource_hash_v6_with_kind(
    address: &Address,
    creatable_index: u64,
    resource_data: &[u8],
    affinity: u32,
    kind: HashKind,
) -> [u8; ELEMENT_SIZE] {
    let mut hasher = Sha512_256::new();
    hasher.update(address.0);
    hasher.update(creatable_index.to_be_bytes());
    hasher.update(resource_data);
    let hash = hasher.finalize();

    let mut element = [0u8; ELEMENT_SIZE];
    element[0..4].copy_from_slice(&affinity.to_be_bytes());
    element[4] = kind as u8;
    element[5..36].copy_from_slice(&hash[1..32]);
    element
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
        prehash.extend_from_slice(&creatable_index.to_be_bytes());
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
        prehash.extend_from_slice(&creatable_index.to_be_bytes());
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
        // Verify that resource prehash is exactly address || index(8 BE) || data
        let addr = Address([0xCD; 32]);
        let index: u64 = 0x0000_0000_0000_002A; // 42
        let data = vec![0x80]; // empty msgpack map

        let mut expected_prehash = Vec::new();
        expected_prehash.extend_from_slice(&[0xCD; 32]);
        expected_prehash.extend_from_slice(&index.to_be_bytes());
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
}
