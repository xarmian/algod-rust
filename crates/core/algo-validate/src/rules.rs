// Epic 10: Stateless protocol rules (fees, rounds, groups)

use algo_codec::{canonical_encode_transaction, canonical_encode_tx_group};
use algo_error::AlgoError;
use algo_types::{Digest, SignedTransaction, Transaction};
use serde_bytes::ByteBuf;
use sha2::{Digest as _, Sha512_256};

// Consensus defaults — stable across all protocol versions to date.
// Future: load from consensus params.
pub const MIN_TXN_FEE: u64 = 1000;
pub const MAX_TXN_LIFE: u64 = 1000;
pub const MAX_NOTE_SIZE: usize = 1024;
pub const MAX_GROUP_SIZE: usize = 16;
pub const MAX_LEASE_SIZE: usize = 32;

// Block-level consensus constants.
/// Maximum seconds a block timestamp can exceed the previous block's timestamp.
/// Matches go-algorand `MaxTimestampIncrement` (set in v7, unchanged since).
pub const MAX_TIMESTAMP_INCREMENT: i64 = 25;

/// Maximum total transaction bytes per block (v7–v32).
pub const MAX_TXN_BYTES_PER_BLOCK_V32: usize = 1_000_000;

/// Maximum total transaction bytes per block (v33+).
pub const MAX_TXN_BYTES_PER_BLOCK_V33: usize = 5 * 1024 * 1024;

// ── Known protocol versions ─────────────────────────────────────────
// Mirrors go-algorand `protocol/consensus.go` at tag v4.5.1-stable.
// Only versions v7+ are relevant; v0–v6 are deprecated and never seen on
// mainnet/testnet/devnet blocks.

/// All protocol version strings recognised by go-algorand v4.5.1-stable.
pub const KNOWN_PROTOCOL_VERSIONS: &[&str] = &[
    // Short-form versions (v7–v12)
    "v7",
    "v8",
    "v9",
    "v10",
    "v11",
    "v12",
    // Spec-URL versions (v13–v41)
    "https://github.com/algorand/spec/tree/0c8a9dc44d7368cc266d5407b79fb3311f4fc795", // v13
    "https://github.com/algorand/spec/tree/2526b6ae062b4fe5e163e06e41e1d9b9219135a9", // v14
    "https://github.com/algorand/spec/tree/a26ed78ed8f834e2b9ccb6eb7d3ee9f629a6e622", // v15
    "https://github.com/algorand/spec/tree/22726c9dcd12d9cddce4a8bd7e8ccaa707f74101", // v16
    "https://github.com/algorandfoundation/specs/tree/5615adc36bad610c7f165fa2967f4ecfa75125f0", // v17
    "https://github.com/algorandfoundation/specs/tree/6c6bd668be0ab14098e51b37e806c509f7b7e31f", // v18
    "https://github.com/algorandfoundation/specs/tree/0e196e82bfd6e327994bec373c4cc81bc878ef5c", // v19
    "https://github.com/algorandfoundation/specs/tree/4a9db6a25595c6fd097cf9cc137cc83027787eaa", // v20
    "https://github.com/algorandfoundation/specs/tree/8096e2df2da75c3339986317f9abe69d4fa86b4b", // v21
    "https://github.com/algorandfoundation/specs/tree/57016b942f6d97e6d4c0688b373bb0a2fc85a1a2", // v22
    "https://github.com/algorandfoundation/specs/tree/e5f565421d720c6f75cdd186f7098495caf9101f", // v23
    "https://github.com/algorandfoundation/specs/tree/3a83c4c743f8b17adfd73944b4319c25722a6782", // v24
    "https://github.com/algorandfoundation/specs/tree/bea19289bf41217d2c0af30522fa222ef1366466", // v25
    "https://github.com/algorandfoundation/specs/tree/ac2255d586c4474d4ebcf3809acccb59b7ef34ff", // v26
    "https://github.com/algorandfoundation/specs/tree/d050b3cade6d5c664df8bd729bf219f179812595", // v27
    "https://github.com/algorandfoundation/specs/tree/65b4ab3266c52c56a0fa7d591754887d68faad0a", // v28
    "https://github.com/algorandfoundation/specs/tree/abc54f79f9ad679d2d22f0fb9909fb005c16f8a1", // v29
    "https://github.com/algorandfoundation/specs/tree/bc36005dbd776e6d1eaf0c560619bb183215645c", // v30
    "https://github.com/algorandfoundation/specs/tree/85e6db1fdbdef00aa232c75199e10dc5fe9498f6", // v31
    "https://github.com/algorandfoundation/specs/tree/d5ac876d7ede07367dbaa26e149aa42589aac1f7", // v32
    "https://github.com/algorandfoundation/specs/tree/830a4e673148498cc7230a0d1ba1ed0a5471acc6", // v33
    "https://github.com/algorandfoundation/specs/tree/2dd5435993f6f6d65691140f592ebca5ef19ffbd", // v34
    "https://github.com/algorandfoundation/specs/tree/433d8e9a7274b6fca703d91213e05c7e6a589e69", // v35
    "https://github.com/algorandfoundation/specs/tree/44fa607d6051730f5264526bf3c108d51f0eadb6", // v36
    "https://github.com/algorandfoundation/specs/tree/1ac4dd1f85470e1fb36c8a65520e1313d7dfed5e", // v37
    "https://github.com/algorandfoundation/specs/tree/abd3d4823c6f77349fc04c3af7b1e99fe4df699f", // v38
    "https://github.com/algorandfoundation/specs/tree/925a46433742afb0b51bb939354bd907fa88bf95", // v39
    "https://github.com/algorandfoundation/specs/tree/236dcc18c9c507d794813ab768e467ea42d1b4d9", // v40
    "https://github.com/algorandfoundation/specs/tree/953304de35264fc3ef91bcd05c123242015eeaed", // v41
    // Special versions
    "future",
    "alpha1",
    "alpha2",
    "alpha3",
    "alpha4",
    "alpha5",
];

/// Validate individual transaction rules (fee, round window, note size,
/// lease size, group size). Does NOT validate group membership or signatures.
pub fn validate_transaction_rules(txn: &Transaction) -> Result<(), AlgoError> {
    // Fee must meet minimum (per-txn check). NOTE: Algorand allows fee pooling
    // in atomic groups where one txn overpays for others. Group-level fee
    // validation is deferred — see Known Limitations in PHASE1_PROPOSAL.md.
    if txn.fee < MIN_TXN_FEE {
        return Err(AlgoError::Validation {
            message: format!(
                "transaction fee {} is below minimum {}",
                txn.fee, MIN_TXN_FEE
            ),
        });
    }

    // Last valid must be >= first valid.
    if txn.last_valid < txn.first_valid {
        return Err(AlgoError::Validation {
            message: format!(
                "last valid round {} is before first valid round {}",
                txn.last_valid, txn.first_valid
            ),
        });
    }

    // Round window must not exceed MAX_TXN_LIFE.
    let window = txn.last_valid.0 - txn.first_valid.0;
    if window > MAX_TXN_LIFE {
        return Err(AlgoError::Validation {
            message: format!(
                "transaction validity window {} exceeds maximum {}",
                window, MAX_TXN_LIFE
            ),
        });
    }

    // Note must not exceed MAX_NOTE_SIZE.
    if txn.note.len() > MAX_NOTE_SIZE {
        return Err(AlgoError::Validation {
            message: format!(
                "note size {} exceeds maximum {}",
                txn.note.len(),
                MAX_NOTE_SIZE
            ),
        });
    }

    // Lease must be empty or exactly 32 bytes.
    if !txn.lease.is_empty() && txn.lease.len() != MAX_LEASE_SIZE {
        return Err(AlgoError::Validation {
            message: format!(
                "lease must be empty or exactly {} bytes, got {}",
                MAX_LEASE_SIZE,
                txn.lease.len()
            ),
        });
    }

    // Group must be empty or exactly 32 bytes.
    if !txn.group.is_empty() && txn.group.len() != 32 {
        return Err(AlgoError::Validation {
            message: format!(
                "group field must be empty or exactly 32 bytes, got {}",
                txn.group.len()
            ),
        });
    }

    Ok(())
}

/// Validate that a block's protocol version is known.
///
/// go-algorand rejects blocks whose `proto` field is not in the consensus
/// params map. We replicate this by checking against `KNOWN_PROTOCOL_VERSIONS`.
pub fn validate_protocol_version(version: &str) -> Result<(), AlgoError> {
    if version.is_empty() {
        return Err(AlgoError::Validation {
            message: "block protocol version is empty".to_string(),
        });
    }
    if !KNOWN_PROTOCOL_VERSIONS.contains(&version) {
        return Err(AlgoError::Validation {
            message: format!("unknown protocol version: {version}"),
        });
    }
    Ok(())
}

/// Index in `KNOWN_PROTOCOL_VERSIONS` where the v33 5-MiB block size limit
/// begins. All versions at this index and beyond (including future/alpha)
/// use the larger limit.
const V33_START_INDEX: usize = 26;

/// Expected prefix of the v33 protocol version URL at `V33_START_INDEX`.
/// Used as a compile-time assertion to catch if the version list is reordered.
const V33_URL_PREFIX: &str = "https://github.com/algorandfoundation/specs/tree/830a4e67";

/// Return the maximum transaction bytes per block for the given protocol
/// version string. Versions v33+ use the larger 5 MiB limit; earlier
/// versions use the 1 MiB limit. Returns an error for unknown versions.
pub fn max_txn_bytes_per_block(version: &str) -> Result<usize, AlgoError> {
    // Compile-time assertion: verify that V33_START_INDEX points to the
    // expected v33 version string. This catches accidental reordering of
    // the KNOWN_PROTOCOL_VERSIONS array.
    const _: () = {
        let v33 = KNOWN_PROTOCOL_VERSIONS[V33_START_INDEX].as_bytes();
        let prefix = V33_URL_PREFIX.as_bytes();
        let mut i = 0;
        while i < prefix.len() {
            assert!(
                v33[i] == prefix[i],
                // const assert messages must be string literals
                // "KNOWN_PROTOCOL_VERSIONS[V33_START_INDEX] does not start with expected v33 URL"
            );
            i += 1;
        }
    };

    validate_protocol_version(version)?;
    let idx = KNOWN_PROTOCOL_VERSIONS
        .iter()
        .position(|&v| v == version)
        .expect("validate_protocol_version already checked");
    if idx >= V33_START_INDEX {
        // v33+ or special versions (future/alpha inherit latest params)
        Ok(MAX_TXN_BYTES_PER_BLOCK_V33)
    } else {
        Ok(MAX_TXN_BYTES_PER_BLOCK_V32)
    }
}

/// Domain separation prefix for transaction ID hashing.
const TX_PREFIX: &[u8] = b"TX";

/// Domain separation prefix for group ID hashing.
const TG_PREFIX: &[u8] = b"TG";

/// Compute the group ID for a set of transactions.
///
/// For each transaction, zeros the `grp` field, computes its txn ID
/// (`SHA512/256("TX" || canonical_encode(txn))`), then encodes the list
/// of txn IDs via `canonical_encode_tx_group` and hashes with the "TG" prefix.
pub fn compute_group_id(txns: &[Transaction]) -> Digest {
    let hashes: Vec<Digest> = txns
        .iter()
        .map(|txn| {
            let mut zeroed = txn.clone();
            zeroed.group = ByteBuf::new();
            let canonical = canonical_encode_transaction(&zeroed);
            let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
            msg.extend_from_slice(TX_PREFIX);
            msg.extend_from_slice(&canonical);
            let hash = Sha512_256::digest(&msg);
            let mut out = [0u8; 32];
            out.copy_from_slice(&hash);
            Digest(out)
        })
        .collect();

    let encoded = canonical_encode_tx_group(&hashes);
    let mut msg = Vec::with_capacity(TG_PREFIX.len() + encoded.len());
    msg.extend_from_slice(TG_PREFIX);
    msg.extend_from_slice(&encoded);
    let hash = Sha512_256::digest(&msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    Digest(out)
}

/// Iterate contiguous runs of transactions sharing the same non-empty `grp`
/// field, invoking the callback for each group slice.
fn for_each_group<F>(txns: &[SignedTransaction], mut f: F) -> Result<(), AlgoError>
where
    F: FnMut(&[SignedTransaction]) -> Result<(), AlgoError>,
{
    let mut i = 0;
    while i < txns.len() {
        let grp = &txns[i].txn.group;
        if grp.is_empty() {
            i += 1;
            continue;
        }

        // Find the contiguous run sharing the same group ID.
        let start = i;
        while i < txns.len() && txns[i].txn.group == *grp {
            i += 1;
        }
        f(&txns[start..i])?;
    }
    Ok(())
}

/// Validate transaction groups within a block payset.
///
/// Extracts contiguous runs of transactions sharing the same non-empty `grp`
/// field. Each group must have 2..=MAX_GROUP_SIZE members and the stored group
/// ID must match the computed one. Standalone (empty `grp`) transactions are
/// skipped.
///
/// **Contiguity assumption**: this function assumes that all members of a given
/// group are contiguous in the payset, which is the invariant enforced by
/// go-algorand. If the same group ID appeared in non-contiguous positions, each
/// contiguous run would be treated as a separate (smaller) group.
pub fn validate_transaction_group(txns: &[SignedTransaction]) -> Result<(), AlgoError> {
    for_each_group(txns, |group_slice| {
        let size = group_slice.len();

        if size < 2 {
            return Err(AlgoError::Validation {
                message: format!("transaction group has only {size} member(s), minimum is 2"),
            });
        }

        if size > MAX_GROUP_SIZE {
            return Err(AlgoError::Validation {
                message: format!(
                    "transaction group has {size} members, maximum is {MAX_GROUP_SIZE}"
                ),
            });
        }

        // Compute and verify the group ID.
        let txn_refs: Vec<Transaction> = group_slice.iter().map(|s| s.txn.clone()).collect();
        let computed = compute_group_id(&txn_refs);

        let grp = &group_slice[0].txn.group;
        if grp.as_ref() != computed.as_bytes().as_slice() {
            return Err(AlgoError::Validation {
                message: format!(
                    "group ID mismatch: stored {} != computed {}",
                    hex::encode(grp.as_ref()),
                    hex::encode(computed.as_bytes())
                ),
            });
        }

        Ok(())
    })
}

/// Validate lease constraints within transaction groups.
///
/// Within each contiguous group, no two transactions from the same sender
/// may share the same lease value. Ungrouped transactions with leases are
/// allowed (cross-block lease enforcement is stateful, deferred to Phase 2).
pub fn validate_lease_constraints(txns: &[SignedTransaction]) -> Result<(), AlgoError> {
    for_each_group(txns, |group_slice| {
        // Collect (sender, lease) pairs for txns with non-empty leases.
        let mut seen = std::collections::HashSet::new();
        for stx in group_slice {
            if stx.txn.lease.is_empty() {
                continue;
            }
            let key = (stx.txn.sender, stx.txn.lease.to_vec());
            if !seen.insert(key) {
                return Err(AlgoError::Validation {
                    message: format!(
                        "duplicate lease within group: sender {} lease {}",
                        stx.txn.sender,
                        hex::encode(&stx.txn.lease)
                    ),
                });
            }
        }
        Ok(())
    })
}

/// Validate genesis ID and genesis hash consistency.
///
/// For each transaction, if `gen` is non-empty it must match `block_genesis_id`.
/// If `gh` is non-empty it must match `block_genesis_hash`.
pub fn validate_genesis_consistency(
    txns: &[SignedTransaction],
    block_genesis_id: &str,
    block_genesis_hash: &[u8],
) -> Result<(), AlgoError> {
    for (idx, stx) in txns.iter().enumerate() {
        if !stx.txn.genesis_id.is_empty() && stx.txn.genesis_id != block_genesis_id {
            return Err(AlgoError::Validation {
                message: format!(
                    "txn {} genesis ID mismatch: txn has '{}', block has '{}'",
                    idx, stx.txn.genesis_id, block_genesis_id
                ),
            });
        }
        if !stx.txn.genesis_hash.is_empty() && stx.txn.genesis_hash.as_ref() != block_genesis_hash {
            return Err(AlgoError::Validation {
                message: format!(
                    "txn {} genesis hash mismatch: txn has {}, block has {}",
                    idx,
                    hex::encode(&stx.txn.genesis_hash),
                    hex::encode(block_genesis_hash)
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::{Address, Round};
    use serde_bytes::ByteBuf;

    /// Build a minimal valid transaction for testing.
    fn make_valid_txn() -> Transaction {
        Transaction {
            txn_type: "pay".to_string(),
            sender: Address::default(),
            fee: MIN_TXN_FEE,
            first_valid: Round(1000),
            last_valid: Round(1100),
            note: ByteBuf::new(),
            genesis_id: String::new(),
            genesis_hash: ByteBuf::new(),
            group: ByteBuf::new(),
            lease: ByteBuf::new(),
            ..Default::default()
        }
    }

    #[test]
    fn test_valid_transaction_passes() {
        let txn = make_valid_txn();
        assert!(validate_transaction_rules(&txn).is_ok());
    }

    #[test]
    fn test_fee_too_low_fails() {
        let mut txn = make_valid_txn();
        txn.fee = 999;
        let err = validate_transaction_rules(&txn).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("below minimum"), "unexpected error: {msg}");
    }

    #[test]
    fn test_fee_zero_fails() {
        let mut txn = make_valid_txn();
        txn.fee = 0;
        let err = validate_transaction_rules(&txn).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("below minimum"), "unexpected error: {msg}");
    }

    #[test]
    fn test_round_window_too_large_fails() {
        let mut txn = make_valid_txn();
        txn.first_valid = Round(1000);
        txn.last_valid = Round(2001);
        let err = validate_transaction_rules(&txn).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("exceeds maximum"), "unexpected error: {msg}");
    }

    #[test]
    fn test_last_valid_before_first_valid_fails() {
        let mut txn = make_valid_txn();
        txn.first_valid = Round(2000);
        txn.last_valid = Round(1000);
        let err = validate_transaction_rules(&txn).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("before first valid"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_round_window_at_boundary_passes() {
        let mut txn = make_valid_txn();
        txn.first_valid = Round(1000);
        txn.last_valid = Round(2000); // window = 1000 == MAX_TXN_LIFE
        assert!(validate_transaction_rules(&txn).is_ok());
    }

    #[test]
    fn test_first_valid_equals_last_valid_passes() {
        let mut txn = make_valid_txn();
        txn.first_valid = Round(1000);
        txn.last_valid = Round(1000);
        assert!(validate_transaction_rules(&txn).is_ok());
    }

    #[test]
    fn test_note_too_large_fails() {
        let mut txn = make_valid_txn();
        txn.note = ByteBuf::from(vec![0u8; MAX_NOTE_SIZE + 1]);
        let err = validate_transaction_rules(&txn).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("note size"), "unexpected error: {msg}");
    }

    #[test]
    fn test_note_at_limit_passes() {
        let mut txn = make_valid_txn();
        txn.note = ByteBuf::from(vec![0u8; MAX_NOTE_SIZE]);
        assert!(validate_transaction_rules(&txn).is_ok());
    }

    #[test]
    fn test_lease_wrong_size_fails() {
        let mut txn = make_valid_txn();
        txn.lease = ByteBuf::from(vec![0u8; 16]); // not 32
        let err = validate_transaction_rules(&txn).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("lease"), "unexpected error: {msg}");
    }

    #[test]
    fn test_lease_exactly_32_passes() {
        let mut txn = make_valid_txn();
        txn.lease = ByteBuf::from(vec![0u8; 32]);
        assert!(validate_transaction_rules(&txn).is_ok());
    }

    #[test]
    fn test_group_field_wrong_size_fails() {
        let mut txn = make_valid_txn();
        txn.group = ByteBuf::from(vec![0u8; 10]); // not 32
        let err = validate_transaction_rules(&txn).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("group field"), "unexpected error: {msg}");
    }

    // ── Group validation tests ──────────────────────────────────

    /// Wrap a Transaction into a SignedTransaction with default sig fields.
    fn wrap_signed(txn: Transaction) -> SignedTransaction {
        SignedTransaction {
            txn,
            sig: ByteBuf::from(vec![0u8; 64]),
            msig: None,
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        }
    }

    #[test]
    fn test_group_id_computation() {
        let txn1 = make_valid_txn();
        let mut txn2 = make_valid_txn();
        txn2.amount = 999;

        let gid = compute_group_id(&[txn1, txn2]);
        assert_eq!(gid.as_bytes().len(), 32);
        assert!(!gid.is_zero(), "group ID should not be all zeros");
    }

    #[test]
    fn test_group_too_large_fails() {
        // Create 17 txns in a group.
        let base = make_valid_txn();
        let txns: Vec<Transaction> = (0..17)
            .map(|i| {
                let mut t = base.clone();
                t.amount = i;
                t
            })
            .collect();
        let gid = compute_group_id(&txns);

        let signed: Vec<SignedTransaction> = txns
            .into_iter()
            .map(|mut t| {
                t.group = ByteBuf::from(gid.as_bytes().to_vec());
                wrap_signed(t)
            })
            .collect();

        let err = validate_transaction_group(&signed).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("maximum"),
            "expected max group size error, got: {msg}"
        );
    }

    #[test]
    fn test_single_txn_group_fails() {
        let mut txn = make_valid_txn();
        // Set a non-empty group ID on a single txn.
        txn.group = ByteBuf::from(vec![0xAA; 32]);
        let signed = vec![wrap_signed(txn)];

        let err = validate_transaction_group(&signed).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("only 1 member"),
            "expected single-txn group error, got: {msg}"
        );
    }

    #[test]
    fn test_group_id_mismatch_fails() {
        let txn1 = make_valid_txn();
        let mut txn2 = make_valid_txn();
        txn2.amount = 999;

        // Use a wrong group ID.
        let wrong_gid = ByteBuf::from(vec![0xFF; 32]);
        let mut s1 = txn1;
        s1.group = wrong_gid.clone();
        let mut s2 = txn2;
        s2.group = wrong_gid;

        let signed = vec![wrap_signed(s1), wrap_signed(s2)];
        let err = validate_transaction_group(&signed).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mismatch"),
            "expected group ID mismatch error, got: {msg}"
        );
    }

    #[test]
    fn test_standalone_txn_no_group_passes() {
        let txn = make_valid_txn();
        let signed = vec![wrap_signed(txn)];
        assert!(validate_transaction_group(&signed).is_ok());
    }

    #[test]
    fn test_valid_group_passes() {
        let txn1 = make_valid_txn();
        let mut txn2 = make_valid_txn();
        txn2.amount = 999;

        let gid = compute_group_id(&[txn1.clone(), txn2.clone()]);

        let mut s1 = txn1;
        s1.group = ByteBuf::from(gid.as_bytes().to_vec());
        let mut s2 = txn2;
        s2.group = ByteBuf::from(gid.as_bytes().to_vec());

        let signed = vec![wrap_signed(s1), wrap_signed(s2)];
        assert!(validate_transaction_group(&signed).is_ok());
    }

    // ── Lease constraint tests ──────────────────────────────────

    #[test]
    fn test_lease_duplicate_in_group_fails() {
        let mut txn1 = make_valid_txn();
        txn1.lease = ByteBuf::from(vec![0x42; 32]);
        let mut txn2 = make_valid_txn();
        txn2.lease = ByteBuf::from(vec![0x42; 32]); // same sender, same lease
        txn2.amount = 999;

        let gid = compute_group_id(&[txn1.clone(), txn2.clone()]);
        txn1.group = ByteBuf::from(gid.as_bytes().to_vec());
        txn2.group = ByteBuf::from(gid.as_bytes().to_vec());

        let signed = vec![wrap_signed(txn1), wrap_signed(txn2)];
        let err = validate_lease_constraints(&signed).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate lease"),
            "expected duplicate lease error, got: {msg}"
        );
    }

    #[test]
    fn test_lease_unique_in_group_passes() {
        let mut txn1 = make_valid_txn();
        txn1.lease = ByteBuf::from(vec![0x42; 32]);
        let mut txn2 = make_valid_txn();
        txn2.lease = ByteBuf::from(vec![0x43; 32]); // different lease
        txn2.amount = 999;

        let gid = compute_group_id(&[txn1.clone(), txn2.clone()]);
        txn1.group = ByteBuf::from(gid.as_bytes().to_vec());
        txn2.group = ByteBuf::from(gid.as_bytes().to_vec());

        let signed = vec![wrap_signed(txn1), wrap_signed(txn2)];
        assert!(validate_lease_constraints(&signed).is_ok());
    }

    // ── Genesis consistency tests ───────────────────────────────

    #[test]
    fn test_genesis_id_mismatch_fails() {
        let mut txn = make_valid_txn();
        txn.genesis_id = "testnet-v1.0".to_string();
        let signed = vec![wrap_signed(txn)];

        let err = validate_genesis_consistency(&signed, "mainnet-v1.0", &[]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("genesis ID mismatch"),
            "expected genesis ID mismatch, got: {msg}"
        );
    }

    #[test]
    fn test_genesis_hash_mismatch_fails() {
        let mut txn = make_valid_txn();
        txn.genesis_hash = ByteBuf::from(vec![0xAA; 32]);
        let signed = vec![wrap_signed(txn)];

        let err = validate_genesis_consistency(&signed, "", &[0xBB; 32]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("genesis hash mismatch"),
            "expected genesis hash mismatch, got: {msg}"
        );
    }

    #[test]
    fn test_genesis_fields_match_passes() {
        let mut txn = make_valid_txn();
        txn.genesis_id = "testnet-v1.0".to_string();
        txn.genesis_hash = ByteBuf::from(vec![0xAA; 32]);
        let signed = vec![wrap_signed(txn)];

        assert!(validate_genesis_consistency(&signed, "testnet-v1.0", &[0xAA; 32]).is_ok());
    }

    #[test]
    fn test_genesis_empty_fields_pass() {
        // Txns with empty genesis fields should pass regardless of block values.
        let txn = make_valid_txn();
        let signed = vec![wrap_signed(txn)];
        assert!(validate_genesis_consistency(&signed, "mainnet-v1.0", &[0xFF; 32]).is_ok());
    }

    // ── Protocol version tests ───────────────────────────────────

    #[test]
    fn test_known_short_version_passes() {
        assert!(validate_protocol_version("v7").is_ok());
        assert!(validate_protocol_version("v12").is_ok());
    }

    #[test]
    fn test_known_url_version_passes() {
        // v41
        assert!(validate_protocol_version(
            "https://github.com/algorandfoundation/specs/tree/953304de35264fc3ef91bcd05c123242015eeaed"
        ).is_ok());
    }

    #[test]
    fn test_future_version_passes() {
        assert!(validate_protocol_version("future").is_ok());
    }

    #[test]
    fn test_alpha_version_passes() {
        assert!(validate_protocol_version("alpha1").is_ok());
    }

    #[test]
    fn test_unknown_version_fails() {
        let err = validate_protocol_version("v99").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unknown protocol version"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_empty_version_fails() {
        let err = validate_protocol_version("").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("empty"), "unexpected error: {msg}");
    }

    #[test]
    fn test_max_txn_bytes_v12_returns_1mb() {
        assert_eq!(
            max_txn_bytes_per_block("v12").unwrap(),
            MAX_TXN_BYTES_PER_BLOCK_V32
        );
    }

    #[test]
    fn test_max_txn_bytes_v33_returns_5mb() {
        // v33 URL
        assert_eq!(
            max_txn_bytes_per_block(
                "https://github.com/algorandfoundation/specs/tree/830a4e673148498cc7230a0d1ba1ed0a5471acc6"
            ).unwrap(),
            MAX_TXN_BYTES_PER_BLOCK_V33
        );
    }

    #[test]
    fn test_max_txn_bytes_future_returns_5mb() {
        assert_eq!(
            max_txn_bytes_per_block("future").unwrap(),
            MAX_TXN_BYTES_PER_BLOCK_V33
        );
    }

    #[test]
    fn test_max_txn_bytes_unknown_version_fails() {
        assert!(max_txn_bytes_per_block("v99").is_err());
    }
}
