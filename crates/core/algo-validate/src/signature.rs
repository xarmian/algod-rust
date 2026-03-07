use algo_codec::canonical_encode_transaction;
use algo_error::AlgoError;
use algo_types::{Address, LogicSig, MultisigSig, SignedTransaction};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha512_256};

/// Domain separation prefix for transaction signing/verification.
const TX_PREFIX: &[u8] = b"TX";

/// Domain separation prefix for multisig address derivation.
const MSIG_ADDR_PREFIX: &[u8] = b"MultisigAddr";

/// Domain separation prefix for logic signature / program hashing.
const PROGRAM_PREFIX: &[u8] = b"Program";

/// Verify a single ed25519 signature on a signed transaction.
///
/// The signed message is `b"TX" || canonical_encode(txn)`.
/// The public key is derived from the sender address (or `auth_addr` if rekeyed).
pub fn verify_single_sig(stx: &SignedTransaction) -> Result<(), AlgoError> {
    if stx.sig.is_empty() {
        return Err(AlgoError::Validation {
            message: "single-sig verification called but sig field is empty".into(),
        });
    }

    let sig_bytes: [u8; 64] = stx.sig[..].try_into().map_err(|_| AlgoError::Validation {
        message: format!(
            "invalid signature length: expected 64 bytes, got {}",
            stx.sig.len()
        ),
    })?;
    let signature = Signature::from_bytes(&sig_bytes);

    // Use auth_addr (rekeyed) if present, otherwise sender IS the public key.
    let pk_bytes = match &stx.auth_addr {
        Some(addr) => addr.0,
        None => stx.txn.sender.0,
    };

    let verifying_key = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| AlgoError::Validation {
        message: format!("invalid public key: {e}"),
    })?;

    // Build the signed message: "TX" || canonical_encode(txn)
    let canonical = canonical_encode_transaction(&stx.txn);
    let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
    msg.extend_from_slice(TX_PREFIX);
    msg.extend_from_slice(&canonical);

    verifying_key
        .verify(&msg, &signature)
        .map_err(|e| AlgoError::Validation {
            message: format!("ed25519 signature verification failed: {e}"),
        })
}

/// Compute the multisig address from the multisig parameters.
///
/// Address = SHA512/256("MultisigAddr" || version || threshold || pk1 || pk2 || ... || pkN)
fn compute_multisig_address(msig: &MultisigSig) -> Address {
    let mut hasher = Sha512_256::new();
    hasher.update(MSIG_ADDR_PREFIX);
    hasher.update([msig.version]);
    hasher.update([msig.threshold]);
    for subsig in &msig.subsigs {
        hasher.update(&subsig.public_key[..]);
    }
    let hash = hasher.finalize();
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&hash);
    Address(addr)
}

/// Validate multisig parameters (version, threshold, subsig count).
///
/// Rejects unsupported versions, threshold of 0, threshold exceeding subsig count,
/// and more than 255 subsigs (which would overflow a u8 counter).
fn validate_multisig_params(msig: &MultisigSig) -> Result<(), AlgoError> {
    if msig.version != 1 {
        return Err(AlgoError::Validation {
            message: format!("unsupported multisig version: {}", msig.version),
        });
    }
    if msig.threshold == 0 || msig.threshold as usize > msig.subsigs.len() {
        return Err(AlgoError::Validation {
            message: format!(
                "invalid multisig threshold: {} (subsigs: {})",
                msig.threshold,
                msig.subsigs.len()
            ),
        });
    }
    if msig.subsigs.len() > 255 {
        return Err(AlgoError::Validation {
            message: format!(
                "too many multisig subsigs: {} (max 255)",
                msig.subsigs.len()
            ),
        });
    }
    Ok(())
}

/// Verify multisig subsignatures against a message, returning Ok if threshold is met.
///
/// This is the shared inner function used by both transaction multisig and logicsig
/// delegated multisig verification.
fn verify_multisig_subsigs(msig: &MultisigSig, msg: &[u8], context: &str) -> Result<(), AlgoError> {
    validate_multisig_params(msig)?;

    let mut valid_count: u16 = 0;
    for subsig in &msig.subsigs {
        // Validate public key length for all subsigs, even unsigned ones.
        if subsig.public_key.len() != 32 {
            return Err(AlgoError::Validation {
                message: format!(
                    "invalid {context} subsig public key length: expected 32 bytes, got {}",
                    subsig.public_key.len()
                ),
            });
        }

        if subsig.signature.is_empty() {
            continue;
        }

        let sig_bytes: [u8; 64] =
            subsig.signature[..]
                .try_into()
                .map_err(|_| AlgoError::Validation {
                    message: format!(
                        "invalid {context} subsig length: expected 64 bytes, got {}",
                        subsig.signature.len()
                    ),
                })?;
        let signature = Signature::from_bytes(&sig_bytes);

        let pk_bytes: [u8; 32] =
            subsig.public_key[..]
                .try_into()
                .map_err(|_| AlgoError::Validation {
                    message: format!(
                        "invalid {context} public key length: expected 32 bytes, got {}",
                        subsig.public_key.len()
                    ),
                })?;
        let verifying_key =
            VerifyingKey::from_bytes(&pk_bytes).map_err(|e| AlgoError::Validation {
                message: format!("invalid {context} public key: {e}"),
            })?;

        verifying_key
            .verify(msg, &signature)
            .map_err(|e| AlgoError::Validation {
                message: format!("{context} subsig verification failed: {e}"),
            })?;

        valid_count += 1;
    }

    if valid_count < msig.threshold as u16 {
        return Err(AlgoError::Validation {
            message: format!(
                "{context} threshold not met: have {valid_count} valid signatures, need {}",
                msig.threshold
            ),
        });
    }

    Ok(())
}

/// Check that the multisig address matches the expected sender/auth_addr.
fn check_multisig_address(
    stx: &SignedTransaction,
    msig: &MultisigSig,
    context: &str,
) -> Result<(), AlgoError> {
    let msig_addr = compute_multisig_address(msig);
    let expected_addr = match &stx.auth_addr {
        Some(addr) => addr,
        None => &stx.txn.sender,
    };
    if *expected_addr != msig_addr {
        return Err(AlgoError::Validation {
            message: format!(
                "{context}: sender/auth_addr does not match computed multisig address"
            ),
        });
    }
    Ok(())
}

/// Verify a multisig signature on a signed transaction.
///
/// 1. Validate multisig parameters (version, threshold, subsig count).
/// 2. Compute the multisig address from the subsig public keys.
/// 3. Check that sender (or auth_addr if rekeyed) matches the multisig address.
/// 4. Verify each non-empty subsig against the transaction signing message.
/// 5. Check that the number of valid signatures >= threshold.
pub fn verify_multisig(stx: &SignedTransaction, msig: &MultisigSig) -> Result<(), AlgoError> {
    check_multisig_address(stx, msig, "multisig address mismatch")?;

    // Build the signing message: "TX" || canonical_encode(txn)
    let canonical = canonical_encode_transaction(&stx.txn);
    let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
    msg.extend_from_slice(TX_PREFIX);
    msg.extend_from_slice(&canonical);

    verify_multisig_subsigs(msig, &msg, "multisig")
}

/// Verify a multisig used in a logicsig delegation context.
///
/// Similar to `verify_multisig` but verifies against "Program" || logic instead of "TX" || txn.
fn verify_logicsig_multisig(
    stx: &SignedTransaction,
    msig: &MultisigSig,
    program_msg: &[u8],
) -> Result<(), AlgoError> {
    check_multisig_address(stx, msig, "logicsig delegated multisig")?;
    verify_multisig_subsigs(msig, program_msg, "logicsig multisig")
}

/// Verify a logic signature on a signed transaction.
///
/// Three modes:
/// 1. Delegated (sig present): verify ed25519 signature on "Program" || logic
/// 2. Delegated multisig (msig present): verify multisig on "Program" || logic
/// 3. Contract account: sender = SHA512/256("Program" || logic)
///
/// TEAL program evaluation is deferred to Phase 3.
pub fn verify_logicsig(stx: &SignedTransaction, lsig: &LogicSig) -> Result<(), AlgoError> {
    // LogicSig sig and msig are mutually exclusive.
    if !lsig.sig.is_empty() && lsig.msig.is_some() {
        return Err(AlgoError::Validation {
            message: "logicsig has both sig and msig set; expected at most one".into(),
        });
    }

    // Build program message: "Program" || logic
    let mut program_msg = Vec::with_capacity(PROGRAM_PREFIX.len() + lsig.logic.len());
    program_msg.extend_from_slice(PROGRAM_PREFIX);
    program_msg.extend_from_slice(&lsig.logic);

    if !lsig.sig.is_empty() {
        // Mode 1: Delegated single-sig
        let sig_bytes: [u8; 64] = lsig.sig[..].try_into().map_err(|_| AlgoError::Validation {
            message: format!(
                "invalid logicsig signature length: expected 64 bytes, got {}",
                lsig.sig.len()
            ),
        })?;
        let signature = Signature::from_bytes(&sig_bytes);

        // The signer is the sender (or auth_addr if rekeyed).
        let pk_bytes = match &stx.auth_addr {
            Some(addr) => addr.0,
            None => stx.txn.sender.0,
        };

        let verifying_key =
            VerifyingKey::from_bytes(&pk_bytes).map_err(|e| AlgoError::Validation {
                message: format!("invalid logicsig delegated public key: {e}"),
            })?;

        verifying_key
            .verify(&program_msg, &signature)
            .map_err(|e| AlgoError::Validation {
                message: format!("logicsig delegated signature verification failed: {e}"),
            })?;
    } else if let Some(msig) = &lsig.msig {
        // Mode 2: Delegated multisig
        verify_logicsig_multisig(stx, msig, &program_msg)?;
    } else {
        // Mode 3: Contract account — sender should be SHA512/256("Program" || logic)
        let hash = Sha512_256::digest(&program_msg);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&hash);
        let expected_addr = Address(expected);

        let sender = match &stx.auth_addr {
            Some(addr) => addr,
            None => &stx.txn.sender,
        };

        if *sender != expected_addr {
            return Err(AlgoError::Validation {
                message: "logicsig contract account: sender does not match program hash".into(),
            });
        }
    }

    tracing::debug!("TEAL program evaluation skipped (deferred to Phase 3)");
    Ok(())
}

/// Verify the signature on a signed transaction, dispatching by signature type.
///
/// - Single-sig (`sig` present): verifies ed25519 signature.
/// - Multisig (`msig` present): verifies multisig threshold signature.
/// - LogicSig (`lsig` present): verifies logic signature (delegated or contract account).
/// - No signature present: returns an error.
pub fn verify_transaction_signature(stx: &SignedTransaction) -> Result<(), AlgoError> {
    // Go-algorand requires exactly one of sig/msig/lsig.
    let has_sig = !stx.sig.is_empty();
    let has_msig = stx.msig.is_some();
    let has_lsig = stx.lsig.is_some();
    let count = has_sig as u8 + has_msig as u8 + has_lsig as u8;
    if count == 0 {
        return Err(AlgoError::Validation {
            message: "transaction has no signature (no sig, msig, or lsig)".into(),
        });
    }
    if count != 1 {
        return Err(AlgoError::Validation {
            message: format!("expected exactly one signature type, found {count}"),
        });
    }

    if has_sig {
        return verify_single_sig(stx);
    }

    if let Some(msig) = &stx.msig {
        return verify_multisig(stx, msig);
    }

    if let Some(lsig) = &stx.lsig {
        return verify_logicsig(stx, lsig);
    }

    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::{Address, MultisigSubsig, Round, Transaction};
    use ed25519_dalek::SigningKey;
    use serde_bytes::ByteBuf;

    /// Create a signing key from a fixed seed for reproducibility.
    fn test_signing_key() -> SigningKey {
        let seed: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        SigningKey::from_bytes(&seed)
    }

    /// Create a signing key from a given seed byte (fills 32 bytes with the same value).
    fn signing_key_from_seed(seed_byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed_byte; 32])
    }

    /// Build a minimal pay transaction with the given sender address.
    fn minimal_pay_txn(sender: Address) -> Transaction {
        Transaction {
            txn_type: "pay".into(),
            sender,
            fee: 1000,
            first_valid: Round(1),
            last_valid: Round(1000),
            receiver: Address([0x42; 32]),
            amount: 100_000,
            ..Default::default()
        }
    }

    /// Sign a transaction with the given key, returning the 64-byte signature.
    fn sign_txn(key: &SigningKey, txn: &Transaction) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let canonical = canonical_encode_transaction(txn);
        let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
        msg.extend_from_slice(TX_PREFIX);
        msg.extend_from_slice(&canonical);
        let sig = key.sign(&msg);
        sig.to_bytes().to_vec()
    }

    /// Sign a program message ("Program" || logic) with the given key.
    fn sign_program(key: &SigningKey, logic: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let mut msg = Vec::with_capacity(PROGRAM_PREFIX.len() + logic.len());
        msg.extend_from_slice(PROGRAM_PREFIX);
        msg.extend_from_slice(logic);
        let sig = key.sign(&msg);
        sig.to_bytes().to_vec()
    }

    /// Build a MultisigSig with N keys, signing with the specified key indices.
    fn build_multisig(
        keys: &[SigningKey],
        sign_indices: &[usize],
        threshold: u8,
        txn: &Transaction,
    ) -> MultisigSig {
        let subsigs: Vec<MultisigSubsig> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let pk = key.verifying_key();
                let signature = if sign_indices.contains(&i) {
                    ByteBuf::from(sign_txn(key, txn))
                } else {
                    ByteBuf::new()
                };
                MultisigSubsig {
                    public_key: ByteBuf::from(pk.to_bytes().to_vec()),
                    signature,
                }
            })
            .collect();

        MultisigSig {
            version: 1,
            threshold,
            subsigs,
        }
    }

    /// Compute the multisig address for a set of keys with given version/threshold.
    fn compute_msig_addr(keys: &[SigningKey], version: u8, threshold: u8) -> Address {
        let msig = MultisigSig {
            version,
            threshold,
            subsigs: keys
                .iter()
                .map(|k| MultisigSubsig {
                    public_key: ByteBuf::from(k.verifying_key().to_bytes().to_vec()),
                    signature: ByteBuf::new(),
                })
                .collect(),
        };
        compute_multisig_address(&msig)
    }

    #[test]
    fn verify_correct_single_sig() {
        let key = test_signing_key();
        let pk = key.verifying_key();
        let sender = Address(pk.to_bytes());
        let txn = minimal_pay_txn(sender);
        let sig = sign_txn(&key, &txn);

        let stx = SignedTransaction {
            txn,
            sig: ByteBuf::from(sig),
            msig: None,
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        assert!(verify_single_sig(&stx).is_ok());
        assert!(verify_transaction_signature(&stx).is_ok());
    }

    #[test]
    fn verify_wrong_sig_fails() {
        let key = test_signing_key();
        let pk = key.verifying_key();
        let sender = Address(pk.to_bytes());
        let txn = minimal_pay_txn(sender);

        // Use a corrupted signature (flip a byte).
        let mut sig = sign_txn(&key, &txn);
        sig[0] ^= 0xFF;

        let stx = SignedTransaction {
            txn,
            sig: ByteBuf::from(sig),
            msig: None,
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        let err = verify_single_sig(&stx).unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
    }

    #[test]
    fn verify_wrong_key_fails() {
        let key = test_signing_key();
        let txn = minimal_pay_txn(Address([0xAA; 32])); // wrong sender
        let sig = sign_txn(&key, &txn);

        let stx = SignedTransaction {
            txn,
            sig: ByteBuf::from(sig),
            msig: None,
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        // Sender 0xAA..AA is not a valid ed25519 public key, so this should fail.
        let err = verify_single_sig(&stx).unwrap_err();
        assert!(
            err.to_string().contains("invalid public key")
                || err.to_string().contains("signature verification failed")
        );
    }

    #[test]
    fn verify_no_sig_errors() {
        let txn = minimal_pay_txn(Address([0x01; 32]));
        let stx = SignedTransaction {
            txn,
            sig: ByteBuf::from(vec![]),
            msig: None,
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        let err = verify_transaction_signature(&stx).unwrap_err();
        assert!(err.to_string().contains("no signature"));
    }

    #[test]
    fn verify_rekeyed_account() {
        let key = test_signing_key();
        let pk = key.verifying_key();
        let auth = Address(pk.to_bytes());

        // Sender is different from auth_addr (simulating a rekeyed account).
        let different_sender = Address([0xBB; 32]);
        let txn = minimal_pay_txn(different_sender);
        let sig = sign_txn(&key, &txn);

        let stx = SignedTransaction {
            txn,
            sig: ByteBuf::from(sig),
            msig: None,
            lsig: None,
            auth_addr: Some(auth),
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        assert!(verify_single_sig(&stx).is_ok());
    }

    // ---- Multisig tests ----

    #[test]
    fn verify_multisig_2_of_3_passes() {
        let keys: Vec<SigningKey> = (10u8..13).map(signing_key_from_seed).collect();
        let msig_addr = compute_msig_addr(&keys, 1, 2);
        let txn = minimal_pay_txn(msig_addr);

        // Sign with keys 0 and 2 (2 of 3).
        let msig = build_multisig(&keys, &[0, 2], 2, &txn);

        let stx = SignedTransaction {
            txn,
            sig: ByteBuf::new(),
            msig: Some(msig),
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        assert!(verify_multisig(&stx, stx.msig.as_ref().unwrap()).is_ok());
        assert!(verify_transaction_signature(&stx).is_ok());
    }

    #[test]
    fn verify_multisig_below_threshold_fails() {
        let keys: Vec<SigningKey> = (10u8..13).map(signing_key_from_seed).collect();
        let msig_addr = compute_msig_addr(&keys, 1, 2);
        let txn = minimal_pay_txn(msig_addr);

        // Sign with only key 1 (1 of 3, threshold is 2).
        let msig = build_multisig(&keys, &[1], 2, &txn);

        let stx = SignedTransaction {
            txn,
            sig: ByteBuf::new(),
            msig: Some(msig),
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        let err = verify_multisig(&stx, stx.msig.as_ref().unwrap()).unwrap_err();
        assert!(err.to_string().contains("threshold not met"));
    }

    #[test]
    fn verify_multisig_wrong_address_fails() {
        let keys: Vec<SigningKey> = (10u8..13).map(signing_key_from_seed).collect();
        // Use a wrong sender (not the multisig address).
        let wrong_sender = Address([0xCC; 32]);
        let txn = minimal_pay_txn(wrong_sender);

        let msig = build_multisig(&keys, &[0, 1], 2, &txn);

        let stx = SignedTransaction {
            txn,
            sig: ByteBuf::new(),
            msig: Some(msig),
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        let err = verify_multisig(&stx, stx.msig.as_ref().unwrap()).unwrap_err();
        assert!(err.to_string().contains("address mismatch"));
    }

    // ---- LogicSig tests ----

    #[test]
    fn verify_logicsig_contract_account() {
        // A dummy TEAL program (just some bytes).
        let logic = vec![0x06, 0x81, 0x01]; // TEAL v6, int 1

        // Compute contract account address: SHA512/256("Program" || logic)
        let mut program_msg = Vec::new();
        program_msg.extend_from_slice(PROGRAM_PREFIX);
        program_msg.extend_from_slice(&logic);
        let hash = Sha512_256::digest(&program_msg);
        let mut addr_bytes = [0u8; 32];
        addr_bytes.copy_from_slice(&hash);
        let contract_addr = Address(addr_bytes);

        let txn = minimal_pay_txn(contract_addr);
        let lsig = LogicSig {
            logic: ByteBuf::from(logic),
            sig: ByteBuf::new(),
            msig: None,
            args: None,
            lmsig: None,
        };

        let stx = SignedTransaction {
            txn,
            sig: ByteBuf::new(),
            msig: None,
            lsig: Some(lsig),
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        assert!(verify_logicsig(&stx, stx.lsig.as_ref().unwrap()).is_ok());
        assert!(verify_transaction_signature(&stx).is_ok());
    }

    #[test]
    fn verify_logicsig_contract_account_wrong_sender() {
        let logic = vec![0x06, 0x81, 0x01];
        let wrong_sender = Address([0xDD; 32]);
        let txn = minimal_pay_txn(wrong_sender);
        let lsig = LogicSig {
            logic: ByteBuf::from(logic),
            sig: ByteBuf::new(),
            msig: None,
            args: None,
            lmsig: None,
        };

        let stx = SignedTransaction {
            txn,
            sig: ByteBuf::new(),
            msig: None,
            lsig: Some(lsig),
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        let err = verify_logicsig(&stx, stx.lsig.as_ref().unwrap()).unwrap_err();
        assert!(err.to_string().contains("does not match program hash"));
    }

    #[test]
    fn verify_logicsig_delegated_sig() {
        let key = test_signing_key();
        let pk = key.verifying_key();
        let sender = Address(pk.to_bytes());

        let logic = vec![0x06, 0x81, 0x01];
        let sig = sign_program(&key, &logic);

        let txn = minimal_pay_txn(sender);
        let lsig = LogicSig {
            logic: ByteBuf::from(logic),
            sig: ByteBuf::from(sig),
            msig: None,
            args: None,
            lmsig: None,
        };

        let stx = SignedTransaction {
            txn,
            sig: ByteBuf::new(),
            msig: None,
            lsig: Some(lsig),
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        assert!(verify_logicsig(&stx, stx.lsig.as_ref().unwrap()).is_ok());
        assert!(verify_transaction_signature(&stx).is_ok());
    }

    #[test]
    fn verify_logicsig_delegated_multisig() {
        let keys: Vec<SigningKey> = (20u8..23).map(signing_key_from_seed).collect();
        let msig_addr = compute_msig_addr(&keys, 1, 2);

        let logic = vec![0x06, 0x81, 0x01];

        // Build multisig over program message, signing with keys 0 and 1.
        let subsigs: Vec<MultisigSubsig> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let pk = key.verifying_key();
                let signature = if i < 2 {
                    ByteBuf::from(sign_program(key, &logic))
                } else {
                    ByteBuf::new()
                };
                MultisigSubsig {
                    public_key: ByteBuf::from(pk.to_bytes().to_vec()),
                    signature,
                }
            })
            .collect();

        let msig = MultisigSig {
            version: 1,
            threshold: 2,
            subsigs,
        };

        let txn = minimal_pay_txn(msig_addr);
        let lsig = LogicSig {
            logic: ByteBuf::from(logic),
            sig: ByteBuf::new(),
            msig: Some(msig),
            args: None,
            lmsig: None,
        };

        let stx = SignedTransaction {
            txn,
            sig: ByteBuf::new(),
            msig: None,
            lsig: Some(lsig),
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        assert!(verify_logicsig(&stx, stx.lsig.as_ref().unwrap()).is_ok());
        assert!(verify_transaction_signature(&stx).is_ok());
    }

    // ---- Security / edge-case tests ----

    #[test]
    fn verify_multisig_threshold_zero_fails() {
        let keys: Vec<SigningKey> = (10u8..13).map(signing_key_from_seed).collect();
        // Build a multisig with threshold 0 — should be rejected.
        let msig_addr = compute_msig_addr(&keys, 1, 0);
        let txn = minimal_pay_txn(msig_addr);
        let msig = build_multisig(&keys, &[], 0, &txn);

        let stx = SignedTransaction {
            txn,
            sig: ByteBuf::new(),
            msig: Some(msig),
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        let err = verify_multisig(&stx, stx.msig.as_ref().unwrap()).unwrap_err();
        assert!(
            err.to_string().contains("invalid multisig threshold"),
            "expected threshold validation error, got: {err}"
        );
    }

    #[test]
    fn verify_multisig_unsupported_version_fails() {
        let keys: Vec<SigningKey> = (10u8..13).map(signing_key_from_seed).collect();
        // Version 2 is not supported.
        let msig_addr = compute_msig_addr(&keys, 2, 2);
        let txn = minimal_pay_txn(msig_addr);

        let mut msig = build_multisig(&keys, &[0, 1], 2, &txn);
        msig.version = 2;

        let stx = SignedTransaction {
            txn,
            sig: ByteBuf::new(),
            msig: Some(msig),
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        let err = verify_multisig(&stx, stx.msig.as_ref().unwrap()).unwrap_err();
        assert!(
            err.to_string().contains("unsupported multisig version"),
            "expected version validation error, got: {err}"
        );
    }

    #[test]
    fn verify_multisig_threshold_exceeds_subsigs_fails() {
        let keys: Vec<SigningKey> = (10u8..12).map(signing_key_from_seed).collect(); // only 2 keys
        let msig_addr = compute_msig_addr(&keys, 1, 3);
        let txn = minimal_pay_txn(msig_addr);
        let msig = build_multisig(&keys, &[0, 1], 3, &txn); // threshold 3 but only 2 subsigs

        let stx = SignedTransaction {
            txn,
            sig: ByteBuf::new(),
            msig: Some(msig),
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        let err = verify_multisig(&stx, stx.msig.as_ref().unwrap()).unwrap_err();
        assert!(
            err.to_string().contains("invalid multisig threshold"),
            "expected threshold validation error, got: {err}"
        );
    }

    #[test]
    fn verify_multiple_sig_types_fails() {
        let key = test_signing_key();
        let pk = key.verifying_key();
        let sender = Address(pk.to_bytes());
        let txn = minimal_pay_txn(sender);
        let sig = sign_txn(&key, &txn);

        // Transaction has both sig AND msig — should be rejected.
        let keys: Vec<SigningKey> = (10u8..13).map(signing_key_from_seed).collect();
        let msig = build_multisig(&keys, &[0, 1], 2, &txn);

        let stx = SignedTransaction {
            txn,
            sig: ByteBuf::from(sig),
            msig: Some(msig),
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        let err = verify_transaction_signature(&stx).unwrap_err();
        assert!(
            err.to_string().contains("exactly one signature type"),
            "expected mutual exclusivity error, got: {err}"
        );
    }

    #[test]
    fn verify_logicsig_both_sig_and_msig_fails() {
        let key = test_signing_key();
        let pk = key.verifying_key();
        let sender = Address(pk.to_bytes());

        let logic = vec![0x06, 0x81, 0x01];
        let sig = sign_program(&key, &logic);

        // Build a logicsig that has BOTH sig and msig — should be rejected.
        let keys: Vec<SigningKey> = (20u8..23).map(signing_key_from_seed).collect();
        let subsigs: Vec<MultisigSubsig> = keys
            .iter()
            .map(|k| MultisigSubsig {
                public_key: ByteBuf::from(k.verifying_key().to_bytes().to_vec()),
                signature: ByteBuf::new(),
            })
            .collect();
        let msig = MultisigSig {
            version: 1,
            threshold: 2,
            subsigs,
        };

        let txn = minimal_pay_txn(sender);
        let lsig = LogicSig {
            logic: ByteBuf::from(logic),
            sig: ByteBuf::from(sig),
            msig: Some(msig),
            args: None,
            lmsig: None,
        };

        let stx = SignedTransaction {
            txn,
            sig: ByteBuf::new(),
            msig: None,
            lsig: Some(lsig),
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        let err = verify_logicsig(&stx, stx.lsig.as_ref().unwrap()).unwrap_err();
        assert!(
            err.to_string().contains("both sig and msig"),
            "expected mutual exclusivity error, got: {err}"
        );
    }

    #[test]
    fn verify_multisig_invalid_pk_length_fails() {
        let keys: Vec<SigningKey> = (10u8..13).map(signing_key_from_seed).collect();
        let txn = minimal_pay_txn(Address([0; 32])); // placeholder sender

        let mut msig = build_multisig(&keys, &[0, 1], 2, &txn);
        // Corrupt the third subsig's public key to be wrong length (unsigned subsig).
        msig.subsigs[2].public_key = ByteBuf::from(vec![0u8; 16]); // 16 bytes instead of 32

        // Compute the address from the corrupted msig so the address check passes.
        let msig_addr = compute_multisig_address(&msig);
        let txn = minimal_pay_txn(msig_addr);
        // Rebuild signatures for keys 0 and 1 with the correct txn.
        msig.subsigs[0].signature = ByteBuf::from(sign_txn(&keys[0], &txn));
        msig.subsigs[1].signature = ByteBuf::from(sign_txn(&keys[1], &txn));

        let stx = SignedTransaction {
            txn,
            sig: ByteBuf::new(),
            msig: Some(msig),
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        let err = verify_multisig(&stx, stx.msig.as_ref().unwrap()).unwrap_err();
        assert!(
            err.to_string().contains("public key length"),
            "expected public key length error, got: {err}"
        );
    }
}
