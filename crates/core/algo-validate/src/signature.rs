use algo_avm::group::GroupBudget;
use algo_avm::logicsig_context::LogicSigAvmContext;
use algo_avm::run_logicsig_program;
use algo_codec::canonical_encode_transaction;
use algo_error::AlgoError;
use algo_types::consensus::ConsensusParams;
use algo_types::{Address, HeartbeatProof, LogicSig, MultisigSig, SignedTransaction};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha512_256};

/// Domain separation prefix for transaction signing/verification.
const TX_PREFIX: &[u8] = b"TX";

/// Domain separation prefix for multisig address derivation.
const MSIG_ADDR_PREFIX: &[u8] = b"MultisigAddr";

/// Domain separation prefix for logic signature / program hashing.
const PROGRAM_PREFIX: &[u8] = b"Program";

/// Domain separation prefix for logic multisig program (lmsig) hashing.
/// Used when verifying LMsig delegation: `"MsigProgram" || addr || program`.
const MSIG_PROGRAM_PREFIX: &[u8] = b"MsigProgram";

/// Domain separation prefix for one-time signature batch subkey (level 1).
/// Used to sign `OneTimeSignatureSubkeyBatchID` under the master vote key.
const OT1_PREFIX: &[u8] = b"OT1";

/// Domain separation prefix for one-time signature offset subkey (level 2).
/// Used to sign `OneTimeSignatureSubkeyOffsetID` under the batch subkey.
const OT2_PREFIX: &[u8] = b"OT2";

/// Domain separation prefix for seed signing.
/// Used to sign the block seed under the ephemeral key.
const SEED_PREFIX: &[u8] = b"SD";

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
/// Four modes (exactly one of sig/msig/lmsig must be set, or none for contract account):
/// 1. Delegated (sig present): verify ed25519 signature on "Program" || logic
/// 2. Delegated multisig (msig present): verify multisig on "Program" || logic
/// 3. Delegated logic-multisig (lmsig present): verify multisig on "MsigProgram" || addr || logic
/// 4. Contract account (no sig/msig/lmsig): sender = SHA512/256("Program" || logic)
///
/// After signature verification, the TEAL program is executed via the AVM.
/// The `group` slice is the full transaction group (used for `gtxn` access).
/// `group_index` is the index of `stx` within that group.
/// `budget` is the shared LogicSig budget pool for the group (each txn
/// contributes `LOGICSIG_BUDGET` = 20,000 opcodes).
///
pub fn verify_logicsig(
    stx: &SignedTransaction,
    lsig: &LogicSig,
    group: &[SignedTransaction],
    group_index: usize,
    budget: &mut GroupBudget,
    consensus: &ConsensusParams,
) -> Result<(), AlgoError> {
    // ── Structural sanity checks (Go: logicSigSanityCheckBatchPrep) ──
    // Empty program is always invalid.
    if lsig.logic.is_empty() {
        return Err(AlgoError::Validation {
            message: "LogicSig.Logic empty".into(),
        });
    }

    // Size check: len(logic) + sum(len(args[i])) must not exceed LogicSigMaxSize.
    // When EnableLogicSigSizePooling is true (v40+), the per-txn check is
    // skipped and the total is checked at group level instead (see
    // `verify_group_logicsig_size`).
    let mut lsig_len: u64 = lsig.logic.len() as u64;
    if let Some(ref args) = lsig.args {
        for arg in args {
            lsig_len += arg.len() as u64;
        }
    }
    if !consensus.enable_logicsig_size_pooling && lsig_len > consensus.logic_sig_max_size {
        return Err(AlgoError::Validation {
            message: format!(
                "LogicSig too long: {} bytes exceeds maximum {}",
                lsig_len, consensus.logic_sig_max_size
            ),
        });
    }

    // Count how many of sig/msig/lmsig are set — must be 0 or 1 (matches Go).
    let has_sig = !lsig.sig.is_empty();
    let has_msig = lsig.msig.is_some();
    let has_lmsig = lsig.lmsig.is_some();
    let num_sigs = has_sig as u8 + has_msig as u8 + has_lmsig as u8;

    if num_sigs > 1 {
        return Err(AlgoError::Validation {
            message: "LogicSig should only have one of Sig, Msig, or LMsig but has more than one"
                .into(),
        });
    }

    // The authorizer is auth_addr if set, otherwise sender.
    let authorizer = match &stx.auth_addr {
        Some(addr) => addr,
        None => &stx.txn.sender,
    };

    if num_sigs == 0 {
        // Mode 4: Contract account — authorizer should be SHA512/256("Program" || logic)
        let mut program_msg = Vec::with_capacity(PROGRAM_PREFIX.len() + lsig.logic.len());
        program_msg.extend_from_slice(PROGRAM_PREFIX);
        program_msg.extend_from_slice(&lsig.logic);
        let hash = Sha512_256::digest(&program_msg);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&hash);
        let expected_addr = Address(expected);

        if *authorizer != expected_addr {
            return Err(AlgoError::Validation {
                message: "logicsig contract account: sender does not match program hash".into(),
            });
        }
    } else if has_sig {
        // Mode 1: Delegated single-sig — verify signature on "Program" || logic
        let mut program_msg = Vec::with_capacity(PROGRAM_PREFIX.len() + lsig.logic.len());
        program_msg.extend_from_slice(PROGRAM_PREFIX);
        program_msg.extend_from_slice(&lsig.logic);

        let sig_bytes: [u8; 64] = lsig.sig[..].try_into().map_err(|_| AlgoError::Validation {
            message: format!(
                "invalid logicsig signature length: expected 64 bytes, got {}",
                lsig.sig.len()
            ),
        })?;
        let signature = Signature::from_bytes(&sig_bytes);

        let verifying_key =
            VerifyingKey::from_bytes(&authorizer.0).map_err(|e| AlgoError::Validation {
                message: format!("invalid logicsig delegated public key: {e}"),
            })?;

        verifying_key
            .verify(&program_msg, &signature)
            .map_err(|e| AlgoError::Validation {
                message: format!("logicsig delegated signature verification failed: {e}"),
            })?;
    } else if let Some(msig) = &lsig.msig {
        // Mode 2: Delegated multisig — verify multisig on "Program" || logic
        let mut program_msg = Vec::with_capacity(PROGRAM_PREFIX.len() + lsig.logic.len());
        program_msg.extend_from_slice(PROGRAM_PREFIX);
        program_msg.extend_from_slice(&lsig.logic);
        verify_logicsig_multisig(stx, msig, &program_msg)?;
    } else if let Some(lmsig) = &lsig.lmsig {
        // Mode 3: Delegated logic-multisig (lmsig)
        // Signed data: "MsigProgram" || authorizer_addr || program
        // This matches Go's MultisigProgram{Addr: Digest(authorizer), Program: logic}.ToBeHashed()
        let mut lmsig_msg = Vec::with_capacity(MSIG_PROGRAM_PREFIX.len() + 32 + lsig.logic.len());
        lmsig_msg.extend_from_slice(MSIG_PROGRAM_PREFIX);
        lmsig_msg.extend_from_slice(&authorizer.0);
        lmsig_msg.extend_from_slice(&lsig.logic);
        verify_logicsig_multisig(stx, lmsig, &lmsig_msg)?;
    }

    // ── TEAL program execution ──
    // Build LogicSig arguments from the lsig.args field.
    let args: Vec<Vec<u8>> = lsig
        .args
        .as_ref()
        .map(|a| a.iter().map(|b| b.to_vec()).collect())
        .unwrap_or_default();

    let mut ctx = LogicSigAvmContext::new(group, group_index, &lsig.logic, args, consensus.clone());

    let pass =
        run_logicsig_program(&lsig.logic, &mut ctx, budget).map_err(|e| AlgoError::Validation {
            message: format!("LogicSig program error: {e}"),
        })?;

    if !pass {
        return Err(AlgoError::Validation {
            message: "LogicSig program rejected the transaction".into(),
        });
    }

    Ok(())
}

/// Encode a `OneTimeSignatureSubkeyBatchID` in canonical msgpack format.
///
/// Matches Go's `msgp_gen.go` `(*OneTimeSignatureSubkeyBatchID).MarshalMsg()`:
/// ```text
/// fixmap(2)
///   fixstr("batch") → uint64(batch)
///   fixstr("pk")    → bin(pk_bytes)
/// ```
///
/// The struct uses `codec:""` (non-omitempty), so ALL fields are always
/// encoded, even when zero.
fn encode_batch_id(pk: &[u8; 32], batch: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(50);
    // fixmap(2) + fixstr("batch")
    buf.extend_from_slice(&[0x82, 0xa5, b'b', b'a', b't', b'c', b'h']);
    // uint64 batch (use rmp for correct compact encoding)
    rmp::encode::write_uint(&mut buf, batch).unwrap();
    // fixstr("pk")
    buf.extend_from_slice(&[0xa2, b'p', b'k']);
    // bin(pk_bytes) — 32 bytes
    rmp::encode::write_bin(&mut buf, pk).unwrap();
    buf
}

/// Encode a `OneTimeSignatureSubkeyOffsetID` in canonical msgpack format.
///
/// Matches Go's `msgp_gen.go` `(*OneTimeSignatureSubkeyOffsetID).MarshalMsg()`:
/// ```text
/// fixmap(3)
///   fixstr("batch")  → uint64(batch)
///   fixstr("off")    → uint64(offset)
///   fixstr("pk")     → bin(pk_bytes)
/// ```
///
/// The struct uses `codec:""` (non-omitempty), so ALL fields are always
/// encoded, even when zero.
fn encode_offset_id(pk: &[u8; 32], batch: u64, offset: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(60);
    // fixmap(3) + fixstr("batch")
    buf.extend_from_slice(&[0x83, 0xa5, b'b', b'a', b't', b'c', b'h']);
    // uint64 batch
    rmp::encode::write_uint(&mut buf, batch).unwrap();
    // fixstr("off")
    buf.extend_from_slice(&[0xa3, b'o', b'f', b'f']);
    // uint64 offset
    rmp::encode::write_uint(&mut buf, offset).unwrap();
    // fixstr("pk")
    buf.extend_from_slice(&[0xa2, b'p', b'k']);
    // bin(pk_bytes) — 32 bytes
    rmp::encode::write_bin(&mut buf, pk).unwrap();
    buf
}

/// Verify a heartbeat proof (three-level ed25519 ephemeral key tree).
///
/// This implements the same verification as Go's `HeartbeatProof.BatchPrep()`
/// in `crypto/onetimesig.go`. The proof is a three-level ed25519 key tree:
///
/// 1. **PK2Sig**: `vote_id` signs `"OT1" || encode(BatchID{batch, pk2})`
/// 2. **PK1Sig**: `pk2` signs `"OT2" || encode(OffsetID{pk, batch, offset})`
/// 3. **Sig**: `pk` signs `"SD" || seed`
///
/// Where `batch = last_valid / key_dilution` and `offset = last_valid % key_dilution`.
pub fn verify_heartbeat_proof(
    proof: &HeartbeatProof,
    vote_id: &[u8],
    last_valid: u64,
    key_dilution: u64,
    seed: &[u8],
) -> Result<(), AlgoError> {
    // Guard against division by zero.
    if key_dilution == 0 {
        return Err(AlgoError::Validation {
            message: "heartbeat proof: key_dilution is zero".into(),
        });
    }

    // Extract fixed-size arrays from ByteBuf fields.
    let pk: [u8; 32] = proof.pk[..].try_into().map_err(|_| AlgoError::Validation {
        message: format!(
            "heartbeat proof: invalid pk length: expected 32, got {}",
            proof.pk.len()
        ),
    })?;
    let pk2: [u8; 32] = proof.pk2[..]
        .try_into()
        .map_err(|_| AlgoError::Validation {
            message: format!(
                "heartbeat proof: invalid pk2 length: expected 32, got {}",
                proof.pk2.len()
            ),
        })?;
    let vote_id_bytes: [u8; 32] = vote_id.try_into().map_err(|_| AlgoError::Validation {
        message: format!(
            "heartbeat proof: invalid vote_id length: expected 32, got {}",
            vote_id.len()
        ),
    })?;

    let pk2_sig: [u8; 64] = proof.pk2_sig[..]
        .try_into()
        .map_err(|_| AlgoError::Validation {
            message: format!(
                "heartbeat proof: invalid pk2_sig length: expected 64, got {}",
                proof.pk2_sig.len()
            ),
        })?;
    let pk1_sig: [u8; 64] = proof.pk1_sig[..]
        .try_into()
        .map_err(|_| AlgoError::Validation {
            message: format!(
                "heartbeat proof: invalid pk1_sig length: expected 64, got {}",
                proof.pk1_sig.len()
            ),
        })?;
    let sig: [u8; 64] = proof.sig[..]
        .try_into()
        .map_err(|_| AlgoError::Validation {
            message: format!(
                "heartbeat proof: invalid sig length: expected 64, got {}",
                proof.sig.len()
            ),
        })?;

    let batch = last_valid / key_dilution;
    let offset = last_valid % key_dilution;

    // 1. Verify PK2Sig: vote_id signs BatchID(pk2, batch)
    let batch_id_encoded = encode_batch_id(&pk2, batch);
    let mut batch_msg = Vec::with_capacity(OT1_PREFIX.len() + batch_id_encoded.len());
    batch_msg.extend_from_slice(OT1_PREFIX);
    batch_msg.extend_from_slice(&batch_id_encoded);

    let vk_master =
        VerifyingKey::from_bytes(&vote_id_bytes).map_err(|e| AlgoError::Validation {
            message: format!("heartbeat proof: invalid vote_id key: {e}"),
        })?;
    vk_master
        .verify(&batch_msg, &Signature::from_bytes(&pk2_sig))
        .map_err(|e| AlgoError::Validation {
            message: format!("heartbeat proof: PK2Sig verification failed: {e}"),
        })?;

    // 2. Verify PK1Sig: pk2 signs OffsetID(pk, batch, offset)
    let offset_id_encoded = encode_offset_id(&pk, batch, offset);
    let mut offset_msg = Vec::with_capacity(OT2_PREFIX.len() + offset_id_encoded.len());
    offset_msg.extend_from_slice(OT2_PREFIX);
    offset_msg.extend_from_slice(&offset_id_encoded);

    let vk_batch = VerifyingKey::from_bytes(&pk2).map_err(|e| AlgoError::Validation {
        message: format!("heartbeat proof: invalid pk2 key: {e}"),
    })?;
    vk_batch
        .verify(&offset_msg, &Signature::from_bytes(&pk1_sig))
        .map_err(|e| AlgoError::Validation {
            message: format!("heartbeat proof: PK1Sig verification failed: {e}"),
        })?;

    // 3. Verify Sig: pk signs "SD" || seed
    let mut seed_msg = Vec::with_capacity(SEED_PREFIX.len() + seed.len());
    seed_msg.extend_from_slice(SEED_PREFIX);
    seed_msg.extend_from_slice(seed);

    let vk_ephemeral = VerifyingKey::from_bytes(&pk).map_err(|e| AlgoError::Validation {
        message: format!("heartbeat proof: invalid pk key: {e}"),
    })?;
    vk_ephemeral
        .verify(&seed_msg, &Signature::from_bytes(&sig))
        .map_err(|e| AlgoError::Validation {
            message: format!("heartbeat proof: Sig verification failed: {e}"),
        })?;

    Ok(())
}

/// Check that AuthAddr (if non-zero) is different from Sender.
///
/// Matches Go's `EnforceAuthAddrSenderDiff` consensus parameter check.
/// This is currently only enabled for `future` consensus versions in Go,
/// but we implement it gated on a boolean parameter for forward compatibility.
pub fn verify_auth_addr_sender_diff(
    stx: &SignedTransaction,
    enforce: bool,
) -> Result<(), AlgoError> {
    if !enforce {
        return Ok(());
    }
    if let Some(auth_addr) = &stx.auth_addr {
        if *auth_addr == stx.txn.sender {
            return Err(AlgoError::Validation {
                message: "AuthAddr must be different from Sender".into(),
            });
        }
    }
    Ok(())
}

/// Verify the signature on a signed transaction, dispatching by signature type.
///
/// - Single-sig (`sig` present): verifies ed25519 signature.
/// - Multisig (`msig` present): verifies multisig threshold signature.
/// - LogicSig (`lsig` present): verifies logic signature and executes TEAL program.
/// - No signature present: returns an error.
///
/// For LogicSig transactions, `group` is the full transaction group (needed
/// for `gtxn` opcode access), `group_index` is the index of `stx` within that
/// group, and `lsig_budget` is the shared LogicSig opcode budget pool.
/// For non-LogicSig transactions these parameters are ignored.
pub fn verify_transaction_signature(
    stx: &SignedTransaction,
    group: &[SignedTransaction],
    group_index: usize,
    lsig_budget: &mut GroupBudget,
    consensus: &ConsensusParams,
) -> Result<(), AlgoError> {
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
        return verify_logicsig(stx, lsig, group, group_index, lsig_budget, consensus);
    }

    unreachable!()
}

/// Compute the total LogicSig size for a group of transactions.
///
/// Returns the sum of `len(logic) + sum(len(arg))` across all LogicSigs in the group.
/// Non-LogicSig transactions contribute 0.
pub fn logicsig_group_size(group: &[SignedTransaction]) -> u64 {
    let mut total: u64 = 0;
    for stx in group {
        if let Some(lsig) = &stx.lsig {
            total += lsig.logic.len() as u64;
            if let Some(ref args) = lsig.args {
                for arg in args {
                    total += arg.len() as u64;
                }
            }
        }
    }
    total
}

/// Verify that the pooled LogicSig size for a group does not exceed the limit.
///
/// Called when `EnableLogicSigSizePooling` is true (v40+). The total available
/// pool is `group_size * LogicSigMaxSize`.
pub fn verify_group_logicsig_size(
    group: &[SignedTransaction],
    consensus: &ConsensusParams,
) -> Result<(), AlgoError> {
    let pooled_size = logicsig_group_size(group);
    let max_pooled = group.len() as u64 * consensus.logic_sig_max_size;
    if pooled_size > max_pooled {
        return Err(AlgoError::Validation {
            message: format!(
                "txgroup had {pooled_size} bytes of LogicSigs, more than the available pool of {max_pooled} bytes"
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_avm::group::GroupBudget;
    use algo_types::{Address, MultisigSubsig, Round, Transaction};
    use ed25519_dalek::SigningKey;
    use serde_bytes::ByteBuf;

    /// Helper: verify a transaction signature with a single-element group and
    /// a fresh LogicSig budget.  Used by tests that don't need group-level
    /// budget pooling semantics.
    fn verify_sig(stx: &SignedTransaction) -> Result<(), AlgoError> {
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        verify_transaction_signature(stx, &group, 0, &mut budget, &ConsensusParams::default())
    }

    /// Helper: verify a logicsig with a single-element group and fresh budget.
    fn verify_lsig(stx: &SignedTransaction, lsig: &LogicSig) -> Result<(), AlgoError> {
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        verify_logicsig(
            stx,
            lsig,
            &group,
            0,
            &mut budget,
            &ConsensusParams::default(),
        )
    }

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
        assert!(verify_sig(&stx).is_ok());
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

        let err = verify_sig(&stx).unwrap_err();
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
        assert!(verify_sig(&stx).is_ok());
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

        assert!(verify_lsig(&stx, stx.lsig.as_ref().unwrap()).is_ok());
        assert!(verify_sig(&stx).is_ok());
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

        let err = verify_lsig(&stx, stx.lsig.as_ref().unwrap()).unwrap_err();
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

        assert!(verify_lsig(&stx, stx.lsig.as_ref().unwrap()).is_ok());
        assert!(verify_sig(&stx).is_ok());
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

        assert!(verify_lsig(&stx, stx.lsig.as_ref().unwrap()).is_ok());
        assert!(verify_sig(&stx).is_ok());
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

        let err = verify_sig(&stx).unwrap_err();
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

        let err = verify_lsig(&stx, stx.lsig.as_ref().unwrap()).unwrap_err();
        assert!(
            err.to_string()
                .contains("only have one of Sig, Msig, or LMsig"),
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

    // ---- LMsig (logic multisig) tests ----

    /// Build the lmsig message: "MsigProgram" || addr || program
    fn build_lmsig_msg(addr: &Address, logic: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(MSIG_PROGRAM_PREFIX.len() + 32 + logic.len());
        msg.extend_from_slice(MSIG_PROGRAM_PREFIX);
        msg.extend_from_slice(&addr.0);
        msg.extend_from_slice(logic);
        msg
    }

    /// Sign an lmsig message with a key.
    fn sign_lmsig_msg(key: &SigningKey, addr: &Address, logic: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let msg = build_lmsig_msg(addr, logic);
        let sig = key.sign(&msg);
        sig.to_bytes().to_vec()
    }

    #[test]
    fn verify_logicsig_delegated_lmsig() {
        let keys: Vec<SigningKey> = (30u8..33).map(signing_key_from_seed).collect();
        let msig_addr = compute_msig_addr(&keys, 1, 2);

        let logic = vec![0x06, 0x81, 0x01];

        // Build lmsig with keys 0 and 1 signing "MsigProgram" || msig_addr || logic
        let subsigs: Vec<MultisigSubsig> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let pk = key.verifying_key();
                let signature = if i < 2 {
                    ByteBuf::from(sign_lmsig_msg(key, &msig_addr, &logic))
                } else {
                    ByteBuf::new()
                };
                MultisigSubsig {
                    public_key: ByteBuf::from(pk.to_bytes().to_vec()),
                    signature,
                }
            })
            .collect();

        let lmsig = MultisigSig {
            version: 1,
            threshold: 2,
            subsigs,
        };

        let txn = minimal_pay_txn(msig_addr);
        let lsig = LogicSig {
            logic: ByteBuf::from(logic),
            sig: ByteBuf::new(),
            msig: None,
            args: None,
            lmsig: Some(lmsig),
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

        assert!(verify_lsig(&stx, stx.lsig.as_ref().unwrap()).is_ok());
        assert!(verify_sig(&stx).is_ok());
    }

    #[test]
    fn verify_logicsig_lmsig_wrong_addr_fails() {
        let keys: Vec<SigningKey> = (30u8..33).map(signing_key_from_seed).collect();
        let msig_addr = compute_msig_addr(&keys, 1, 2);

        let logic = vec![0x06, 0x81, 0x01];

        // Sign with a DIFFERENT address in the lmsig message
        let wrong_addr = Address([0xEE; 32]);
        let subsigs: Vec<MultisigSubsig> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let pk = key.verifying_key();
                let signature = if i < 2 {
                    // Signed with wrong_addr, but the txn sender is msig_addr
                    ByteBuf::from(sign_lmsig_msg(key, &wrong_addr, &logic))
                } else {
                    ByteBuf::new()
                };
                MultisigSubsig {
                    public_key: ByteBuf::from(pk.to_bytes().to_vec()),
                    signature,
                }
            })
            .collect();

        let lmsig = MultisigSig {
            version: 1,
            threshold: 2,
            subsigs,
        };

        let txn = minimal_pay_txn(msig_addr);
        let lsig = LogicSig {
            logic: ByteBuf::from(logic),
            sig: ByteBuf::new(),
            msig: None,
            args: None,
            lmsig: Some(lmsig),
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

        // Should fail because lmsig signatures were made with wrong_addr
        let err = verify_lsig(&stx, stx.lsig.as_ref().unwrap()).unwrap_err();
        assert!(
            err.to_string().contains("verification failed"),
            "expected verification failure, got: {err}"
        );
    }

    #[test]
    fn verify_logicsig_sig_and_lmsig_fails() {
        let key = test_signing_key();
        let pk = key.verifying_key();
        let sender = Address(pk.to_bytes());

        let logic = vec![0x06, 0x81, 0x01];
        let sig = sign_program(&key, &logic);

        let keys: Vec<SigningKey> = (30u8..33).map(signing_key_from_seed).collect();
        let subsigs: Vec<MultisigSubsig> = keys
            .iter()
            .map(|k| MultisigSubsig {
                public_key: ByteBuf::from(k.verifying_key().to_bytes().to_vec()),
                signature: ByteBuf::new(),
            })
            .collect();
        let lmsig = MultisigSig {
            version: 1,
            threshold: 2,
            subsigs,
        };

        let txn = minimal_pay_txn(sender);
        let lsig = LogicSig {
            logic: ByteBuf::from(logic),
            sig: ByteBuf::from(sig),
            msig: None,
            args: None,
            lmsig: Some(lmsig),
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

        let err = verify_lsig(&stx, stx.lsig.as_ref().unwrap()).unwrap_err();
        assert!(
            err.to_string()
                .contains("only have one of Sig, Msig, or LMsig"),
            "expected mutual exclusivity error, got: {err}"
        );
    }

    // ---- AuthAddr == Sender rejection tests ----

    #[test]
    fn verify_auth_addr_equals_sender_rejected_when_enforced() {
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
            auth_addr: Some(sender), // Same as sender
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        // With enforcement enabled, should fail.
        let err = verify_auth_addr_sender_diff(&stx, true).unwrap_err();
        assert!(
            err.to_string()
                .contains("AuthAddr must be different from Sender"),
            "expected auth addr error, got: {err}"
        );

        // With enforcement disabled, should pass.
        assert!(verify_auth_addr_sender_diff(&stx, false).is_ok());
    }

    #[test]
    fn verify_auth_addr_different_from_sender_passes() {
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
            auth_addr: Some(Address([0xFF; 32])), // Different from sender
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        assert!(verify_auth_addr_sender_diff(&stx, true).is_ok());
    }

    #[test]
    fn verify_auth_addr_none_passes() {
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

        assert!(verify_auth_addr_sender_diff(&stx, true).is_ok());
    }

    // ---- Heartbeat proof tests ----

    /// Build a valid three-level ed25519 heartbeat proof.
    ///
    /// Returns `(proof, master_pk, seed)` where the proof verifies
    /// under the master public key for the given `last_valid` and `key_dilution`.
    fn build_heartbeat_proof(
        last_valid: u64,
        key_dilution: u64,
    ) -> (HeartbeatProof, [u8; 32], [u8; 32]) {
        use ed25519_dalek::Signer;

        let batch = last_valid / key_dilution;
        let offset = last_valid % key_dilution;
        let seed = [0x42u8; 32];

        // Three levels of keys: master -> batch -> ephemeral
        let master_key = SigningKey::from_bytes(&[0x01; 32]);
        let batch_key = SigningKey::from_bytes(&[0x02; 32]);
        let ephemeral_key = SigningKey::from_bytes(&[0x03; 32]);

        let master_pk = master_key.verifying_key().to_bytes();
        let batch_pk = batch_key.verifying_key().to_bytes();
        let ephemeral_pk = ephemeral_key.verifying_key().to_bytes();

        // 1. Master signs BatchID(batch_pk, batch)
        let batch_id_encoded = encode_batch_id(&batch_pk, batch);
        let mut batch_msg = Vec::new();
        batch_msg.extend_from_slice(OT1_PREFIX);
        batch_msg.extend_from_slice(&batch_id_encoded);
        let pk2_sig = master_key.sign(&batch_msg);

        // 2. Batch key signs OffsetID(ephemeral_pk, batch, offset)
        let offset_id_encoded = encode_offset_id(&ephemeral_pk, batch, offset);
        let mut offset_msg = Vec::new();
        offset_msg.extend_from_slice(OT2_PREFIX);
        offset_msg.extend_from_slice(&offset_id_encoded);
        let pk1_sig = batch_key.sign(&offset_msg);

        // 3. Ephemeral key signs "SD" || seed
        let mut seed_msg = Vec::new();
        seed_msg.extend_from_slice(SEED_PREFIX);
        seed_msg.extend_from_slice(&seed);
        let sig = ephemeral_key.sign(&seed_msg);

        let proof = HeartbeatProof {
            sig: ByteBuf::from(sig.to_bytes().to_vec()),
            pk: ByteBuf::from(ephemeral_pk.to_vec()),
            pk2: ByteBuf::from(batch_pk.to_vec()),
            pk1_sig: ByteBuf::from(pk1_sig.to_bytes().to_vec()),
            pk2_sig: ByteBuf::from(pk2_sig.to_bytes().to_vec()),
        };

        (proof, master_pk, seed)
    }

    #[test]
    fn heartbeat_proof_valid() {
        let last_valid = 1000u64;
        let key_dilution = 100u64;
        let (proof, master_pk, seed) = build_heartbeat_proof(last_valid, key_dilution);
        assert!(
            verify_heartbeat_proof(&proof, &master_pk, last_valid, key_dilution, &seed).is_ok()
        );
    }

    #[test]
    fn heartbeat_proof_valid_with_large_round() {
        // Test with a large round number that exercises batch/offset calculation.
        let last_valid = 999_999u64;
        let key_dilution = 256u64;
        let (proof, master_pk, seed) = build_heartbeat_proof(last_valid, key_dilution);
        assert!(
            verify_heartbeat_proof(&proof, &master_pk, last_valid, key_dilution, &seed).is_ok()
        );
    }

    #[test]
    fn heartbeat_proof_valid_offset_zero() {
        // Test when offset is exactly 0 (last_valid is a multiple of key_dilution).
        let key_dilution = 100u64;
        let last_valid = 500u64; // 500 % 100 = 0
        let (proof, master_pk, seed) = build_heartbeat_proof(last_valid, key_dilution);
        assert!(
            verify_heartbeat_proof(&proof, &master_pk, last_valid, key_dilution, &seed).is_ok()
        );
    }

    #[test]
    fn heartbeat_proof_invalid_pk2sig_wrong_master() {
        let last_valid = 1000u64;
        let key_dilution = 100u64;
        let (proof, _master_pk, seed) = build_heartbeat_proof(last_valid, key_dilution);

        // Use a different master key — PK2Sig should fail.
        let wrong_master = SigningKey::from_bytes(&[0xFF; 32]);
        let wrong_master_pk = wrong_master.verifying_key().to_bytes();

        let err = verify_heartbeat_proof(&proof, &wrong_master_pk, last_valid, key_dilution, &seed)
            .unwrap_err();
        assert!(
            err.to_string().contains("PK2Sig verification failed"),
            "expected PK2Sig failure, got: {err}"
        );
    }

    #[test]
    fn heartbeat_proof_invalid_pk1sig_wrong_batch_key() {
        use ed25519_dalek::Signer;

        let last_valid = 1000u64;
        let key_dilution = 100u64;
        let batch = last_valid / key_dilution;
        let offset = last_valid % key_dilution;
        let seed = [0x42u8; 32];

        let master_key = SigningKey::from_bytes(&[0x01; 32]);
        let batch_key = SigningKey::from_bytes(&[0x02; 32]);
        let wrong_batch_key = SigningKey::from_bytes(&[0xAA; 32]);
        let ephemeral_key = SigningKey::from_bytes(&[0x03; 32]);

        let master_pk = master_key.verifying_key().to_bytes();
        let batch_pk = batch_key.verifying_key().to_bytes();
        let ephemeral_pk = ephemeral_key.verifying_key().to_bytes();

        // PK2Sig is valid (master signed batch_pk correctly)
        let batch_id_encoded = encode_batch_id(&batch_pk, batch);
        let mut batch_msg = Vec::new();
        batch_msg.extend_from_slice(OT1_PREFIX);
        batch_msg.extend_from_slice(&batch_id_encoded);
        let pk2_sig = master_key.sign(&batch_msg);

        // PK1Sig is INVALID — signed by wrong_batch_key instead of batch_key
        let offset_id_encoded = encode_offset_id(&ephemeral_pk, batch, offset);
        let mut offset_msg = Vec::new();
        offset_msg.extend_from_slice(OT2_PREFIX);
        offset_msg.extend_from_slice(&offset_id_encoded);
        let pk1_sig = wrong_batch_key.sign(&offset_msg);

        // Sig is valid
        let mut seed_msg = Vec::new();
        seed_msg.extend_from_slice(SEED_PREFIX);
        seed_msg.extend_from_slice(&seed);
        let sig = ephemeral_key.sign(&seed_msg);

        let proof = HeartbeatProof {
            sig: ByteBuf::from(sig.to_bytes().to_vec()),
            pk: ByteBuf::from(ephemeral_pk.to_vec()),
            pk2: ByteBuf::from(batch_pk.to_vec()),
            pk1_sig: ByteBuf::from(pk1_sig.to_bytes().to_vec()),
            pk2_sig: ByteBuf::from(pk2_sig.to_bytes().to_vec()),
        };

        let err = verify_heartbeat_proof(&proof, &master_pk, last_valid, key_dilution, &seed)
            .unwrap_err();
        assert!(
            err.to_string().contains("PK1Sig verification failed"),
            "expected PK1Sig failure, got: {err}"
        );
    }

    #[test]
    fn heartbeat_proof_invalid_sig_wrong_seed() {
        let last_valid = 1000u64;
        let key_dilution = 100u64;
        let (proof, master_pk, _seed) = build_heartbeat_proof(last_valid, key_dilution);

        // Use a different seed — ephemeral Sig should fail.
        let wrong_seed = [0xFF; 32];
        let err = verify_heartbeat_proof(&proof, &master_pk, last_valid, key_dilution, &wrong_seed)
            .unwrap_err();
        assert!(
            err.to_string().contains("Sig verification failed"),
            "expected Sig failure, got: {err}"
        );
    }

    #[test]
    fn heartbeat_proof_invalid_sig_wrong_ephemeral_key() {
        use ed25519_dalek::Signer;

        let last_valid = 1000u64;
        let key_dilution = 100u64;
        let batch = last_valid / key_dilution;
        let offset = last_valid % key_dilution;
        let seed = [0x42u8; 32];

        let master_key = SigningKey::from_bytes(&[0x01; 32]);
        let batch_key = SigningKey::from_bytes(&[0x02; 32]);
        let ephemeral_key = SigningKey::from_bytes(&[0x03; 32]);
        let wrong_ephemeral_key = SigningKey::from_bytes(&[0xBB; 32]);

        let master_pk = master_key.verifying_key().to_bytes();
        let batch_pk = batch_key.verifying_key().to_bytes();
        let ephemeral_pk = ephemeral_key.verifying_key().to_bytes();

        // PK2Sig valid
        let batch_id_encoded = encode_batch_id(&batch_pk, batch);
        let mut batch_msg = Vec::new();
        batch_msg.extend_from_slice(OT1_PREFIX);
        batch_msg.extend_from_slice(&batch_id_encoded);
        let pk2_sig = master_key.sign(&batch_msg);

        // PK1Sig valid (signed by batch_key for ephemeral_pk)
        let offset_id_encoded = encode_offset_id(&ephemeral_pk, batch, offset);
        let mut offset_msg = Vec::new();
        offset_msg.extend_from_slice(OT2_PREFIX);
        offset_msg.extend_from_slice(&offset_id_encoded);
        let pk1_sig = batch_key.sign(&offset_msg);

        // Sig INVALID — signed by wrong ephemeral key
        let mut seed_msg = Vec::new();
        seed_msg.extend_from_slice(SEED_PREFIX);
        seed_msg.extend_from_slice(&seed);
        let sig = wrong_ephemeral_key.sign(&seed_msg);

        let proof = HeartbeatProof {
            sig: ByteBuf::from(sig.to_bytes().to_vec()),
            pk: ByteBuf::from(ephemeral_pk.to_vec()),
            pk2: ByteBuf::from(batch_pk.to_vec()),
            pk1_sig: ByteBuf::from(pk1_sig.to_bytes().to_vec()),
            pk2_sig: ByteBuf::from(pk2_sig.to_bytes().to_vec()),
        };

        let err = verify_heartbeat_proof(&proof, &master_pk, last_valid, key_dilution, &seed)
            .unwrap_err();
        assert!(
            err.to_string().contains("Sig verification failed"),
            "expected Sig failure, got: {err}"
        );
    }

    #[test]
    fn heartbeat_proof_wrong_batch_from_last_valid() {
        let last_valid = 1000u64;
        let key_dilution = 100u64;
        let (proof, master_pk, seed) = build_heartbeat_proof(last_valid, key_dilution);

        // Use a different last_valid — batch/offset will be different, PK2Sig should fail.
        let wrong_last_valid = 1050u64; // batch=10, offset=50 (different from 1000/100=10,0)
        let err = verify_heartbeat_proof(&proof, &master_pk, wrong_last_valid, key_dilution, &seed)
            .unwrap_err();
        // The offset changed (0 -> 50), so PK1Sig will fail because the offset
        // in the signed OffsetID doesn't match.
        assert!(
            err.to_string().contains("verification failed"),
            "expected verification failure with wrong last_valid, got: {err}"
        );
    }

    #[test]
    fn heartbeat_proof_wrong_key_dilution() {
        let last_valid = 1000u64;
        let key_dilution = 100u64;
        let (proof, master_pk, seed) = build_heartbeat_proof(last_valid, key_dilution);

        // Different key_dilution changes both batch and offset.
        let wrong_kd = 200u64; // batch=5, offset=0 vs batch=10, offset=0
        let err =
            verify_heartbeat_proof(&proof, &master_pk, last_valid, wrong_kd, &seed).unwrap_err();
        assert!(
            err.to_string().contains("verification failed"),
            "expected verification failure with wrong key_dilution, got: {err}"
        );
    }

    #[test]
    fn heartbeat_proof_zero_key_dilution_errors() {
        let (proof, master_pk, seed) = build_heartbeat_proof(1000, 100);
        let err = verify_heartbeat_proof(&proof, &master_pk, 1000, 0, &seed).unwrap_err();
        assert!(
            err.to_string().contains("key_dilution is zero"),
            "expected division-by-zero guard, got: {err}"
        );
    }

    #[test]
    fn heartbeat_proof_invalid_pk_length() {
        let (mut proof, master_pk, seed) = build_heartbeat_proof(1000, 100);
        proof.pk = ByteBuf::from(vec![0u8; 16]); // Wrong length
        let err = verify_heartbeat_proof(&proof, &master_pk, 1000, 100, &seed).unwrap_err();
        assert!(
            err.to_string().contains("invalid pk length"),
            "expected pk length error, got: {err}"
        );
    }

    #[test]
    fn heartbeat_proof_invalid_sig_length() {
        let (mut proof, master_pk, seed) = build_heartbeat_proof(1000, 100);
        proof.sig = ByteBuf::from(vec![0u8; 32]); // 32 instead of 64
        let err = verify_heartbeat_proof(&proof, &master_pk, 1000, 100, &seed).unwrap_err();
        assert!(
            err.to_string().contains("invalid sig length"),
            "expected sig length error, got: {err}"
        );
    }

    #[test]
    fn heartbeat_proof_invalid_vote_id_length() {
        let (proof, _master_pk, seed) = build_heartbeat_proof(1000, 100);
        let bad_vote_id = [0u8; 16]; // 16 instead of 32
        let err = verify_heartbeat_proof(&proof, &bad_vote_id, 1000, 100, &seed).unwrap_err();
        assert!(
            err.to_string().contains("invalid vote_id length"),
            "expected vote_id length error, got: {err}"
        );
    }

    // ---- BatchID / OffsetID encoding tests ----

    #[test]
    fn encode_batch_id_matches_go() {
        // Verify that our encoding matches Go's msgp_gen.go MarshalMsg output.
        // BatchID with batch=0 and pk=all zeros should produce:
        //   0x82 (fixmap 2)
        //   0xa5 "batch"  -> 0x00 (positive fixint 0)
        //   0xa2 "pk"     -> 0xc4 0x20 [32 zero bytes]
        let pk = [0u8; 32];
        let encoded = encode_batch_id(&pk, 0);

        // fixmap(2)
        assert_eq!(encoded[0], 0x82);
        // fixstr("batch") = a5 + "batch"
        assert_eq!(&encoded[1..7], &[0xa5, b'b', b'a', b't', b'c', b'h']);
        // uint 0 = 0x00
        assert_eq!(encoded[7], 0x00);
        // fixstr("pk") = a2 + "pk"
        assert_eq!(&encoded[8..11], &[0xa2, b'p', b'k']);
        // bin8 header for 32 bytes = c4 20
        assert_eq!(encoded[11], 0xc4);
        assert_eq!(encoded[12], 0x20);
        // 32 zero bytes
        assert_eq!(&encoded[13..45], &[0u8; 32]);
        assert_eq!(encoded.len(), 45);
    }

    #[test]
    fn encode_offset_id_matches_go() {
        // OffsetID with batch=0, offset=0, pk=all zeros:
        //   0x83 (fixmap 3)
        //   0xa5 "batch"  -> 0x00
        //   0xa3 "off"    -> 0x00
        //   0xa2 "pk"     -> 0xc4 0x20 [32 zero bytes]
        let pk = [0u8; 32];
        let encoded = encode_offset_id(&pk, 0, 0);

        assert_eq!(encoded[0], 0x83);
        // "batch"
        assert_eq!(&encoded[1..7], &[0xa5, b'b', b'a', b't', b'c', b'h']);
        assert_eq!(encoded[7], 0x00); // batch = 0
                                      // "off"
        assert_eq!(&encoded[8..12], &[0xa3, b'o', b'f', b'f']);
        assert_eq!(encoded[12], 0x00); // offset = 0
                                       // "pk"
        assert_eq!(&encoded[13..16], &[0xa2, b'p', b'k']);
        assert_eq!(encoded[16], 0xc4);
        assert_eq!(encoded[17], 0x20);
        assert_eq!(&encoded[18..50], &[0u8; 32]);
        assert_eq!(encoded.len(), 50);
    }

    #[test]
    fn encode_batch_id_nonzero_batch() {
        // Verify that a non-zero batch value is encoded correctly.
        // batch=10 (0x0a) should encode as positive fixint 0x0a.
        let pk = [0xAA; 32];
        let encoded = encode_batch_id(&pk, 10);
        // batch value at position 7
        assert_eq!(encoded[7], 0x0a);
    }

    #[test]
    fn encode_offset_id_nonzero_values() {
        // batch=256, offset=42 — 256 requires uint16 encoding (0xcd 0x01 0x00).
        let pk = [0xBB; 32];
        let encoded = encode_offset_id(&pk, 256, 42);
        // batch=256 is encoded as uint16: cd 01 00
        assert_eq!(&encoded[7..10], &[0xcd, 0x01, 0x00]);
        // "off" at offset 10..14
        assert_eq!(&encoded[10..14], &[0xa3, b'o', b'f', b'f']);
        // offset=42 is positive fixint: 0x2a
        assert_eq!(encoded[14], 0x2a);
    }
}
