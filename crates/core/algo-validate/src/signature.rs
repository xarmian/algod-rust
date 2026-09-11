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

//! Transaction/LogicSig/heartbeat authorization checks, including ed25519
//! signature verification.
//!
//! ## ed25519 malleability-acceptance ruleset (issue #1136)
//!
//! go-algorand's single-signature ed25519 verify (`ed25519Verify`,
//! `crypto/curve25519.go`) does **not** call libsodium's plain
//! `crypto_sign_ed25519_verify_detached`. It deliberately calls
//! `crypto_sign_ed25519_bv_compatible_verify_detached` instead, so that
//! single-signature verification always agrees with go-algorand's batch
//! verifier on the same signature -- avoiding a class of fork risk where
//! two conforming nodes could disagree on whether a maliciously-crafted
//! signature is valid.
//!
//! `bv_compatible` differs from `ed25519_dalek::Verifier::verify()`'s
//! default (RFC 8032-ish, "cofactorless") ruleset in three ways, confirmed
//! by porting go-algorand's `TestBatchVerifierTamingEdDSAsEdgeCases` /
//! `TestBatchVerifierEd25519ConsensusTestData` / `TestBatchVerifierLibsodiumTestData`
//! / `TestBatchVerifierFilippoVectors` vectors (`crypto/gobatchverifier_test.go`)
//! through this module's actual verify path -- see the `bv_compatible_vectors`
//! test module below:
//!
//! 1. **Cofactored vs. cofactorless verification equation.** `bv_compatible`
//!    checks `[8][s]B == [8]R + [8][h]A'` (multiplying the *difference* by
//!    the curve's cofactor, 8, before comparing to the identity element).
//!    `ed25519_dalek::verify()` checks the stricter `[s]B == R + [h]A'`
//!    with no cofactor multiplication. This means some signatures with a
//!    torsion (small-order) component in `R` or `A` that go-algorand's
//!    verify (and its batch verifier) **accepts** are **rejected** by
//!    `ed25519_dalek::verify()` -- see "Taming the many EdDSAs" (Appendix
//!    C) vectors #3-#6, all `expectedFail: false` under go's criteria
//!    despite `S*B != R + h*A`.
//! 2. **Small-order public key (`A`) rejection.** `bv_compatible` explicitly
//!    rejects a small-order `A` (`ge25519_has_small_order(pk)`), which
//!    `ed25519_dalek::verify()` does not check at all (only its
//!    `verify_strict()` does, and that method keeps the *stricter*
//!    cofactorless equation from point 1, so it does not reproduce
//!    `bv_compatible` either).
//! 3. **Non-canonical point encoding.** `bv_compatible` rejects a
//!    non-canonically-encoded `A` (`ge25519_is_canonical_vartime(pk)`).
//!    `ed25519_dalek::VerifyingKey::from_bytes` explicitly follows ZIP-215
//!    decompression rules and accepts (mod-`p`-reduces) non-canonical `A`
//!    encodings -- see its doc comment.
//!
//! Neither `ed25519_dalek::verify()` nor `verify_strict()` reproduces this
//! ruleset, so [`ed25519_bv_compatible_verify`] implements it directly
//! against `curve25519-dalek` primitives (the same crate `ed25519-dalek`
//! itself builds on) and is used at every ed25519 signature-check call site
//! in this module -- single-sig, multisig subsigs, LogicSig delegated sig,
//! and heartbeat proofs -- so single-signature verification in algod-rust
//! matches go-algorand's `ed25519Verify` bit-for-bit on the full ported
//! vector corpus, closing the fork-risk gap described in issue #1136.

use algo_avm::group::GroupBudget;
use algo_avm::logicsig_context::{LogicSigAvmContext, SigBlockSource};
use algo_avm::{run_logicsig_program, run_logicsig_program_with_tracer, EvalTracer};
use algo_codec::canonical_encode_transaction;
use algo_error::AlgoError;
use algo_types::consensus::ConsensusParams;
use algo_types::{
    Address, HeartbeatProof, LogicSig, MultisigSig, PQDelegatedProgram, PQSig, SignedTransaction,
};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use sha2::{Digest, Sha512, Sha512_256};

/// Domain separation prefix for transaction signing/verification.
const TX_PREFIX: &[u8] = b"TX";

/// Domain separation prefix for multisig address derivation.
const MSIG_ADDR_PREFIX: &[u8] = b"MultisigAddr";

/// Domain separation prefix for logic signature / program hashing.
const PROGRAM_PREFIX: &[u8] = b"Program";

/// The contract-account address for a LogicSig program: `SHA512/256("Program"
/// || logic)`. Mirrors go's `logic.HashProgram` (`data/transactions/logic/
/// program.go`) -- used both by the escrow (no-delegation-signature)
/// LogicSig dispatch and by simulation's placeholder-delegated-PQ-signature
/// fallback (issue #835), which converts a validated placeholder into an
/// escrow account authorized by the program hash.
pub fn hash_program(logic: &[u8]) -> Address {
    let mut program_msg = Vec::with_capacity(PROGRAM_PREFIX.len() + logic.len());
    program_msg.extend_from_slice(PROGRAM_PREFIX);
    program_msg.extend_from_slice(logic);
    let hash = Sha512_256::digest(&program_msg);
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&hash);
    Address(expected)
}

/// Domain separation prefix for logic multisig program (lmsig) hashing.
/// Used when verifying LMsig delegation: `"MsigProgram" || addr || program`.
const MSIG_PROGRAM_PREFIX: &[u8] = b"MsigProgram";

/// Maximum number of arguments to a LogicSig, enforced at TEAL-eval entry.
///
/// Matches go-algorand's `transactions.EvalMaxArgs`
/// (`data/transactions/logicsig.go`), checked in `EvalSignatureFull`
/// (`data/transactions/logic/eval.go`) -- see `TestTooManyArgs`
/// (`data/transactions/logic/eval_test.go`).
const EVAL_MAX_ARGS: usize = 255;

/// Maximum size of a single LogicSig argument, enforced at TEAL-eval entry.
///
/// Matches go-algorand's `transactions.MaxLogicSigArgSize` (`data/
/// transactions/logicsig.go`), which is `config.MaxAVMBytesSize` -- the
/// same 4096-byte ceiling as [`algo_avm::opcode::MAX_STRING_SIZE`]. Checked
/// in `EvalSignatureFull` -- see `TestArgTooLarge`
/// (`data/transactions/logic/eval_test.go`).
const MAX_LOGIC_SIG_ARG_SIZE: usize = algo_avm::opcode::MAX_STRING_SIZE;

/// Domain separation prefix for one-time signature batch subkey (level 1).
/// Used to sign `OneTimeSignatureSubkeyBatchID` under the master vote key.
const OT1_PREFIX: &[u8] = b"OT1";

/// Domain separation prefix for one-time signature offset subkey (level 2).
/// Used to sign `OneTimeSignatureSubkeyOffsetID` under the batch subkey.
const OT2_PREFIX: &[u8] = b"OT2";

/// Domain separation prefix for seed signing.
/// Used to sign the block seed under the ephemeral key.
const SEED_PREFIX: &[u8] = b"SD";

/// Verify a raw ed25519 signature against libsodium's `bv_compatible`
/// malleability-acceptance ruleset, matching go-algorand's `ed25519Verify`
/// (`crypto/curve25519.go`, which calls
/// `crypto_sign_ed25519_bv_compatible_verify_detached` rather than plain
/// verification). See this module's doc comment for the full rationale and
/// the exact rules this diverges from `ed25519_dalek::Verifier::verify()`
/// on (issue #1136). This is the SOLE ed25519 verify primitive used by
/// every signature-check call site in this module, mirroring go's
/// `crypto/libsodium-fork/src/libsodium/crypto_sign/ed25519/ref10/
/// open_bv_compat.c`'s `_crypto_sign_ed25519_bv_compatible_verify_detached`
/// step for step:
///
/// 1. reject a non-canonical `S` (`s >= L`);
/// 2. reject a non-canonically-encoded `R` (or one that doesn't decode to a
///    valid curve point at all);
/// 3. reject a non-canonically-encoded `A`, and reject a canonical but
///    small-order `A` (this is the check `ed25519_dalek::verify()` doesn't
///    perform at all, and `verify_strict()` only performs alongside a
///    *different*, stricter verification equation -- see point 4);
/// 4. compute `h = SHA512(R || A || M) mod L`, then accept iff
///    `[8]([s]B - [h]A' - R)` is the identity element -- the *cofactored*
///    verification equation, not `ed25519_dalek`'s cofactorless
///    `[s]B == R + [h]A'`.
#[allow(non_snake_case)]
fn ed25519_bv_compatible_verify(pk_bytes: &[u8; 32], msg: &[u8], sig_bytes: &[u8; 64]) -> bool {
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig_bytes[0..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig_bytes[32..64]);

    // 1. Canonical S: 0 <= s < L.
    let s_scalar = match Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) {
        Some(s) => s,
        None => return false,
    };

    // 2. R must decode to a valid curve point AND be canonically encoded
    // (re-compressing the decoded point must reproduce the original bytes).
    let R = match CompressedEdwardsY(r_bytes).decompress() {
        Some(p) => p,
        None => return false,
    };
    if R.compress().0 != r_bytes {
        return false;
    }

    // 3. A must decode to a valid curve point, be canonically encoded, and
    // NOT have small order (this small-order rejection is the bv_compatible-
    // specific check absent from ed25519_dalek's default `verify()`).
    let A = match CompressedEdwardsY(*pk_bytes).decompress() {
        Some(p) => p,
        None => return false,
    };
    if A.compress().0 != *pk_bytes || A.is_small_order() {
        return false;
    }

    // 4. h = SHA512(R || A || M) mod L.
    let mut hasher = Sha512::new();
    Digest::update(&mut hasher, r_bytes);
    Digest::update(&mut hasher, pk_bytes);
    Digest::update(&mut hasher, msg);
    let h_wide: [u8; 64] = Digest::finalize(hasher).into();
    let h = Scalar::from_bytes_mod_order_wide(&h_wide);

    // Cofactored check: [8]([s]B - [h]A' - R) == identity.
    let r_calc = EdwardsPoint::vartime_double_scalar_mul_basepoint(&(-h), &A, &s_scalar);
    (r_calc - R).mul_by_cofactor().is_identity()
}

/// Verify a single ed25519 signature on a signed transaction.
///
/// The signed message is `b"TX" || canonical_encode(txn)`.
/// The public key is derived from the sender address (or `auth_addr` if rekeyed).
pub fn verify_single_sig(stx: &SignedTransaction) -> Result<(), AlgoError> {
    if stx.sig == [0u8; 64] {
        return Err(AlgoError::Validation {
            message: "single-sig verification called but sig field is empty".into(),
        });
    }

    // Use auth_addr (rekeyed) if present, otherwise sender IS the public key.
    let pk_bytes = match &stx.auth_addr {
        Some(addr) => addr.0,
        None => stx.txn.sender.0,
    };

    // Build the signed message: "TX" || canonical_encode(txn)
    let canonical = canonical_encode_transaction(&stx.txn);
    let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
    msg.extend_from_slice(TX_PREFIX);
    msg.extend_from_slice(&canonical);

    if ed25519_bv_compatible_verify(&pk_bytes, &msg, &stx.sig) {
        Ok(())
    } else {
        Err(AlgoError::Validation {
            message: "ed25519 signature verification failed".into(),
        })
    }
}

/// Verify a post-quantum (Falcon-1024) authorization proof over raw
/// to-be-signed `message` bytes, mirroring go's `PQSig.Verify(proto,
/// message, authorizer)` (`data/transactions/pqsig.go`):
/// 1. the envelope is non-blank;
/// 2. the carried scheme is a *known* scheme (only Falcon-1024 is
///    registered; an unregistered-but-defined tag like the reserved
///    Falcon-512 is rejected here, matching go's `LookupPQScheme` miss);
/// 3. the scheme is *enabled* under `consensus` (`PQSchemeEnabled`);
/// 4. the address derived from `{scheme, salt, public_key}` equals
///    `authorizer`;
/// 5. the signature bytes are non-empty;
/// 6. the Falcon-1024 signature verifies over `message`.
///
/// `message` must already be the raw domain-tag-prefixed bytes Falcon signs
/// (go's `crypto.HashRep(message)` — NOT a hash of them; the tag is
/// prepended, not hashed in). Callers build this via
/// [`canonical_encode_transaction`] prefixed with `"TX"` (top-level PQSig)
/// or [`PQDelegatedProgram::to_be_signed`] (PQ-delegated LogicSig).
/// Validate that a `PQSig` carries a known, consensus-enabled scheme,
/// without checking the public-key-derived authorizer or signature bytes.
/// Mirrors go's `PQSig.ValidateScheme` (`data/transactions/pqsig.go`) —
/// used for the simulation "scheme-only" placeholder (see issue #835).
pub fn validate_pqsig_scheme(pqsig: &PQSig, consensus: &ConsensusParams) -> Result<(), AlgoError> {
    if pqsig.blank() {
        return Err(AlgoError::Validation {
            message: "pq signature is blank".into(),
        });
    }
    // Reject any scheme tag not in the registered dispatch table (Go:
    // `LookupPQScheme` miss → `ErrPQSchemeNotSupported`) before checking
    // whether it's consensus-enabled -- an unregistered tag has no verifier
    // to dispatch to regardless of what the consensus params say.
    if algo_consensus_crypto::lookup_pq_scheme(pqsig.scheme).is_none() {
        return Err(AlgoError::Validation {
            message: format!("pq signature scheme not supported: {:?}", pqsig.scheme),
        });
    }
    if !consensus.pq_scheme_enabled(pqsig.scheme) {
        return Err(AlgoError::Validation {
            message: "pq signature scheme not enabled".into(),
        });
    }
    Ok(())
}

/// Validate the stateless, consensus-relevant PQ authorization envelope
/// (scheme + public-key-derived authorizer address), excluding the
/// signature bytes. Mirrors go's `PQSig.ValidateEnvelope`
/// (`data/transactions/pqsig.go`) — used for the simulation "full"
/// placeholder (public key set, signature empty; see issue #835).
pub fn validate_pqsig_envelope(
    pqsig: &PQSig,
    authorizer: &Address,
    consensus: &ConsensusParams,
) -> Result<(), AlgoError> {
    validate_pqsig_scheme(pqsig, consensus)?;

    // Reject an oversized public key BEFORE hashing it for address
    // derivation. `public_key` is attacker-controlled wire input (bounded
    // upstream by overall txn/message size caps, but not by a per-field
    // limit at decode time the way go's `allocbound=crypto.MaxPQPublicKeySize`
    // msgp codegen bounds it) — without this check, a public key blob much
    // larger than a real Falcon-1024 key would still get hashed in full by
    // `pqsig.address()` below before any cheap size check could reject it.
    // go's own `VerifyFalcon1024` performs the equivalent size check, just
    // later (inside signature verification); doing it first here is strictly
    // cheaper and avoids hashing attacker-controlled oversized input.
    if pqsig.public_key.len() != algo_falcon::FALCON_DET1024_PUBKEY_SIZE {
        return Err(AlgoError::Validation {
            message: format!(
                "pq public key size {} does not match falcon-1024 public key size {}",
                pqsig.public_key.len(),
                algo_falcon::FALCON_DET1024_PUBKEY_SIZE
            ),
        });
    }

    let derived = pqsig.address();
    if derived != *authorizer {
        return Err(AlgoError::Validation {
            message: format!(
                "pq signature authorizer mismatch: derived {derived}, expected {authorizer}"
            ),
        });
    }

    Ok(())
}

fn verify_pqsig_bytes(
    pqsig: &PQSig,
    message: &[u8],
    authorizer: &Address,
    consensus: &ConsensusParams,
) -> Result<(), AlgoError> {
    validate_pqsig_envelope(pqsig, authorizer, consensus)?;

    if pqsig.signature.is_empty() {
        return Err(AlgoError::Validation {
            message: "pq signature is empty".into(),
        });
    }

    // `validate_pqsig_envelope` above already confirmed `pqsig.scheme` is a
    // registered scheme, so this lookup cannot miss -- dispatch through it
    // (rather than calling `algo_falcon::falcon_verify` directly) so this is
    // the single place scheme-specific PQ verification is chosen, mirroring
    // go's `stxnCoreChecks`'s use of `LookupPQScheme` at the call site.
    let verifier = algo_consensus_crypto::lookup_pq_scheme(pqsig.scheme).ok_or_else(|| {
        AlgoError::Validation {
            message: format!("pq signature scheme not supported: {:?}", pqsig.scheme),
        }
    })?;
    verifier
        .verify(message, &pqsig.public_key, &pqsig.signature)
        .map_err(|e| AlgoError::Validation {
            message: format!("pq falcon signature verification failed: {e}"),
        })?;

    Ok(())
}

/// Verify a top-level `PQSig` transaction authorization proof, mirroring
/// go's `stxnCoreChecks`'s `case pqSig:` branch
/// (`data/transactions/verify/txn.go`): `PQsig.Verify(proto, s.Txn,
/// s.Authorizer())`, where the signed message is `"TX" ||
/// canonical_encode(txn)` — the exact same message ed25519 single-sig signs
/// (see [`verify_single_sig`]), just authorized by a different signature
/// scheme.
pub fn verify_pqsig(
    stx: &SignedTransaction,
    pqsig: &PQSig,
    consensus: &ConsensusParams,
) -> Result<(), AlgoError> {
    let canonical = canonical_encode_transaction(&stx.txn);
    let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
    msg.extend_from_slice(TX_PREFIX);
    msg.extend_from_slice(&canonical);

    let authorizer = match &stx.auth_addr {
        Some(addr) => addr,
        None => &stx.txn.sender,
    };

    verify_pqsig_bytes(pqsig, &msg, authorizer, consensus)
}

/// Verify a PQ-delegated LogicSig's authorization proof, mirroring go's
/// `logicSigSanityCheckBatchPrep`'s PQ-delegated branch
/// (`data/transactions/verify/txn.go`, added by commit `ef838f4e9`): the
/// signed message is `PQDelegatedProgram{Addr: authorizer, Program:
/// lsig.Logic}.ToBeHashed()`'s `HashRep`, i.e. `"PQProgram" || authorizer ||
/// logic`. Verified in-place (never batched) — PQ (Falcon) signatures are
/// not ed25519-batchable, matching upstream's explicit carve-out. This
/// crate has no ed25519 batch verifier to carve PQSig out of in the first
/// place (every signature path here already verifies eagerly/in-place), so
/// no additional plumbing is needed to satisfy that constraint.
fn verify_pq_delegated_logicsig(
    lsig: &LogicSig,
    pqsig: &PQSig,
    authorizer: &Address,
    consensus: &ConsensusParams,
) -> Result<(), AlgoError> {
    let program = PQDelegatedProgram {
        addr: *authorizer,
        program: lsig.logic.to_vec(),
    };
    verify_pqsig_bytes(pqsig, &program.to_be_signed(), authorizer, consensus).map_err(|e| {
        AlgoError::Validation {
            message: format!("pq delegated logic signature validation failed: {e}"),
        }
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
    // Matches go's `crypto.MultisigBatchPrep` (`crypto/multisig.go`), which
    // begins with:
    //   if (len(sig.Subsigs) == 0 || sig.Subsigs[0] == MultisigSubsig{}) {
    //       return errInvalidNumberOfSignature
    //   }
    // -- unconditionally rejecting a MultisigSig whose first subsig is the
    // zero-valued {Key: zero pubkey, Sig: zero signature} placeholder,
    // before ever computing/comparing the multisig address. Without this,
    // a multisig address that happens to include an all-zero pubkey as one
    // of its configured signers (a slot no private key can ever sign for)
    // could be accepted here on the strength of its *other* signers
    // reaching threshold, even though go-algorand always rejects it
    // outright (issue #1307).
    if msig.subsigs.is_empty()
        || (msig.subsigs[0].public_key == [0u8; 32] && msig.subsigs[0].signature == [0u8; 64])
    {
        return Err(AlgoError::Validation {
            message: "invalid number of signatures: first multisig subsig is empty".into(),
        });
    }
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
        // Public key length is now enforced by the type system ([u8; 32]).

        if subsig.signature == [0u8; 64] {
            continue;
        }

        if !ed25519_bv_compatible_verify(&subsig.public_key, msg, &subsig.signature) {
            return Err(AlgoError::Validation {
                message: format!("{context} subsig verification failed"),
            });
        }

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

/// Signature-level sanity check for a LogicSig, mirroring go-algorand's
/// `verify.LogicSigSanityCheck` (`data/transactions/verify/txn.go:360-444`)
/// **without** executing the program.
///
/// Verifies the structural rules (empty program, at-most-one of
/// sig/msig/lmsig) and the delegation signature itself:
/// - **no sig/msig/lmsig**: contract account — the txn authorizer (auth_addr
///   else sender) must equal `SHA512/256("Program" || logic)`;
/// - **sig**: ed25519 over `"Program" || logic` against the authorizer;
/// - **msig**: multisig over `"Program" || logic`;
/// - **lmsig**: multisig over `"MsigProgram" || authorizer || logic`.
///
/// This is what `goal clerk sign` runs before writing a LogicSig-signed file
/// (the node re-runs the full check, including TEAL execution, on submit).
pub fn logicsig_sanity_check(stx: &SignedTransaction, lsig: &LogicSig) -> Result<(), AlgoError> {
    if lsig.logic.is_empty() {
        return Err(AlgoError::Validation {
            message: "LogicSig.Logic empty".into(),
        });
    }

    let has_sig = lsig.sig != [0u8; 64];
    let has_msig = lsig.msig.is_some();
    let has_lmsig = lsig.lmsig.is_some();
    let num_sigs = has_sig as u8 + has_msig as u8 + has_lmsig as u8;

    if num_sigs > 1 {
        return Err(AlgoError::Validation {
            message: "LogicSig should only have one of Sig, Msig, or LMsig but has more than one"
                .into(),
        });
    }

    let authorizer = match &stx.auth_addr {
        Some(addr) => addr,
        None => &stx.txn.sender,
    };

    if num_sigs == 0 {
        let mut program_msg = Vec::with_capacity(PROGRAM_PREFIX.len() + lsig.logic.len());
        program_msg.extend_from_slice(PROGRAM_PREFIX);
        program_msg.extend_from_slice(&lsig.logic);
        let hash = Sha512_256::digest(&program_msg);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&hash);
        if *authorizer != Address(expected) {
            return Err(AlgoError::Validation {
                message: "logicsig contract account: sender does not match program hash".into(),
            });
        }
    } else if has_sig {
        let mut program_msg = Vec::with_capacity(PROGRAM_PREFIX.len() + lsig.logic.len());
        program_msg.extend_from_slice(PROGRAM_PREFIX);
        program_msg.extend_from_slice(&lsig.logic);
        if !ed25519_bv_compatible_verify(&authorizer.0, &program_msg, &lsig.sig) {
            return Err(AlgoError::Validation {
                message: "logicsig delegated signature verification failed".into(),
            });
        }
    } else if let Some(msig) = &lsig.msig {
        let mut program_msg = Vec::with_capacity(PROGRAM_PREFIX.len() + lsig.logic.len());
        program_msg.extend_from_slice(PROGRAM_PREFIX);
        program_msg.extend_from_slice(&lsig.logic);
        verify_logicsig_multisig(stx, msig, &program_msg)?;
    } else if let Some(lmsig) = &lsig.lmsig {
        let mut lmsig_msg = Vec::with_capacity(MSIG_PROGRAM_PREFIX.len() + 32 + lsig.logic.len());
        lmsig_msg.extend_from_slice(MSIG_PROGRAM_PREFIX);
        lmsig_msg.extend_from_slice(&authorizer.0);
        lmsig_msg.extend_from_slice(&lsig.logic);
        verify_logicsig_multisig(stx, lmsig, &lmsig_msg)?;
    }

    Ok(())
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
    verify_logicsig_with_tracer(stx, lsig, group, group_index, budget, consensus, None, None)
}

/// Like [`verify_logicsig`], but threads an optional [`EvalTracer`] through the
/// TEAL program execution so the simulation engine can capture logic-sig opcode
/// traces, and an optional [`SigBlockSource`] so `txn FirstValidTime`/`block
/// BlkTimestamp` resolve against real block-header history when a caller has
/// one available (issue #1116). All callers that don't need either use
/// [`verify_logicsig`], which passes `None` for both -- matching go-algorand's
/// `NoHeaderLedger` default, so a caller with no ledger access (e.g. isolated
/// LogicSig checks) is unaffected and those two opcodes still error with "no
/// block header access" exactly as before.
#[allow(clippy::too_many_arguments)]
pub fn verify_logicsig_with_tracer(
    stx: &SignedTransaction,
    lsig: &LogicSig,
    group: &[SignedTransaction],
    group_index: usize,
    budget: &mut GroupBudget,
    consensus: &ConsensusParams,
    tracer: Option<&mut dyn EvalTracer>,
    sig_ledger: Option<&dyn SigBlockSource>,
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

    // Absolute per-LogicSig program cap (Go: `logicSigSanityCheckBatchPrep`,
    // `data/transactions/verify/txn.go`, v5.0.0-stable): independent of group
    // pooling, a single LogicSig program longer than
    // `MaxAbsoluteLogicSigProgramSize` is never well-formed, no matter how
    // much of the group's pooled allowance is unused. Zero means LogicSigs
    // are not yet supported by this protocol version (pre-v18), in which case
    // this check is a no-op and the version gate elsewhere is authoritative.
    if consensus.max_absolute_logic_sig_program_size > 0
        && lsig.logic.len() as u64 > consensus.max_absolute_logic_sig_program_size
    {
        return Err(AlgoError::Validation {
            message: format!(
                "LogicSig.Logic too long. max size is {} bytes",
                consensus.max_absolute_logic_sig_program_size
            ),
        });
    }

    // Count how many of sig/msig/lmsig/pqsig are set — must be 0 or 1
    // (matches Go's `logicSigSanityCheckBatchPrep`, which added `PQsig` to
    // this same mutual-exclusivity count in commit `ef838f4e9`).
    let has_sig = lsig.sig != [0u8; 64];
    let has_msig = lsig.msig.is_some();
    let has_lmsig = lsig.lmsig.is_some();
    let has_pqsig = lsig.pqsig.as_ref().is_some_and(|p| !p.blank());
    let num_sigs = has_sig as u8 + has_msig as u8 + has_lmsig as u8 + has_pqsig as u8;

    if num_sigs > 1 {
        return Err(AlgoError::Validation {
            message: "LogicSig should have only one type of delegation signature".into(),
        });
    }

    // The authorizer is auth_addr if set, otherwise sender.
    let authorizer = match &stx.auth_addr {
        Some(addr) => addr,
        None => &stx.txn.sender,
    };

    // PQ-delegated LogicSig: verified in-place (never batched — Falcon is
    // not ed25519-batchable), and short-circuits before the ed25519
    // sig/msig/lmsig/contract-account dispatch below, matching go's
    // `logicSigSanityCheckBatchPrep`'s early-return PQ branch.
    if has_pqsig {
        let pqsig = lsig.pqsig.as_ref().expect("has_pqsig implies Some");
        verify_pq_delegated_logicsig(lsig, pqsig, authorizer, consensus)?;
    } else if num_sigs == 0 {
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

        if !ed25519_bv_compatible_verify(&authorizer.0, &program_msg, &sig_bytes) {
            return Err(AlgoError::Validation {
                message: "logicsig delegated signature verification failed".into(),
            });
        }
    } else if let Some(msig) = &lsig.msig {
        // Mode 2: Delegated multisig — verify multisig on "Program" || logic.
        // Gated on `LogicSigMsig` (Go: `data/transactions/verify/txn.go`'s
        // `logicSigSanityCheckBatchPrep`, v18+, retired at v41 in favor of
        // `LogicSigLMsig` -- see issue #752).
        if !consensus.logic_sig_msig {
            return Err(AlgoError::Validation {
                message: "LogicSig Msig field not supported in this consensus version".into(),
            });
        }
        let mut program_msg = Vec::with_capacity(PROGRAM_PREFIX.len() + lsig.logic.len());
        program_msg.extend_from_slice(PROGRAM_PREFIX);
        program_msg.extend_from_slice(&lsig.logic);
        verify_logicsig_multisig(stx, msig, &program_msg)?;
    } else if let Some(lmsig) = &lsig.lmsig {
        // Mode 3: Delegated logic-multisig (lmsig). Gated on `LogicSigLMsig`
        // (Go: same function, v41+ -- see issue #752).
        if !consensus.logic_sig_lmsig {
            return Err(AlgoError::Validation {
                message: "LogicSig LMsig field not supported in this consensus version".into(),
            });
        }
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

    // Eval-time argument limits (Go: `EvalSignatureFull`,
    // `data/transactions/logic/eval.go`): checked at the same point go does
    // -- right before the TEAL program runs, independent of the earlier
    // structural/size sanity checks above, which bound the whole LogicSig
    // (program + args combined) rather than the argument count/per-arg size.
    if lsig.args.is_some() {
        if args.len() > EVAL_MAX_ARGS {
            return Err(AlgoError::Validation {
                message: format!(
                    "LogicSig has too many arguments: {} > {EVAL_MAX_ARGS}",
                    args.len()
                ),
            });
        }
        for arg in &args {
            if arg.len() > MAX_LOGIC_SIG_ARG_SIZE {
                return Err(AlgoError::Validation {
                    message: format!(
                        "LogicSig argument too large: {} > {MAX_LOGIC_SIG_ARG_SIZE}",
                        arg.len()
                    ),
                });
            }
        }
    }

    let mut ctx = LogicSigAvmContext::new(group, group_index, &lsig.logic, args, consensus.clone());
    if let Some(sig_ledger) = sig_ledger {
        ctx = ctx.with_sig_ledger(sig_ledger);
    }

    // Run the program, capturing an opcode trace when a tracer is supplied
    // (simulation `exec-trace`). The untraced path is identical aside from the
    // tracer callbacks.
    let run_result = match tracer {
        Some(tracer) => run_logicsig_program_with_tracer(&lsig.logic, &mut ctx, budget, tracer),
        None => run_logicsig_program(&lsig.logic, &mut ctx, budget),
    };
    let pass = match run_result {
        Ok(pass) => pass,
        // A structured evaluation failure (pc/group-index/eval-states --
        // see issue #1113) is propagated as-is rather than collapsed into a
        // generic `Validation` error, so callers can still recover the
        // diagnostics go-algorand's `EvalError` attaches.
        Err(e @ AlgoError::AvmLogicSig { .. }) => return Err(e),
        Err(e) => {
            return Err(AlgoError::Validation {
                message: format!("LogicSig program error: {e}"),
            })
        }
    };

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

    // Fixed-size arrays are now enforced by the type system.
    let pk = proof.pk;
    let pk2 = proof.pk2;
    let vote_id_bytes: [u8; 32] = vote_id.try_into().map_err(|_| AlgoError::Validation {
        message: format!(
            "heartbeat proof: invalid vote_id length: expected 32, got {}",
            vote_id.len()
        ),
    })?;
    let pk2_sig = proof.pk2_sig;
    let pk1_sig = proof.pk1_sig;
    let sig = proof.sig;

    let batch = last_valid / key_dilution;
    let offset = last_valid % key_dilution;

    // 1. Verify PK2Sig: vote_id signs BatchID(pk2, batch)
    let batch_id_encoded = encode_batch_id(&pk2, batch);
    let mut batch_msg = Vec::with_capacity(OT1_PREFIX.len() + batch_id_encoded.len());
    batch_msg.extend_from_slice(OT1_PREFIX);
    batch_msg.extend_from_slice(&batch_id_encoded);

    if !ed25519_bv_compatible_verify(&vote_id_bytes, &batch_msg, &pk2_sig) {
        return Err(AlgoError::Validation {
            message: "heartbeat proof: PK2Sig verification failed".into(),
        });
    }

    // 2. Verify PK1Sig: pk2 signs OffsetID(pk, batch, offset)
    let offset_id_encoded = encode_offset_id(&pk, batch, offset);
    let mut offset_msg = Vec::with_capacity(OT2_PREFIX.len() + offset_id_encoded.len());
    offset_msg.extend_from_slice(OT2_PREFIX);
    offset_msg.extend_from_slice(&offset_id_encoded);

    if !ed25519_bv_compatible_verify(&pk2, &offset_msg, &pk1_sig) {
        return Err(AlgoError::Validation {
            message: "heartbeat proof: PK1Sig verification failed".into(),
        });
    }

    // 3. Verify Sig: pk signs "SD" || seed
    let mut seed_msg = Vec::with_capacity(SEED_PREFIX.len() + seed.len());
    seed_msg.extend_from_slice(SEED_PREFIX);
    seed_msg.extend_from_slice(seed);

    if !ed25519_bv_compatible_verify(&pk, &seed_msg, &sig) {
        return Err(AlgoError::Validation {
            message: "heartbeat proof: Sig verification failed".into(),
        });
    }

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

/// Reject a signed transaction carrying a non-zero `AuthAddr` when the
/// consensus version does not support rekeying at all.
///
/// Matches Go's `verify.txnBatchPrep` (`data/transactions/verify/txn.go`):
/// `if !groupCtx.consensusParams.SupportRekeying && !s.AuthAddr.IsZero() { ... }`
/// (`errRekeyingNotSupported`, "nonempty AuthAddr but rekeying is not
/// supported"). This is distinct from `Transaction.WellFormed`'s
/// `SupportRekeying`/`RekeyTo` check (`rules.rs`): that one rejects a
/// transaction whose *own* `RekeyTo` field is set pre-rekeying, while this
/// one rejects a *signed* transaction whose `AuthAddr` — asserting it was
/// authorized by a previously-rekeyed-to address — is set at all, regardless
/// of this transaction's own `RekeyTo`. `SupportRekeying` became true at
/// consensus v24 (go-algorand commit `90152c46a`, first released v2.0.7-stable).
pub fn verify_rekeying_supported(
    stx: &SignedTransaction,
    support_rekeying: bool,
) -> Result<(), AlgoError> {
    if support_rekeying {
        return Ok(());
    }
    if stx.auth_addr.is_some() {
        return Err(AlgoError::Validation {
            message: "nonempty AuthAddr but rekeying is not supported".into(),
        });
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
    verify_transaction_signature_with_tracer(
        stx,
        group,
        group_index,
        lsig_budget,
        consensus,
        None,
        None,
    )
}

/// Like [`verify_transaction_signature`], but threads an optional [`EvalTracer`]
/// through the LogicSig program execution so the simulation engine can capture
/// logic-sig opcode traces, and an optional [`SigBlockSource`] (issue #1116)
/// so a LogicSig's `txn FirstValidTime`/`block BlkTimestamp` resolve against
/// real block-header history when the caller has ledger access (e.g.
/// simulation, which has a `LedgerStore` in scope). Both are only consulted
/// on the LogicSig path; for single-sig and multisig transactions they are
/// ignored. `None` for `sig_ledger` matches go-algorand's `NoHeaderLedger`
/// default and leaves behavior unchanged for every existing caller.
#[allow(clippy::too_many_arguments)]
pub fn verify_transaction_signature_with_tracer(
    stx: &SignedTransaction,
    group: &[SignedTransaction],
    group_index: usize,
    lsig_budget: &mut GroupBudget,
    consensus: &ConsensusParams,
    tracer: Option<&mut dyn EvalTracer>,
    sig_ledger: Option<&dyn SigBlockSource>,
) -> Result<(), AlgoError> {
    // Pre-activation gate (mirrors go's `stxnCoreChecks`, commit `fc46c74ef`
    // "transactions: disallow empty pq signatures"): hard-reject BEFORE any
    // sig-type-count dispatch if PQ signatures are not enabled under
    // consensus but either the top-level `SignedTxn.pqsig` or the
    // LogicSig-delegated `Lsig.pqsig` is non-blank.
    let stx_pqsig_present = stx.pqsig.as_ref().is_some_and(|p| !p.blank());
    let lsig_pqsig_present = stx
        .lsig
        .as_ref()
        .and_then(|l| l.pqsig.as_ref())
        .is_some_and(|p| !p.blank());
    if !consensus.pq_sig_enabled() && (stx_pqsig_present || lsig_pqsig_present) {
        return Err(AlgoError::Validation {
            message: "pq signature not enabled".into(),
        });
    }

    // Go-algorand requires exactly one of sig/msig/lsig/pqsig — a 5th
    // mutually-exclusive signature category alongside sig/msig/lsig/
    // state-proof-txn (Go: `checkTxnSigTypeCounts`, commit `569ae3d4b`).
    let has_sig = stx.sig != [0u8; 64];
    let has_msig = stx.msig.is_some();
    let has_lsig = stx.lsig.is_some();
    let has_pqsig = stx_pqsig_present;
    let count = has_sig as u8 + has_msig as u8 + has_lsig as u8 + has_pqsig as u8;
    if count == 0 {
        // Special case (Go: `checkTxnSigTypeCounts`, `verify/txn.go:344`):
        // the special state-proof sender address may issue a state-proof
        // transaction with NO signature at all -- well-formedness
        // (`rules.rs`'s `txn_type == "stpf"` branch) already guarantees such
        // a transaction can pay no fee and carries no other interesting
        // fields besides the state-proof payload itself, so there is
        // nothing here to authenticate with a conventional signature; the
        // proof's own cryptographic validity is checked separately at
        // block-apply time (`apply_stateproof.rs`). Found missing during
        // issue #814's live mixed-cluster verification: without this, a
        // genuine zero-signature `StateProofTx` -- whether the node's own
        // locally-built proof or one gossiped in from a peer -- was
        // universally rejected as "no signature", even after the pool's
        // separate blanket stpf-rejection (fixed alongside this) was
        // removed.
        if stx.txn.sender == Address::STATE_PROOF_SENDER && stx.txn.txn_type == "stpf" {
            return Ok(());
        }
        return Err(AlgoError::Validation {
            message: "transaction has no signature (no sig, msig, lsig, or pqsig)".into(),
        });
    }
    if count != 1 {
        return Err(AlgoError::Validation {
            message: format!("signedtxn should have only one type of signature, found {count}"),
        });
    }

    if has_sig {
        return verify_single_sig(stx);
    }

    if let Some(msig) = &stx.msig {
        return verify_multisig(stx, msig);
    }

    if let Some(lsig) = &stx.lsig {
        return verify_logicsig_with_tracer(
            stx,
            lsig,
            group,
            group_index,
            lsig_budget,
            consensus,
            tracer,
            sig_ledger,
        );
    }

    if has_pqsig {
        let pqsig = stx.pqsig.as_ref().expect("has_pqsig implies Some");
        return verify_pqsig(stx, pqsig, consensus);
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

/// Group-level LogicSig size check (Go: `verify.logicSigGroupSizeCheck`,
/// `data/transactions/verify/txn.go`, v5.0.0-stable). Replaces
/// [`verify_group_logicsig_size`]'s flat total-byte pool (which unconditionally
/// pools *both* program and arg bytes) with version-aware behavior:
///
/// - A LogicSig with no program but non-empty other fields (msig/args/lmsig)
///   is rejected once `TxnSizePricingEnabled()` (v42+, `per_byte_txn_surcharge
///   != 0`) — an "orphan" LogicSig can no longer carry unpriced content.
/// - Before size pricing, the *entire* pooled size (program + args) must fit
///   `len(group) * LogicSigMaxSize` — this is the same check
///   [`verify_group_logicsig_size`] performs, now folded in here.
/// - Once size pricing is enabled, program bytes are billed via
///   [`crate::fee::logic_sig_program_fee_contribution`] instead of pool-capped,
///   so only LogicSig *args* remain subject to the pool.
///
/// Should be called once per transaction group, unconditionally (matching
/// upstream, which no longer gates this behind a boolean feature flag).
pub fn logic_sig_group_size_check(
    group: &[SignedTransaction],
    consensus: &ConsensusParams,
) -> Result<(), AlgoError> {
    let mut lsig_pooled_size: u64 = 0;
    let mut lsig_args_size: u64 = 0;
    let mut lsig_args_need_size_pooling = false;

    let reject_orphan_lsig_content = consensus.per_byte_txn_surcharge != 0;
    let pool_orphan_lsig_args =
        consensus.max_absolute_logic_sig_program_size > consensus.logic_sig_max_size;

    for stx in group {
        let lsig = stx.lsig.as_ref();
        let has_program = lsig.is_some_and(|l| !l.logic.is_empty());
        let is_blank = match lsig {
            None => true,
            Some(l) => {
                l.logic.is_empty()
                    && l.sig == [0u8; 64]
                    && l.msig.is_none()
                    && l.args.is_none()
                    && l.lmsig.is_none()
            }
        };

        if !has_program {
            if !is_blank && reject_orphan_lsig_content {
                return Err(AlgoError::Validation {
                    message: "LogicSig fields without LogicSig program".into(),
                });
            }
            if !pool_orphan_lsig_args {
                continue;
            }
        }

        let logic_len = lsig.map(|l| l.logic.len() as u64).unwrap_or(0);
        let args_len: u64 = lsig
            .and_then(|l| l.args.as_ref())
            .map(|args| args.iter().map(|a| a.len() as u64).sum())
            .unwrap_or(0);

        lsig_pooled_size += logic_len + args_len;
        lsig_args_size += args_len;
        if args_len > consensus.logic_sig_max_size {
            lsig_args_need_size_pooling = true;
        }
    }

    let lsig_available_pool = group.len() as u64 * consensus.logic_sig_max_size;

    // Protocols without per-byte surcharge cannot pay for LogicSig bytes above
    // the group pool: keep those protocols on the legacy total LogicSig size check.
    if !reject_orphan_lsig_content && lsig_pooled_size > lsig_available_pool {
        return Err(AlgoError::Validation {
            message: format!(
                "txgroup had {lsig_pooled_size} bytes of LogicSigs, more than the available pool of {lsig_available_pool} bytes"
            ),
        });
    }
    // LogicSig args are unpriced. Each LogicSig may carry up to LogicSigMaxSize
    // without pooling; larger args are allowed only when the group's pool
    // covers the group's total args.
    if lsig_args_need_size_pooling && lsig_args_size > lsig_available_pool {
        return Err(AlgoError::Validation {
            message: format!(
                "txgroup had {lsig_args_size} bytes of LogicSig args, more than the available size pool of {lsig_available_pool} bytes (per-LogicSig allowance is {})",
                consensus.logic_sig_max_size
            ),
        });
    }

    Ok(())
}

/// Regression suite porting go-algorand's ed25519 malleability-acceptance
/// test vectors (issue #1136) -- see `signature/bv_compatible_vectors.rs`.
#[cfg(test)]
mod bv_compatible_vectors;

#[cfg(test)]
mod tests {
    use super::*;
    use algo_avm::group::GroupBudget;
    use algo_error::AvmDiagnosticValue;
    use algo_types::{
        Address, MultisigSubsig, PQAddressSalt, Round, Transaction, PQ_SCHEME_FALCON1024,
    };
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
    fn sign_txn(key: &SigningKey, txn: &Transaction) -> [u8; 64] {
        use ed25519_dalek::Signer;
        let canonical = canonical_encode_transaction(txn);
        let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
        msg.extend_from_slice(TX_PREFIX);
        msg.extend_from_slice(&canonical);
        let sig = key.sign(&msg);
        sig.to_bytes()
    }

    /// Sign a program message ("Program" || logic) with the given key.
    fn sign_program(key: &SigningKey, logic: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        let mut msg = Vec::with_capacity(PROGRAM_PREFIX.len() + logic.len());
        msg.extend_from_slice(PROGRAM_PREFIX);
        msg.extend_from_slice(logic);
        let sig = key.sign(&msg);
        sig.to_bytes()
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
                    sign_txn(key, txn)
                } else {
                    [0u8; 64]
                };
                MultisigSubsig {
                    public_key: pk.to_bytes(),
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
                    public_key: k.verifying_key().to_bytes(),
                    signature: [0u8; 64],
                })
                .collect(),
        };
        compute_multisig_address(&msig)
    }

    /// The `int 1` (v2) program and its contract-account address bytes.
    fn int1_program() -> Vec<u8> {
        vec![0x02u8, 0x20, 0x01, 0x01, 0x22]
    }

    #[test]
    fn logicsig_sanity_check_contract_account_ok_and_mismatch() {
        let program = int1_program();
        // authorizer == HashProgram(program) → contract account, OK.
        let mut msg = Vec::new();
        msg.extend_from_slice(PROGRAM_PREFIX);
        msg.extend_from_slice(&program);
        let hash = Sha512_256::digest(&msg);
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&hash);

        let lsig = LogicSig {
            logic: ByteBuf::from(program.clone()),
            ..LogicSig::default()
        };
        let stx = SignedTransaction {
            txn: minimal_pay_txn(Address(addr)),
            lsig: Some(lsig.clone()),
            ..Default::default()
        };
        assert!(logicsig_sanity_check(&stx, &lsig).is_ok());

        // authorizer != program hash, no delegated sig → rejected.
        let bad = SignedTransaction {
            txn: minimal_pay_txn(Address([0u8; 32])),
            lsig: Some(lsig.clone()),
            ..Default::default()
        };
        assert!(logicsig_sanity_check(&bad, &lsig).is_err());
    }

    /// Port of go-algorand's `TestLogicErrorDetails`
    /// (`data/transactions/logic/eval_test.go`): a LogicSig evaluation
    /// failure must carry structured diagnostics -- program counter, group
    /// index, and a scratch-space/stack dump -- not just a bare message.
    /// See issue #1113.
    #[test]
    fn verify_logicsig_error_carries_structured_details() {
        // Mirrors go's `badsource` (built with `notrack()` there to bypass
        // its assembler's static type checker): store an int and a byte
        // string into scratch, then attempt `==` on mismatched types. The
        // Rust assembler statically rejects this same mismatch at assemble
        // time (`type_track.rs`), so the raw bytecode is hand-built here to
        // reach the identical *runtime* type-mismatch path go's test
        // exercises.
        //
        //   pushint 5; store 10          -- int 5; store 10
        //   pushbytes 0x01020300; store 15  -- byte 0x01020300; store 15
        //   pushint 100                  -- int 100
        //   pushbytes 0x0201             -- byte 0x0201
        //   ==                            -- type mismatch
        let program: Vec<u8> = vec![
            8, // version
            0x81, 5, // pushint 5
            0x35, 10, // store 10
            0x80, 4, 0x01, 0x02, 0x03, 0x00, // pushbytes 0x01020300
            0x35, 15, // store 15
            0x81, 100, // pushint 100
            0x80, 2, 0x02, 0x01, // pushbytes 0x0201
            0x12, // ==
        ];

        // Contract-account authorization so evaluation actually runs
        // (mode 4: sender == SHA512/256(\"Program\" || logic)).
        let mut msg = Vec::new();
        msg.extend_from_slice(PROGRAM_PREFIX);
        msg.extend_from_slice(&program);
        let hash = Sha512_256::digest(&msg);
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&hash);

        let lsig = LogicSig {
            logic: ByteBuf::from(program),
            ..LogicSig::default()
        };
        let stx = SignedTransaction {
            txn: minimal_pay_txn(Address(addr)),
            lsig: Some(lsig.clone()),
            ..Default::default()
        };

        let err = verify_lsig(&stx, &lsig).expect_err("type-mismatch == must fail");
        match err {
            AlgoError::AvmLogicSig {
                group_index,
                eval_states,
                pc,
                ..
            } => {
                assert_eq!(group_index, 0, "single-txn group: group-index must be 0");
                assert!(pc > 0, "pc should point at (or past) the failing opcode");
                assert_eq!(
                    eval_states.len(),
                    1,
                    "eval-states must have one entry per txn up to group_index"
                );

                let state = &eval_states[0];
                // Stack at failure: [100, 0x0201] (0x0201 popped second, on top).
                assert_eq!(
                    state.stack,
                    vec![
                        AvmDiagnosticValue::Uint(100),
                        AvmDiagnosticValue::Bytes(vec![0x02, 0x01]),
                    ]
                );
                // Scratch trimmed to one past slot 15: slots 10 and 15 set,
                // everything else at its zero value.
                assert_eq!(state.scratch.len(), 16);
                assert_eq!(state.scratch[10], AvmDiagnosticValue::Uint(5));
                assert_eq!(
                    state.scratch[15],
                    AvmDiagnosticValue::Bytes(vec![0x01, 0x02, 0x03, 0x00])
                );
                assert_eq!(state.scratch[0], AvmDiagnosticValue::Uint(0));
            }
            other => panic!("expected AlgoError::AvmLogicSig, got {other:?}"),
        }
    }

    #[test]
    fn logicsig_sanity_check_delegated_sig_verifies() {
        let key = test_signing_key();
        let signer = Address(key.verifying_key().to_bytes());
        let program = int1_program();
        let good_sig = sign_program(&key, &program);

        // Delegated (sig present) signed by the sender → OK.
        let lsig = LogicSig {
            logic: ByteBuf::from(program.clone()),
            sig: good_sig,
            ..LogicSig::default()
        };
        let stx = SignedTransaction {
            txn: minimal_pay_txn(signer),
            lsig: Some(lsig.clone()),
            ..Default::default()
        };
        assert!(logicsig_sanity_check(&stx, &lsig).is_ok());

        // A garbage delegated sig must be rejected (the Codex round-3 fix:
        // `clerk sign -L bad.lsig` must not write an unverified delegation).
        let bad_lsig = LogicSig {
            logic: ByteBuf::from(program),
            sig: [0x11u8; 64],
            ..LogicSig::default()
        };
        let bad = SignedTransaction {
            txn: minimal_pay_txn(signer),
            lsig: Some(bad_lsig.clone()),
            ..Default::default()
        };
        assert!(logicsig_sanity_check(&bad, &bad_lsig).is_err());
    }

    #[test]
    fn ed25519_bv_compatible_verify_rejects_zero_signature_and_zero_pubkey() {
        // TestVerifyZeros (crypto/curve25519_test.go): a zero signature
        // against a zero public key must never verify, for any message.
        // A zero-byte pubkey decompresses to a small-order curve point, so
        // `ed25519_bv_compatible_verify`'s small-order-A rejection (issue
        // #1136) fires regardless of the (also zero) signature bytes.
        let pk = [0u8; 32];
        let sig = [0u8; 64];
        for x in 0u8..255 {
            let msg = [x];
            assert!(
                !ed25519_bv_compatible_verify(&pk, &msg, &sig),
                "zero sig with zero pk unexpectedly verified message {x:#x}"
            );
        }
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
            sig,
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
            sig,
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
            sig,
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
            sig: [0u8; 64],
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

    /// Issue #814 live-verification fix: a genuine zero-signature state-proof
    /// transaction (sender == `Address::STATE_PROOF_SENDER`, type "stpf") must
    /// be *accepted* with no signature at all -- mirroring go's
    /// `checkTxnSigTypeCounts` special case (`verify/txn.go:344`). Before
    /// this fix, `verify_no_sig_errors` above (a different sender/type) would
    /// have covered this case identically and wrongly rejected it too.
    #[test]
    fn verify_zero_sig_state_proof_txn_is_accepted() {
        let txn = Transaction {
            txn_type: "stpf".into(),
            sender: Address::STATE_PROOF_SENDER,
            fee: 0,
            first_valid: Round(1),
            last_valid: Round(1000),
            ..Default::default()
        };
        let stx = SignedTransaction {
            txn,
            sig: [0u8; 64],
            msig: None,
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        assert!(
            verify_sig(&stx).is_ok(),
            "a zero-signature stpf transaction from the state-proof sender must be accepted"
        );
    }

    /// The zero-signature exemption above must be narrowly scoped: a
    /// zero-signature transaction from an ordinary sender (even one with an
    /// otherwise-identical shape) must still be rejected exactly as
    /// `verify_no_sig_errors` proves for the "pay" case.
    #[test]
    fn verify_zero_sig_wrong_sender_still_rejected() {
        let txn = Transaction {
            txn_type: "stpf".into(),
            sender: Address([0x01; 32]), // not STATE_PROOF_SENDER
            fee: 0,
            first_valid: Round(1),
            last_valid: Round(1000),
            ..Default::default()
        };
        let stx = SignedTransaction {
            txn,
            sig: [0u8; 64],
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

    /// Nor does the exemption widen to non-stpf transaction types from the
    /// state-proof sender address.
    #[test]
    fn verify_zero_sig_wrong_type_still_rejected() {
        let txn = Transaction {
            txn_type: "pay".into(),
            sender: Address::STATE_PROOF_SENDER,
            fee: 0,
            first_valid: Round(1),
            last_valid: Round(1000),
            receiver: Address([0x42; 32]),
            ..Default::default()
        };
        let stx = SignedTransaction {
            txn,
            sig: [0u8; 64],
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
            sig,
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
            sig: [0u8; 64],
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
            sig: [0u8; 64],
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
            sig: [0u8; 64],
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

    /// Go-parity (issue #1307): go-algorand's `MultisigBatchPrep`
    /// (`crypto/multisig.go`) unconditionally rejects a `MultisigSig` whose
    /// `Subsigs[0]` is the exact zero-valued `MultisigSubsig{}` (zero
    /// pubkey, zero sig) -- checked *before* the address is even computed
    /// -- regardless of whether the other subsigs are validly signed and
    /// reach threshold. This constructs a real multisig address that
    /// includes an all-zero pubkey as its first configured signer (a slot
    /// nobody can ever produce a valid signature for), with that slot left
    /// blank and the other two signers validly reaching threshold: go
    /// rejects this outright, so algod-rust must too.
    #[test]
    fn verify_multisig_rejects_all_zero_first_subsig() {
        let keys: Vec<SigningKey> = (10u8..12).map(signing_key_from_seed).collect();

        // Address computed over [zero-pubkey, key0-pubkey, key1-pubkey].
        let msig_addr = compute_multisig_address(&MultisigSig {
            version: 1,
            threshold: 2,
            subsigs: vec![
                MultisigSubsig {
                    public_key: [0u8; 32],
                    signature: [0u8; 64],
                },
                MultisigSubsig {
                    public_key: keys[0].verifying_key().to_bytes(),
                    signature: [0u8; 64],
                },
                MultisigSubsig {
                    public_key: keys[1].verifying_key().to_bytes(),
                    signature: [0u8; 64],
                },
            ],
        });

        let txn = minimal_pay_txn(msig_addr);
        let msig = MultisigSig {
            version: 1,
            threshold: 2,
            subsigs: vec![
                MultisigSubsig {
                    public_key: [0u8; 32],
                    signature: [0u8; 64],
                },
                MultisigSubsig {
                    public_key: keys[0].verifying_key().to_bytes(),
                    signature: sign_txn(&keys[0], &txn),
                },
                MultisigSubsig {
                    public_key: keys[1].verifying_key().to_bytes(),
                    signature: sign_txn(&keys[1], &txn),
                },
            ],
        };

        let stx = SignedTransaction {
            txn,
            sig: [0u8; 64],
            msig: Some(msig),
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        // Sanity: both real signers reach the threshold (2), and the
        // address matches -- so without the zero-subsig[0] guard this
        // would otherwise verify successfully.
        let err = verify_multisig(&stx, stx.msig.as_ref().unwrap()).unwrap_err();
        assert!(
            err.to_string().contains("subsig") || err.to_string().contains("zero"),
            "expected a subsig/zero-related rejection, got: {err}"
        );
    }

    /// Go-parity placement (issue #1207): go-algorand's `MultisigVerify`
    /// (via `MultisigBatchPrep`, `crypto/multisig.go:260`) is the ONLY
    /// place a >255-pubkey multisig is rejected -- `MultisigAddrGen`
    /// itself places no cap. A 256-key multisig address must therefore
    /// generate successfully (see `algo_consensus_crypto::multisig`'s
    /// `addr_gen_allows_more_than_max_multisig_keys`) and be rejected
    /// only here, at verify time, with Go's exact "too many subsigs"
    /// placement (checked after the address-match check, before the
    /// threshold-met check).
    #[test]
    fn verify_multisig_rejects_more_than_255_subsigs_at_verify_time() {
        // 256 distinct keys: `signing_key_from_seed` fills all 32 seed
        // bytes with the same value, so seeds 0..=255 give 256 distinct
        // signers -- exactly enough to exceed the 255-subsig cap.
        let keys: Vec<SigningKey> = (0u8..=255).map(signing_key_from_seed).collect();
        assert_eq!(keys.len(), 256);
        let msig_addr = compute_msig_addr(&keys, 1, 1);
        let txn = minimal_pay_txn(msig_addr);

        // Sign with key 0 only (threshold is 1, so this would otherwise pass).
        let msig = build_multisig(&keys, &[0], 1, &txn);

        let stx = SignedTransaction {
            txn,
            sig: [0u8; 64],
            msig: Some(msig),
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        let err = verify_multisig(&stx, stx.msig.as_ref().unwrap()).unwrap_err();
        assert!(
            err.to_string().contains("too many multisig subsigs"),
            "unexpected error: {err}"
        );
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
            sig: [0u8; 64],
            msig: None,
            args: None,
            lmsig: None,
            pqsig: None,
        };

        let stx = SignedTransaction {
            txn,
            sig: [0u8; 64],
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
    fn verify_logicsig_contract_account_with_blank_pqsig_unchanged() {
        // Port of go's TestTxnGroupLogicOnlyAccountRemainsUnchanged
        // (data/transactions/verify/txn_test.go): a logic-only (contract
        // account) LogicSig that also carries an explicit but blank/zeroed
        // `Lsig.PQsig` field must verify exactly as if PQsig were absent --
        // `Lsig.pqsig.blank()` must not be counted toward the
        // sig/msig/lmsig/pqsig mutual-exclusivity total (see `has_pqsig` in
        // `verify_logicsig_with_tracer`), and program-only ("logic-only
        // account") authorization must still succeed.
        let logic = vec![0x06, 0x81, 0x01]; // TEAL v6, int 1

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
            sig: [0u8; 64],
            msig: None,
            args: None,
            lmsig: None,
            pqsig: Some(PQSig::default()), // present but blank
        };

        let stx = SignedTransaction {
            txn,
            sig: [0u8; 64],
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
            sig: [0u8; 64],
            msig: None,
            args: None,
            lmsig: None,
            pqsig: None,
        };

        let stx = SignedTransaction {
            txn,
            sig: [0u8; 64],
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
            sig,
            msig: None,
            args: None,
            lmsig: None,
            pqsig: None,
        };

        let stx = SignedTransaction {
            txn,
            sig: [0u8; 64],
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
                    sign_program(key, &logic)
                } else {
                    [0u8; 64]
                };
                MultisigSubsig {
                    public_key: pk.to_bytes(),
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
            sig: [0u8; 64],
            msig: Some(msig),
            args: None,
            lmsig: None,
            pqsig: None,
        };

        let stx = SignedTransaction {
            txn,
            sig: [0u8; 64],
            msig: None,
            lsig: Some(lsig),
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        // `verify_lsig`/`verify_sig`'s default (v42) consensus has
        // `LogicSigMsig = false` (retired at v41, issue #752) -- use a
        // pre-v41 version that still accepts msig delegation for both legs
        // of this check.
        let msig_consensus = algo_types::consensus::consensus_params_for_version(
            algo_types::consensus::CONSENSUS_V40,
        )
        .expect("v40 must be a known protocol version");
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        assert!(verify_logicsig(
            &stx,
            stx.lsig.as_ref().unwrap(),
            &group,
            0,
            &mut budget,
            &msig_consensus
        )
        .is_ok());
        assert!(
            verify_transaction_signature(&stx, &group, 0, &mut budget, &msig_consensus).is_ok()
        );
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
            sig: [0u8; 64],
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
            sig: [0u8; 64],
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
            sig: [0u8; 64],
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
            sig,
            msig: Some(msig),
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        let err = verify_sig(&stx).unwrap_err();
        assert!(
            err.to_string().contains("only one type of signature"),
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
                public_key: k.verifying_key().to_bytes(),
                signature: [0u8; 64],
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
            sig,
            msig: Some(msig),
            args: None,
            lmsig: None,
            pqsig: None,
        };

        let stx = SignedTransaction {
            txn,
            sig: [0u8; 64],
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
                .contains("only one type of delegation signature"),
            "expected mutual exclusivity error, got: {err}"
        );
    }

    #[test]
    fn verify_multisig_invalid_pk_fails() {
        // With [u8; 32] public_key, wrong-length keys are impossible at the type level.
        // Instead test that a corrupted (but valid-length) key causes a verification failure.
        let keys: Vec<SigningKey> = (10u8..13).map(signing_key_from_seed).collect();
        let txn = minimal_pay_txn(Address([0; 32])); // placeholder sender

        let mut msig = build_multisig(&keys, &[0, 1, 2], 2, &txn);
        // Corrupt the third subsig's public key (valid length but wrong key).
        msig.subsigs[2].public_key = [0xFFu8; 32];

        // Compute the address from the corrupted msig so the address check passes.
        let msig_addr = compute_multisig_address(&msig);
        let txn = minimal_pay_txn(msig_addr);
        // Rebuild signatures for keys 0 and 1 with the correct txn.
        msig.subsigs[0].signature = sign_txn(&keys[0], &txn);
        msig.subsigs[1].signature = sign_txn(&keys[1], &txn);

        let stx = SignedTransaction {
            txn,
            sig: [0u8; 64],
            msig: Some(msig),
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        // Key 2 has a corrupted public key but its signature was built with the real key,
        // so verification should fail.
        let err = verify_multisig(&stx, stx.msig.as_ref().unwrap()).unwrap_err();
        assert!(
            err.to_string().contains("public key")
                || err.to_string().contains("verification failed"),
            "expected public key error, got: {err}"
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
    fn sign_lmsig_msg(key: &SigningKey, addr: &Address, logic: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        let msg = build_lmsig_msg(addr, logic);
        let sig = key.sign(&msg);
        sig.to_bytes()
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
                    sign_lmsig_msg(key, &msig_addr, &logic)
                } else {
                    [0u8; 64]
                };
                MultisigSubsig {
                    public_key: pk.to_bytes(),
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
            sig: [0u8; 64],
            msig: None,
            args: None,
            lmsig: Some(lmsig),
            pqsig: None,
        };

        let stx = SignedTransaction {
            txn,
            sig: [0u8; 64],
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
                    sign_lmsig_msg(key, &wrong_addr, &logic)
                } else {
                    [0u8; 64]
                };
                MultisigSubsig {
                    public_key: pk.to_bytes(),
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
            sig: [0u8; 64],
            msig: None,
            args: None,
            lmsig: Some(lmsig),
            pqsig: None,
        };

        let stx = SignedTransaction {
            txn,
            sig: [0u8; 64],
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

    // ---- LogicSigMsig / LogicSigLMsig consensus gating (issue #752) ----
    //
    // `logicsig_sanity_check` (the client-tool path exercised by the tests
    // above) never had a consensus version to gate against, by design. The
    // real, live-acceptance gate lives in `verify_logicsig`/
    // `verify_logicsig_with_tracer` (`data/transactions/verify/txn.go`'s
    // `logicSigSanityCheckBatchPrep`, v5.0.0-stable), which these tests
    // exercise end-to-end (delegation check + actual TEAL execution).

    /// Build a real, verifiable msig-delegated LogicSig over `int1_program()`
    /// (approves unconditionally), plus the `SignedTransaction` whose sender
    /// is the msig address.
    fn msig_delegated_int1_lsig() -> (SignedTransaction, LogicSig) {
        let keys: Vec<SigningKey> = (40u8..43).map(signing_key_from_seed).collect();
        let msig_addr = compute_msig_addr(&keys, 1, 2);
        let program = int1_program();

        let mut program_msg = Vec::with_capacity(PROGRAM_PREFIX.len() + program.len());
        program_msg.extend_from_slice(PROGRAM_PREFIX);
        program_msg.extend_from_slice(&program);

        let subsigs: Vec<MultisigSubsig> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                use ed25519_dalek::Signer;
                let pk = key.verifying_key();
                let signature = if i < 2 {
                    key.sign(&program_msg).to_bytes()
                } else {
                    [0u8; 64]
                };
                MultisigSubsig {
                    public_key: pk.to_bytes(),
                    signature,
                }
            })
            .collect();
        let msig = MultisigSig {
            version: 1,
            threshold: 2,
            subsigs,
        };

        let lsig = LogicSig {
            logic: ByteBuf::from(program),
            msig: Some(msig),
            ..LogicSig::default()
        };
        let stx = SignedTransaction {
            txn: minimal_pay_txn(msig_addr),
            lsig: Some(lsig.clone()),
            ..Default::default()
        };
        (stx, lsig)
    }

    /// Build a real, verifiable lmsig-delegated LogicSig over
    /// `int1_program()`, plus the `SignedTransaction` whose sender is the
    /// msig address.
    fn lmsig_delegated_int1_lsig() -> (SignedTransaction, LogicSig) {
        let keys: Vec<SigningKey> = (50u8..53).map(signing_key_from_seed).collect();
        let msig_addr = compute_msig_addr(&keys, 1, 2);
        let program = int1_program();

        let subsigs: Vec<MultisigSubsig> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let pk = key.verifying_key();
                let signature = if i < 2 {
                    sign_lmsig_msg(key, &msig_addr, &program)
                } else {
                    [0u8; 64]
                };
                MultisigSubsig {
                    public_key: pk.to_bytes(),
                    signature,
                }
            })
            .collect();
        let lmsig = MultisigSig {
            version: 1,
            threshold: 2,
            subsigs,
        };

        let lsig = LogicSig {
            logic: ByteBuf::from(program),
            lmsig: Some(lmsig),
            ..LogicSig::default()
        };
        let stx = SignedTransaction {
            txn: minimal_pay_txn(msig_addr),
            lsig: Some(lsig.clone()),
            ..Default::default()
        };
        (stx, lsig)
    }

    #[test]
    fn verify_logicsig_msig_rejected_at_v41_plus() {
        // v41 retires `LogicSigMsig` (config/consensus.go:1525) -- a
        // correctly-signed msig-delegated LogicSig must now be rejected
        // outright, never reaching program execution.
        let (stx, lsig) = msig_delegated_int1_lsig();
        let consensus = algo_types::consensus::consensus_params_for_version(
            algo_types::consensus::CONSENSUS_V41,
        )
        .expect("v41 must be a known protocol version");
        assert!(
            !consensus.logic_sig_msig,
            "v41 must have LogicSigMsig=false"
        );

        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        let err = verify_logicsig(&stx, &lsig, &group, 0, &mut budget, &consensus)
            .expect_err("msig delegation must be rejected once LogicSigMsig is retired");
        assert!(
            err.to_string().contains("Msig field not supported"),
            "expected a Msig-not-supported error, got: {err}"
        );
    }

    #[test]
    fn verify_logicsig_msig_accepted_before_v41() {
        // v40 (LogicSigMsig=true, LogicSigLMsig=false) must still accept a
        // correctly-signed msig-delegated LogicSig, actually executing the
        // program.
        let (stx, lsig) = msig_delegated_int1_lsig();
        let consensus = algo_types::consensus::consensus_params_for_version(
            algo_types::consensus::CONSENSUS_V40,
        )
        .expect("v40 must be a known protocol version");
        assert!(consensus.logic_sig_msig, "v40 must have LogicSigMsig=true");

        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        assert!(verify_logicsig(&stx, &lsig, &group, 0, &mut budget, &consensus).is_ok());
    }

    #[test]
    fn verify_logicsig_lmsig_rejected_before_v41() {
        // Before v41, `LogicSigLMsig` is false -- an lmsig-delegated LogicSig
        // must be rejected outright even though the signature itself is
        // valid, matching go's `logicSigSanityCheckBatchPrep`.
        let (stx, lsig) = lmsig_delegated_int1_lsig();
        let consensus = algo_types::consensus::consensus_params_for_version(
            algo_types::consensus::CONSENSUS_V40,
        )
        .expect("v40 must be a known protocol version");
        assert!(
            !consensus.logic_sig_lmsig,
            "v40 must have LogicSigLMsig=false"
        );

        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        let err = verify_logicsig(&stx, &lsig, &group, 0, &mut budget, &consensus)
            .expect_err("lmsig delegation must be rejected before LogicSigLMsig activates");
        assert!(
            err.to_string().contains("LMsig field not supported"),
            "expected an LMsig-not-supported error, got: {err}"
        );
    }

    #[test]
    fn verify_logicsig_lmsig_accepted_at_v41_plus() {
        // At/after v41 (LogicSigLMsig=true), a correctly-signed
        // lmsig-delegated LogicSig must be accepted end-to-end.
        let (stx, lsig) = lmsig_delegated_int1_lsig();
        let consensus = ConsensusParams::default(); // v42, LogicSigLMsig=true
        assert!(
            consensus.logic_sig_lmsig,
            "current consensus must allow LMsig"
        );

        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        assert!(verify_logicsig(&stx, &lsig, &group, 0, &mut budget, &consensus).is_ok());
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
                public_key: k.verifying_key().to_bytes(),
                signature: [0u8; 64],
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
            sig,
            msig: None,
            args: None,
            lmsig: Some(lmsig),
            pqsig: None,
        };

        let stx = SignedTransaction {
            txn,
            sig: [0u8; 64],
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
                .contains("only one type of delegation signature"),
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
            sig,
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
            sig,
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
            sig,
            msig: None,
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        assert!(verify_auth_addr_sender_diff(&stx, true).is_ok());
    }

    // ---- Rekeying-not-supported (AuthAddr) tests (issue #1271) ----

    #[test]
    fn verify_rekeying_supported_rejects_nonempty_auth_addr_when_unsupported() {
        let key = test_signing_key();
        let pk = key.verifying_key();
        let sender = Address(pk.to_bytes());
        let txn = minimal_pay_txn(sender);
        let sig = sign_txn(&key, &txn);

        let stx = SignedTransaction {
            txn,
            sig,
            msig: None,
            lsig: None,
            auth_addr: Some(Address([0xFF; 32])),
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        let err = verify_rekeying_supported(&stx, false).unwrap_err();
        assert!(
            err.to_string()
                .contains("nonempty AuthAddr but rekeying is not supported"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_rekeying_supported_accepts_nonempty_auth_addr_when_supported() {
        let key = test_signing_key();
        let pk = key.verifying_key();
        let sender = Address(pk.to_bytes());
        let txn = minimal_pay_txn(sender);
        let sig = sign_txn(&key, &txn);

        let stx = SignedTransaction {
            txn,
            sig,
            msig: None,
            lsig: None,
            auth_addr: Some(Address([0xFF; 32])),
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        assert!(verify_rekeying_supported(&stx, true).is_ok());
    }

    #[test]
    fn verify_rekeying_supported_accepts_none_auth_addr_regardless() {
        let key = test_signing_key();
        let pk = key.verifying_key();
        let sender = Address(pk.to_bytes());
        let txn = minimal_pay_txn(sender);
        let sig = sign_txn(&key, &txn);

        let stx = SignedTransaction {
            txn,
            sig,
            msig: None,
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };

        assert!(verify_rekeying_supported(&stx, false).is_ok());
        assert!(verify_rekeying_supported(&stx, true).is_ok());
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
            sig: sig.to_bytes(),
            pk: ephemeral_pk,
            pk2: batch_pk,
            pk1_sig: pk1_sig.to_bytes(),
            pk2_sig: pk2_sig.to_bytes(),
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
            sig: sig.to_bytes(),
            pk: ephemeral_pk,
            pk2: batch_pk,
            pk1_sig: pk1_sig.to_bytes(),
            pk2_sig: pk2_sig.to_bytes(),
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
            sig: sig.to_bytes(),
            pk: ephemeral_pk,
            pk2: batch_pk,
            pk1_sig: pk1_sig.to_bytes(),
            pk2_sig: pk2_sig.to_bytes(),
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
    fn heartbeat_proof_corrupted_pk() {
        // With [u8; 32] pk, wrong-length is impossible at the type level.
        // Instead test that a zeroed pk (wrong key) causes verification to fail.
        let (mut proof, master_pk, seed) = build_heartbeat_proof(1000, 100);
        proof.pk = [0u8; 32]; // Corrupted key
        let err = verify_heartbeat_proof(&proof, &master_pk, 1000, 100, &seed).unwrap_err();
        assert!(
            err.to_string().contains("public key")
                || err.to_string().contains("verification failed"),
            "expected verification error, got: {err}"
        );
    }

    #[test]
    fn heartbeat_proof_corrupted_sig() {
        // With [u8; 64] sig, wrong-length is impossible at the type level.
        // Instead test that a zeroed sig causes verification to fail.
        let (mut proof, master_pk, seed) = build_heartbeat_proof(1000, 100);
        proof.sig = [0u8; 64]; // Corrupted signature
        let err = verify_heartbeat_proof(&proof, &master_pk, 1000, 100, &seed).unwrap_err();
        assert!(
            err.to_string().contains("verification failed"),
            "expected verification error, got: {err}"
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

    // ── Post-quantum (PQSig) signature tests (issue #660) ──────────────────
    //
    // Adversarial coverage for the native PQ (Falcon-1024) account
    // authorization path added by go-algorand commits `569ae3d4b` (native PQ
    // accounts), `ef838f4e9` (PQ-delegated LogicSig), and `fc46c74ef`
    // (disallow empty PQ signatures).

    /// Generate a real Falcon-1024 keypair and its canonical PQ address for a
    /// given deterministic seed byte, for use by the tests below. Exercises
    /// the actual `algo-falcon` primitive end-to-end (keygen + sign +
    /// verify), not a stub.
    fn falcon_identity(seed_byte: u8) -> (Vec<u8>, Vec<u8>, PQAddressSalt, Address) {
        let seed = [seed_byte; algo_falcon::FALCON_SEED_SIZE];
        let (pk, sk) = algo_falcon::falcon_keygen(&seed).expect("falcon keygen");
        let (salt, addr) = algo_types::canonical_pq_address_salt(PQ_SCHEME_FALCON1024, &pk)
            .expect("a canonical PQ salt must exist");
        (pk, sk, salt, addr)
    }

    fn pq_enabled_consensus() -> ConsensusParams {
        ConsensusParams {
            enable_pq_scheme_falcon1024: true,
            ..Default::default()
        }
    }

    fn pq_disabled_consensus() -> ConsensusParams {
        ConsensusParams {
            enable_pq_scheme_falcon1024: false,
            ..Default::default()
        }
    }

    #[test]
    fn pqsig_valid_signature_is_accepted() {
        let (pk, sk, salt, addr) = falcon_identity(1);
        let txn = minimal_pay_txn(addr);

        let canonical = canonical_encode_transaction(&txn);
        let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
        msg.extend_from_slice(TX_PREFIX);
        msg.extend_from_slice(&canonical);
        let sig = algo_falcon::falcon_sign(&sk, &msg).expect("falcon sign");

        let pqsig = PQSig {
            scheme: PQ_SCHEME_FALCON1024,
            salt,
            public_key: ByteBuf::from(pk),
            signature: ByteBuf::from(sig),
        };
        let stx = SignedTransaction {
            txn,
            pqsig: Some(pqsig),
            ..Default::default()
        };

        let consensus = pq_enabled_consensus();
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        assert!(verify_transaction_signature(&stx, &group, 0, &mut budget, &consensus).is_ok());
    }

    /// Port of go's `TestPQSigVerifyRejectsChangedTransaction`
    /// (`data/transactions/pqsig_test.go:332`), at the pqsig-over-Transaction
    /// wiring level (`verify_transaction_signature`) rather than just the
    /// Falcon crypto-primitive level (`test_verify_wrong_message` in
    /// `algo-falcon`): a valid PQSig signed over one transaction must be
    /// rejected once the transaction it accompanies is mutated afterward
    /// (the signed message is derived from the transaction's own canonical
    /// encoding, so it must change too).
    #[test]
    fn pqsig_rejects_when_transaction_changed_after_signing() {
        let (pk, sk, salt, addr) = falcon_identity(21);
        let txn = minimal_pay_txn(addr);

        let canonical = canonical_encode_transaction(&txn);
        let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
        msg.extend_from_slice(TX_PREFIX);
        msg.extend_from_slice(&canonical);
        let sig = algo_falcon::falcon_sign(&sk, &msg).expect("falcon sign");

        let pqsig = PQSig {
            scheme: PQ_SCHEME_FALCON1024,
            salt,
            public_key: ByteBuf::from(pk),
            signature: ByteBuf::from(sig),
        };
        let mut stx = SignedTransaction {
            txn,
            pqsig: Some(pqsig),
            ..Default::default()
        };
        // Mutate the transaction after signing -- the signature was computed
        // over the original amount.
        stx.txn.amount += 1;

        let consensus = pq_enabled_consensus();
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        let err = verify_transaction_signature(&stx, &group, 0, &mut budget, &consensus)
            .expect_err("a PQSig must not verify against a transaction it wasn't signed over");
        assert!(
            err.to_string()
                .contains("pq falcon signature verification failed"),
            "expected a signature-verification failure, got: {err}"
        );
    }

    /// Port of go's `TestPQSigVerifyRejectsChangedSignature`
    /// (`data/transactions/pqsig_test.go:343`), at the pqsig-over-Transaction
    /// wiring level rather than just the Falcon crypto-primitive level
    /// (`test_verify_wrong_pubkey` in `algo-falcon`): flipping a byte of the
    /// signature itself (transaction and public key unchanged) must be
    /// rejected too.
    #[test]
    fn pqsig_rejects_when_signature_bytes_changed() {
        let (pk, sk, salt, addr) = falcon_identity(22);
        let txn = minimal_pay_txn(addr);

        let canonical = canonical_encode_transaction(&txn);
        let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
        msg.extend_from_slice(TX_PREFIX);
        msg.extend_from_slice(&canonical);
        let mut sig = algo_falcon::falcon_sign(&sk, &msg).expect("falcon sign");
        // Flip a byte inside the signature payload (mirrors the existing
        // `stxn.Lsig.PQsig.Signature[0] ^= 1` pattern go uses for its
        // "wrong-signature" subtest).
        sig[0] ^= 0x01;

        let pqsig = PQSig {
            scheme: PQ_SCHEME_FALCON1024,
            salt,
            public_key: ByteBuf::from(pk),
            signature: ByteBuf::from(sig),
        };
        let stx = SignedTransaction {
            txn,
            pqsig: Some(pqsig),
            ..Default::default()
        };

        let consensus = pq_enabled_consensus();
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        let err = verify_transaction_signature(&stx, &group, 0, &mut budget, &consensus)
            .expect_err("a tampered PQSig signature must not verify");
        assert!(
            err.to_string()
                .contains("pq falcon signature verification failed"),
            "expected a signature-verification failure, got: {err}"
        );
    }

    #[test]
    fn pqsig_pre_activation_gate_rejects_when_consensus_disabled() {
        // A well-formed, otherwise-valid PQSig must be hard-rejected before
        // any scheme/signature check runs when PQSigEnabled() is false
        // (mirrors go's `stxnCoreChecks` pre-activation gate, commit
        // `fc46c74ef`).
        let (pk, sk, salt, addr) = falcon_identity(2);
        let txn = minimal_pay_txn(addr);
        let canonical = canonical_encode_transaction(&txn);
        let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
        msg.extend_from_slice(TX_PREFIX);
        msg.extend_from_slice(&canonical);
        let sig = algo_falcon::falcon_sign(&sk, &msg).expect("falcon sign");

        let pqsig = PQSig {
            scheme: PQ_SCHEME_FALCON1024,
            salt,
            public_key: ByteBuf::from(pk),
            signature: ByteBuf::from(sig),
        };
        let stx = SignedTransaction {
            txn,
            pqsig: Some(pqsig),
            ..Default::default()
        };

        let consensus = pq_disabled_consensus();
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        let err = verify_transaction_signature(&stx, &group, 0, &mut budget, &consensus)
            .expect_err("PQ signature must be rejected when PQ is not enabled");
        assert!(
            err.to_string().contains("not enabled"),
            "expected a 'not enabled' pre-activation error, got: {err}"
        );
    }

    #[test]
    fn pqsig_empty_signature_bytes_rejected_even_when_scheme_enabled() {
        // A PQSig with a real scheme/salt/pubkey but an EMPTY signature is
        // non-blank (so it passes the pre-activation gate and the sig-type
        // count) but must still be rejected — mirrors go's
        // `errPQSigEmpty`/commit `fc46c74ef`'s intent that an empty
        // signature is never a valid authorization proof.
        let (pk, _sk, salt, addr) = falcon_identity(3);
        let txn = minimal_pay_txn(addr);

        let pqsig = PQSig {
            scheme: PQ_SCHEME_FALCON1024,
            salt,
            public_key: ByteBuf::from(pk),
            signature: ByteBuf::new(), // empty — never signed
        };
        let stx = SignedTransaction {
            txn,
            pqsig: Some(pqsig),
            ..Default::default()
        };

        let consensus = pq_enabled_consensus();
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        let err = verify_transaction_signature(&stx, &group, 0, &mut budget, &consensus)
            .expect_err("an empty PQ signature must never verify");
        assert!(
            err.to_string().contains("empty"),
            "expected an empty-signature error, got: {err}"
        );
    }

    #[test]
    fn pqsig_oversized_public_key_rejected_cheaply() {
        // A public key blob far larger than a real Falcon-1024 key (1793
        // bytes) must be rejected on a cheap length check, not hashed in
        // full for address derivation first — regression test for the
        // pre-hash size guard in `verify_pqsig_bytes`.
        let (_pk, sk, salt, addr) = falcon_identity(12);
        let txn = minimal_pay_txn(addr);
        let canonical = canonical_encode_transaction(&txn);
        let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
        msg.extend_from_slice(TX_PREFIX);
        msg.extend_from_slice(&canonical);
        let sig = algo_falcon::falcon_sign(&sk, &msg).expect("falcon sign");

        let oversized_pk = vec![0x11u8; 10 * algo_falcon::FALCON_DET1024_PUBKEY_SIZE];
        let pqsig = PQSig {
            scheme: PQ_SCHEME_FALCON1024,
            salt,
            public_key: ByteBuf::from(oversized_pk),
            signature: ByteBuf::from(sig),
        };
        let stx = SignedTransaction {
            txn,
            pqsig: Some(pqsig),
            ..Default::default()
        };

        let consensus = pq_enabled_consensus();
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        let err = verify_transaction_signature(&stx, &group, 0, &mut budget, &consensus)
            .expect_err("an oversized PQ public key must be rejected");
        assert!(
            err.to_string().contains("public key size"),
            "expected a public-key-size error, got: {err}"
        );
    }

    #[test]
    fn pqsig_wrong_scheme_rejected() {
        let (pk, sk, salt, addr) = falcon_identity(4);
        let txn = minimal_pay_txn(addr);
        let canonical = canonical_encode_transaction(&txn);
        let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
        msg.extend_from_slice(TX_PREFIX);
        msg.extend_from_slice(&canonical);
        let sig = algo_falcon::falcon_sign(&sk, &msg).expect("falcon sign");

        // "f2" (Falcon-512) is a defined scheme tag upstream but has no
        // registered verifier — must be rejected as unsupported.
        let pqsig = PQSig {
            scheme: *b"f2",
            salt,
            public_key: ByteBuf::from(pk),
            signature: ByteBuf::from(sig),
        };
        let stx = SignedTransaction {
            txn,
            pqsig: Some(pqsig),
            ..Default::default()
        };

        let consensus = pq_enabled_consensus();
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        let err = verify_transaction_signature(&stx, &group, 0, &mut budget, &consensus)
            .expect_err("an unsupported PQ scheme must be rejected");
        assert!(
            err.to_string().contains("not supported"),
            "expected an unsupported-scheme error, got: {err}"
        );
    }

    #[test]
    fn pqsig_address_mismatch_rejected() {
        // The public key derives a different address than the transaction's
        // sender/authorizer — must be rejected regardless of signature
        // validity.
        let (pk, sk, salt, addr) = falcon_identity(5);
        // Use a DIFFERENT sender than the one the PQ key actually derives.
        let mut wrong_sender = addr;
        wrong_sender.0[0] ^= 0xFF;
        let txn = minimal_pay_txn(wrong_sender);

        let canonical = canonical_encode_transaction(&txn);
        let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
        msg.extend_from_slice(TX_PREFIX);
        msg.extend_from_slice(&canonical);
        let sig = algo_falcon::falcon_sign(&sk, &msg).expect("falcon sign");

        let pqsig = PQSig {
            scheme: PQ_SCHEME_FALCON1024,
            salt,
            public_key: ByteBuf::from(pk),
            signature: ByteBuf::from(sig),
        };
        let stx = SignedTransaction {
            txn,
            pqsig: Some(pqsig),
            ..Default::default()
        };

        let consensus = pq_enabled_consensus();
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        let err = verify_transaction_signature(&stx, &group, 0, &mut budget, &consensus)
            .expect_err("a PQ public key that derives a different address must be rejected");
        assert!(
            err.to_string().contains("authorizer mismatch"),
            "expected an authorizer-mismatch error, got: {err}"
        );
    }

    /// Mirrors go's `TestTxnValidationPQSigWithAuthAddr`
    /// (`data/transactions/verify/txn_test.go:389`): unlike
    /// `pqsig_address_mismatch_rejected` above (which pins the rejection
    /// direction), this pins the positive case -- a rekeyed account whose
    /// `auth_addr` is correctly set to the PQ key's derived address is
    /// accepted, even though `sender` itself differs from that address.
    #[test]
    fn pqsig_with_auth_addr_matching_is_accepted() {
        let (pk, sk, salt, addr) = falcon_identity(6);
        // The transaction is sent from a different (rekeyed) sender address;
        // AuthAddr correctly points at the PQ key's own derived address.
        let mut sender = addr;
        sender.0[0] ^= 0xFF;
        let mut txn = minimal_pay_txn(sender);
        txn.rekey_to = Some(addr);

        let canonical = canonical_encode_transaction(&txn);
        let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
        msg.extend_from_slice(TX_PREFIX);
        msg.extend_from_slice(&canonical);
        let sig = algo_falcon::falcon_sign(&sk, &msg).expect("falcon sign");

        let pqsig = PQSig {
            scheme: PQ_SCHEME_FALCON1024,
            salt,
            public_key: ByteBuf::from(pk),
            signature: ByteBuf::from(sig),
        };
        let stx = SignedTransaction {
            txn,
            pqsig: Some(pqsig),
            auth_addr: Some(addr),
            ..Default::default()
        };

        let consensus = pq_enabled_consensus();
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        assert!(
            verify_transaction_signature(&stx, &group, 0, &mut budget, &consensus).is_ok(),
            "a correctly-set AuthAddr matching the PQ key's derived address must be accepted"
        );
    }

    #[test]
    fn pqsig_and_regular_sig_both_set_rejected() {
        // Two mutually-exclusive signature categories set at once (regular
        // ed25519 `sig` AND `pqsig`) must be rejected as not well-formed —
        // mirrors go's `checkTxnSigTypeCounts`'s `numSigCategories > 1` path.
        let key = test_signing_key();
        let (pk, sk, salt, addr) = falcon_identity(6);
        let txn = minimal_pay_txn(addr);

        let ed_sig = sign_txn(&key, &txn);

        let canonical = canonical_encode_transaction(&txn);
        let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
        msg.extend_from_slice(TX_PREFIX);
        msg.extend_from_slice(&canonical);
        let pq_sig_bytes = algo_falcon::falcon_sign(&sk, &msg).expect("falcon sign");

        let pqsig = PQSig {
            scheme: PQ_SCHEME_FALCON1024,
            salt,
            public_key: ByteBuf::from(pk),
            signature: ByteBuf::from(pq_sig_bytes),
        };
        let stx = SignedTransaction {
            txn,
            sig: ed_sig,
            pqsig: Some(pqsig),
            ..Default::default()
        };

        let consensus = pq_enabled_consensus();
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        let err = verify_transaction_signature(&stx, &group, 0, &mut budget, &consensus)
            .expect_err("setting both sig and pqsig must be rejected as not well-formed");
        assert!(
            err.to_string().contains("only one type of signature"),
            "expected a not-well-formed signature-count error, got: {err}"
        );
    }

    #[test]
    fn pq_delegated_logicsig_valid_signature_is_accepted() {
        let (pk, sk, salt, addr) = falcon_identity(7);
        let program = int1_program();

        let dp = PQDelegatedProgram {
            addr,
            program: program.clone(),
        };
        let sig = algo_falcon::falcon_sign(&sk, &dp.to_be_signed()).expect("falcon sign");

        let pqsig = PQSig {
            scheme: PQ_SCHEME_FALCON1024,
            salt,
            public_key: ByteBuf::from(pk),
            signature: ByteBuf::from(sig),
        };
        let lsig = LogicSig {
            logic: ByteBuf::from(program),
            pqsig: Some(pqsig),
            ..LogicSig::default()
        };
        let stx = SignedTransaction {
            txn: minimal_pay_txn(addr),
            lsig: Some(lsig.clone()),
            ..Default::default()
        };

        let consensus = pq_enabled_consensus();
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        assert!(verify_logicsig(&stx, &lsig, &group, 0, &mut budget, &consensus).is_ok());
    }

    #[test]
    fn pq_delegated_logicsig_tampered_program_rejected() {
        // Sign over the original program, then submit a DIFFERENT program
        // under the same delegation signature. Since the PQ-delegated
        // signature covers `"PQProgram" || addr || program`, tampering with
        // the program bytes after signing must invalidate the signature.
        let (pk, sk, salt, addr) = falcon_identity(8);
        let original_program = int1_program();

        let dp = PQDelegatedProgram {
            addr,
            program: original_program.clone(),
        };
        let sig = algo_falcon::falcon_sign(&sk, &dp.to_be_signed()).expect("falcon sign");

        let mut tampered_program = original_program;
        tampered_program.push(0x81); // append an extra opcode byte

        let pqsig = PQSig {
            scheme: PQ_SCHEME_FALCON1024,
            salt,
            public_key: ByteBuf::from(pk),
            signature: ByteBuf::from(sig),
        };
        let lsig = LogicSig {
            logic: ByteBuf::from(tampered_program),
            pqsig: Some(pqsig),
            ..LogicSig::default()
        };
        let stx = SignedTransaction {
            txn: minimal_pay_txn(addr),
            lsig: Some(lsig.clone()),
            ..Default::default()
        };

        let consensus = pq_enabled_consensus();
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        let err = verify_logicsig(&stx, &lsig, &group, 0, &mut budget, &consensus)
            .expect_err("a PQ-delegated LogicSig with a tampered program must be rejected");
        assert!(
            err.to_string().contains("pq delegated logic signature"),
            "expected a pq-delegated-logic-signature error, got: {err}"
        );
    }

    #[test]
    fn pq_delegated_logicsig_and_regular_sig_both_set_rejected() {
        let key = test_signing_key();
        let (pk, sk, salt, addr) = falcon_identity(9);
        let program = int1_program();
        let good_ed_sig = sign_program(&key, &program);

        let dp = PQDelegatedProgram {
            addr,
            program: program.clone(),
        };
        let pq_sig_bytes = algo_falcon::falcon_sign(&sk, &dp.to_be_signed()).expect("falcon sign");
        let pqsig = PQSig {
            scheme: PQ_SCHEME_FALCON1024,
            salt,
            public_key: ByteBuf::from(pk),
            signature: ByteBuf::from(pq_sig_bytes),
        };

        let lsig = LogicSig {
            logic: ByteBuf::from(program),
            sig: good_ed_sig,
            pqsig: Some(pqsig),
            ..LogicSig::default()
        };
        let stx = SignedTransaction {
            txn: minimal_pay_txn(addr),
            lsig: Some(lsig.clone()),
            ..Default::default()
        };

        let consensus = pq_enabled_consensus();
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        let err = verify_logicsig(&stx, &lsig, &group, 0, &mut budget, &consensus).expect_err(
            "a LogicSig with both a regular delegated sig and a pqsig must be rejected",
        );
        assert!(
            err.to_string()
                .contains("only one type of delegation signature"),
            "expected a not-well-formed delegation-signature-count error, got: {err}"
        );
    }

    #[test]
    fn pq_delegated_logicsig_pre_activation_gate_rejects_when_consensus_disabled() {
        let (pk, sk, salt, addr) = falcon_identity(10);
        let program = int1_program();
        let dp = PQDelegatedProgram {
            addr,
            program: program.clone(),
        };
        let sig = algo_falcon::falcon_sign(&sk, &dp.to_be_signed()).expect("falcon sign");

        let pqsig = PQSig {
            scheme: PQ_SCHEME_FALCON1024,
            salt,
            public_key: ByteBuf::from(pk),
            signature: ByteBuf::from(sig),
        };
        let lsig = LogicSig {
            logic: ByteBuf::from(program),
            pqsig: Some(pqsig),
            ..LogicSig::default()
        };
        let stx = SignedTransaction {
            txn: minimal_pay_txn(addr),
            lsig: Some(lsig.clone()),
            ..Default::default()
        };

        // Dispatch through the top-level entry point, which is where the
        // pre-activation gate lives (it must inspect `Lsig.pqsig` too, not
        // just the top-level `SignedTxn.pqsig`).
        let consensus = pq_disabled_consensus();
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        let err = verify_transaction_signature(&stx, &group, 0, &mut budget, &consensus)
            .expect_err("a PQ-delegated LogicSig must be rejected when PQ is not enabled");
        assert!(
            err.to_string().contains("not enabled"),
            "expected a 'not enabled' pre-activation error, got: {err}"
        );
    }

    #[test]
    fn pqsig_blank_is_not_a_signature_category() {
        // A `pqsig: Some(PQSig::default())` (all-zero fields) is Blank() and
        // must NOT count as a signature category — it behaves exactly like
        // `pqsig: None` (matches go's `PQSig.Blank()` semantics: a
        // present-but-zeroed struct is the "absent" representation).
        let (_pk, _sk, _salt, addr) = falcon_identity(11);
        let txn = minimal_pay_txn(addr);

        let stx = SignedTransaction {
            txn,
            pqsig: Some(PQSig::default()),
            ..Default::default()
        };

        let consensus = pq_enabled_consensus();
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        let err = verify_transaction_signature(&stx, &group, 0, &mut budget, &consensus)
            .expect_err("a blank pqsig must not count as a signature category");
        assert!(
            err.to_string().contains("no signature"),
            "expected a no-signature error, got: {err}"
        );
    }

    // ------------------------------------------------------------------
    // Issue #1109: LogicSig eval-time arg-count/arg-size limits, ported
    // from go's `TestTooManyArgs`/`TestArgTooLarge`
    // (`data/transactions/logic/eval_test.go`). Both use a trivial
    // always-accepting contract-account LogicSig ("int 1") so that, absent
    // the fix, the program would otherwise pass -- isolating the two new
    // checks from everything else `verify_logicsig` does.
    // ------------------------------------------------------------------

    #[test]
    fn verify_logicsig_too_many_args_rejected() {
        let program = int1_program();
        let addr = hash_program(&program);
        let lsig = LogicSig {
            logic: ByteBuf::from(program),
            // go: `transactions.EvalMaxArgs + 1` empty args.
            args: Some(vec![ByteBuf::from(Vec::new()); EVAL_MAX_ARGS + 1]),
            ..LogicSig::default()
        };
        let stx = SignedTransaction {
            txn: minimal_pay_txn(addr),
            lsig: Some(lsig.clone()),
            ..Default::default()
        };

        let consensus = ConsensusParams::default();
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        let err = verify_logicsig(&stx, &lsig, &group, 0, &mut budget, &consensus)
            .expect_err("a LogicSig with more than EvalMaxArgs arguments must be rejected");
        assert!(
            err.to_string().contains("too many arguments"),
            "expected a too-many-arguments error, got: {err}"
        );
    }

    #[test]
    fn verify_logicsig_arg_too_large_rejected() {
        let program = int1_program();
        let addr = hash_program(&program);
        let lsig = LogicSig {
            logic: ByteBuf::from(program),
            // go: a single arg of `transactions.MaxLogicSigArgSize + 1` bytes.
            args: Some(vec![ByteBuf::from(vec![0u8; MAX_LOGIC_SIG_ARG_SIZE + 1])]),
            ..LogicSig::default()
        };
        let stx = SignedTransaction {
            txn: minimal_pay_txn(addr),
            lsig: Some(lsig.clone()),
            ..Default::default()
        };

        let consensus = ConsensusParams::default();
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        let err = verify_logicsig(&stx, &lsig, &group, 0, &mut budget, &consensus)
            .expect_err("a LogicSig argument exceeding MaxLogicSigArgSize must be rejected");
        assert!(
            err.to_string().contains("argument too large"),
            "expected an argument-too-large error, got: {err}"
        );
    }

    #[test]
    fn verify_logicsig_args_at_limits_accepted() {
        // Exactly at both limits (EvalMaxArgs count, MaxLogicSigArgSize each)
        // must still pass -- the checks are strictly-greater-than, matching
        // go's `len(...) > transactions.EvalMaxArgs` / `len(arg) >
        // transactions.MaxLogicSigArgSize`.
        let program = int1_program();
        let addr = hash_program(&program);
        let lsig = LogicSig {
            logic: ByteBuf::from(program),
            args: Some(vec![
                ByteBuf::from(vec![0u8; MAX_LOGIC_SIG_ARG_SIZE]);
                EVAL_MAX_ARGS
            ]),
            ..LogicSig::default()
        };
        let stx = SignedTransaction {
            txn: minimal_pay_txn(addr),
            lsig: Some(lsig.clone()),
            ..Default::default()
        };

        let consensus = ConsensusParams::default();
        let group = [stx.clone()];
        let mut budget = GroupBudget::for_logicsig(1);
        assert!(
            verify_logicsig(&stx, &lsig, &group, 0, &mut budget, &consensus).is_ok(),
            "args exactly at both limits must be accepted"
        );
    }

    // ------------------------------------------------------------------
    // Issue #1017: `VerifiedTransactionCache` update-on-success tests,
    // ported from go's `data/transactions/verify/txn_test.go`
    // (`TestTxnGroupCacheUpdate`/`TestTxnGroupCacheUpdateMultiSig`/
    // `TestTxnGroupCacheUpdateRejLogic`/`TestTxnGroupCacheUpdateLogicWithSig`).
    // Each pins the same contract go's `verifyGroup` helper checks: a group
    // whose signature verification fails is NEVER added to the cache (a
    // corrected resubmission is still verified for real), and a group that
    // verifies is added and becomes a cache hit.
    // ------------------------------------------------------------------

    /// "int 0" -- rejects (a false top-of-stack value) unlike
    /// [`int1_program`]'s always-accepting "int 1".
    fn int0_program() -> Vec<u8> {
        vec![0x02, 0x20, 0x01, 0x00, 0x22]
    }

    fn cache_test_context() -> crate::verified_txn_cache::VerificationContext {
        crate::verified_txn_cache::VerificationContext {
            spec_addrs: crate::rules::SpecialAddresses::default(),
            consensus_version: "cache-update-test".to_string(),
        }
    }

    #[test]
    fn txn_group_cache_update_single_sig() {
        use crate::verified_txn_cache::{
            verify_transaction_group_cached, VerifiedTransactionCache,
        };

        let key = test_signing_key();
        let sender = Address(key.verifying_key().to_bytes());
        let txn = minimal_pay_txn(sender);
        let good_sig = sign_txn(&key, &txn);

        let cache = VerifiedTransactionCache::new(100);
        let context = cache_test_context();
        let consensus = ConsensusParams::default();

        // A broken signature fails verification and must NOT be cached.
        let mut broken = SignedTransaction {
            txn: txn.clone(),
            sig: good_sig,
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };
        broken.sig[0] ^= 0xFF;
        let group = vec![broken.clone()];
        assert!(verify_transaction_group_cached(&group, &context, &consensus, &cache).is_err());
        assert_eq!(
            cache
                .get_unverified_transaction_groups(&[group], &context)
                .len(),
            1,
            "a failed group must not be cached"
        );

        // The corrected signature verifies and IS cached.
        let fixed = SignedTransaction {
            sig: good_sig,
            ..broken
        };
        let group = vec![fixed];
        assert!(verify_transaction_group_cached(&group, &context, &consensus, &cache).is_ok());
        assert!(
            cache
                .get_unverified_transaction_groups(&[group], &context)
                .is_empty(),
            "a successfully-verified group must be cached"
        );
    }

    #[test]
    fn txn_group_cache_update_multisig() {
        use crate::verified_txn_cache::{
            verify_transaction_group_cached, VerifiedTransactionCache,
        };

        let keys: Vec<SigningKey> = (40u8..43).map(signing_key_from_seed).collect();
        let msig_addr = compute_msig_addr(&keys, 1, 2);
        let txn = minimal_pay_txn(msig_addr);
        let mut msig = build_multisig(&keys, &[0, 2], 2, &txn);

        let cache = VerifiedTransactionCache::new(100);
        let context = cache_test_context();
        let consensus = ConsensusParams::default();

        // Corrupt one subsig -- the whole group fails and must not be cached.
        msig.subsigs[0].signature[0] ^= 0xFF;
        let broken_stx = SignedTransaction {
            txn: txn.clone(),
            sig: [0u8; 64],
            msig: Some(msig.clone()),
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };
        let group = vec![broken_stx];
        assert!(verify_transaction_group_cached(&group, &context, &consensus, &cache).is_err());
        assert_eq!(
            cache
                .get_unverified_transaction_groups(&[group], &context)
                .len(),
            1,
            "a group with any failed subsig must not be cached"
        );

        // Restore the subsig -- now every signature is correct, and the
        // group verifies and is cached.
        msig.subsigs[0].signature[0] ^= 0xFF;
        let good_stx = SignedTransaction {
            txn,
            sig: [0u8; 64],
            msig: Some(msig),
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };
        let group = vec![good_stx];
        assert!(verify_transaction_group_cached(&group, &context, &consensus, &cache).is_ok());
        assert!(
            cache
                .get_unverified_transaction_groups(&[group], &context)
                .is_empty(),
            "a fully-signed multisig group must be cached"
        );
    }

    #[test]
    fn txn_group_cache_update_logicsig_rejected() {
        use crate::verified_txn_cache::{
            verify_transaction_group_cached, VerifiedTransactionCache,
        };

        // Contract-account LogicSig: sender == hash of the program.
        let rejecting_program = int0_program();
        let mut msg = Vec::new();
        msg.extend_from_slice(PROGRAM_PREFIX);
        msg.extend_from_slice(&rejecting_program);
        let hash = Sha512_256::digest(&msg);
        let mut addr_bytes = [0u8; 32];
        addr_bytes.copy_from_slice(&hash);
        let rejecting_addr = Address(addr_bytes);

        let cache = VerifiedTransactionCache::new(100);
        let context = cache_test_context();
        let consensus = ConsensusParams::default();

        // The program evaluates to a false top-of-stack -- rejected, and
        // must not be cached.
        let lsig = LogicSig {
            logic: ByteBuf::from(rejecting_program),
            ..LogicSig::default()
        };
        let stx = SignedTransaction {
            txn: minimal_pay_txn(rejecting_addr),
            lsig: Some(lsig),
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };
        let group = vec![stx];
        let err = verify_transaction_group_cached(&group, &context, &consensus, &cache)
            .expect_err("a rejecting LogicSig program must fail verification");
        assert!(err.to_string().contains("rejected"));
        assert_eq!(
            cache
                .get_unverified_transaction_groups(&[group], &context)
                .len(),
            1,
            "a logic-rejected group must not be cached"
        );

        // An accepting program (same contract-account shape) verifies and
        // is cached.
        let accepting_program = int1_program();
        let mut msg = Vec::new();
        msg.extend_from_slice(PROGRAM_PREFIX);
        msg.extend_from_slice(&accepting_program);
        let hash = Sha512_256::digest(&msg);
        let mut addr_bytes = [0u8; 32];
        addr_bytes.copy_from_slice(&hash);
        let accepting_addr = Address(addr_bytes);
        let lsig = LogicSig {
            logic: ByteBuf::from(accepting_program),
            ..LogicSig::default()
        };
        let stx = SignedTransaction {
            txn: minimal_pay_txn(accepting_addr),
            lsig: Some(lsig),
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };
        let group = vec![stx];
        assert!(verify_transaction_group_cached(&group, &context, &consensus, &cache).is_ok());
        assert!(
            cache
                .get_unverified_transaction_groups(&[group], &context)
                .is_empty(),
            "an accepting logic-sig group must be cached"
        );
    }

    #[test]
    fn txn_group_cache_update_logicsig_with_sig() {
        use crate::verified_txn_cache::{
            verify_transaction_group_cached, VerifiedTransactionCache,
        };

        let key = test_signing_key();
        let sender = Address(key.verifying_key().to_bytes());
        let program = int1_program();
        let good_delegated_sig = sign_program(&key, &program);

        let cache = VerifiedTransactionCache::new(100);
        let context = cache_test_context();
        let consensus = ConsensusParams::default();

        // A garbage delegated sig fails verification and must not be cached.
        let bad_lsig = LogicSig {
            logic: ByteBuf::from(program.clone()),
            sig: [0x11u8; 64],
            ..LogicSig::default()
        };
        let stx = SignedTransaction {
            txn: minimal_pay_txn(sender),
            lsig: Some(bad_lsig),
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };
        let group = vec![stx];
        assert!(verify_transaction_group_cached(&group, &context, &consensus, &cache).is_err());
        assert_eq!(
            cache
                .get_unverified_transaction_groups(&[group], &context)
                .len(),
            1,
            "a bad delegated signature must not be cached"
        );

        // The correctly delegated signature verifies and is cached.
        let good_lsig = LogicSig {
            logic: ByteBuf::from(program),
            sig: good_delegated_sig,
            ..LogicSig::default()
        };
        let stx = SignedTransaction {
            txn: minimal_pay_txn(sender),
            lsig: Some(good_lsig),
            has_genesis_id: false,
            has_genesis_hash: false,
            ..Default::default()
        };
        let group = vec![stx];
        assert!(verify_transaction_group_cached(&group, &context, &consensus, &cache).is_ok());
        assert!(
            cache
                .get_unverified_transaction_groups(&[group], &context)
                .is_empty(),
            "a correctly delegated logic-sig must be cached"
        );
    }
}
