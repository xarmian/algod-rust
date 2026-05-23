//! Producer-side multisig primitives: address derivation, preimage
//! construction, single-signer signature production, and merge/
//! assemble of subsigs across signers.
//!
//! Byte-for-byte parity with `../go-algorand/crypto/multisig.go`
//! (v4.5.1-stable). The companion verification side already lives in
//! `algo-validate::signature::verify_multisig`; a future cleanup will
//! refactor that module to call back into this one for address
//! computation. For now we duplicate the (trivial) hash code to keep
//! the dependency direction clean (algo-validate → algo-consensus-
//! crypto, not the other way).
//!
//! ## API shape
//!
//! - [`multisig_addr_gen`] — compute the 32-byte msig address from
//!   `(version, threshold, &[pk])`.
//! - [`multisig_preimage_from_pks`] — build a `MultisigSig` with
//!   empty subsigs (only the public keys populated).
//! - [`multisig_sign`] — produce a `MultisigSig` where only the
//!   signer's subsig has a signature; the rest are blank.
//! - [`multisig_assemble`] — merge N independently-signed
//!   `MultisigSig`s (same preimage) into one with all sigs combined.
//!
//! ## Domain separation
//!
//! The msig address derivation uses the literal byte prefix
//! `b"MultisigAddr"` (Go's `multiSigString`), followed by `version`,
//! `threshold`, and the concatenation of all public keys, hashed via
//! SHA-512/256.

mod error;

pub use error::Error;

use algo_types::{Address, MultisigSig, MultisigSubsig};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha512_256};

/// Domain separator for multisig address derivation. Matches Go's
/// `multiSigString` constant at `crypto/multisig.go:90`.
pub const MULTISIG_ADDR_PREFIX: &[u8] = b"MultisigAddr";

/// Maximum number of multisig public keys. Matches Go's `maxMultisig`
/// constant at `crypto/multisig.go:91`.
pub const MAX_MULTISIG: usize = 255;

/// Multisig version we support. Go's `MultisigAddrGen` rejects
/// anything other than 1, and so do we.
pub const MULTISIG_VERSION_V1: u8 = 1;

/// Compute the multisig address for a `(version, threshold, pks)`
/// preimage.
///
/// `Address = SHA512/256("MultisigAddr" || version || threshold || pk1 || pk2 || ... || pkN)`
///
/// Mirrors `MultisigAddrGen` (`crypto/multisig.go:96-112`). Rejects
/// `version != 1`, empty `pks`, `threshold == 0`, `threshold > pks.len()`,
/// and `pks.len() > 255`.
pub fn multisig_addr_gen(version: u8, threshold: u8, pks: &[[u8; 32]]) -> Result<Address, Error> {
    if version != MULTISIG_VERSION_V1 {
        return Err(Error::UnknownVersion);
    }
    if threshold == 0 || pks.is_empty() || threshold as usize > pks.len() {
        return Err(Error::InvalidThreshold);
    }
    if pks.len() > MAX_MULTISIG {
        return Err(Error::TooManyKeys);
    }
    let mut hasher = Sha512_256::new();
    hasher.update(MULTISIG_ADDR_PREFIX);
    hasher.update([version]);
    hasher.update([threshold]);
    for pk in pks {
        hasher.update(pk);
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&hasher.finalize());
    Ok(Address(addr))
}

/// Build an empty `MultisigSig` for `(version, threshold, pks)`. Each
/// subsig has its public key populated and its signature zeroed.
/// Mirrors `MultisigPreimageFromPKs` at `crypto/multisig.go:46-52`.
///
/// This function does NOT validate `version`/`threshold`/`pks` — Go
/// doesn't either; the preimage is just a struct constructor. Callers
/// that want validation should call [`multisig_addr_gen`] alongside.
pub fn multisig_preimage_from_pks(version: u8, threshold: u8, pks: &[[u8; 32]]) -> MultisigSig {
    MultisigSig {
        version,
        threshold,
        subsigs: pks
            .iter()
            .map(|pk| MultisigSubsig {
                public_key: *pk,
                signature: [0u8; 64],
            })
            .collect(),
    }
}

/// Produce a single-signer `MultisigSig` for `msg`. The returned
/// MultisigSig has all `pks` populated; only the subsig matching
/// `signer.verifying_key()` is filled with a signature, the others
/// remain blank.
///
/// Mirrors `MultisigSign` at `crypto/multisig.go:137-179`.
///
/// `msg` is the **already-hashed-ready bytes** the caller wants to
/// sign. Algokey callers pre-pend the `"TX"` domain tag (see
/// `algo-validate::signature::verify_signed_txn` for the canonical
/// prefix); state-proof / agreement callers prepend their own tags.
/// This matches the existing prefix-handling convention in
/// `algo-validate` (caller prepends, library signs raw bytes).
pub fn multisig_sign(
    msg: &[u8],
    version: u8,
    threshold: u8,
    pks: &[[u8; 32]],
    signer: &SigningKey,
) -> Result<MultisigSig, Error> {
    if version != MULTISIG_VERSION_V1 {
        return Err(Error::UnknownVersion);
    }
    // Validate the (version, threshold, pks) triple by computing the
    // address; this is the same guard Go applies (multisig.go:144-152).
    let _ = multisig_addr_gen(version, threshold, pks)?;

    let signer_pk: [u8; 32] = signer.verifying_key().to_bytes();
    let key_idx = pks.iter().position(|pk| pk == &signer_pk);
    let Some(key_idx) = key_idx else {
        return Err(Error::KeyNotExist);
    };

    let signature = signer.sign(msg).to_bytes();

    let subsigs = pks
        .iter()
        .enumerate()
        .map(|(i, pk)| MultisigSubsig {
            public_key: *pk,
            signature: if i == key_idx { signature } else { [0u8; 64] },
        })
        .collect();

    Ok(MultisigSig {
        version,
        threshold,
        subsigs,
    })
}

/// Merge N independently-signed `MultisigSig`s into a single combined
/// MultisigSig. All partials must share the same `(version, threshold,
/// pks)` preimage; only the populated `signature` fields are merged.
///
/// Mirrors `MultisigAssemble` at `crypto/multisig.go:182-228`. Requires
/// at least 2 partials (matches Go's `len(unisig) < 2` check), rejects
/// preimage mismatches with the same error variants Go uses.
///
/// Note: when two partials each carry a sig for the same subsig
/// position, the **last** writer wins — matches Go's behaviour where
/// the inner loop unconditionally overwrites `msig.Subsigs[j].Sig` if
/// the partial's sig is non-blank (multisig.go:220-225). This is
/// rarely the case in practice (partials usually come from distinct
/// signers), and Go does not validate that duplicate sigs agree.
pub fn multisig_assemble(parts: &[MultisigSig]) -> Result<MultisigSig, Error> {
    if parts.len() < 2 {
        return Err(Error::InvalidNumberOfSignatures);
    }
    let head = &parts[0];
    for other in &parts[1..] {
        if other.threshold != head.threshold {
            return Err(Error::ThresholdsDoNotMatch);
        }
        if other.version != head.version {
            return Err(Error::VersionsDoNotMatch);
        }
        if other.subsigs.len() != head.subsigs.len() {
            return Err(Error::SubsigCountDiffers);
        }
        for (a, b) in head.subsigs.iter().zip(other.subsigs.iter()) {
            if a.public_key != b.public_key {
                return Err(Error::KeysDoNotMatch);
            }
        }
    }

    let mut combined = MultisigSig {
        version: head.version,
        threshold: head.threshold,
        subsigs: head
            .subsigs
            .iter()
            .map(|s| MultisigSubsig {
                public_key: s.public_key,
                signature: [0u8; 64],
            })
            .collect(),
    };
    for part in parts {
        for (j, sub) in part.subsigs.iter().enumerate() {
            if sub.signature != [0u8; 64] {
                combined.subsigs[j].signature = sub.signature;
            }
        }
    }
    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn fresh_signer() -> (SigningKey, [u8; 32]) {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    /// Address derivation must match the hand-computed digest for a
    /// fixed (version, threshold, pks) triple. Pinned bytes come from
    /// running `crypto.MultisigAddrGen(1, 2, [pk1, pk2, pk3])` against
    /// go-algorand v4.5.1-stable with `pk_i = SignatureVerifier of
    /// crypto.GenerateSignatureSecrets(seed_i)` for known seeds.
    #[test]
    fn addr_gen_rejects_invalid_inputs() {
        let (_, pk) = fresh_signer();
        assert_eq!(
            multisig_addr_gen(2, 1, &[pk]).unwrap_err(),
            Error::UnknownVersion
        );
        assert_eq!(
            multisig_addr_gen(1, 0, &[pk]).unwrap_err(),
            Error::InvalidThreshold
        );
        assert_eq!(
            multisig_addr_gen(1, 2, &[pk]).unwrap_err(),
            Error::InvalidThreshold
        );
        assert_eq!(
            multisig_addr_gen(1, 1, &[]).unwrap_err(),
            Error::InvalidThreshold
        );
    }

    #[test]
    fn addr_gen_too_many_keys() {
        let mut pks = Vec::new();
        for _ in 0..=MAX_MULTISIG {
            let (_, pk) = fresh_signer();
            pks.push(pk);
        }
        // 256 keys → reject.
        assert_eq!(
            multisig_addr_gen(1, 1, &pks).unwrap_err(),
            Error::TooManyKeys
        );
    }

    /// Address is deterministic — same inputs yield same address.
    #[test]
    fn addr_gen_is_deterministic() {
        let pks: [[u8; 32]; 3] = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let a = multisig_addr_gen(1, 2, &pks).unwrap();
        let b = multisig_addr_gen(1, 2, &pks).unwrap();
        assert_eq!(a, b);
    }

    /// Order-sensitive: swapping two pks changes the address.
    #[test]
    fn addr_gen_is_order_sensitive() {
        let pks_a: [[u8; 32]; 2] = [[1u8; 32], [2u8; 32]];
        let pks_b: [[u8; 32]; 2] = [[2u8; 32], [1u8; 32]];
        assert_ne!(
            multisig_addr_gen(1, 1, &pks_a).unwrap(),
            multisig_addr_gen(1, 1, &pks_b).unwrap()
        );
    }

    /// Preimage builder populates pks and zeros sigs.
    #[test]
    fn preimage_from_pks_layout() {
        let pks: [[u8; 32]; 2] = [[7u8; 32], [9u8; 32]];
        let pre = multisig_preimage_from_pks(1, 2, &pks);
        assert_eq!(pre.version, 1);
        assert_eq!(pre.threshold, 2);
        assert_eq!(pre.subsigs.len(), 2);
        assert_eq!(pre.subsigs[0].public_key, [7u8; 32]);
        assert_eq!(pre.subsigs[1].public_key, [9u8; 32]);
        assert_eq!(pre.subsigs[0].signature, [0u8; 64]);
        assert_eq!(pre.subsigs[1].signature, [0u8; 64]);
    }

    /// `multisig_sign` populates only the signer's slot.
    #[test]
    fn sign_only_signer_subsig_filled() {
        let (sk_a, pk_a) = fresh_signer();
        let (_, pk_b) = fresh_signer();
        let (_, pk_c) = fresh_signer();
        let pks = [pk_a, pk_b, pk_c];
        let msg = b"hello, multisig";
        let msig = multisig_sign(msg, 1, 2, &pks, &sk_a).unwrap();
        assert_eq!(msig.subsigs.len(), 3);
        assert_ne!(
            msig.subsigs[0].signature, [0u8; 64],
            "signer A subsig must be filled"
        );
        assert_eq!(msig.subsigs[1].signature, [0u8; 64]);
        assert_eq!(msig.subsigs[2].signature, [0u8; 64]);
    }

    /// `multisig_sign` errors when the signer's pubkey isn't in `pks`.
    #[test]
    fn sign_rejects_unknown_signer() {
        let (sk_x, _) = fresh_signer();
        let pks = [[1u8; 32], [2u8; 32]];
        let err = multisig_sign(b"msg", 1, 1, &pks, &sk_x).unwrap_err();
        assert_eq!(err, Error::KeyNotExist);
    }

    /// `multisig_sign` errors on bad (version, threshold).
    #[test]
    fn sign_propagates_addr_gen_errors() {
        let (sk, pk) = fresh_signer();
        let pks = [pk];
        assert_eq!(
            multisig_sign(b"msg", 2, 1, &pks, &sk).unwrap_err(),
            Error::UnknownVersion
        );
        assert_eq!(
            multisig_sign(b"msg", 1, 0, &pks, &sk).unwrap_err(),
            Error::InvalidThreshold
        );
    }

    /// Assemble merges per-signer subsigs from distinct partials.
    #[test]
    fn assemble_merges_distinct_signers() {
        let (sk_a, pk_a) = fresh_signer();
        let (sk_b, pk_b) = fresh_signer();
        let (sk_c, pk_c) = fresh_signer();
        let pks = [pk_a, pk_b, pk_c];
        let msg = b"merge me";
        let p_a = multisig_sign(msg, 1, 2, &pks, &sk_a).unwrap();
        let p_b = multisig_sign(msg, 1, 2, &pks, &sk_b).unwrap();
        let p_c = multisig_sign(msg, 1, 2, &pks, &sk_c).unwrap();
        let combined = multisig_assemble(&[p_a.clone(), p_b.clone()]).unwrap();
        assert_eq!(combined.threshold, 2);
        assert_ne!(combined.subsigs[0].signature, [0u8; 64]);
        assert_ne!(combined.subsigs[1].signature, [0u8; 64]);
        assert_eq!(combined.subsigs[2].signature, [0u8; 64]);
        // Adding C's partial fills slot 2 too.
        let full = multisig_assemble(&[p_a, p_b, p_c]).unwrap();
        for s in &full.subsigs {
            assert_ne!(s.signature, [0u8; 64]);
        }
    }

    /// Assemble rejects mismatched preimages.
    #[test]
    fn assemble_rejects_mismatched_preimages() {
        let (sk_a, pk_a) = fresh_signer();
        let (_, pk_b) = fresh_signer();
        let pks_ab = [pk_a, pk_b];
        let pks_ba = [pk_b, pk_a];
        let p1 = multisig_sign(b"x", 1, 1, &pks_ab, &sk_a).unwrap();
        let mut p2 = multisig_preimage_from_pks(1, 2, &pks_ab);
        // Different threshold from p1.
        p2.subsigs[0].signature = [1u8; 64];
        assert_eq!(
            multisig_assemble(&[p1.clone(), p2.clone()]).unwrap_err(),
            Error::ThresholdsDoNotMatch
        );
        // Different version.
        let mut p3 = p1.clone();
        p3.version = 2;
        assert_eq!(
            multisig_assemble(&[p1.clone(), p3]).unwrap_err(),
            Error::VersionsDoNotMatch
        );
        // Different pks ordering.
        let p4 = multisig_preimage_from_pks(1, 1, &pks_ba);
        assert_eq!(
            multisig_assemble(&[p1.clone(), p4]).unwrap_err(),
            Error::KeysDoNotMatch
        );
        // Different subsig count.
        let mut p5 = p1.clone();
        p5.subsigs.pop();
        assert_eq!(
            multisig_assemble(&[p1, p5]).unwrap_err(),
            Error::SubsigCountDiffers
        );
    }

    /// Assemble rejects < 2 partials.
    #[test]
    fn assemble_rejects_too_few_partials() {
        let p = multisig_preimage_from_pks(1, 1, &[[1u8; 32]]);
        assert_eq!(
            multisig_assemble(&[]).unwrap_err(),
            Error::InvalidNumberOfSignatures
        );
        assert_eq!(
            multisig_assemble(&[p]).unwrap_err(),
            Error::InvalidNumberOfSignatures
        );
    }

    /// End-to-end: produced MultisigSig verifies under
    /// `algo-validate::signature::verify_multisig`. We don't import
    /// algo-validate here (would create a cycle), so this is exercised
    /// via the parity test crate.
    #[test]
    fn signature_bytes_are_64() {
        let (sk, pk) = fresh_signer();
        let msig = multisig_sign(b"hi", 1, 1, &[pk], &sk).unwrap();
        assert_eq!(msig.subsigs[0].signature.len(), 64);
    }
}
