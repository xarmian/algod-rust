//! One-time signature (OTS) key generation, signing, and forward-secure deletion.
//!
//! Implements a two-level ed25519 ephemeral key tree matching go-algorand's
//! `crypto/onetimesig.go`. The three-level structure is:
//!
//! 1. **Master key** — long-lived ed25519 signing key
//! 2. **Batch subkeys** — ephemeral keys for a range of rounds, each signed by master
//! 3. **Offset subkeys** — ephemeral keys for individual rounds within a batch,
//!    each signed by the corresponding batch subkey
//!
//! # Forward Security
//!
//! After signing, [`OneTimeSignatureSecrets::delete_before`] erases ephemeral keys
//! for past rounds so that a key compromise cannot forge old signatures.
//!
//! # Domain Separation
//!
//! - `"OT1"` — batch subkey signing (`OneTimeSignatureSubkeyBatchID`)
//! - `"OT2"` — offset subkey signing (`OneTimeSignatureSubkeyOffsetID`)
//!
//! These match go-algorand's `protocol.OneTimeSigKey1` / `OneTimeSigKey2`.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::Rng;
use zeroize::Zeroize;

// ── Domain separation prefixes ─────────────────────────────────────────────

/// Generate a random ed25519 signing key using the thread-local RNG.
fn random_signing_key() -> SigningKey {
    let seed: [u8; 32] = rand::thread_rng().gen();
    SigningKey::from_bytes(&seed)
}

/// Domain separation prefix for batch subkey signing (Go: `protocol.OneTimeSigKey1 = "OT1"`).
const OT1_PREFIX: &[u8] = b"OT1";

/// Domain separation prefix for offset subkey signing (Go: `protocol.OneTimeSigKey2 = "OT2"`).
const OT2_PREFIX: &[u8] = b"OT2";

// ── ID types for domain-separated signing ──────────────────────────────────

/// Identifies a batch subkey for signing by the master key.
///
/// Encoded as msgpack with fields `"batch"` (uint64) and `"pk"` (bin32),
/// in alphabetical order (matching Go's `codec:""` non-omitempty encoding).
#[derive(Debug, Clone)]
pub struct OneTimeSignatureSubkeyBatchID {
    /// The batch number.
    pub batch: u64,
    /// The ed25519 public key of the batch subkey.
    pub public_key: [u8; 32],
}

/// Identifies an offset subkey for signing by the batch key.
///
/// Encoded as msgpack with fields `"batch"` (uint64), `"off"` (uint64),
/// and `"pk"` (bin32), in alphabetical order.
#[derive(Debug, Clone)]
pub struct OneTimeSignatureSubkeyOffsetID {
    /// The batch number.
    pub batch: u64,
    /// The offset within the batch.
    pub offset: u64,
    /// The ed25519 public key of the offset subkey.
    pub public_key: [u8; 32],
}

// ── Canonical msgpack encoding ─────────────────────────────────────────────
//
// These must produce byte-identical output to Go's msgp-generated code.
// The Go structs use `codec:""` (non-omitempty), so ALL fields are always encoded.
// Fields are sorted alphabetically by their codec tag names.

/// Encode a `OneTimeSignatureSubkeyBatchID` in canonical msgpack format.
///
/// ```text
/// fixmap(2)
///   fixstr("batch") -> uint64(batch)
///   fixstr("pk")    -> bin(pk_bytes)
/// ```
fn encode_batch_id(pk: &[u8; 32], batch: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(50);
    // fixmap(2) + fixstr("batch")
    buf.extend_from_slice(&[0x82, 0xa5, b'b', b'a', b't', b'c', b'h']);
    // uint64 batch (rmp compact encoding)
    rmp::encode::write_uint(&mut buf, batch).unwrap();
    // fixstr("pk")
    buf.extend_from_slice(&[0xa2, b'p', b'k']);
    // bin(pk_bytes) — 32 bytes
    rmp::encode::write_bin(&mut buf, pk).unwrap();
    buf
}

/// Encode a `OneTimeSignatureSubkeyOffsetID` in canonical msgpack format.
///
/// ```text
/// fixmap(3)
///   fixstr("batch")  -> uint64(batch)
///   fixstr("off")    -> uint64(offset)
///   fixstr("pk")     -> bin(pk_bytes)
/// ```
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

/// Build the domain-separated message for a BatchID: `"OT1" || encode(BatchID)`.
fn batch_id_message(pk: &[u8; 32], batch: u64) -> Vec<u8> {
    let encoded = encode_batch_id(pk, batch);
    let mut msg = Vec::with_capacity(OT1_PREFIX.len() + encoded.len());
    msg.extend_from_slice(OT1_PREFIX);
    msg.extend_from_slice(&encoded);
    msg
}

/// Build the domain-separated message for an OffsetID: `"OT2" || encode(OffsetID)`.
fn offset_id_message(pk: &[u8; 32], batch: u64, offset: u64) -> Vec<u8> {
    let encoded = encode_offset_id(pk, batch, offset);
    let mut msg = Vec::with_capacity(OT2_PREFIX.len() + encoded.len());
    msg.extend_from_slice(OT2_PREFIX);
    msg.extend_from_slice(&encoded);
    msg
}

// ── OneTimeSignature output ────────────────────────────────────────────────

/// A one-time signature produced by the two-level ephemeral key tree.
///
/// This is the signing-side counterpart of `algo_types::HeartbeatProof`
/// (which is used for verification). The fields are identical.
///
/// Verification chain:
/// 1. `pk2_sig`: master key signs `"OT1" || encode(BatchID{pk2, batch})`
/// 2. `pk1_sig`: `pk2` signs `"OT2" || encode(OffsetID{pk, batch, offset})`
/// 3. `sig`: `pk` signs the actual message
#[derive(Debug, Clone)]
pub struct OneTimeSignature {
    /// Signature of the message under the offset (ephemeral) key `pk`.
    pub sig: [u8; 64],
    /// Public key of the offset (ephemeral) key that signed the message.
    pub pk: [u8; 32],
    /// Public key of the batch subkey.
    pub pk2: [u8; 32],
    /// Signature of `OffsetID(pk, batch, offset)` under `pk2`.
    pub pk1_sig: [u8; 64],
    /// Signature of `BatchID(pk2, batch)` under the master key.
    pub pk2_sig: [u8; 64],
}

// ── Internal ephemeral subkey ──────────────────────────────────────────────

/// An ephemeral subkey with its signing key and the signature authenticating it.
///
/// Corresponds to Go's `ephemeralSubkey`.
#[derive(Clone)]
struct EphemeralSubkey {
    /// Ed25519 signing key (includes secret + public).
    sk: SigningKey,
    /// Signature authenticating this subkey's public key under the parent key.
    /// For batch subkeys: master signs `"OT1" || encode(BatchID)`.
    /// For offset subkeys: batch key signs `"OT2" || encode(OffsetID)`.
    pk_sig: [u8; 64],
}

impl EphemeralSubkey {
    /// Return the public key bytes.
    fn pk_bytes(&self) -> [u8; 32] {
        self.sk.verifying_key().to_bytes()
    }
}

impl Drop for EphemeralSubkey {
    fn drop(&mut self) {
        // `SigningKey` already implements `ZeroizeOnDrop`, so `self.sk` is
        // automatically zeroized when this struct is dropped.
        // Explicitly zeroize the authentication signature.
        self.pk_sig.zeroize();
    }
}

// ── OneTimeSignatureSecrets ────────────────────────────────────────────────

/// Master key + ephemeral key tree for producing one-time signatures.
///
/// Corresponds to Go's `OneTimeSignatureSecrets` / `OneTimeSignatureSecretsPersistent`.
///
/// The key tree has two levels:
/// - **Batch subkeys** cover a contiguous range of batch indices.
///   Each is signed by the master key with domain `"OT1"`.
/// - **Offset subkeys** are generated on demand when a batch is "expanded"
///   (either during signing or during `delete_before`). Each is signed by
///   the batch subkey with domain `"OT2"`.
pub struct OneTimeSignatureSecrets {
    /// The master signing key.
    master: SigningKey,

    /// Batch subkeys, indexed as `batches[i]` = subkey for batch `first_batch + i`.
    batches: Vec<EphemeralSubkey>,
    /// The first batch index covered by `batches`.
    first_batch: u64,

    /// Offset subkeys for a partially-consumed batch.
    ///
    /// When `delete_before` advances past some offsets in a batch, the remaining
    /// offset subkeys are stored here. The batch they belong to is `first_batch - 1`.
    offsets: Vec<EphemeralSubkey>,
    /// The first offset index in `offsets`.
    first_offset: u64,
    /// Public key of the batch subkey that signed the offset subkeys.
    offsets_pk2: [u8; 32],
    /// Master's signature on `BatchID(offsets_pk2, first_batch - 1)`.
    offsets_pk2_sig: [u8; 64],
}

impl Drop for OneTimeSignatureSecrets {
    fn drop(&mut self) {
        // `self.master` (SigningKey) implements `ZeroizeOnDrop` and is
        // automatically zeroized when this struct is dropped.
        // Batch and offset `EphemeralSubkey` vecs are zeroized via their own `Drop` impls
        // when each element is dropped. Explicitly clear to ensure they run now.
        self.batches.clear();
        self.offsets.clear();
        self.offsets_pk2.zeroize();
        self.offsets_pk2_sig.zeroize();
    }
}

impl OneTimeSignatureSecrets {
    /// Generate a new OTS key tree covering batches `[start_batch, start_batch + num_batches)`.
    ///
    /// This creates a fresh master ed25519 keypair and pre-generates all batch subkeys.
    /// Offset subkeys are generated lazily during `sign` or `delete_before`.
    pub fn generate(start_batch: u64, num_batches: u64) -> Self {
        let master = random_signing_key();
        Self::generate_with_master(master, start_batch, num_batches)
    }

    /// Generate from a specific master key (useful for deterministic testing).
    pub fn generate_with_master(master: SigningKey, start_batch: u64, num_batches: u64) -> Self {
        let mut batches = Vec::with_capacity(num_batches as usize);

        for i in 0..num_batches {
            let batch_key = random_signing_key();
            let batch_num = start_batch + i;
            let batch_pk = batch_key.verifying_key().to_bytes();

            // Master signs BatchID(batch_pk, batch_num)
            let msg = batch_id_message(&batch_pk, batch_num);
            let sig = master.sign(&msg);

            batches.push(EphemeralSubkey {
                sk: batch_key,
                pk_sig: sig.to_bytes(),
            });
        }

        OneTimeSignatureSecrets {
            master,
            batches,
            first_batch: start_batch,
            offsets: Vec::new(),
            first_offset: 0,
            offsets_pk2: [0u8; 32],
            offsets_pk2_sig: [0u8; 64],
        }
    }

    /// Return the master public key (the `OneTimeSignatureVerifier`).
    pub fn verifier(&self) -> [u8; 32] {
        self.master.verifying_key().to_bytes()
    }

    /// Sign a message for a given round.
    ///
    /// The round is decomposed into `batch = round / key_dilution` and
    /// `offset = round % key_dilution`.
    ///
    /// # Panics
    ///
    /// Panics if `key_dilution` is zero, or if the requested round's batch
    /// is not available (already deleted or never generated).
    pub fn sign(&self, msg: &[u8], round: u64, key_dilution: u64) -> OneTimeSignature {
        assert!(key_dilution > 0, "key_dilution must be > 0");

        let batch = round / key_dilution;
        let offset = round % key_dilution;

        // Case 1: Check if we have pre-expanded offset subkeys for this batch.
        // This happens after delete_before has expanded a batch into offsets.
        // The offsets belong to batch `first_batch - 1`.
        if !self.offsets.is_empty()
            && batch + 1 == self.first_batch
            && offset >= self.first_offset
            && offset - self.first_offset < self.offsets.len() as u64
        {
            let off_idx = (offset - self.first_offset) as usize;
            let offset_subkey = &self.offsets[off_idx];

            let sig = offset_subkey.sk.sign(msg);

            return OneTimeSignature {
                sig: sig.to_bytes(),
                pk: offset_subkey.pk_bytes(),
                pk2: self.offsets_pk2,
                pk1_sig: offset_subkey.pk_sig,
                pk2_sig: self.offsets_pk2_sig,
            };
        }

        // Case 2: Use a batch subkey directly.
        // Generate a fresh offset subkey on the fly (matching Go's behavior).
        assert!(
            batch >= self.first_batch && batch - self.first_batch < self.batches.len() as u64,
            "batch {batch} out of range [first_batch={}, len={}]",
            self.first_batch,
            self.batches.len()
        );

        let batch_idx = (batch - self.first_batch) as usize;
        let batch_subkey = &self.batches[batch_idx];

        // Generate a fresh ephemeral key for this specific offset.
        let offset_key = random_signing_key();
        let offset_pk = offset_key.verifying_key().to_bytes();

        // Offset key signs the message.
        let sig = offset_key.sign(msg);

        // Batch key signs OffsetID(offset_pk, batch, offset).
        let offset_msg = offset_id_message(&offset_pk, batch, offset);
        let pk1_sig = batch_subkey.sk.sign(&offset_msg);

        OneTimeSignature {
            sig: sig.to_bytes(),
            pk: offset_pk,
            pk2: batch_subkey.pk_bytes(),
            pk1_sig: pk1_sig.to_bytes(),
            pk2_sig: batch_subkey.pk_sig,
        }
    }

    /// Delete all ephemeral keys for rounds before `round`, providing forward security.
    ///
    /// After this call, it is impossible to sign messages for any round < `round`.
    ///
    /// This mirrors Go's `DeleteBeforeFineGrained`:
    /// 1. If advancing within the same batch's offset subkeys, trim offsets.
    /// 2. If advancing to a new batch, delete old batches and expand the
    ///    next batch into per-offset subkeys (deleting the batch key itself).
    pub fn delete_before(&mut self, round: u64, key_dilution: u64) {
        assert!(key_dilution > 0, "key_dilution must be > 0");

        let current_batch = round / key_dilution;
        let current_offset = round % key_dilution;

        // Case 1: Advancing within the offset subkeys of the current partial batch.
        // Offsets belong to batch `first_batch - 1`.
        if current_batch + 1 == self.first_batch {
            if current_offset > self.first_offset {
                let jump = std::cmp::min(
                    (current_offset - self.first_offset) as usize,
                    self.offsets.len(),
                );
                self.first_offset += jump as u64;
                self.offsets = self.offsets.split_off(jump);
            }
            return;
        }

        // Case 2: Trying to forget something earlier — nothing to do.
        if current_batch + 1 < self.first_batch {
            return;
        }

        // Case 3: Moving forward to a new batch.

        // 3a. Delete existing offset subkeys (they belong to an old batch).
        self.offsets.clear();

        // 3b. Delete whole batches we're jumping over.
        let jump = current_batch - self.first_batch;
        if jump > self.batches.len() as u64 {
            // Ran out of batches entirely.
            if !self.batches.is_empty() {
                self.first_batch = current_batch;
                self.batches.clear();
            }
            return;
        }
        self.first_batch += jump;
        self.batches = self.batches.split_off(jump as usize);

        // 3c. Expand the next batch into per-offset subkeys.
        if self.batches.is_empty() {
            return;
        }

        let batch_subkey = &self.batches[0];
        self.offsets_pk2 = batch_subkey.pk_bytes();
        self.offsets_pk2_sig = batch_subkey.pk_sig;

        self.first_offset = current_offset;
        let mut new_offsets = Vec::with_capacity((key_dilution - current_offset) as usize);
        for off in current_offset..key_dilution {
            let offset_key = random_signing_key();
            let offset_pk = offset_key.verifying_key().to_bytes();

            // Batch key signs OffsetID(offset_pk, current_batch, off).
            let offset_msg = offset_id_message(&offset_pk, current_batch, off);
            let pk1_sig = batch_subkey.sk.sign(&offset_msg);

            new_offsets.push(EphemeralSubkey {
                sk: offset_key,
                pk_sig: pk1_sig.to_bytes(),
            });
        }
        self.offsets = new_offsets;

        // 3d. Delete the batch subkey we just expanded (it's at index 0).
        self.first_batch += 1;
        self.batches = self.batches.split_off(1);
    }

    /// Return the first batch index still available.
    pub fn first_batch(&self) -> u64 {
        self.first_batch
    }

    /// Return the number of remaining batch subkeys.
    pub fn num_batches(&self) -> usize {
        self.batches.len()
    }

    /// Return the number of remaining offset subkeys.
    pub fn num_offsets(&self) -> usize {
        self.offsets.len()
    }

    /// Return the first offset index in the offset subkeys.
    pub fn first_offset(&self) -> u64 {
        self.first_offset
    }
}

/// Verify a `OneTimeSignature` against a master public key (verifier).
///
/// This performs the same three-level verification as
/// `algo_validate::signature::verify_heartbeat_proof`, but operates on
/// our `OneTimeSignature` type and takes `batch`/`offset` directly.
///
/// Verification chain:
/// 1. `pk2_sig`: `verifier` signs `"OT1" || encode(BatchID{pk2, batch})`
/// 2. `pk1_sig`: `pk2` signs `"OT2" || encode(OffsetID{pk, batch, offset})`
/// 3. `sig`: `pk` signs `msg`
pub fn verify_one_time_signature(
    sig: &OneTimeSignature,
    verifier: &[u8; 32],
    batch: u64,
    offset: u64,
    msg: &[u8],
) -> bool {
    // 1. Verify pk2_sig: verifier signs BatchID(pk2, batch)
    let vk_master = match VerifyingKey::from_bytes(verifier) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let batch_msg = batch_id_message(&sig.pk2, batch);
    // Use non-strict verify to match Go's behavior (ed25519 without cofactor check).
    if vk_master
        .verify(
            &batch_msg,
            &ed25519_dalek::Signature::from_bytes(&sig.pk2_sig),
        )
        .is_err()
    {
        return false;
    }

    // 2. Verify pk1_sig: pk2 signs OffsetID(pk, batch, offset)
    let vk_batch = match VerifyingKey::from_bytes(&sig.pk2) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let offset_msg = offset_id_message(&sig.pk, batch, offset);
    if vk_batch
        .verify(
            &offset_msg,
            &ed25519_dalek::Signature::from_bytes(&sig.pk1_sig),
        )
        .is_err()
    {
        return false;
    }

    // 3. Verify sig: pk signs msg
    let vk_offset = match VerifyingKey::from_bytes(&sig.pk) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    if vk_offset
        .verify(msg, &ed25519_dalek::Signature::from_bytes(&sig.sig))
        .is_err()
    {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Basic: generate keys, sign a message, verify.
    #[test]
    fn sign_and_verify_basic() {
        let start_batch = 0;
        let num_batches = 10;
        let key_dilution = 100;
        let secrets = OneTimeSignatureSecrets::generate(start_batch, num_batches);
        let verifier = secrets.verifier();

        let msg = b"hello, algorand";
        let round = 42u64; // batch=0, offset=42
        let sig = secrets.sign(msg, round, key_dilution);

        let batch = round / key_dilution;
        let offset = round % key_dilution;
        assert!(verify_one_time_signature(
            &sig, &verifier, batch, offset, msg
        ));
    }

    /// Sign at batch boundaries (offset = 0).
    #[test]
    fn sign_at_batch_boundary() {
        let secrets = OneTimeSignatureSecrets::generate(0, 5);
        let verifier = secrets.verifier();
        let key_dilution = 10;

        for batch_idx in 0..5u64 {
            let round = batch_idx * key_dilution;
            let sig = secrets.sign(b"boundary test", round, key_dilution);
            assert!(verify_one_time_signature(
                &sig,
                &verifier,
                batch_idx,
                0,
                b"boundary test"
            ));
        }
    }

    /// Sign at various offsets within a batch.
    #[test]
    fn sign_multiple_offsets() {
        let secrets = OneTimeSignatureSecrets::generate(0, 3);
        let verifier = secrets.verifier();
        let key_dilution = 5;

        for offset in 0..5u64 {
            let round = offset; // batch 0
            let msg = format!("offset {offset}");
            let sig = secrets.sign(msg.as_bytes(), round, key_dilution);
            assert!(verify_one_time_signature(
                &sig,
                &verifier,
                0,
                offset,
                msg.as_bytes()
            ));
        }
    }

    /// Sign across multiple batches.
    #[test]
    fn sign_multiple_batches() {
        let secrets = OneTimeSignatureSecrets::generate(5, 10);
        let verifier = secrets.verifier();
        let key_dilution = 100;

        for batch in 5..15u64 {
            let round = batch * key_dilution + 7; // offset 7 in each batch
            let sig = secrets.sign(b"multi-batch", round, key_dilution);
            assert!(verify_one_time_signature(
                &sig,
                &verifier,
                batch,
                7,
                b"multi-batch"
            ));
        }
    }

    /// Verification fails with wrong verifier (wrong master key).
    #[test]
    fn verify_fails_wrong_verifier() {
        let secrets = OneTimeSignatureSecrets::generate(0, 5);
        let key_dilution = 10;

        let sig = secrets.sign(b"test", 3, key_dilution);

        let wrong_master = random_signing_key();
        let wrong_verifier = wrong_master.verifying_key().to_bytes();
        assert!(!verify_one_time_signature(
            &sig,
            &wrong_verifier,
            0,
            3,
            b"test"
        ));
    }

    /// Verification fails with wrong message.
    #[test]
    fn verify_fails_wrong_message() {
        let secrets = OneTimeSignatureSecrets::generate(0, 5);
        let verifier = secrets.verifier();
        let key_dilution = 10;

        let sig = secrets.sign(b"correct", 3, key_dilution);
        assert!(!verify_one_time_signature(&sig, &verifier, 0, 3, b"wrong"));
    }

    /// Verification fails with wrong batch/offset.
    #[test]
    fn verify_fails_wrong_batch_offset() {
        let secrets = OneTimeSignatureSecrets::generate(0, 5);
        let verifier = secrets.verifier();
        let key_dilution = 10;

        let sig = secrets.sign(b"test", 3, key_dilution); // batch=0, offset=3

        // Wrong batch
        assert!(!verify_one_time_signature(&sig, &verifier, 1, 3, b"test"));
        // Wrong offset
        assert!(!verify_one_time_signature(&sig, &verifier, 0, 4, b"test"));
    }

    /// Forward-secure deletion: delete_before removes old keys.
    #[test]
    fn delete_before_removes_old_batch_keys() {
        let mut secrets = OneTimeSignatureSecrets::generate(0, 5);
        let verifier = secrets.verifier();
        let key_dilution = 10;

        // Sign in batch 0 (round 5) — should work
        let sig_r5 = secrets.sign(b"round5", 5, key_dilution);
        assert!(verify_one_time_signature(
            &sig_r5, &verifier, 0, 5, b"round5"
        ));

        // Delete everything before round 20 (batch 2, offset 0)
        secrets.delete_before(20, key_dilution);

        // Batch 0 and 1 should be gone
        assert_eq!(secrets.first_batch(), 3); // first_batch advanced past the expanded batch

        // Signing in batch 2 should still work (via offset subkeys)
        let sig_r25 = secrets.sign(b"round25", 25, key_dilution);
        assert!(verify_one_time_signature(
            &sig_r25, &verifier, 2, 5, b"round25"
        ));

        // Signing in batch 3 should work (batch subkey still exists)
        let sig_r30 = secrets.sign(b"round30", 30, key_dilution);
        assert!(verify_one_time_signature(
            &sig_r30, &verifier, 3, 0, b"round30"
        ));
    }

    /// Forward-secure deletion within a batch (offset trimming).
    #[test]
    fn delete_before_trims_offsets() {
        let mut secrets = OneTimeSignatureSecrets::generate(0, 5);
        let verifier = secrets.verifier();
        let key_dilution = 10;

        // Expand batch 0 into offset subkeys by deleting before round 0
        // (batch 0, offset 0 — this should expand batch 0)
        secrets.delete_before(0, key_dilution);

        // Now we should have offset subkeys for batch 0 (offsets 0..9)
        assert_eq!(secrets.num_offsets(), 10);
        assert_eq!(secrets.first_offset(), 0);

        // Sign at offset 3 (round 3) using expanded offsets
        let sig_r3 = secrets.sign(b"r3", 3, key_dilution);
        assert!(verify_one_time_signature(&sig_r3, &verifier, 0, 3, b"r3"));

        // Delete before round 5 — should trim offsets 0..4
        secrets.delete_before(5, key_dilution);
        assert_eq!(secrets.first_offset(), 5);
        assert_eq!(secrets.num_offsets(), 5); // offsets 5..9 remain

        // Sign at offset 7 (round 7) should still work
        let sig_r7 = secrets.sign(b"r7", 7, key_dilution);
        assert!(verify_one_time_signature(&sig_r7, &verifier, 0, 7, b"r7"));
    }

    /// Delete before a round in the past is a no-op.
    #[test]
    fn delete_before_past_is_noop() {
        let mut secrets = OneTimeSignatureSecrets::generate(5, 5);
        let key_dilution = 10;

        secrets.delete_before(30, key_dilution); // advance to batch 3
        let batches_before = secrets.num_batches();

        secrets.delete_before(20, key_dilution); // try to go backwards
        assert_eq!(secrets.num_batches(), batches_before); // unchanged
    }

    /// Delete beyond all available batches clears everything.
    #[test]
    fn delete_before_beyond_all_batches() {
        let mut secrets = OneTimeSignatureSecrets::generate(0, 3);
        let key_dilution = 10;

        secrets.delete_before(100, key_dilution); // batch 10, way beyond 0..2
        assert_eq!(secrets.num_batches(), 0);
        assert_eq!(secrets.num_offsets(), 0);
    }

    /// Verify domain separation strings match the expected values.
    #[test]
    fn domain_separation_strings() {
        assert_eq!(OT1_PREFIX, b"OT1");
        assert_eq!(OT2_PREFIX, b"OT2");
    }

    /// Verify encode_batch_id produces correct canonical msgpack.
    #[test]
    fn encode_batch_id_format() {
        let pk = [0xAA; 32];
        let batch = 42u64;
        let encoded = encode_batch_id(&pk, batch);

        // Should start with fixmap(2)
        assert_eq!(encoded[0], 0x82);
        // fixstr("batch") = 0xa5 'b' 'a' 't' 'c' 'h'
        assert_eq!(&encoded[1..7], &[0xa5, b'b', b'a', b't', b'c', b'h']);
        // After batch value, fixstr("pk") = 0xa2 'p' 'k'
        // Then bin(32 bytes)
        assert!(encoded.len() > 10);
    }

    /// Verify encode_offset_id produces correct canonical msgpack.
    #[test]
    fn encode_offset_id_format() {
        let pk = [0xBB; 32];
        let batch = 10u64;
        let offset = 3u64;
        let encoded = encode_offset_id(&pk, batch, offset);

        // Should start with fixmap(3)
        assert_eq!(encoded[0], 0x83);
        // fixstr("batch") follows
        assert_eq!(&encoded[1..7], &[0xa5, b'b', b'a', b't', b'c', b'h']);
    }

    /// Start batch is nonzero.
    #[test]
    fn nonzero_start_batch() {
        let start_batch = 100;
        let secrets = OneTimeSignatureSecrets::generate(start_batch, 5);
        let verifier = secrets.verifier();
        let key_dilution = 50;

        // Round 5007 -> batch 100, offset 7
        let round = start_batch * key_dilution + 7;
        let sig = secrets.sign(b"test", round, key_dilution);
        assert!(verify_one_time_signature(&sig, &verifier, 100, 7, b"test"));
    }

    /// Panic on zero key_dilution in sign.
    #[test]
    #[should_panic(expected = "key_dilution must be > 0")]
    fn sign_panics_on_zero_key_dilution() {
        let secrets = OneTimeSignatureSecrets::generate(0, 5);
        secrets.sign(b"test", 0, 0);
    }

    /// Panic on zero key_dilution in delete_before.
    #[test]
    #[should_panic(expected = "key_dilution must be > 0")]
    fn delete_before_panics_on_zero_key_dilution() {
        let mut secrets = OneTimeSignatureSecrets::generate(0, 5);
        secrets.delete_before(0, 0);
    }

    /// Panic when signing for a batch that was never generated.
    #[test]
    #[should_panic(expected = "out of range")]
    fn sign_panics_out_of_range() {
        let secrets = OneTimeSignatureSecrets::generate(0, 3);
        // batch 5 was never generated
        secrets.sign(b"test", 50, 10);
    }

    /// After deleting, signing old rounds panics.
    #[test]
    #[should_panic(expected = "out of range")]
    fn sign_after_delete_panics() {
        let mut secrets = OneTimeSignatureSecrets::generate(0, 5);
        let key_dilution = 10;

        secrets.delete_before(30, key_dilution); // delete batches 0, 1, 2

        // Try to sign in batch 0 (deleted) - but batch 3 is the first now,
        // and batch 0 would be out of range on the low end.
        // Round 5 -> batch 0, offset 5 -> out of range
        secrets.sign(b"test", 5, key_dilution);
    }

    /// Large key_dilution (single offset per batch effectively).
    #[test]
    fn large_key_dilution() {
        let secrets = OneTimeSignatureSecrets::generate(0, 3);
        let verifier = secrets.verifier();
        let key_dilution = 1_000_000;

        // Round 500 -> batch 0, offset 500
        let sig = secrets.sign(b"large kd", 500, key_dilution);
        assert!(verify_one_time_signature(
            &sig,
            &verifier,
            0,
            500,
            b"large kd"
        ));
    }

    /// key_dilution = 1 means every round is its own batch.
    #[test]
    fn key_dilution_one() {
        let secrets = OneTimeSignatureSecrets::generate(0, 10);
        let verifier = secrets.verifier();
        let key_dilution = 1;

        for round in 0..10u64 {
            let sig = secrets.sign(b"kd1", round, key_dilution);
            // batch = round, offset = 0
            assert!(verify_one_time_signature(&sig, &verifier, round, 0, b"kd1"));
        }
    }

    /// Comprehensive delete_before + sign workflow (Go's typical usage pattern).
    #[test]
    fn delete_and_sign_workflow() {
        let mut secrets = OneTimeSignatureSecrets::generate(0, 10);
        let verifier = secrets.verifier();
        let key_dilution = 4;

        // Sign round 0 (batch 0, offset 0)
        let sig0 = secrets.sign(b"r0", 0, key_dilution);
        assert!(verify_one_time_signature(&sig0, &verifier, 0, 0, b"r0"));

        // Advance to round 2 (batch 0, offset 2) — expands batch 0 into offsets
        secrets.delete_before(2, key_dilution);
        assert_eq!(secrets.first_offset(), 2);

        // Sign round 2 and 3 from expanded offsets
        let sig2 = secrets.sign(b"r2", 2, key_dilution);
        assert!(verify_one_time_signature(&sig2, &verifier, 0, 2, b"r2"));

        let sig3 = secrets.sign(b"r3", 3, key_dilution);
        assert!(verify_one_time_signature(&sig3, &verifier, 0, 3, b"r3"));

        // Advance to round 5 (batch 1, offset 1) — expands batch 1
        secrets.delete_before(5, key_dilution);

        let sig5 = secrets.sign(b"r5", 5, key_dilution);
        assert!(verify_one_time_signature(&sig5, &verifier, 1, 1, b"r5"));

        // Jump to round 36 (batch 9, offset 0)
        let sig36 = secrets.sign(b"r36", 36, key_dilution);
        assert!(verify_one_time_signature(&sig36, &verifier, 9, 0, b"r36"));
    }

    /// Empty message signing works.
    #[test]
    fn sign_empty_message() {
        let secrets = OneTimeSignatureSecrets::generate(0, 1);
        let verifier = secrets.verifier();
        let key_dilution = 10;

        let sig = secrets.sign(b"", 0, key_dilution);
        assert!(verify_one_time_signature(&sig, &verifier, 0, 0, b""));
    }

    /// Two different messages produce different signatures.
    #[test]
    fn different_messages_different_sigs() {
        let secrets = OneTimeSignatureSecrets::generate(0, 5);
        let key_dilution = 10;

        let sig1 = secrets.sign(b"message1", 5, key_dilution);
        let sig2 = secrets.sign(b"message2", 5, key_dilution);

        // The sigs differ (different messages). When signing from an unexpanded
        // batch, Go generates a fresh random offset key per call, so pk will
        // also differ between calls for the same batch/offset.
        assert_ne!(sig1.sig, sig2.sig);
    }
}
