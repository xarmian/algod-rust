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
/// Matches Go's `OneTimeSignature` struct exactly. All fields are always
/// serialized (no omitempty), including `pk_sig_old` which is always zero
/// for new-style signatures but must be present for encoding conformance.
///
/// Verification chain:
/// 1. `pk2_sig`: master key signs `"OT1" || encode(BatchID{pk2, batch})`
/// 2. `pk1_sig`: `pk2` signs `"OT2" || encode(OffsetID{pk, batch, offset})`
/// 3. `sig`: `pk` signs the actual message
#[derive(Debug, Clone)]
pub struct OneTimeSignature {
    /// Signature of the message under the offset (ephemeral) key `pk`.
    /// Go: `Sig ed25519Signature`, codec:"s"
    pub sig: [u8; 64],
    /// Public key of the offset (ephemeral) key that signed the message.
    /// Go: `PK ed25519PublicKey`, codec:"p"
    pub pk: [u8; 32],
    /// Old-style signature, always zero for new keys but always serialized.
    /// Go: `PKSigOld ed25519Signature`, codec:"ps"
    pub pk_sig_old: [u8; 64],
    /// Public key of the batch subkey.
    /// Go: `PK2 ed25519PublicKey`, codec:"p2"
    pub pk2: [u8; 32],
    /// Signature of `OffsetID(pk, batch, offset)` under `pk2`.
    /// Go: `PK1Sig ed25519Signature`, codec:"p1s"
    pub pk1_sig: [u8; 64],
    /// Signature of `BatchID(pk2, batch)` under the master key.
    /// Go: `PK2Sig ed25519Signature`, codec:"p2s"
    pub pk2_sig: [u8; 64],
}

// ── Internal ephemeral subkey ──────────────────────────────────────────────

/// An ephemeral subkey with its signing key and the signatures authenticating it.
///
/// Matches Go's `ephemeralSubkey` struct exactly:
/// ```go
/// type ephemeralSubkey struct {
///     _struct  struct{}           `codec:""`
///     PK       ed25519PublicKey   // codec:"PK"  - [32]byte
///     SK       ed25519PrivateKey  // codec:"SK"  - [64]byte (seed || public)
///     PKSigOld ed25519Signature  // codec:"PKSig" - [64]byte, always zero for new keys
///     PKSigNew ed25519Signature  // codec:"sig2"  - [64]byte, new auth signature
/// }
/// ```
///
/// All 4 fields are always serialized (no omitempty) because of `codec:""`.
#[derive(Clone)]
struct EphemeralSubkey {
    /// Ed25519 public key. Go: `PK ed25519PublicKey`, codec:"PK"
    pk: [u8; 32],
    /// Ed25519 private key in Go's 64-byte format: `seed(32) || public_key(32)`.
    /// Go: `SK ed25519PrivateKey`, codec:"SK"
    sk: [u8; 64],
    /// Old-style auth signature, always zero for new keys but always serialized.
    /// Go: `PKSigOld ed25519Signature`, codec:"PKSig"
    pk_sig_old: [u8; 64],
    /// New-style auth signature (domain-separated).
    /// Go: `PKSigNew ed25519Signature`, codec:"sig2"
    pk_sig_new: [u8; 64],
}

impl EphemeralSubkey {
    /// Reconstruct an `ed25519_dalek::SigningKey` from the first 32 bytes (seed) of `sk`.
    fn signing_key(&self) -> SigningKey {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&self.sk[..32]);
        SigningKey::from_bytes(&seed)
    }

    /// Construct an `EphemeralSubkey` from an `ed25519_dalek::SigningKey`,
    /// expanding it to Go's 64-byte `seed || public` format.
    fn from_signing_key(key: &SigningKey, pk_sig_new: [u8; 64]) -> Self {
        let pk = key.verifying_key().to_bytes();
        let mut sk = [0u8; 64];
        sk[..32].copy_from_slice(key.to_bytes().as_ref());
        sk[32..].copy_from_slice(&pk);
        EphemeralSubkey {
            pk,
            sk,
            pk_sig_old: [0u8; 64],
            pk_sig_new,
        }
    }
}

impl Drop for EphemeralSubkey {
    fn drop(&mut self) {
        self.pk.zeroize();
        self.sk.zeroize();
        self.pk_sig_old.zeroize();
        self.pk_sig_new.zeroize();
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

    /// When deserialized from msgpack, the master private key is not available.
    /// This field stores the master public key (verifier) so that `verifier()`
    /// returns the correct value even after deserialization.
    restored_verifier: Option<[u8; 32]>,

    /// `true` when this struct was deserialized from msgpack. The `master`
    /// field contains a zeroed `SigningKey` and MUST NOT be used for signing.
    /// Any future code path that would use `master` to sign (e.g., generating
    /// new batch subkeys) must check this flag and error/panic.
    is_restored: bool,
}

impl Drop for OneTimeSignatureSecrets {
    fn drop(&mut self) {
        // `self.master` (SigningKey) implements `ZeroizeOnDrop` (via the
        // `zeroize` feature of ed25519-dalek) and is automatically zeroized
        // when this struct is dropped.
        // Batch and offset `EphemeralSubkey` vecs are zeroized via their own `Drop` impls
        // when each element is dropped. Explicitly clear to ensure they run now.
        self.batches.clear();
        self.offsets.clear();
        self.offsets_pk2.zeroize();
        self.offsets_pk2_sig.zeroize();
        if let Some(ref mut v) = self.restored_verifier {
            v.zeroize();
        }
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

            batches.push(EphemeralSubkey::from_signing_key(
                &batch_key,
                sig.to_bytes(),
            ));
        }

        OneTimeSignatureSecrets {
            master,
            batches,
            first_batch: start_batch,
            offsets: Vec::new(),
            first_offset: 0,
            offsets_pk2: [0u8; 32],
            offsets_pk2_sig: [0u8; 64],
            restored_verifier: None,
            is_restored: false,
        }
    }

    /// Access the master signing key, asserting that it is available.
    ///
    /// Currently unused but provided as the canonical guarded accessor for any
    /// future code path that needs the master key for signing (e.g., generating
    /// new batch subkeys at runtime).
    ///
    /// # Panics
    ///
    /// Panics (debug builds) if this instance was deserialized from msgpack,
    /// because the master private key is not persisted and the `master` field
    /// contains a zeroed dummy key.
    #[allow(dead_code)]
    fn master_for_signing(&self) -> &SigningKey {
        debug_assert!(
            !self.is_restored,
            "cannot use master key on restored secrets"
        );
        &self.master
    }

    /// Return the master public key (the `OneTimeSignatureVerifier`).
    ///
    /// If this struct was deserialized from msgpack, the restored verifier
    /// (which was explicitly stored in the persistent format) is returned.
    /// Otherwise, we derive it from the master signing key.
    pub fn verifier(&self) -> [u8; 32] {
        if let Some(v) = self.restored_verifier {
            v
        } else {
            self.master.verifying_key().to_bytes()
        }
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

            let signing_key = offset_subkey.signing_key();
            let sig = signing_key.sign(msg);

            return OneTimeSignature {
                sig: sig.to_bytes(),
                pk: offset_subkey.pk,
                pk_sig_old: [0u8; 64],
                pk2: self.offsets_pk2,
                pk1_sig: offset_subkey.pk_sig_new,
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
        let batch_signing_key = batch_subkey.signing_key();
        let offset_msg = offset_id_message(&offset_pk, batch, offset);
        let pk1_sig = batch_signing_key.sign(&offset_msg);

        OneTimeSignature {
            sig: sig.to_bytes(),
            pk: offset_pk,
            pk_sig_old: [0u8; 64],
            pk2: batch_subkey.pk,
            pk1_sig: pk1_sig.to_bytes(),
            pk2_sig: batch_subkey.pk_sig_new,
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
        self.offsets_pk2 = batch_subkey.pk;
        self.offsets_pk2_sig = batch_subkey.pk_sig_new;

        let batch_signing_key = batch_subkey.signing_key();
        self.first_offset = current_offset;
        let mut new_offsets = Vec::with_capacity((key_dilution - current_offset) as usize);
        for off in current_offset..key_dilution {
            let offset_key = random_signing_key();
            let offset_pk = offset_key.verifying_key().to_bytes();

            // Batch key signs OffsetID(offset_pk, current_batch, off).
            let offset_msg = offset_id_message(&offset_pk, current_batch, off);
            let pk1_sig = batch_signing_key.sign(&offset_msg);

            new_offsets.push(EphemeralSubkey::from_signing_key(
                &offset_key,
                pk1_sig.to_bytes(),
            ));
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

    /// Returns `true` if this struct was deserialized from msgpack.
    ///
    /// When restored, the master private key is NOT available. The struct
    /// can still sign using pre-existing batch/offset subkeys, but cannot
    /// generate new batch subkeys (which would require the master key).
    pub fn is_restored(&self) -> bool {
        self.is_restored
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

// ── Canonical msgpack serialization ────────────────────────────────────────
//
// These functions encode/decode `OneTimeSignatureSecrets` in the same format
// as Go's `OneTimeSignatureSecretsPersistent` (msgp-generated code).
//
// Key points from Go's generated MarshalMsg:
// - `ephemeralSubkey` uses `codec:""` (non-omitempty): all 4 fields always present
// - `OneTimeSignatureSecretsPersistent` uses `codec:",omitempty,omitemptyarray"`
// - The embedded `OneTimeSignatureVerifier` gets the key `"OneTimeSignatureVerifier"`
// - Only the master PUBLIC key is serialized (no private key)

/// Helper: write a msgpack fixstr.
fn write_fixstr(buf: &mut Vec<u8>, s: &str) {
    assert!(s.len() <= 31, "fixstr supports up to 31 bytes");
    buf.push(0xa0 | s.len() as u8);
    buf.extend_from_slice(s.as_bytes());
}

/// Encode an `EphemeralSubkey` in Go's canonical msgpack format.
///
/// NON-omitempty: all 4 fields always serialized, even when zero.
/// Keys sorted alphabetically: `"PK"`, `"PKSig"`, `"SK"`, `"sig2"`.
///
/// ```text
/// fixmap(4)
///   fixstr("PK")    -> bin(32 bytes)
///   fixstr("PKSig") -> bin(64 bytes)
///   fixstr("SK")    -> bin(64 bytes)
///   fixstr("sig2")  -> bin(64 bytes)
/// ```
fn encode_ephemeral_subkey(subkey: &EphemeralSubkey) -> Vec<u8> {
    let mut buf = Vec::with_capacity(240);
    // fixmap(4)
    buf.push(0x84);
    // "PK" -> bin(32)
    write_fixstr(&mut buf, "PK");
    rmp::encode::write_bin(&mut buf, &subkey.pk).unwrap();
    // "PKSig" -> bin(64)
    write_fixstr(&mut buf, "PKSig");
    rmp::encode::write_bin(&mut buf, &subkey.pk_sig_old).unwrap();
    // "SK" -> bin(64)
    write_fixstr(&mut buf, "SK");
    rmp::encode::write_bin(&mut buf, &subkey.sk).unwrap();
    // "sig2" -> bin(64)
    write_fixstr(&mut buf, "sig2");
    rmp::encode::write_bin(&mut buf, &subkey.pk_sig_new).unwrap();
    buf
}

/// Decode an `EphemeralSubkey` from canonical msgpack bytes.
fn decode_ephemeral_subkey(data: &[u8]) -> Result<(EphemeralSubkey, &[u8]), String> {
    let mut cur = data;

    // Read map header
    let (map_len, rest) =
        read_map_header(cur).map_err(|e| format!("ephemeral subkey map header: {e}"))?;
    cur = rest;

    let mut pk = [0u8; 32];
    let mut sk = [0u8; 64];
    let mut pk_sig_old = [0u8; 64];
    let mut pk_sig_new = [0u8; 64];

    let mut seen_pk = false;
    let mut seen_sk = false;
    let mut seen_pk_sig = false;
    let mut seen_sig2 = false;

    for _ in 0..map_len {
        let (key, rest) = read_str(cur).map_err(|e| format!("ephemeral subkey key: {e}"))?;
        cur = rest;

        match key {
            "PK" => {
                let (val, rest) = read_bin(cur).map_err(|e| format!("ephemeral subkey PK: {e}"))?;
                if val.len() != 32 {
                    return Err(format!("PK: expected 32 bytes, got {}", val.len()));
                }
                pk.copy_from_slice(val);
                seen_pk = true;
                cur = rest;
            }
            "SK" => {
                let (val, rest) = read_bin(cur).map_err(|e| format!("ephemeral subkey SK: {e}"))?;
                if val.len() != 64 {
                    return Err(format!("SK: expected 64 bytes, got {}", val.len()));
                }
                sk.copy_from_slice(val);
                seen_sk = true;
                cur = rest;
            }
            "PKSig" => {
                let (val, rest) =
                    read_bin(cur).map_err(|e| format!("ephemeral subkey PKSig: {e}"))?;
                if val.len() != 64 {
                    return Err(format!("PKSig: expected 64 bytes, got {}", val.len()));
                }
                pk_sig_old.copy_from_slice(val);
                seen_pk_sig = true;
                cur = rest;
            }
            "sig2" => {
                let (val, rest) =
                    read_bin(cur).map_err(|e| format!("ephemeral subkey sig2: {e}"))?;
                if val.len() != 64 {
                    return Err(format!("sig2: expected 64 bytes, got {}", val.len()));
                }
                pk_sig_new.copy_from_slice(val);
                seen_sig2 = true;
                cur = rest;
            }
            other => {
                // Skip unknown fields
                let rest = skip_msgpack_value(cur)
                    .map_err(|e| format!("skip unknown field '{other}': {e}"))?;
                cur = rest;
            }
        }
    }

    if !seen_pk {
        return Err("ephemeral subkey missing required field 'PK'".to_string());
    }
    if !seen_sk {
        return Err("ephemeral subkey missing required field 'SK'".to_string());
    }
    if !seen_pk_sig {
        return Err("ephemeral subkey missing required field 'PKSig'".to_string());
    }
    if !seen_sig2 {
        return Err("ephemeral subkey missing required field 'sig2'".to_string());
    }

    Ok((
        EphemeralSubkey {
            pk,
            sk,
            pk_sig_old,
            pk_sig_new,
        },
        cur,
    ))
}

// ── Msgpack decoding helpers ──────────────────────────────────────────────

/// Read a msgpack map header, returning (length, remaining_bytes).
fn read_map_header(data: &[u8]) -> Result<(u32, &[u8]), String> {
    if data.is_empty() {
        return Err("unexpected end of input".to_string());
    }
    let b = data[0];
    if b & 0xf0 == 0x80 {
        // fixmap
        Ok(((b & 0x0f) as u32, &data[1..]))
    } else if b == 0xde {
        // map16
        if data.len() < 3 {
            return Err("map16: unexpected end".to_string());
        }
        let len = u16::from_be_bytes([data[1], data[2]]) as u32;
        Ok((len, &data[3..]))
    } else if b == 0xdf {
        // map32
        if data.len() < 5 {
            return Err("map32: unexpected end".to_string());
        }
        let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        Ok((len, &data[5..]))
    } else {
        Err(format!("expected map header, got 0x{b:02x}"))
    }
}

/// Read a msgpack array header, returning (length, remaining_bytes).
fn read_array_header(data: &[u8]) -> Result<(u32, &[u8]), String> {
    if data.is_empty() {
        return Err("unexpected end of input".to_string());
    }
    let b = data[0];
    if b & 0xf0 == 0x90 {
        // fixarray
        Ok(((b & 0x0f) as u32, &data[1..]))
    } else if b == 0xdc {
        // array16
        if data.len() < 3 {
            return Err("array16: unexpected end".to_string());
        }
        let len = u16::from_be_bytes([data[1], data[2]]) as u32;
        Ok((len, &data[3..]))
    } else if b == 0xdd {
        // array32
        if data.len() < 5 {
            return Err("array32: unexpected end".to_string());
        }
        let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        Ok((len, &data[5..]))
    } else {
        Err(format!("expected array header, got 0x{b:02x}"))
    }
}

/// Read a msgpack string, returning (&str, remaining_bytes).
fn read_str(data: &[u8]) -> Result<(&str, &[u8]), String> {
    if data.is_empty() {
        return Err("unexpected end of input".to_string());
    }
    let b = data[0];
    let (len, rest) = if b & 0xe0 == 0xa0 {
        // fixstr
        ((b & 0x1f) as usize, &data[1..])
    } else if b == 0xd9 {
        // str8
        if data.len() < 2 {
            return Err("str8: unexpected end".to_string());
        }
        (data[1] as usize, &data[2..])
    } else if b == 0xda {
        // str16
        if data.len() < 3 {
            return Err("str16: unexpected end".to_string());
        }
        (u16::from_be_bytes([data[1], data[2]]) as usize, &data[3..])
    } else {
        return Err(format!("expected string, got 0x{b:02x}"));
    };
    if rest.len() < len {
        return Err("string: unexpected end".to_string());
    }
    let s = std::str::from_utf8(&rest[..len]).map_err(|e| format!("invalid utf8: {e}"))?;
    Ok((s, &rest[len..]))
}

/// Read a msgpack binary blob, returning (&[u8], remaining_bytes).
fn read_bin(data: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if data.is_empty() {
        return Err("unexpected end of input".to_string());
    }
    let b = data[0];
    let (len, rest) = if b == 0xc4 {
        // bin8
        if data.len() < 2 {
            return Err("bin8: unexpected end".to_string());
        }
        (data[1] as usize, &data[2..])
    } else if b == 0xc5 {
        // bin16
        if data.len() < 3 {
            return Err("bin16: unexpected end".to_string());
        }
        (u16::from_be_bytes([data[1], data[2]]) as usize, &data[3..])
    } else if b == 0xc6 {
        // bin32
        if data.len() < 5 {
            return Err("bin32: unexpected end".to_string());
        }
        (
            u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize,
            &data[5..],
        )
    } else {
        return Err(format!("expected bin, got 0x{b:02x}"));
    };
    if rest.len() < len {
        return Err("bin: unexpected end".to_string());
    }
    Ok((&rest[..len], &rest[len..]))
}

/// Read a msgpack uint64 (compact encoding).
fn read_uint64(data: &[u8]) -> Result<(u64, &[u8]), String> {
    if data.is_empty() {
        return Err("unexpected end of input".to_string());
    }
    let b = data[0];
    if b <= 0x7f {
        // positive fixint
        Ok((b as u64, &data[1..]))
    } else if b == 0xcc {
        // uint8
        if data.len() < 2 {
            return Err("uint8: unexpected end".to_string());
        }
        Ok((data[1] as u64, &data[2..]))
    } else if b == 0xcd {
        // uint16
        if data.len() < 3 {
            return Err("uint16: unexpected end".to_string());
        }
        Ok((u16::from_be_bytes([data[1], data[2]]) as u64, &data[3..]))
    } else if b == 0xce {
        // uint32
        if data.len() < 5 {
            return Err("uint32: unexpected end".to_string());
        }
        Ok((
            u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as u64,
            &data[5..],
        ))
    } else if b == 0xcf {
        // uint64
        if data.len() < 9 {
            return Err("uint64: unexpected end".to_string());
        }
        Ok((
            u64::from_be_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ]),
            &data[9..],
        ))
    } else {
        Err(format!("expected uint, got 0x{b:02x}"))
    }
}

/// Skip a single msgpack value (any type), returning the remaining bytes.
///
/// Returns `Err` on truncated or malformed input — never panics.
fn skip_msgpack_value(data: &[u8]) -> Result<&[u8], String> {
    if data.is_empty() {
        return Err("unexpected end of input".to_string());
    }
    let b = data[0];
    match b {
        // positive fixint / negative fixint
        0x00..=0x7f | 0xe0..=0xff => Ok(&data[1..]),
        // nil, false, true
        0xc0 | 0xc2 | 0xc3 => Ok(&data[1..]),
        // bin8
        0xc4 => {
            if data.len() < 2 {
                return Err("skip bin8: unexpected end".to_string());
            }
            let len = data[1] as usize;
            if data.len() < 2 + len {
                return Err("skip bin8: payload truncated".to_string());
            }
            Ok(&data[2 + len..])
        }
        // bin16
        0xc5 => {
            if data.len() < 3 {
                return Err("skip bin16: unexpected end".to_string());
            }
            let len = u16::from_be_bytes([data[1], data[2]]) as usize;
            if data.len() < 3 + len {
                return Err("skip bin16: payload truncated".to_string());
            }
            Ok(&data[3 + len..])
        }
        // bin32
        0xc6 => {
            if data.len() < 5 {
                return Err("skip bin32: unexpected end".to_string());
            }
            let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            if data.len() < 5 + len {
                return Err("skip bin32: payload truncated".to_string());
            }
            Ok(&data[5 + len..])
        }
        // float32
        0xca => {
            if data.len() < 5 {
                return Err("skip float32: unexpected end".to_string());
            }
            Ok(&data[5..])
        }
        // float64
        0xcb => {
            if data.len() < 9 {
                return Err("skip float64: unexpected end".to_string());
            }
            Ok(&data[9..])
        }
        // uint8 / int8
        0xcc | 0xd0 => {
            if data.len() < 2 {
                return Err("skip uint8/int8: unexpected end".to_string());
            }
            Ok(&data[2..])
        }
        // uint16 / int16
        0xcd | 0xd1 => {
            if data.len() < 3 {
                return Err("skip uint16/int16: unexpected end".to_string());
            }
            Ok(&data[3..])
        }
        // uint32 / int32
        0xce | 0xd2 => {
            if data.len() < 5 {
                return Err("skip uint32/int32: unexpected end".to_string());
            }
            Ok(&data[5..])
        }
        // uint64 / int64
        0xcf | 0xd3 => {
            if data.len() < 9 {
                return Err("skip uint64/int64: unexpected end".to_string());
            }
            Ok(&data[9..])
        }
        // fixstr
        b if b & 0xe0 == 0xa0 => {
            let len = (b & 0x1f) as usize;
            if data.len() < 1 + len {
                return Err("skip fixstr: payload truncated".to_string());
            }
            Ok(&data[1 + len..])
        }
        // str8
        0xd9 => {
            if data.len() < 2 {
                return Err("skip str8: unexpected end".to_string());
            }
            let len = data[1] as usize;
            if data.len() < 2 + len {
                return Err("skip str8: payload truncated".to_string());
            }
            Ok(&data[2 + len..])
        }
        // str16
        0xda => {
            if data.len() < 3 {
                return Err("skip str16: unexpected end".to_string());
            }
            let len = u16::from_be_bytes([data[1], data[2]]) as usize;
            if data.len() < 3 + len {
                return Err("skip str16: payload truncated".to_string());
            }
            Ok(&data[3 + len..])
        }
        // str32
        0xdb => {
            if data.len() < 5 {
                return Err("skip str32: unexpected end".to_string());
            }
            let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            if data.len() < 5 + len {
                return Err("skip str32: payload truncated".to_string());
            }
            Ok(&data[5 + len..])
        }
        // fixarray
        b if b & 0xf0 == 0x90 => {
            let count = (b & 0x0f) as usize;
            let mut cur = &data[1..];
            for _ in 0..count {
                cur = skip_msgpack_value(cur)?;
            }
            Ok(cur)
        }
        // array16
        0xdc => {
            if data.len() < 3 {
                return Err("skip array16: unexpected end".to_string());
            }
            let count = u16::from_be_bytes([data[1], data[2]]) as usize;
            let mut cur = &data[3..];
            for _ in 0..count {
                cur = skip_msgpack_value(cur)?;
            }
            Ok(cur)
        }
        // array32
        0xdd => {
            if data.len() < 5 {
                return Err("skip array32: unexpected end".to_string());
            }
            let count = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            let mut cur = &data[5..];
            for _ in 0..count {
                cur = skip_msgpack_value(cur)?;
            }
            Ok(cur)
        }
        // fixmap
        b if b & 0xf0 == 0x80 => {
            let count = (b & 0x0f) as usize;
            let mut cur = &data[1..];
            for _ in 0..count {
                cur = skip_msgpack_value(cur)?; // key
                cur = skip_msgpack_value(cur)?; // value
            }
            Ok(cur)
        }
        // map16
        0xde => {
            if data.len() < 3 {
                return Err("skip map16: unexpected end".to_string());
            }
            let count = u16::from_be_bytes([data[1], data[2]]) as usize;
            let mut cur = &data[3..];
            for _ in 0..count {
                cur = skip_msgpack_value(cur)?; // key
                cur = skip_msgpack_value(cur)?; // value
            }
            Ok(cur)
        }
        // map32
        0xdf => {
            if data.len() < 5 {
                return Err("skip map32: unexpected end".to_string());
            }
            let count = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            let mut cur = &data[5..];
            for _ in 0..count {
                cur = skip_msgpack_value(cur)?; // key
                cur = skip_msgpack_value(cur)?; // value
            }
            Ok(cur)
        }
        _ => Err(format!("skip: unsupported msgpack type 0x{b:02x}")),
    }
}

impl OneTimeSignatureSecrets {
    /// Encode to canonical msgpack matching Go's `OneTimeSignatureSecretsPersistent`.
    ///
    /// Only the master PUBLIC key (verifier) is serialized — the master private
    /// key is NOT included, matching Go's persistence format.
    ///
    /// Fields (omitempty, sorted alphabetically by codec tag):
    /// - `"First"` → first_batch (u64)
    /// - `"OneTimeSignatureVerifier"` → verifier ([32]byte)
    /// - `"Sub"` → batches array
    /// - `"firstoff"` → first_offset (u64)
    /// - `"offkeys"` → offsets array
    /// - `"offpk2"` → offsets_pk2 ([32]byte)
    /// - `"offpk2sig"` → offsets_pk2_sig ([64]byte)
    pub fn to_msgpack(&self) -> Vec<u8> {
        // Collect non-empty fields in alphabetical order by codec tag.
        // Go's generated code uses omitempty: skip zero u64, empty arrays, zero byte arrays.
        let mut fields: Vec<(&str, Vec<u8>)> = Vec::new();

        // "First" -> first_batch
        if self.first_batch != 0 {
            let mut buf = Vec::new();
            rmp::encode::write_uint(&mut buf, self.first_batch).unwrap();
            fields.push(("First", buf));
        }

        // "OneTimeSignatureVerifier" -> verifier (master public key)
        let verifier = self.verifier();
        if verifier.iter().any(|&b| b != 0) {
            let mut buf = Vec::new();
            rmp::encode::write_bin(&mut buf, &verifier).unwrap();
            fields.push(("OneTimeSignatureVerifier", buf));
        }

        // "Sub" -> batches array
        if !self.batches.is_empty() {
            let mut buf = Vec::new();
            rmp::encode::write_array_len(&mut buf, self.batches.len() as u32).unwrap();
            for subkey in &self.batches {
                buf.extend_from_slice(&encode_ephemeral_subkey(subkey));
            }
            fields.push(("Sub", buf));
        }

        // "firstoff" -> first_offset
        if self.first_offset != 0 {
            let mut buf = Vec::new();
            rmp::encode::write_uint(&mut buf, self.first_offset).unwrap();
            fields.push(("firstoff", buf));
        }

        // "offkeys" -> offsets array
        if !self.offsets.is_empty() {
            let mut buf = Vec::new();
            rmp::encode::write_array_len(&mut buf, self.offsets.len() as u32).unwrap();
            for subkey in &self.offsets {
                buf.extend_from_slice(&encode_ephemeral_subkey(subkey));
            }
            fields.push(("offkeys", buf));
        }

        // "offpk2" -> offsets_pk2
        if self.offsets_pk2.iter().any(|&b| b != 0) {
            let mut buf = Vec::new();
            rmp::encode::write_bin(&mut buf, &self.offsets_pk2).unwrap();
            fields.push(("offpk2", buf));
        }

        // "offpk2sig" -> offsets_pk2_sig
        if self.offsets_pk2_sig.iter().any(|&b| b != 0) {
            let mut buf = Vec::new();
            rmp::encode::write_bin(&mut buf, &self.offsets_pk2_sig).unwrap();
            fields.push(("offpk2sig", buf));
        }

        // Fields are already in alphabetical order, but sort to be safe.
        fields.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

        let mut out = Vec::new();
        // Use fixmap if <= 15 entries (always true here, max 7 fields)
        out.push(0x80 | fields.len() as u8);
        for (key, val) in &fields {
            // Write the key as a msgpack string.
            // "OneTimeSignatureVerifier" is 24 bytes, fits in fixstr (up to 31 bytes).
            if key.len() <= 31 {
                write_fixstr(&mut out, key);
            } else {
                rmp::encode::write_str(&mut out, key).unwrap();
            }
            out.extend_from_slice(val);
        }
        out
    }

    /// Decode from canonical msgpack in Go's `OneTimeSignatureSecretsPersistent` format.
    ///
    /// Since the master private key is NOT in the persistent format, we create a
    /// zeroed `SigningKey` for the `master` field. The restored secrets can still
    /// sign using batch/offset subkeys (which contain their own `SK` fields), but
    /// cannot generate NEW batch subkeys (which would require the master private key).
    ///
    /// The `verifier()` method will return the correct master public key because
    /// we store it in a way that can be recovered. However, since `ed25519_dalek::SigningKey`
    /// derives the public key from the seed, we store the deserialized verifier separately
    /// and override `verifier()` behavior via a flag.
    pub fn from_msgpack(data: &[u8]) -> Result<Self, String> {
        let (map_len, mut cur) =
            read_map_header(data).map_err(|e| format!("OTS map header: {e}"))?;

        let mut verifier = [0u8; 32];
        let mut first_batch = 0u64;
        let mut batches: Vec<EphemeralSubkey> = Vec::new();
        let mut first_offset = 0u64;
        let mut offsets: Vec<EphemeralSubkey> = Vec::new();
        let mut offsets_pk2 = [0u8; 32];
        let mut offsets_pk2_sig = [0u8; 64];

        for _ in 0..map_len {
            let (key, rest) = read_str(cur).map_err(|e| format!("OTS field key: {e}"))?;
            cur = rest;

            match key {
                "First" => {
                    let (val, rest) = read_uint64(cur).map_err(|e| format!("OTS First: {e}"))?;
                    first_batch = val;
                    cur = rest;
                }
                "OneTimeSignatureVerifier" => {
                    let (val, rest) = read_bin(cur).map_err(|e| format!("OTS verifier: {e}"))?;
                    if val.len() != 32 {
                        return Err(format!("verifier: expected 32 bytes, got {}", val.len()));
                    }
                    verifier.copy_from_slice(val);
                    cur = rest;
                }
                "Sub" => {
                    let (arr_len, rest) =
                        read_array_header(cur).map_err(|e| format!("OTS Sub header: {e}"))?;
                    cur = rest;
                    batches = Vec::with_capacity(arr_len as usize);
                    for i in 0..arr_len {
                        let (subkey, rest) = decode_ephemeral_subkey(cur)
                            .map_err(|e| format!("OTS Sub[{i}]: {e}"))?;
                        batches.push(subkey);
                        cur = rest;
                    }
                }
                "firstoff" => {
                    let (val, rest) = read_uint64(cur).map_err(|e| format!("OTS firstoff: {e}"))?;
                    first_offset = val;
                    cur = rest;
                }
                "offkeys" => {
                    let (arr_len, rest) =
                        read_array_header(cur).map_err(|e| format!("OTS offkeys header: {e}"))?;
                    cur = rest;
                    offsets = Vec::with_capacity(arr_len as usize);
                    for i in 0..arr_len {
                        let (subkey, rest) = decode_ephemeral_subkey(cur)
                            .map_err(|e| format!("OTS offkeys[{i}]: {e}"))?;
                        offsets.push(subkey);
                        cur = rest;
                    }
                }
                "offpk2" => {
                    let (val, rest) = read_bin(cur).map_err(|e| format!("OTS offpk2: {e}"))?;
                    if val.len() != 32 {
                        return Err(format!("offpk2: expected 32 bytes, got {}", val.len()));
                    }
                    offsets_pk2.copy_from_slice(val);
                    cur = rest;
                }
                "offpk2sig" => {
                    let (val, rest) = read_bin(cur).map_err(|e| format!("OTS offpk2sig: {e}"))?;
                    if val.len() != 64 {
                        return Err(format!("offpk2sig: expected 64 bytes, got {}", val.len()));
                    }
                    offsets_pk2_sig.copy_from_slice(val);
                    cur = rest;
                }
                other => {
                    cur = skip_msgpack_value(cur)
                        .map_err(|e| format!("OTS skip unknown field '{other}': {e}"))?;
                }
            }
        }

        // Create a dummy master SigningKey from zeroed seed.
        // The actual verifier (master public key) is stored in `restored_verifier`.
        // After deserialization, sign() still works via batch/offset subkeys.
        let master = SigningKey::from_bytes(&[0u8; 32]);

        Ok(OneTimeSignatureSecrets {
            master,
            batches,
            first_batch,
            offsets,
            first_offset,
            offsets_pk2,
            offsets_pk2_sig,
            restored_verifier: Some(verifier),
            is_restored: true,
        })
    }
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

    /// Verify that the 64-byte SK format is `seed(32) || public_key(32)`,
    /// matching Go's `ed25519PrivateKey` layout.
    #[test]
    fn ephemeral_subkey_sk_64byte_format() {
        let key = random_signing_key();
        let pk = key.verifying_key().to_bytes();
        let subkey = EphemeralSubkey::from_signing_key(&key, [0xAA; 64]);

        // First 32 bytes of sk should be the seed
        assert_eq!(&subkey.sk[..32], key.to_bytes().as_ref());
        // Last 32 bytes of sk should be the public key
        assert_eq!(&subkey.sk[32..], &pk);
        // pk field should match
        assert_eq!(subkey.pk, pk);
        // pk_sig_old should be zero
        assert_eq!(subkey.pk_sig_old, [0u8; 64]);
        // pk_sig_new should be what we passed in
        assert_eq!(subkey.pk_sig_new, [0xAA; 64]);
    }

    /// Verify that `from_signing_key` -> `signing_key()` roundtrips correctly.
    #[test]
    fn ephemeral_subkey_from_signing_key_roundtrip() {
        let original_key = random_signing_key();
        let sig_bytes = [0x42; 64];
        let subkey = EphemeralSubkey::from_signing_key(&original_key, sig_bytes);

        // Reconstruct the signing key from the stored 64-byte sk
        let recovered_key = subkey.signing_key();

        // The recovered key should produce the same public key
        assert_eq!(
            recovered_key.verifying_key().to_bytes(),
            original_key.verifying_key().to_bytes()
        );

        // The recovered key should produce valid signatures
        let msg = b"roundtrip test";
        let sig = recovered_key.sign(msg);
        let vk = recovered_key.verifying_key();
        assert!(vk.verify(msg, &sig).is_ok());

        // The recovered key's seed bytes should match the original
        assert_eq!(recovered_key.to_bytes(), original_key.to_bytes());
    }

    /// Verify that `OneTimeSignature.pk_sig_old` is always zero.
    #[test]
    fn one_time_signature_pk_sig_old_is_zero() {
        let secrets = OneTimeSignatureSecrets::generate(0, 5);
        let key_dilution = 10;

        // Sign from unexpanded batch
        let sig1 = secrets.sign(b"test1", 5, key_dilution);
        assert_eq!(sig1.pk_sig_old, [0u8; 64]);

        // Sign from expanded offsets
        let mut secrets2 = OneTimeSignatureSecrets::generate(0, 5);
        secrets2.delete_before(0, key_dilution);
        let sig2 = secrets2.sign(b"test2", 3, key_dilution);
        assert_eq!(sig2.pk_sig_old, [0u8; 64]);
    }

    // ── Serialization tests ────────────────────────────────────────────────

    /// Encode → decode roundtrip preserves all fields.
    #[test]
    fn msgpack_roundtrip_basic() {
        let secrets = OneTimeSignatureSecrets::generate(5, 3);
        let verifier_before = secrets.verifier();
        let first_batch_before = secrets.first_batch();
        let num_batches_before = secrets.num_batches();

        let encoded = secrets.to_msgpack();
        let restored = OneTimeSignatureSecrets::from_msgpack(&encoded).unwrap();

        assert_eq!(restored.verifier(), verifier_before);
        assert_eq!(restored.first_batch(), first_batch_before);
        assert_eq!(restored.num_batches(), num_batches_before);
        assert_eq!(restored.num_offsets(), 0);
        assert_eq!(restored.first_offset(), 0);
    }

    /// After encode → decode, sign() produces valid signatures that verify() accepts.
    #[test]
    fn msgpack_roundtrip_sign_and_verify() {
        let secrets = OneTimeSignatureSecrets::generate(0, 5);
        let verifier = secrets.verifier();
        let key_dilution = 10;

        let encoded = secrets.to_msgpack();
        let restored = OneTimeSignatureSecrets::from_msgpack(&encoded).unwrap();

        // Sign using restored secrets (from batch subkeys)
        let sig = restored.sign(b"roundtrip msg", 15, key_dilution);
        assert!(verify_one_time_signature(
            &sig,
            &verifier,
            1,
            5,
            b"roundtrip msg"
        ));
    }

    /// After encode → decode, verifier() returns the correct master public key.
    #[test]
    fn msgpack_roundtrip_verifier() {
        let secrets = OneTimeSignatureSecrets::generate(0, 3);
        let original_verifier = secrets.verifier();

        let encoded = secrets.to_msgpack();
        let restored = OneTimeSignatureSecrets::from_msgpack(&encoded).unwrap();

        assert_eq!(restored.verifier(), original_verifier);
    }

    /// After delete_before → encode → decode, the trimmed state is preserved.
    #[test]
    fn msgpack_roundtrip_after_delete_before() {
        let mut secrets = OneTimeSignatureSecrets::generate(0, 10);
        let verifier = secrets.verifier();
        let key_dilution = 4;

        // Expand batch 0 into offsets, advance to offset 2
        secrets.delete_before(2, key_dilution);

        let first_batch_before = secrets.first_batch();
        let num_batches_before = secrets.num_batches();
        let num_offsets_before = secrets.num_offsets();
        let first_offset_before = secrets.first_offset();

        let encoded = secrets.to_msgpack();
        let restored = OneTimeSignatureSecrets::from_msgpack(&encoded).unwrap();

        assert_eq!(restored.verifier(), verifier);
        assert_eq!(restored.first_batch(), first_batch_before);
        assert_eq!(restored.num_batches(), num_batches_before);
        assert_eq!(restored.num_offsets(), num_offsets_before);
        assert_eq!(restored.first_offset(), first_offset_before);

        // Sign from restored offset subkeys (batch 0, offset 2)
        let sig = restored.sign(b"after delete", 2, key_dilution);
        assert!(verify_one_time_signature(
            &sig,
            &verifier,
            0,
            2,
            b"after delete"
        ));

        // Sign from restored batch subkeys (batch 2)
        let sig2 = restored.sign(b"batch key", 8, key_dilution);
        assert!(verify_one_time_signature(
            &sig2,
            &verifier,
            2,
            0,
            b"batch key"
        ));
    }

    /// encode_ephemeral_subkey always writes all 4 fields, even when pk_sig_old is zero.
    #[test]
    fn encode_ephemeral_subkey_always_writes_all_fields() {
        let subkey = EphemeralSubkey {
            pk: [0u8; 32],
            sk: [0u8; 64],
            pk_sig_old: [0u8; 64], // zero
            pk_sig_new: [0u8; 64], // zero
        };
        let encoded = encode_ephemeral_subkey(&subkey);

        // Should start with fixmap(4)
        assert_eq!(encoded[0], 0x84, "expected fixmap(4)");

        // Decode it back and verify all fields round-trip
        let (decoded, rest) = decode_ephemeral_subkey(&encoded).unwrap();
        assert!(rest.is_empty(), "should consume all bytes");
        assert_eq!(decoded.pk, [0u8; 32]);
        assert_eq!(decoded.sk, [0u8; 64]);
        assert_eq!(decoded.pk_sig_old, [0u8; 64]);
        assert_eq!(decoded.pk_sig_new, [0u8; 64]);
    }

    /// Encoded format has correct msgpack structure (map lengths, key ordering).
    #[test]
    fn encode_ephemeral_subkey_correct_structure() {
        let subkey = EphemeralSubkey {
            pk: [0xAA; 32],
            sk: [0xBB; 64],
            pk_sig_old: [0xCC; 64],
            pk_sig_new: [0xDD; 64],
        };
        let encoded = encode_ephemeral_subkey(&subkey);

        // fixmap(4)
        assert_eq!(encoded[0], 0x84);

        // Verify key ordering by finding each key in sequence
        let mut pos = 1;
        // Key 1: "PK" (0xa2, 'P', 'K')
        assert_eq!(&encoded[pos..pos + 3], &[0xa2, b'P', b'K']);
        pos += 3;
        // bin8(32) = 0xc4, 0x20
        assert_eq!(&encoded[pos..pos + 2], &[0xc4, 32]);
        pos += 2 + 32;

        // Key 2: "PKSig" (0xa5, 'P', 'K', 'S', 'i', 'g')
        assert_eq!(
            &encoded[pos..pos + 6],
            &[0xa5, b'P', b'K', b'S', b'i', b'g']
        );
        pos += 6;
        // bin8(64) = 0xc4, 0x40
        assert_eq!(&encoded[pos..pos + 2], &[0xc4, 64]);
        pos += 2 + 64;

        // Key 3: "SK" (0xa2, 'S', 'K')
        assert_eq!(&encoded[pos..pos + 3], &[0xa2, b'S', b'K']);
        pos += 3;
        assert_eq!(&encoded[pos..pos + 2], &[0xc4, 64]);
        pos += 2 + 64;

        // Key 4: "sig2" (0xa4, 's', 'i', 'g', '2')
        assert_eq!(&encoded[pos..pos + 5], &[0xa4, b's', b'i', b'g', b'2']);
        pos += 5;
        assert_eq!(&encoded[pos..pos + 2], &[0xc4, 64]);
        pos += 2 + 64;

        assert_eq!(pos, encoded.len(), "should have consumed all bytes");
    }

    /// Ephemeral subkey roundtrip with non-zero values.
    #[test]
    fn ephemeral_subkey_encode_decode_roundtrip() {
        let key = random_signing_key();
        let subkey = EphemeralSubkey::from_signing_key(&key, [0x42; 64]);

        let encoded = encode_ephemeral_subkey(&subkey);
        let (decoded, rest) = decode_ephemeral_subkey(&encoded).unwrap();

        assert!(rest.is_empty());
        assert_eq!(decoded.pk, subkey.pk);
        assert_eq!(decoded.sk, subkey.sk);
        assert_eq!(decoded.pk_sig_old, subkey.pk_sig_old);
        assert_eq!(decoded.pk_sig_new, subkey.pk_sig_new);
    }

    /// to_msgpack produces a valid map with correct field ordering.
    #[test]
    fn to_msgpack_field_ordering() {
        let secrets = OneTimeSignatureSecrets::generate(5, 3);
        let encoded = secrets.to_msgpack();

        // First byte should be a fixmap
        assert!(encoded[0] & 0xf0 == 0x80, "expected fixmap");

        let map_len = (encoded[0] & 0x0f) as usize;
        // With first_batch=5, non-zero verifier, and 3 batches, we should have
        // at least 3 fields: "First", "OneTimeSignatureVerifier", "Sub"
        assert!(map_len >= 3, "expected at least 3 fields, got {map_len}");

        // Verify field ordering by reading keys
        let mut cur = &encoded[1..];
        let mut keys = Vec::new();
        for _ in 0..map_len {
            let (key, rest) = read_str(cur).unwrap();
            keys.push(key.to_string());
            cur = rest;
            // Skip the value
            cur = skip_msgpack_value(cur).unwrap();
        }

        // Keys should be sorted alphabetically
        let mut sorted_keys = keys.clone();
        sorted_keys.sort();
        assert_eq!(keys, sorted_keys, "keys should be in alphabetical order");
    }

    /// Empty secrets (no batches, no offsets) encode to a minimal map.
    #[test]
    fn msgpack_empty_secrets() {
        let mut secrets = OneTimeSignatureSecrets::generate(0, 1);
        let key_dilution = 10;

        // Delete everything
        secrets.delete_before(100, key_dilution);
        assert_eq!(secrets.num_batches(), 0);
        assert_eq!(secrets.num_offsets(), 0);

        let encoded = secrets.to_msgpack();
        let restored = OneTimeSignatureSecrets::from_msgpack(&encoded).unwrap();

        assert_eq!(restored.verifier(), secrets.verifier());
        assert_eq!(restored.num_batches(), 0);
        assert_eq!(restored.num_offsets(), 0);
    }

    /// Double roundtrip: encode → decode → encode produces identical bytes.
    #[test]
    fn msgpack_double_roundtrip_deterministic() {
        let secrets = OneTimeSignatureSecrets::generate(3, 5);

        let encoded1 = secrets.to_msgpack();
        let restored = OneTimeSignatureSecrets::from_msgpack(&encoded1).unwrap();
        let encoded2 = restored.to_msgpack();

        assert_eq!(
            encoded1, encoded2,
            "double roundtrip should be deterministic"
        );
    }

    /// Double roundtrip with offsets: encode → decode → encode produces identical bytes.
    #[test]
    fn msgpack_double_roundtrip_with_offsets() {
        let mut secrets = OneTimeSignatureSecrets::generate(0, 5);
        let key_dilution = 4;

        // Create some offset subkeys
        secrets.delete_before(2, key_dilution);

        let encoded1 = secrets.to_msgpack();
        let restored = OneTimeSignatureSecrets::from_msgpack(&encoded1).unwrap();
        let encoded2 = restored.to_msgpack();

        assert_eq!(
            encoded1, encoded2,
            "double roundtrip with offsets should be deterministic"
        );
    }

    // ── Negative deserialization tests ────────────────────────────────────

    /// `from_msgpack` rejects empty input.
    #[test]
    fn from_msgpack_empty_input() {
        let err = OneTimeSignatureSecrets::from_msgpack(&[]).err().unwrap();
        assert!(err.contains("unexpected end"), "got: {err}");
    }

    /// `from_msgpack` rejects truncated input (map header present but fields missing).
    #[test]
    fn from_msgpack_truncated_input() {
        // fixmap(2) with no key-value pairs following
        assert!(OneTimeSignatureSecrets::from_msgpack(&[0x82]).is_err());
    }

    /// `from_msgpack` rejects non-map type at top level.
    #[test]
    fn from_msgpack_wrong_type() {
        // 0x91 is fixarray(1), not a map
        let err = OneTimeSignatureSecrets::from_msgpack(&[0x91, 0x00])
            .err()
            .unwrap();
        assert!(err.contains("expected map"), "got: {err}");
    }

    // ── skip_msgpack_value robustness tests ──────────────────────────────

    /// `skip_msgpack_value` returns Err on truncated bin8 payload.
    #[test]
    fn skip_msgpack_value_truncated_bin8() {
        // bin8 header says 10 bytes but only 2 bytes of data follow
        let data = [0xc4, 10, 0x00, 0x00];
        let result = skip_msgpack_value(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("truncated"));
    }

    /// `skip_msgpack_value` returns Err on truncated fixstr payload.
    #[test]
    fn skip_msgpack_value_truncated_fixstr() {
        // fixstr(5) but only 2 bytes of data follow
        let data = [0xa5, b'h', b'i'];
        let result = skip_msgpack_value(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("truncated"));
    }

    /// `skip_msgpack_value` returns Err on truncated float32.
    #[test]
    fn skip_msgpack_value_truncated_float32() {
        // float32 needs 5 bytes total, only 3 given
        let data = [0xca, 0x00, 0x00];
        let result = skip_msgpack_value(&data);
        assert!(result.is_err());
    }

    /// `skip_msgpack_value` returns Err on truncated uint64.
    #[test]
    fn skip_msgpack_value_truncated_uint64() {
        // uint64 needs 9 bytes total, only 5 given
        let data = [0xcf, 0x00, 0x00, 0x00, 0x00];
        let result = skip_msgpack_value(&data);
        assert!(result.is_err());
    }

    // ── delete_before on restored secrets ────────────────────────────────

    /// Serialize secrets to msgpack, deserialize, run `delete_before` on the
    /// restored copy, and verify signing still works for remaining keys.
    #[test]
    fn delete_before_on_restored_secrets() {
        let key_dilution = 4u64;
        let secrets = OneTimeSignatureSecrets::generate(0, 5);
        let verifier = secrets.verifier();

        // Serialize and deserialize (round-trip through msgpack).
        let blob = secrets.to_msgpack();
        let mut restored = OneTimeSignatureSecrets::from_msgpack(&blob).unwrap();
        assert!(restored.is_restored());

        // Delete keys before round 8 (batch 2, offset 0).
        restored.delete_before(8, key_dilution);

        // Should be able to sign round 8 (batch 2, offset 0).
        let sig = restored.sign(b"restored signing", 8, key_dilution);
        assert!(verify_one_time_signature(
            &sig,
            &verifier,
            2,
            0,
            b"restored signing"
        ));

        // Should also be able to sign round 9 (batch 2, offset 1).
        let sig = restored.sign(b"restored signing 2", 9, key_dilution);
        assert!(verify_one_time_signature(
            &sig,
            &verifier,
            2,
            1,
            b"restored signing 2"
        ));

        // Re-serialize after delete_before and restore again.
        let blob2 = restored.to_msgpack();
        let restored2 = OneTimeSignatureSecrets::from_msgpack(&blob2).unwrap();

        // Should still be able to sign round 10 (batch 2, offset 2).
        let sig = restored2.sign(b"double restored", 10, key_dilution);
        assert!(verify_one_time_signature(
            &sig,
            &verifier,
            2,
            2,
            b"double restored"
        ));
    }

    // ── from_msgpack wrong-length blob rejection ─────────────────────────

    /// `from_msgpack` rejects a verifier blob that is not exactly 32 bytes.
    #[test]
    fn from_msgpack_wrong_length_verifier_31() {
        // Build a minimal msgpack map with a 31-byte verifier.
        let mut data = Vec::new();
        data.push(0x81); // fixmap(1)
        write_fixstr(&mut data, "OneTimeSignatureVerifier");
        rmp::encode::write_bin(&mut data, &[0u8; 31]).unwrap();
        let err = OneTimeSignatureSecrets::from_msgpack(&data).err().unwrap();
        assert!(err.contains("expected 32 bytes"), "got: {err}");
    }

    #[test]
    fn from_msgpack_wrong_length_verifier_33() {
        let mut data = Vec::new();
        data.push(0x81); // fixmap(1)
        write_fixstr(&mut data, "OneTimeSignatureVerifier");
        rmp::encode::write_bin(&mut data, &[0u8; 33]).unwrap();
        let err = OneTimeSignatureSecrets::from_msgpack(&data).err().unwrap();
        assert!(err.contains("expected 32 bytes"), "got: {err}");
    }

    /// `from_msgpack` rejects a subkey with wrong-length PK (not 32 bytes).
    #[test]
    fn from_msgpack_wrong_length_pk_in_subkey() {
        // Build a map with Sub array containing one subkey with 31-byte PK.
        let mut data = Vec::new();
        data.push(0x81); // fixmap(1)
        write_fixstr(&mut data, "Sub");
        rmp::encode::write_array_len(&mut data, 1).unwrap();
        // subkey map with 1 field: PK = 31 bytes
        data.push(0x81); // fixmap(1)
        write_fixstr(&mut data, "PK");
        rmp::encode::write_bin(&mut data, &[0u8; 31]).unwrap();
        let err = OneTimeSignatureSecrets::from_msgpack(&data).err().unwrap();
        assert!(err.contains("expected 32 bytes"), "got: {err}");
    }

    /// `from_msgpack` rejects a subkey with wrong-length SK (not 64 bytes).
    #[test]
    fn from_msgpack_wrong_length_sk_in_subkey() {
        // Build a map with Sub array containing one subkey with 63-byte SK.
        let mut data = Vec::new();
        data.push(0x81); // fixmap(1)
        write_fixstr(&mut data, "Sub");
        rmp::encode::write_array_len(&mut data, 1).unwrap();
        // subkey map with 1 field: SK = 63 bytes
        data.push(0x81); // fixmap(1)
        write_fixstr(&mut data, "SK");
        rmp::encode::write_bin(&mut data, &[0u8; 63]).unwrap();
        let err = OneTimeSignatureSecrets::from_msgpack(&data).err().unwrap();
        assert!(err.contains("expected 64 bytes"), "got: {err}");
    }

    /// Decoding an ephemeral subkey blob missing a required field must fail.
    #[test]
    fn decode_ephemeral_subkey_missing_field_rejected() {
        // Build a subkey map with 3 fields (missing "SK")
        let mut data = Vec::new();
        // fixmap(3)
        data.push(0x83);
        // "PK" -> bin(32)
        write_fixstr(&mut data, "PK");
        rmp::encode::write_bin(&mut data, &[0xAAu8; 32]).unwrap();
        // "PKSig" -> bin(64)
        write_fixstr(&mut data, "PKSig");
        rmp::encode::write_bin(&mut data, &[0xBBu8; 64]).unwrap();
        // "sig2" -> bin(64)
        write_fixstr(&mut data, "sig2");
        rmp::encode::write_bin(&mut data, &[0xCCu8; 64]).unwrap();

        match decode_ephemeral_subkey(&data) {
            Ok(_) => panic!("expected error for missing SK field, got Ok"),
            Err(err) => assert!(
                err.contains("missing required field 'SK'"),
                "expected missing-SK error, got: {err}"
            ),
        }
    }
}
