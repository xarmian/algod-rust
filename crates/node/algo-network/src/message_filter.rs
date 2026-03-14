//! Digest-based seen-message cache for deduplication.
//!
//! Mirrors Go's `network/messageFilter.go` — a bucketed filter that tracks
//! SHA-512/256 digests of recently seen messages to avoid processing duplicates.
//! Go's `crypto.Hash()` uses `sha512.Sum512_256()`, so we use the `Sha512_256`
//! hasher from the `sha2` crate.
//!
//! Two usage patterns:
//! - **Incoming filter**: uses a per-filter random nonce prepended before
//!   hashing so that different nodes produce different digest spaces (prevents
//!   collision attacks). See [`MessageFilter::check_incoming_message`].
//! - **Outgoing filter**: uses [`generate_message_digest`] which omits the
//!   nonce, producing a digest that is consistent across all peers.

use std::collections::HashSet;
use std::sync::Mutex;

use rand::RngCore;
use sha2::{Digest as _, Sha512_256};

use crate::tag::Tag;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Messages with encoded length greater than this threshold trigger a
/// `MsgDigestSkip` notification to peers, telling them "I already have this".
///
/// Matches Go's `messageFilterSize` in `network/wsNetwork.go`.
pub const MESSAGE_FILTER_SIZE: usize = 5000;

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

/// Compute the SHA-512/256 digest of `tag || data` **without** a nonce.
///
/// This is the digest format used for outgoing-filter notifications
/// (`MsgDigestSkip` messages) and must be consistent across all peers.
///
/// Mirrors Go's `generateMessageDigest()` which uses `crypto.Hash()`
/// (SHA-512/256).
pub fn generate_message_digest(tag: &Tag, data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512_256::new();
    hasher.update(tag.as_bytes());
    hasher.update(data);
    hasher.finalize().into()
}

/// Returns `true` if the given tag represents a message type that is safe to
/// deduplicate on receipt.
///
/// In Go (`dedupSafeTag` in `wsPeer.go`), only `AV` (AgreementVote) and `TX`
/// (Transaction) are considered safe for dedup.
pub fn dedup_safe_tag(tag: &Tag) -> bool {
    matches!(tag, Tag::AgreementVote | Tag::Transaction)
}

// ---------------------------------------------------------------------------
// MessageFilter
// ---------------------------------------------------------------------------

/// A bucketed seen-message filter.
///
/// Internally maintains two hash-set "buckets" (current and previous). When the
/// current bucket reaches capacity it is rotated: the old previous bucket is
/// dropped, the current becomes previous, and a fresh empty bucket becomes
/// current.
///
/// Thread-safe: all mutable state is behind an internal [`Mutex`].
pub struct MessageFilter {
    inner: Mutex<FilterInner>,
}

struct FilterInner {
    /// Two buckets: index 0 = current, index 1 = previous.
    current: HashSet<[u8; 32]>,
    previous: HashSet<[u8; 32]>,
    /// Maximum number of entries per bucket before auto-rotation.
    max_bucket_size: usize,
    /// Random nonce prepended when computing incoming-message digests.
    nonce: [u8; 16],
}

impl MessageFilter {
    /// Create a new `MessageFilter` with the given per-bucket capacity.
    pub fn new(capacity: usize) -> Self {
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        Self {
            inner: Mutex::new(FilterInner {
                current: HashSet::with_capacity(capacity),
                previous: HashSet::new(),
                max_bucket_size: capacity,
                nonce,
            }),
        }
    }

    /// Check whether a message (identified by `tag` + `data`) has already been
    /// seen by this filter.
    ///
    /// The digest is computed as `SHA-512/256(nonce || tag_bytes || data)`,
    /// making it specific to this filter instance (different nodes will have
    /// different nonces).
    ///
    /// - If `add` is `true` and the message was **not** previously seen, it is
    ///   inserted into the current bucket.
    /// - If `promote` is `true` and the message was found in the **previous**
    ///   bucket, it is moved to the current bucket.
    ///
    /// Returns `true` if the message was already present **before** this call.
    pub fn check_incoming_message(&self, tag: &Tag, data: &[u8], add: bool, promote: bool) -> bool {
        let inner = self.inner.lock().unwrap();
        let digest = Self::compute_incoming_digest(&inner.nonce, tag, data);
        drop(inner);
        self.check_digest(&digest, add, promote)
    }

    /// Check whether a pre-computed digest has already been seen.
    ///
    /// This is the entry point for the outgoing filter path where the digest
    /// has already been calculated via [`generate_message_digest`].
    ///
    /// Same `add` / `promote` semantics as [`check_incoming_message`].
    ///
    /// Returns `true` if the digest was already present **before** this call.
    pub fn check_digest(&self, digest: &[u8; 32], add: bool, promote: bool) -> bool {
        let mut inner = self.inner.lock().unwrap();

        let in_current = inner.current.contains(digest);
        let in_previous = inner.previous.contains(digest);
        let has = in_current || in_previous;

        if !add {
            return has;
        }

        if !has {
            // Not seen — insert into current bucket.
            inner.current.insert(*digest);
        } else if promote && in_previous && !in_current {
            // Promote from previous to current.
            inner.previous.remove(digest);
            inner.current.insert(*digest);
        }

        // Auto-rotate if the current bucket reached capacity.
        if inner.current.len() >= inner.max_bucket_size {
            Self::rotate_inner(&mut inner);
        }

        has
    }

    /// Manually rotate the buckets: current becomes previous, previous is
    /// cleared.
    pub fn rotate(&self) {
        let mut inner = self.inner.lock().unwrap();
        Self::rotate_inner(&mut inner);
    }

    /// Internal rotation (caller holds the lock).
    fn rotate_inner(inner: &mut FilterInner) {
        let old_current = std::mem::replace(
            &mut inner.current,
            HashSet::with_capacity(inner.max_bucket_size),
        );
        inner.previous = old_current;
    }

    /// Compute the incoming-message digest: `SHA-512/256(nonce || tag || data)`.
    fn compute_incoming_digest(nonce: &[u8; 16], tag: &Tag, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha512_256::new();
        hasher.update(nonce);
        hasher.update(tag.as_bytes());
        hasher.update(data);
        hasher.finalize().into()
    }

    // -- Test helpers --------------------------------------------------------

    /// Create a filter with a specific nonce (for deterministic tests).
    #[cfg(test)]
    fn with_nonce(capacity: usize, nonce: [u8; 16]) -> Self {
        Self {
            inner: Mutex::new(FilterInner {
                current: HashSet::with_capacity(capacity),
                previous: HashSet::new(),
                max_bucket_size: capacity,
                nonce,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_check() {
        let filter = MessageFilter::new(1024);
        let tag = Tag::Transaction;
        let data = b"hello world";

        // First check — not seen yet.
        assert!(!filter.check_incoming_message(&tag, data, true, false));
        // Second check — now it should be seen.
        assert!(filter.check_incoming_message(&tag, data, false, false));
    }

    #[test]
    fn check_without_add_does_not_insert() {
        let filter = MessageFilter::new(1024);
        let tag = Tag::Transaction;
        let data = b"payload";

        // Check without add=true should not insert.
        assert!(!filter.check_incoming_message(&tag, data, false, false));
        // Still not present.
        assert!(!filter.check_incoming_message(&tag, data, false, false));
    }

    #[test]
    fn promotion_from_previous_to_current() {
        let filter = MessageFilter::new(1024);
        let tag = Tag::AgreementVote;
        let data = b"vote-data";

        // Insert into current bucket.
        assert!(!filter.check_incoming_message(&tag, data, true, false));

        // Rotate — message moves to previous.
        filter.rotate();

        // Should still be found (in previous).
        assert!(filter.check_incoming_message(&tag, data, false, false));

        // Promote it back to current.
        assert!(filter.check_incoming_message(&tag, data, true, true));

        // Rotate again — message should still survive in previous.
        filter.rotate();
        assert!(filter.check_incoming_message(&tag, data, false, false));
    }

    #[test]
    fn bucket_rotation_preserves_previous() {
        let filter = MessageFilter::new(1024);
        let tag = Tag::Transaction;
        let data = b"tx-1";

        // Insert.
        assert!(!filter.check_incoming_message(&tag, data, true, false));

        // Rotate: current -> previous, new empty current.
        filter.rotate();

        // Still findable in previous.
        assert!(filter.check_incoming_message(&tag, data, false, false));
    }

    #[test]
    fn double_rotation_forgets_old_items() {
        let filter = MessageFilter::new(1024);
        let tag = Tag::Transaction;
        let data = b"will-be-forgotten";

        // Insert into current.
        assert!(!filter.check_incoming_message(&tag, data, true, false));

        // First rotation: current -> previous.
        filter.rotate();

        // Second rotation: previous is cleared, the item is gone.
        filter.rotate();

        // Not found anymore.
        assert!(!filter.check_incoming_message(&tag, data, false, false));
    }

    #[test]
    fn dedup_safe_tag_check() {
        assert!(dedup_safe_tag(&Tag::AgreementVote));
        assert!(dedup_safe_tag(&Tag::Transaction));
        assert!(!dedup_safe_tag(&Tag::ProposalPayload));
        assert!(!dedup_safe_tag(&Tag::MsgOfInterest));
        assert!(!dedup_safe_tag(&Tag::MsgDigestSkip));
        assert!(!dedup_safe_tag(&Tag::UniEnsBlockReq));
        assert!(!dedup_safe_tag(&Tag::VoteBundle));
        assert!(!dedup_safe_tag(&Tag::StateProofSig));
        assert!(!dedup_safe_tag(&Tag::NetPrioResponse));
        assert!(!dedup_safe_tag(&Tag::PingDeprecated));
    }

    #[test]
    fn generate_message_digest_deterministic() {
        let tag = Tag::Transaction;
        let data = b"some transaction data";

        let d1 = generate_message_digest(&tag, data);
        let d2 = generate_message_digest(&tag, data);
        assert_eq!(d1, d2);
    }

    #[test]
    fn generate_message_digest_different_inputs() {
        let d1 = generate_message_digest(&Tag::Transaction, b"data-a");
        let d2 = generate_message_digest(&Tag::Transaction, b"data-b");
        let d3 = generate_message_digest(&Tag::AgreementVote, b"data-a");
        assert_ne!(d1, d2);
        assert_ne!(d1, d3);
    }

    #[test]
    fn nonce_isolation_between_filters() {
        let nonce_a = [1u8; 16];
        let nonce_b = [2u8; 16];
        let filter_a = MessageFilter::with_nonce(1024, nonce_a);
        let filter_b = MessageFilter::with_nonce(1024, nonce_b);

        let tag = Tag::Transaction;
        let data = b"same-data";

        // Insert in filter_a.
        assert!(!filter_a.check_incoming_message(&tag, data, true, false));

        // Compute the digest manually for filter_a's nonce space.
        let digest_a = MessageFilter::compute_incoming_digest(&nonce_a, &tag, data);
        let digest_b = MessageFilter::compute_incoming_digest(&nonce_b, &tag, data);

        // Different nonces produce different digests.
        assert_ne!(digest_a, digest_b);

        // filter_b should NOT see the message (different nonce space).
        assert!(!filter_b.check_incoming_message(&tag, data, false, false));
    }

    #[test]
    fn check_digest_with_precomputed_digest() {
        let filter = MessageFilter::new(1024);
        let tag = Tag::Transaction;
        let data = b"outgoing-message";

        let digest = generate_message_digest(&tag, data);

        // Not seen initially.
        assert!(!filter.check_digest(&digest, false, false));

        // Add it.
        assert!(!filter.check_digest(&digest, true, false));

        // Now seen.
        assert!(filter.check_digest(&digest, false, false));
    }

    #[test]
    fn check_digest_promotion() {
        let filter = MessageFilter::new(1024);
        let digest = generate_message_digest(&Tag::Transaction, b"msg");

        // Insert.
        assert!(!filter.check_digest(&digest, true, false));

        // Rotate to move to previous.
        filter.rotate();

        // Promote back to current.
        assert!(filter.check_digest(&digest, true, true));

        // Rotate again — still in previous (was promoted to current, which is
        // now previous).
        filter.rotate();
        assert!(filter.check_digest(&digest, false, false));

        // One more rotate — now it should be gone.
        filter.rotate();
        assert!(!filter.check_digest(&digest, false, false));
    }

    #[test]
    fn auto_rotation_on_capacity() {
        // Capacity of 2: after inserting 2 items, the bucket auto-rotates.
        let filter = MessageFilter::new(2);

        let d1 = generate_message_digest(&Tag::Transaction, b"msg-1");
        let d2 = generate_message_digest(&Tag::Transaction, b"msg-2");
        let d3 = generate_message_digest(&Tag::Transaction, b"msg-3");

        // Insert first two — second insert triggers auto-rotation.
        assert!(!filter.check_digest(&d1, true, false));
        assert!(!filter.check_digest(&d2, true, false));
        // d2 triggered auto-rotation: d1 and d2 are now in previous.

        // Insert d3 into the new current bucket.
        assert!(!filter.check_digest(&d3, true, false));

        // d1 should still be findable (in previous).
        assert!(filter.check_digest(&d1, false, false));
        // d2 should still be findable (in previous).
        assert!(filter.check_digest(&d2, false, false));
        // d3 is in current.
        assert!(filter.check_digest(&d3, false, false));
    }

    #[test]
    fn message_filter_size_constant() {
        assert_eq!(MESSAGE_FILTER_SIZE, 5000);
    }

    #[test]
    fn filter_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MessageFilter>();
    }
}
