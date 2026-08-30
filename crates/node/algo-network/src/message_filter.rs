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
//!
//! # Bucket count
//!
//! Go's `messageFilter` (`network/messageFilter.go:33`) is a ring of
//! `bucketsCount` buckets (`makeMessageFilter(bucketsCount, maxBucketSize)`),
//! not a fixed current/previous pair — [`MessageFilter::new`] takes the same
//! two parameters and generalizes the ring-eviction logic accordingly
//! (issue #768 wired `config.Local`'s `Incoming`/`OutgoingMessageFilterBucketCount`/
//! `Size` fields into this constructor, which previously hardcoded a
//! single 2-bucket current/previous pair sized off an unrelated constant —
//! see [`MESSAGE_FILTER_SIZE`]'s doc comment). A `bucket_count` of `2`
//! reproduces the prior current/previous behavior exactly, since rotation
//! is just "advance the ring pointer by one slot, clearing that slot".

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
/// Matches Go's `messageFilterSize` in `network/wsNetwork.go` — a
/// large-message notification threshold, **not** a bucket-size default (the
/// two are unrelated in go despite algod-rust previously conflating them:
/// this constant used to be passed directly as `MessageFilter::new`'s sole
/// bucket-capacity argument before issue #768 wired the real
/// `IncomingMessageFilterBucketCount`/`Size` config fields through instead).
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
/// Internally maintains a ring of `bucket_count` hash-set "buckets". When
/// the current (top) bucket reaches capacity, the ring pointer advances to
/// the next (oldest) slot and that slot is cleared, becoming the new
/// current bucket — go's `messageFilter.CheckDigest` eviction policy
/// (`network/messageFilter.go:57-79`).
///
/// Thread-safe: all mutable state is behind an internal [`Mutex`].
pub struct MessageFilter {
    inner: Mutex<FilterInner>,
}

struct FilterInner {
    /// Ring of buckets; `buckets[current_top_bucket]` is the one new
    /// entries are inserted into.
    buckets: Vec<HashSet<[u8; 32]>>,
    /// Maximum number of entries per bucket before auto-rotation.
    max_bucket_size: usize,
    /// Index into `buckets` of the current (newest) bucket.
    current_top_bucket: usize,
    /// Random nonce prepended when computing incoming-message digests.
    nonce: [u8; 16],
}

impl MessageFilter {
    /// Create a new `MessageFilter` with `bucket_count` ring buckets, each
    /// capped at `max_bucket_size` entries. Matches go's
    /// `makeMessageFilter(bucketsCount, maxBucketSize)`.
    ///
    /// `bucket_count` is clamped to at least `1` — a zero-bucket ring has
    /// nowhere to insert into and would make every check_digest an
    /// instant auto-rotation of an empty ring.
    pub fn new(bucket_count: usize, max_bucket_size: usize) -> Self {
        let bucket_count = bucket_count.max(1);
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut buckets = Vec::with_capacity(bucket_count);
        buckets.push(HashSet::with_capacity(max_bucket_size));
        for _ in 1..bucket_count {
            buckets.push(HashSet::new());
        }
        Self {
            inner: Mutex::new(FilterInner {
                buckets,
                max_bucket_size,
                current_top_bucket: 0,
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
    /// - If `promote` is `true` and the message was found in an **older**
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

        let found_idx = Self::find(&inner, digest);

        if !add {
            return found_idx.is_some();
        }

        let current = inner.current_top_bucket;
        match found_idx {
            None => {
                // Not seen — insert into the current bucket.
                inner.buckets[current].insert(*digest);
            }
            Some(idx) if promote && idx != current => {
                // Promote from an older bucket to current.
                inner.buckets[idx].remove(digest);
                inner.buckets[current].insert(*digest);
            }
            Some(_) => {}
        }

        // Auto-rotate if the current bucket reached capacity — go:
        // `f.currentTopBucket = (f.currentTopBucket + len(f.buckets) - 1) %
        // len(f.buckets)`, then clear the new current bucket.
        if inner.buckets[current].len() >= inner.max_bucket_size {
            Self::advance_ring(&mut inner);
        }

        found_idx.is_some()
    }

    /// Manually advance the ring by one slot, clearing the new current
    /// bucket — go's rotation step in isolation, exposed for callers that
    /// want to force a rotation independent of reaching capacity (mirrors
    /// the previous `rotate()` entry point).
    pub fn rotate(&self) {
        let mut inner = self.inner.lock().unwrap();
        Self::advance_ring(&mut inner);
    }

    /// Find which bucket (if any) currently holds `digest`. Go's `find`
    /// (`network/messageFilter.go:88-96`) walks every bucket in the ring;
    /// order doesn't affect correctness here since a digest lives in at
    /// most one bucket at a time.
    fn find(inner: &FilterInner, digest: &[u8; 32]) -> Option<usize> {
        inner.buckets.iter().position(|b| b.contains(digest))
    }

    /// Internal ring-advance (caller holds the lock): the current slot
    /// becomes the *oldest* live slot and the previously-oldest slot (one
    /// step back in the ring) becomes the new, empty current slot.
    fn advance_ring(inner: &mut FilterInner) {
        let len = inner.buckets.len();
        inner.current_top_bucket = (inner.current_top_bucket + len - 1) % len;
        inner.buckets[inner.current_top_bucket] = HashSet::with_capacity(inner.max_bucket_size);
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
    fn with_nonce(bucket_count: usize, max_bucket_size: usize, nonce: [u8; 16]) -> Self {
        let bucket_count = bucket_count.max(1);
        let mut buckets = Vec::with_capacity(bucket_count);
        buckets.push(HashSet::with_capacity(max_bucket_size));
        for _ in 1..bucket_count {
            buckets.push(HashSet::new());
        }
        Self {
            inner: Mutex::new(FilterInner {
                buckets,
                max_bucket_size,
                current_top_bucket: 0,
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
        let filter = MessageFilter::new(2, 1024);
        let tag = Tag::Transaction;
        let data = b"hello world";

        // First check — not seen yet.
        assert!(!filter.check_incoming_message(&tag, data, true, false));
        // Second check — now it should be seen.
        assert!(filter.check_incoming_message(&tag, data, false, false));
    }

    #[test]
    fn check_without_add_does_not_insert() {
        let filter = MessageFilter::new(2, 1024);
        let tag = Tag::Transaction;
        let data = b"payload";

        // Check without add=true should not insert.
        assert!(!filter.check_incoming_message(&tag, data, false, false));
        // Still not present.
        assert!(!filter.check_incoming_message(&tag, data, false, false));
    }

    #[test]
    fn promotion_from_previous_to_current() {
        let filter = MessageFilter::new(2, 1024);
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
        let filter = MessageFilter::new(2, 1024);
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
        let filter = MessageFilter::new(2, 1024);
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
        let filter_a = MessageFilter::with_nonce(2, 1024, nonce_a);
        let filter_b = MessageFilter::with_nonce(2, 1024, nonce_b);

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
        let filter = MessageFilter::new(2, 1024);
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
        let filter = MessageFilter::new(2, 1024);
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
        let filter = MessageFilter::new(2, 2);

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

    // --- N-bucket ring generalization (issue #768) ------------------------

    #[test]
    fn three_bucket_ring_evicts_after_two_rotations_not_one() {
        // With 3 buckets, an item survives one rotation (moves from
        // current into the ring) but is evicted only after enough
        // rotations to cycle back to its slot — unlike the 2-bucket case
        // where a single rotation already exposes it to eviction on the
        // next one.
        let filter = MessageFilter::new(3, 1024);
        let digest = generate_message_digest(&Tag::Transaction, b"three-bucket-item");

        assert!(!filter.check_digest(&digest, true, false));
        filter.rotate();
        assert!(
            filter.check_digest(&digest, false, false),
            "still present after 1 rotation of 3"
        );
        filter.rotate();
        assert!(
            filter.check_digest(&digest, false, false),
            "still present after 2 rotations of 3"
        );
        filter.rotate();
        assert!(
            !filter.check_digest(&digest, false, false),
            "evicted after the 3rd rotation wraps back to its bucket"
        );
    }

    #[test]
    fn bucket_count_is_clamped_to_at_least_one() {
        // A configured bucket count of 0 must not panic or produce a
        // ring with nowhere to insert.
        let filter = MessageFilter::new(0, 4);
        let digest = generate_message_digest(&Tag::Transaction, b"zero-bucket-count");
        assert!(!filter.check_digest(&digest, true, false));
        assert!(filter.check_digest(&digest, false, false));
    }
}
