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

//! A cached store of recently verified transaction groups, mirroring go's
//! `VerifiedTransactionCache` (`data/transactions/verify/verifiedTxnCache.go`).
//!
//! The cache has two tiers. The bottom tier is a small ring of cyclic
//! buckets: once the current bucket fills past its capacity, the cache
//! rotates to the next bucket and discards whatever the bucket after that
//! held (a 3-bucket ring gives roughly 2 buckets' worth of live history at
//! any time, go's `entriesPerBucket = (cacheSize + 1) / 2`). The top tier is
//! a "pinned" map for transactions that made it into the transaction pool
//! and must not be evicted by cycling alone — only an explicit
//! [`VerifiedTransactionCache::update_pinned`] call (driven by pool
//! bookkeeping) removes a pinned entry.
//!
//! This module intentionally implements only the cache itself (issue
//! #947's `VerifiedTransactionCache`-equivalent half); wiring it into the
//! gossip/mempool-admission and block-verification hot paths, and the
//! `StreamToBatch`-equivalent async worker pool, are tracked separately —
//! see the issue for the full scope and the follow-up filed alongside this
//! change.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use algo_avm::group::GroupBudget;
use algo_codec::compute_txn_id;
use algo_error::AlgoError;
use algo_types::{Digest, SignedTransaction};

use crate::rules::{ConsensusParams, SpecialAddresses};
use crate::signature::verify_transaction_signature;

/// Number of cyclic buckets in the bottom cache tier (Go:
/// `len(v.buckets) == 3`, `verifiedTxnCache.go`'s `MakeVerifiedTransactionCache`).
const NUM_BUCKETS: usize = 3;

/// Maximum number of entries the pinned tier may hold before [`
/// VerifiedTransactionCache::pin`] starts refusing new pins (Go:
/// `maxPinnedEntries`, `verifiedTxnCache.go`). Reaching this in practice
/// would mean pinned entries aren't being retired as transactions leave the
/// pool.
const MAX_PINNED_ENTRIES: usize = 500_000;

/// Error returned by [`VerifiedTransactionCache`] bookkeeping operations,
/// mirroring go's `VerifiedTxnCacheError` (`verifiedTxnCache.go`) — kept
/// distinct from a general signature-verification error so callers can tell
/// "cache bookkeeping failed" apart from "the signature itself is bad."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedTxnCacheError {
    /// Go: `errTooManyPinnedEntries` — pinning would exceed
    /// [`MAX_PINNED_ENTRIES`].
    TooManyPinnedEntries,
    /// Go: `errMissingPinnedEntry` — a transaction referenced by `Pin` or
    /// `UpdatePinned` is not present anywhere in the cache (neither pinned
    /// nor in a bucket).
    MissingPinnedEntry,
}

impl fmt::Display for VerifiedTxnCacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifiedTxnCacheError::TooManyPinnedEntries => write!(f, "too many pinned entries"),
            VerifiedTxnCacheError::MissingPinnedEntry => write!(f, "missing pinned entry"),
        }
    }
}

impl std::error::Error for VerifiedTxnCacheError {}

/// The context under which a transaction group was verified: the block
/// header's special addresses and protocol version. Mirrors go's
/// `GroupContext{specAddrs, consensusVersion}` equality check (Go:
/// `GroupContext.Equal`, `data/transactions/verify/txn.go`) — a cached
/// "verified" entry is only trusted again when looked up under the
/// *identical* context, since the fee sink, rewards pool, or consensus
/// version can change which bytes are even well-formed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationContext {
    pub spec_addrs: SpecialAddresses,
    pub consensus_version: String,
}

/// A verified transaction group, together with the context it was verified
/// under. Mirrors go's `*GroupContext` as stored in the cache's buckets and
/// pinned map.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupContext {
    pub context: VerificationContext,
    pub signed_group_txns: Vec<SignedTransaction>,
}

impl GroupContext {
    pub fn new(context: VerificationContext, signed_group_txns: Vec<SignedTransaction>) -> Self {
        Self {
            context,
            signed_group_txns,
        }
    }
}

/// The mutable cache state, guarded by [`VerifiedTransactionCache`]'s mutex.
struct Inner {
    /// Number of entries allowed in each bucket before rotation (Go:
    /// `entriesPerBucket`).
    entries_per_bucket: usize,
    /// The circular cache buckets buffer (Go: `buckets`).
    buckets: Vec<HashMap<Digest, Arc<GroupContext>>>,
    /// The pinned transactions tier (Go: `pinned`).
    pinned: HashMap<Digest, Arc<GroupContext>>,
    /// Index into `buckets` where the next entry is written (Go: `base`).
    base: usize,
}

/// Search the bucket ring for `id`, starting at `base` and walking
/// backward (wrapping), matching go's `(base + len) % len` trick in
/// `GetUnverifiedTransactionGroups`/`Pin`/`UpdatePinned`. Returns the bucket
/// index the entry was found in (so callers can continue subsequent
/// per-transaction lookups from there, exactly like go's `baseBucket`
/// threading) and a clone of the cached group pointer.
fn find_in_buckets(
    buckets: &[HashMap<Digest, Arc<GroupContext>>],
    base: usize,
    id: &Digest,
) -> Option<(usize, Arc<GroupContext>)> {
    let n = buckets.len();
    for offset in 0..n {
        let bucket_idx = (base + n - offset) % n;
        if let Some(ctx) = buckets[bucket_idx].get(id) {
            return Some((bucket_idx, ctx.clone()));
        }
    }
    None
}

/// Add `group_ctx` to the currently-active bucket, rotating to the next
/// bucket first if it doesn't have room (Go: `verifiedTransactionCache.add`).
fn add_locked(inner: &mut Inner, group_ctx: Arc<GroupContext>) {
    if inner.buckets[inner.base].len() + group_ctx.signed_group_txns.len()
        > inner.entries_per_bucket
    {
        inner.base = (inner.base + 1) % inner.buckets.len();
        inner.buckets[inner.base] = HashMap::with_capacity(inner.entries_per_bucket);
    }
    for txn in &group_ctx.signed_group_txns {
        let id = compute_txn_id(&txn.txn);
        inner.buckets[inner.base].insert(id, group_ctx.clone());
    }
}

/// A cached store of recently verified transaction groups. See the module
/// docs for the two-tier (cyclic buckets + pinned) design this mirrors from
/// go's `verifiedTransactionCache`.
pub struct VerifiedTransactionCache {
    inner: Mutex<Inner>,
}

impl VerifiedTransactionCache {
    /// Create a cache sized for roughly `cache_size` non-pinned entries
    /// (spread across the bucket ring) plus up to [`MAX_PINNED_ENTRIES`]
    /// pinned entries. Mirrors go's `MakeVerifiedTransactionCache`.
    pub fn new(cache_size: usize) -> Self {
        let entries_per_bucket = cache_size.div_ceil(2);
        let buckets = (0..NUM_BUCKETS)
            .map(|_| HashMap::with_capacity(entries_per_bucket))
            .collect();
        VerifiedTransactionCache {
            inner: Mutex::new(Inner {
                entries_per_bucket,
                buckets,
                pinned: HashMap::with_capacity(cache_size),
                base: 0,
            }),
        }
    }

    /// Add a verified transaction group to the cache. If any of its
    /// transactions already appear in the cache, the new entry overrides
    /// the old one. Mirrors go's `Add`.
    pub fn add(&self, group_ctx: Arc<GroupContext>) {
        let mut inner = self
            .inner
            .lock()
            .expect("verified txn cache mutex poisoned");
        add_locked(&mut inner, group_ctx);
    }

    /// Add several transaction groups at once. Mirrors go's `AddPayset`.
    pub fn add_payset(&self, group_ctxs: &[Arc<GroupContext>]) {
        let mut inner = self
            .inner
            .lock()
            .expect("verified txn cache mutex poisoned");
        for group_ctx in group_ctxs {
            add_locked(&mut inner, group_ctx.clone());
        }
    }

    /// Compare `txn_groups` against the cache under `context` and return the
    /// subset of groups that are *not* fully covered by a cached entry —
    /// i.e. the groups that still need real signature verification. Mirrors
    /// go's `GetUnverifiedTransactionGroups`.
    ///
    /// A group counts as covered only when every one of its transactions is
    /// found (pinned or bucketed) under the same [`VerificationContext`],
    /// with authorization fields (`sig`/`msig`/`lsig`/`pqsig`/`auth_addr`)
    /// byte-identical to what's cached — the transaction ID alone doesn't
    /// cover the signature envelope, since the ID hashes only the txn body.
    pub fn get_unverified_transaction_groups(
        &self,
        txn_groups: &[Vec<SignedTransaction>],
        context: &VerificationContext,
    ) -> Vec<Vec<SignedTransaction>> {
        let inner = self
            .inner
            .lock()
            .expect("verified txn cache mutex poisoned");
        let mut unverified = Vec::with_capacity(txn_groups.len());

        for signed_txn_group in txn_groups {
            let mut verified_txn = 0usize;
            let mut base_bucket = inner.base;

            for (txn_idx, txn) in signed_txn_group.iter().enumerate() {
                let id = compute_txn_id(&txn.txn);

                // Check pinned first, then fall back to the bucket ring.
                let mut entry_group = inner.pinned.get(&id).cloned();
                if entry_group.is_none() {
                    if let Some((bucket_idx, ctx)) =
                        find_in_buckets(&inner.buckets, base_bucket, &id)
                    {
                        entry_group = Some(ctx);
                        base_bucket = bucket_idx;
                    }
                }

                let entry_group = match entry_group {
                    Some(e) => e,
                    None => break,
                };

                if entry_group.context != *context {
                    break;
                }

                let cached_txn = match entry_group.signed_group_txns.get(txn_idx) {
                    Some(t) => t,
                    None => break,
                };

                if cached_txn.sig != txn.sig
                    || cached_txn.msig != txn.msig
                    || cached_txn.lsig != txn.lsig
                    || cached_txn.pqsig != txn.pqsig
                    || cached_txn.auth_addr != txn.auth_addr
                {
                    break;
                }

                verified_txn += 1;
            }

            if verified_txn != signed_txn_group.len() || verified_txn == 0 {
                unverified.push(signed_txn_group.clone());
            }
        }

        unverified
    }

    /// Replace the pinned tier with the entries named by `pinned_txns`
    /// (typically a subset of what's already pinned). A transaction that
    /// isn't already pinned is looked up in the bucket ring instead; if
    /// it's found nowhere, [`VerifiedTxnCacheError::MissingPinnedEntry`] is
    /// returned (after still installing whatever *was* found — matching
    /// go's `UpdatePinned`, which always assigns `v.pinned = pinned` even on
    /// error). Mirrors go's `UpdatePinned`.
    pub fn update_pinned(
        &self,
        pinned_txns: &HashMap<Digest, SignedTransaction>,
    ) -> Result<(), VerifiedTxnCacheError> {
        let mut inner = self
            .inner
            .lock()
            .expect("verified txn cache mutex poisoned");
        let mut pinned = HashMap::with_capacity(pinned_txns.len());
        let mut err = None;

        for txid in pinned_txns.keys() {
            if let Some(entry) = inner.pinned.get(txid) {
                pinned.insert(*txid, entry.clone());
                continue;
            }

            let mut found = false;
            let n = inner.buckets.len();
            for offset in 0..n {
                let bucket_idx = (inner.base + n - offset) % n;
                if let Some(ctx) = inner.buckets[bucket_idx].get(txid) {
                    pinned.insert(*txid, ctx.clone());
                    found = true;
                    break;
                }
            }
            if !found {
                err = Some(VerifiedTxnCacheError::MissingPinnedEntry);
            }
        }

        inner.pinned = pinned;
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Mark `txgroup`'s transactions as pinned, moving them out of the
    /// bucket ring so bucket cycling can no longer evict them. Mirrors go's
    /// `Pin`.
    pub fn pin(&self, txgroup: &[SignedTransaction]) -> Result<(), VerifiedTxnCacheError> {
        let mut inner = self
            .inner
            .lock()
            .expect("verified txn cache mutex poisoned");

        if inner.pinned.len() + txgroup.len() > MAX_PINNED_ENTRIES {
            return Err(VerifiedTxnCacheError::TooManyPinnedEntries);
        }

        let mut transaction_missing = false;
        let mut base_bucket = inner.base;

        for txn in txgroup {
            let id = compute_txn_id(&txn.txn);
            if inner.pinned.contains_key(&id) {
                // Already pinned; keep going.
                continue;
            }

            if let Some((bucket_idx, ctx)) = find_in_buckets(&inner.buckets, base_bucket, &id) {
                inner.pinned.insert(id, ctx);
                inner.buckets[bucket_idx].remove(&id);
                base_bucket = bucket_idx;
            } else {
                transaction_missing = true;
            }
        }

        if transaction_missing {
            Err(VerifiedTxnCacheError::MissingPinnedEntry)
        } else {
            Ok(())
        }
    }
}

/// Verify `txgroup`'s signatures, consulting and updating `cache` exactly
/// like go's `TxnGroup` (`data/transactions/verify/txn.go`): a group that is
/// already fully covered by `cache` under the identical `context` skips real
/// signature verification entirely; otherwise every member is verified for
/// real, and the group is added to `cache` only once every member's
/// signature checks out (a partially- or fully-failed group is never
/// cached, so a later resubmission — e.g. with a corrected signature — is
/// verified for real rather than incorrectly trusted).
///
/// This is the single call site both the gossip/mempool-admission path
/// (`SimpleBlockEvaluator::validate_group_stateless_inner`,
/// `bin/algod-rust/src/commands/participate.rs`) and block verification
/// (`crate::block::validate_block`) should use once a
/// [`VerifiedTransactionCache`] is available, so the skip-on-cache-hit
/// behavior and the cache-population-on-success behavior stay in one place.
///
/// Like go's `TxnGroup`, an unexpected panic anywhere during verification
/// (e.g. a poisoned cache mutex from an earlier panic elsewhere) is caught
/// and converted into an ordinary `Err` rather than propagated to the
/// caller — this repo's gossip/mempool-admission and block-verification
/// callers process many independent, mutually-untrusted transaction groups
/// per call, and one group's internal bug must not take the whole batch (or
/// the calling task) down with it.
pub fn verify_transaction_group_cached(
    txgroup: &[SignedTransaction],
    context: &VerificationContext,
    consensus: &ConsensusParams,
    cache: &VerifiedTransactionCache,
) -> Result<(), AlgoError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_transaction_group_cached_inner(txgroup, context, consensus, cache)
    }))
    .unwrap_or_else(|payload| {
        let msg = payload
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic payload".to_string());
        Err(AlgoError::Validation {
            message: format!("panic while verifying transaction group: {msg}"),
        })
    })
}

fn verify_transaction_group_cached_inner(
    txgroup: &[SignedTransaction],
    context: &VerificationContext,
    consensus: &ConsensusParams,
    cache: &VerifiedTransactionCache,
) -> Result<(), AlgoError> {
    if txgroup.is_empty() {
        return Err(AlgoError::Validation {
            message: "empty transaction group".into(),
        });
    }

    let owned_group = txgroup.to_vec();
    let unverified =
        cache.get_unverified_transaction_groups(std::slice::from_ref(&owned_group), context);
    if unverified.is_empty() {
        // The whole group is already verified under this exact context.
        return Ok(());
    }

    let mut lsig_budget = GroupBudget::for_logicsig(txgroup.len());
    for (group_index, stx) in txgroup.iter().enumerate() {
        verify_transaction_signature(stx, txgroup, group_index, &mut lsig_budget, consensus)?;
    }

    cache.add(Arc::new(GroupContext::new(context.clone(), owned_group)));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::{Address, Round, Transaction};

    /// Build a minimal, uniquely-identified pay transaction: `note` is used
    /// purely to make transaction IDs distinct across a batch of otherwise
    /// identical fixtures.
    fn test_txn(note: u64) -> Transaction {
        Transaction {
            txn_type: "pay".into(),
            sender: Address([1u8; 32]),
            fee: 1000,
            first_valid: Round(1),
            last_valid: Round(1000),
            receiver: Address([0x42; 32]),
            amount: 100_000,
            note: serde_bytes::ByteBuf::from(note.to_be_bytes().to_vec()),
            ..Default::default()
        }
    }

    fn test_stxn(note: u64) -> SignedTransaction {
        SignedTransaction {
            txn: test_txn(note),
            sig: [note as u8; 64],
            ..Default::default()
        }
    }

    fn test_context() -> VerificationContext {
        VerificationContext {
            spec_addrs: SpecialAddresses::default(),
            consensus_version: "v41".to_string(),
        }
    }

    fn group_ctx(txns: Vec<SignedTransaction>) -> Arc<GroupContext> {
        Arc::new(GroupContext::new(test_context(), txns))
    }

    #[test]
    fn adding_to_cache_populates_current_bucket() {
        let cache = VerifiedTransactionCache::new(500);
        let stxn = test_stxn(1);
        let ctx = group_ctx(vec![stxn.clone()]);
        cache.add(ctx.clone());

        let inner = cache.inner.lock().unwrap();
        let id = compute_txn_id(&stxn.txn);
        let entry = inner.buckets[inner.base]
            .get(&id)
            .expect("txn should be in the active bucket");
        assert_eq!(entry.signed_group_txns, ctx.signed_group_txns);
    }

    #[test]
    fn bucket_cycling_rotates_and_clears_next_bucket() {
        let bucket_count = 3;
        let entries_per_bucket = 100;
        let cache = VerifiedTransactionCache::new(entries_per_bucket * (bucket_count - 1));

        // Fill up the cache with one-txn groups; the base index should
        // advance by one bucket every `entries_per_bucket` additions.
        for i in 0..(entries_per_bucket * bucket_count) {
            let ctx = group_ctx(vec![test_stxn(i as u64)]);
            cache.add(ctx);
            let inner = cache.inner.lock().unwrap();
            assert_eq!(inner.base, i / entries_per_bucket);
        }

        {
            let inner = cache.inner.lock().unwrap();
            for (idx, bucket) in inner.buckets.iter().enumerate() {
                assert_eq!(
                    bucket.len(),
                    entries_per_bucket,
                    "bucket {idx} doesn't contain expected number of entries; base = {}",
                    inner.base
                );
            }
        }

        // All buckets are full at this point; one more add rotates back to
        // bucket 0 and clears it down to just the new entry.
        let ctx = group_ctx(vec![test_stxn((entries_per_bucket * bucket_count) as u64)]);
        cache.add(ctx);
        let inner = cache.inner.lock().unwrap();
        assert_eq!(inner.base, 0);
        assert_eq!(inner.buckets[0].len(), 1);
    }

    #[test]
    fn get_unverified_transaction_groups_skips_cached_half() {
        let cache = VerifiedTransactionCache::new(600);
        let context = test_context();

        let mut all_groups = Vec::new();
        let mut expected_unverified = Vec::new();
        for i in 0..40u64 {
            let group = vec![test_stxn(i)];
            if i % 2 == 0 {
                expected_unverified.push(group.clone());
            } else {
                cache.add(group_ctx(group.clone()));
            }
            all_groups.push(group);
        }

        let unverified = cache.get_unverified_transaction_groups(&all_groups, &context);
        assert_eq!(unverified.len(), expected_unverified.len());
        assert_eq!(unverified, expected_unverified);
    }

    #[test]
    fn get_unverified_transaction_groups_rejects_mutated_signature() {
        let cache = VerifiedTransactionCache::new(10);
        let context = test_context();

        let stxn = test_stxn(7);
        cache.add(group_ctx(vec![stxn.clone()]));

        // Sanity: the original is recognized as verified (empty result).
        let unverified = cache.get_unverified_transaction_groups(&[vec![stxn.clone()]], &context);
        assert!(unverified.is_empty());

        // A transaction with the *same* txn body (hence the same ID, since
        // the ID hashes only the body) but a different `sig` byte must NOT
        // be treated as already-verified -- the ID alone doesn't cover the
        // authorization envelope.
        let mut mutated = stxn.clone();
        mutated.sig[0] ^= 1;
        let id_before = compute_txn_id(&stxn.txn);
        let id_after = compute_txn_id(&mutated.txn);
        assert_eq!(id_before, id_after, "note field, not sig, must vary the ID");

        let unverified =
            cache.get_unverified_transaction_groups(&[vec![mutated.clone()]], &context);
        assert_eq!(unverified, vec![vec![mutated]]);
    }

    #[test]
    fn get_unverified_transaction_groups_rejects_context_mismatch() {
        let cache = VerifiedTransactionCache::new(10);
        let stxn = test_stxn(3);
        cache.add(group_ctx(vec![stxn.clone()]));

        let mut other_context = test_context();
        other_context.consensus_version = "v42".to_string();

        let unverified =
            cache.get_unverified_transaction_groups(&[vec![stxn.clone()]], &other_context);
        assert_eq!(unverified, vec![vec![stxn]]);
    }

    #[test]
    fn update_pinned_finds_entries_across_pinned_and_buckets() {
        let cache = VerifiedTransactionCache::new(1000);
        let mut groups = Vec::new();
        for i in 0..40u64 {
            let group = vec![test_stxn(i)];
            cache.add(group_ctx(group.clone()));
            groups.push(group);
        }

        // Pin the first half.
        for group in &groups[0..20] {
            cache.pin(group).expect("should find previously-added txn");
        }

        // Ask to update pinned to a set spanning both the already-pinned
        // half and the still-bucketed half.
        let mut pinned_txns = HashMap::new();
        for group in &groups[10..30] {
            for txn in group {
                pinned_txns.insert(compute_txn_id(&txn.txn), txn.clone());
            }
        }
        assert!(cache.update_pinned(&pinned_txns).is_ok());
    }

    #[test]
    fn pin_previously_added_ok_pin_unknown_errors() {
        let cache = VerifiedTransactionCache::new(100);
        let mut groups = Vec::new();
        for i in 0..20u64 {
            let group = vec![test_stxn(i)];
            cache.add(group_ctx(group.clone()));
            groups.push(group);
        }

        // A previously-added entry pins successfully.
        assert!(cache.pin(&groups[0]).is_ok());

        // An entry that was never added is missing.
        let unknown = vec![test_stxn(9999)];
        assert_eq!(
            cache.pin(&unknown),
            Err(VerifiedTxnCacheError::MissingPinnedEntry)
        );
    }

    #[test]
    fn pin_too_many_entries_is_rejected() {
        // MAX_PINNED_ENTRIES is 500_000; fake it out by directly seeding the
        // pinned map to just below the cap so this stays a fast unit test
        // instead of performing hundreds of thousands of real pins.
        let cache = VerifiedTransactionCache::new(10);
        let filler_group = vec![test_stxn(0)];
        cache.add(group_ctx(filler_group));
        {
            let mut inner = cache.inner.lock().unwrap();
            let filler_ctx = Arc::new(GroupContext::new(test_context(), vec![]));
            for i in 0..(MAX_PINNED_ENTRIES - 1) as u64 {
                let mut bytes = [0u8; 32];
                bytes[0..8].copy_from_slice(&i.to_be_bytes());
                inner.pinned.insert(Digest(bytes), filler_ctx.clone());
            }
        }

        let two_more = vec![test_stxn(1), test_stxn(2)];
        assert_eq!(
            cache.pin(&two_more),
            Err(VerifiedTxnCacheError::TooManyPinnedEntries)
        );
    }

    /// Port of go's `TestTxnGroupRecoversPanic` (`data/transactions/verify/
    /// txn_test.go`): go's `TxnGroup` recovers a panic during group
    /// preparation (there: a nil `*BlockHeader` dereference) into an
    /// ordinary error rather than propagating it -- "one bad group must not
    /// take down the caller" carries over even though Rust's type system
    /// already rules out go's specific trigger (there is no nullable
    /// `VerificationContext` to dereference).
    ///
    /// A general, always-reachable panic surface exists here too: a
    /// std::sync::Mutex that panicked while held becomes poisoned, and every
    /// subsequent `.lock().expect(..)` on it panics. This test poisons the
    /// cache's internal mutex the same way an unrelated bug elsewhere in the
    /// same process could, then asserts `verify_transaction_group_cached`
    /// still returns a normal `Err` (mentioning "panic") instead of
    /// unwinding into the caller.
    #[test]
    fn verify_transaction_group_cached_recovers_panic() {
        let cache = VerifiedTransactionCache::new(10);

        // Poison the cache's internal mutex by panicking while it's held,
        // exactly as an unrelated bug elsewhere touching this same cache
        // could.
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = cache.inner.lock().unwrap();
            panic!("simulated bug while holding the verified-txn-cache lock");
        }));
        assert!(poisoned.is_err(), "the setup panic itself must have fired");

        let group = vec![test_stxn(1)];
        let context = test_context();
        let params = crate::rules::ConsensusParams::default();

        let result = verify_transaction_group_cached(&group, &context, &params, &cache);
        let err = result.expect_err(
            "verification against a poisoned cache must return an Err, not unwind the caller",
        );
        assert!(
            err.to_string().contains("panic"),
            "expected a panic-recovery error, got: {err}"
        );
    }
}
