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
use algo_types::{Address, Digest, LogicSig, MultisigSig, SaltedKeySig, SignedTransaction};

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

/// Maximum `retained_size` total of the entries in one bucket (Go:
/// `maxBucketRetainedBytes`, `verifiedTxnCache.go`), in addition to the limit
/// on their number.
const MAX_BUCKET_RETAINED_BYTES: usize = 64 << 20;

// The in-memory sizes go's `retainedSize` counts (`unsafe.Sizeof` of its
// types on a 64-bit target). They are go's numbers on purpose: the byte limit
// decides when a bucket rotates, and that has to happen at the same point.
const SLICE_HEADER_SIZE: usize = 24;
const MULTISIG_SUBSIG_SIZE: usize = 96;
const LOGIC_SIG_SIZE: usize = 232;
const MULTISIG_SIG_SIZE: usize = 32;
const SALTED_KEY_SIG_SIZE: usize = 56;

/// What a cache entry remembers of one verified transaction (Go:
/// `verifiedTxnCtx`): the context it was verified under and the
/// authorization material that was checked. The key is the transaction ID,
/// which covers none of that material.
///
/// `lsig`, `msig` and `pqsig` are `Some` only when the transaction carried
/// them, exactly as go keeps them out of line behind pointers (`txnAuth`).
#[derive(Debug, Clone, PartialEq)]
struct Entry {
    context: Arc<VerificationContext>,
    sig: [u8; 64],
    auth_addr: Address,
    lsig: Option<LogicSig>,
    msig: Option<MultisigSig>,
    pqsig: Option<SaltedKeySig>,
}

// ---------------------------------------------------------------------------
// Authorization comparison, with go's `Blank`/`Equal` semantics
// ---------------------------------------------------------------------------

/// Go's `MultisigSig.Equal`: version, threshold, and the subsigs by length and
/// element. Rust spells go's "no multisig" as `None`, which equals the zero
/// value here exactly as `Equal` treats a nil `Subsigs`.
fn multisig_equal(a: Option<&MultisigSig>, b: Option<&MultisigSig>) -> bool {
    let zero = MultisigSig::default();
    let a = a.unwrap_or(&zero);
    let b = b.unwrap_or(&zero);
    a.version == b.version && a.threshold == b.threshold && a.subsigs == b.subsigs
}

/// Go's `SaltedKeySig.Equal` (`bytes.Equal` on the keys: nil equals empty).
fn salted_key_sig_equal(a: Option<&SaltedKeySig>, b: Option<&SaltedKeySig>) -> bool {
    let zero = SaltedKeySig::default();
    *a.unwrap_or(&zero) == *b.unwrap_or(&zero)
}

/// Go's `LogicSig.Equal`: the signatures, then the program, then the
/// arguments. Arguments matter because the cache is keyed by the transaction
/// ID, which does not cover them. Like go it tells a nil argument (`None`)
/// from an empty one (`Some(empty)`), and compares only the number of
/// arguments (`len`), not whether the list itself is nil.
fn logic_sig_equal(a: &LogicSig, b: &LogicSig) -> bool {
    if a.sig != b.sig
        || !multisig_equal(a.msig.as_ref(), b.msig.as_ref())
        || !multisig_equal(a.lmsig.as_ref(), b.lmsig.as_ref())
        || !salted_key_sig_equal(a.pqsig.as_ref(), b.pqsig.as_ref())
        || a.logic.as_slice() != b.logic.as_slice()
    {
        return false;
    }
    let none: Vec<Option<serde_bytes::ByteBuf>> = Vec::new();
    let a_args = a.args.as_ref().unwrap_or(&none);
    let b_args = b.args.as_ref().unwrap_or(&none);
    a_args == b_args
}

/// The `LogicSig` a cache entry keeps: `None` when `lsig` equals the zero
/// value. Deliberately `Equal` against the zero value, as go's
/// `outOfLineAuth` does, so an `lsig` that go would tell from an absent one
/// is kept and compared.
fn out_of_line_lsig(lsig: &Option<LogicSig>) -> Option<&LogicSig> {
    lsig.as_ref()
        .filter(|l| !logic_sig_equal(l, &LogicSig::default()))
}

/// The salted-key signature a cache entry keeps: `None` when blank.
fn out_of_line_pqsig(pqsig: &Option<SaltedKeySig>) -> Option<&SaltedKeySig> {
    pqsig.as_ref().filter(|p| !p.blank())
}

/// Go's `retainedSize`: the heap a cache entry keeps alive through its
/// out-of-line parts. Go counts slice capacities; this counts lengths, as a
/// Rust decode allocates exactly what it holds.
fn retained_size(
    lsig: Option<&LogicSig>,
    msig: Option<&MultisigSig>,
    pqsig: Option<&SaltedKeySig>,
) -> usize {
    let mut n = 0;
    if let Some(l) = lsig {
        n += LOGIC_SIG_SIZE + l.logic.len();
        if let Some(args) = &l.args {
            n += SLICE_HEADER_SIZE * args.len();
            n += args
                .iter()
                .map(|a| a.as_ref().map_or(0, |b| b.len()))
                .sum::<usize>();
        }
        n += MULTISIG_SUBSIG_SIZE
            * (l.msig.as_ref().map_or(0, |m| m.subsigs.len())
                + l.lmsig.as_ref().map_or(0, |m| m.subsigs.len()));
        if let Some(p) = &l.pqsig {
            n += p.public_key.len() + p.signature.len();
        }
    }
    if let Some(m) = msig {
        n += MULTISIG_SIG_SIZE + MULTISIG_SUBSIG_SIZE * m.subsigs.len();
    }
    if let Some(p) = pqsig {
        n += SALTED_KEY_SIG_SIZE + p.public_key.len() + p.signature.len();
    }
    n
}

impl Entry {
    fn new(context: Arc<VerificationContext>, txn: &SignedTransaction) -> Self {
        Entry {
            context,
            sig: txn.sig,
            auth_addr: txn.auth_addr.unwrap_or(Address::ZERO),
            lsig: out_of_line_lsig(&txn.lsig).cloned(),
            msig: txn.msig.clone(),
            pqsig: out_of_line_pqsig(&txn.pqsig).cloned(),
        }
    }

    fn retained_size(&self) -> usize {
        retained_size(self.lsig.as_ref(), self.msig.as_ref(), self.pqsig.as_ref())
    }

    /// Whether this entry records a verification that still applies to `txn`
    /// under `context` (Go: `verifiedTxnCtx.matches`). Both halves are
    /// required: the same context, and the same authorization material that
    /// was verified back then.
    fn matches(&self, context: &VerificationContext, txn: &SignedTransaction) -> bool {
        if *self.context != *context
            || self.sig != txn.sig
            || self.auth_addr != txn.auth_addr.unwrap_or(Address::ZERO)
        {
            return false;
        }
        // Presence has to agree before the contents are compared: the entry
        // holds an `lsig`/`pqsig` only when the transaction carried one that
        // is not equal to the zero value / blank, and a `msig` only when it
        // was not blank (go's nil `Subsigs`).
        match (self.lsig.as_ref(), out_of_line_lsig(&txn.lsig)) {
            (None, None) => {}
            (Some(cached), Some(probe)) if logic_sig_equal(cached, probe) => {}
            _ => return false,
        }
        match (self.msig.as_ref(), txn.msig.as_ref()) {
            (None, None) => {}
            (Some(cached), Some(probe)) if multisig_equal(Some(cached), Some(probe)) => {}
            _ => return false,
        }
        match (self.pqsig.as_ref(), out_of_line_pqsig(&txn.pqsig)) {
            (None, None) => {}
            (Some(cached), Some(probe)) if salted_key_sig_equal(Some(cached), Some(probe)) => {}
            _ => return false,
        }
        true
    }
}

/// The mutable cache state, guarded by [`VerifiedTransactionCache`]'s mutex.
struct Inner {
    /// Number of entries allowed in each bucket before rotation (Go:
    /// `entriesPerBucket`).
    entries_per_bucket: usize,
    /// Limit on the `retained_size` total of one bucket (Go:
    /// `bytesPerBucket`).
    bytes_per_bucket: isize,
    /// The `retained_size` total of the entries in `buckets[base]` (Go:
    /// `retainedBytes`).
    /// Signed like go's `int`: a group that repeats a transaction ID replaces
    /// its own earlier entry before the group's bytes are added, so the count
    /// can dip below zero for a moment (and, as in go, stay under-counted).
    retained_bytes: isize,
    /// The circular cache buckets buffer (Go: `buckets`).
    buckets: Vec<HashMap<Digest, Arc<Entry>>>,
    /// The pinned transactions tier (Go: `pinned`).
    pinned: HashMap<Digest, Arc<Entry>>,
    /// Index into `buckets` where the next entry is written (Go: `base`).
    base: usize,
}

/// Search the bucket ring for `id`, starting at `base` and walking
/// backward (wrapping), matching go's `(base + len) % len` trick in
/// `GetUnverifiedTransactionGroups`/`Pin`/`UpdatePinned`. Returns the bucket
/// index the entry was found in (so callers can continue subsequent
/// per-transaction lookups from there, exactly like go's `baseBucket`
/// threading) and the cached entry.
fn find_in_buckets(
    buckets: &[HashMap<Digest, Arc<Entry>>],
    base: usize,
    id: &Digest,
) -> Option<(usize, Arc<Entry>)> {
    let n = buckets.len();
    for offset in 0..n {
        let bucket_idx = (base + n - offset) % n;
        if let Some(entry) = buckets[bucket_idx].get(id) {
            return Some((bucket_idx, entry.clone()));
        }
    }
    None
}

/// Add `group_ctx` to the currently-active bucket, rotating to the next
/// bucket first if it doesn't have room (Go: `verifiedTransactionCache.add`).
fn add_locked(inner: &mut Inner, group_ctx: &GroupContext) {
    let txns = &group_ctx.signed_group_txns;
    let mut group_bytes: isize = txns
        .iter()
        .map(|t| {
            retained_size(
                out_of_line_lsig(&t.lsig),
                t.msig.as_ref(),
                out_of_line_pqsig(&t.pqsig),
            ) as isize
        })
        .sum();
    // A group that exceeds the byte limit by itself still goes into the
    // current bucket when nothing there counts against the limit, so every
    // group is cached and a bucket goes over the limit by at most one group.
    if inner.buckets[inner.base].len() + txns.len() > inner.entries_per_bucket
        || (inner.retained_bytes > 0 && inner.retained_bytes + group_bytes > inner.bytes_per_bucket)
    {
        inner.base = (inner.base + 1) % inner.buckets.len();
        let base = inner.base;
        inner.buckets[base].clear();
        inner.retained_bytes = 0;
    }
    let context = Arc::new(group_ctx.context.clone());
    for txn in txns {
        let entry = Arc::new(Entry::new(context.clone(), txn));
        let id = compute_txn_id(&txn.txn);
        // Lookups consult the pinned entries first and do not fall back to
        // the buckets when a pinned entry does not match. So when the pool
        // verifies a pending transaction again, under a new consensus version
        // or because the pinned entry is for a different signing of it (a
        // LogicSig's args are not part of its ID), the new entry must replace
        // the pinned one, or the pool's copy would never be found verified.
        if let std::collections::hash_map::Entry::Occupied(mut pinned) = inner.pinned.entry(id) {
            group_bytes -= entry.retained_size() as isize;
            pinned.insert(entry);
            continue;
        }
        let base = inner.base;
        if let Some(old) = inner.buckets[base].insert(id, entry) {
            inner.retained_bytes -= old.retained_size() as isize;
        }
    }
    inner.retained_bytes += group_bytes;
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
                bytes_per_bucket: MAX_BUCKET_RETAINED_BYTES as isize,
                retained_bytes: 0,
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
        add_locked(&mut inner, &group_ctx);
    }

    /// Add several transaction groups at once. Mirrors go's `AddPayset`.
    pub fn add_payset(&self, group_ctxs: &[Arc<GroupContext>]) {
        let mut inner = self
            .inner
            .lock()
            .expect("verified txn cache mutex poisoned");
        for group_ctx in group_ctxs {
            add_locked(&mut inner, group_ctx);
        }
    }

    /// Compare `txn_groups` against the cache under `context` and return the
    /// subset of groups that are *not* fully covered by a cached entry —
    /// i.e. the groups that still need real signature verification. Mirrors
    /// go's `GetUnverifiedTransactionGroups`.
    ///
    /// A group counts as covered only when every one of its transactions is
    /// found (pinned or bucketed) under the same [`VerificationContext`],
    /// with its authorization material (`sig`/`msig`/`lsig`/`pqsig`/
    /// `auth_addr`) equal, by go's `Equal` rules, to what was cached for that
    /// transaction ID — the ID alone doesn't cover the signature envelope,
    /// since it hashes only the txn body.
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

            for txn in signed_txn_group {
                let id = compute_txn_id(&txn.txn);

                // Check pinned first, then fall back to the bucket ring.
                let mut entry = inner.pinned.get(&id).cloned();
                if entry.is_none() {
                    if let Some((bucket_idx, found)) =
                        find_in_buckets(&inner.buckets, base_bucket, &id)
                    {
                        entry = Some(found);
                        base_bucket = bucket_idx;
                    }
                }

                match entry {
                    Some(e) if e.matches(context, txn) => verified_txn += 1,
                    _ => break,
                }
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

            match find_in_buckets(&inner.buckets, inner.base, txid) {
                Some((_, entry)) => {
                    pinned.insert(*txid, entry);
                }
                None => err = Some(VerifiedTxnCacheError::MissingPinnedEntry),
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

            if let Some((bucket_idx, entry)) = find_in_buckets(&inner.buckets, base_bucket, &id) {
                inner.buckets[bucket_idx].remove(&id);
                if bucket_idx == inner.base {
                    inner.retained_bytes -= entry.retained_size() as isize;
                }
                inner.pinned.insert(id, entry);
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

    // Group-level LogicSig size check (go: `txnGroupBatchPrep` ->
    // `logicSigGroupSizeCheck`, `data/transactions/verify/txn.go`), run
    // before the cache lookup (cheap, O(group)) so a cache hit can never skip
    // it, and before any signature work, like go. Without it a group whose
    // LogicSig args exceed the pool would be admitted to the pool and
    // proposed in a block that block validation (and go peers) reject
    // (issue #2054, FIND-ba9c86e5-01).
    crate::signature::logic_sig_group_size_check(txgroup, consensus)?;

    let owned_group = txgroup.to_vec();
    let unverified =
        cache.get_unverified_transaction_groups(std::slice::from_ref(&owned_group), context);
    if unverified.is_empty() {
        // The whole group is already verified under this exact context. A
        // heartbeat proof is not part of what the cache vouches for (block
        // validation caches a group without it), so it is checked on a hit too.
        crate::signature::check_heartbeat_proofs(txgroup)?;
        return Ok(());
    }

    // No `SigBlockSource` is threaded through here (issue #1116): pool
    // admission has no `LedgerStore` reference in scope at all -- this
    // module, like `block.rs`, is deliberately stateless (Go's pool
    // equivalent, `data/pool/transactionPool.go`, calls the same
    // `Ledger`-backed `verify.TxnGroup` the block evaluator uses, so this is
    // a real behavioral gap, not just an unused parameter). A LogicSig using
    // `txn FirstValidTime`/`block BlkTimestamp` therefore still errors with
    // "no block header access" at pool-admission time; giving the pool real
    // ledger access would mean threading a store reference through this
    // crate's admission API (`algo-validate` is a dependency of `algo-ledger`,
    // not the reverse, so it can't hold a concrete `LedgerStore` itself) --
    // out of scope for this issue's minimal-surface fix. Tracked as a
    // follow-up rather than silently left undocumented.
    // LogicSig opcode budget is pooled across the whole atomic group only
    // when `EnableLogicSigCostPooling` is set for the active protocol
    // version (go: v39+, `config/consensus.go`). Before that, go-algorand
    // gives each LogicSig its own independent `LogicSigMaxCost` budget
    // (`data/transactions/logic/eval.go`'s `remainingBudget()`, taken when
    // `PooledLogicSigBudget == nil`) -- see issue #1253. Mirrors the same
    // gating in `block.rs`'s per-group LogicSig budget construction.
    let pooled_lsig = consensus.enable_logicsig_cost_pooling;
    let mut lsig_budget = GroupBudget::for_logicsig(if pooled_lsig { txgroup.len() } else { 1 });
    for (group_index, stx) in txgroup.iter().enumerate() {
        if !pooled_lsig {
            // Non-pooled: each transaction gets a fresh, independent budget.
            lsig_budget = GroupBudget::for_logicsig(1);
        }
        verify_transaction_signature(stx, txgroup, group_index, &mut lsig_budget, consensus)?;
    }
    // go's batch also holds each heartbeat's proof (issue #2218): a group with
    // a bad proof is never cached as verified.
    crate::signature::check_heartbeat_proofs(txgroup)?;

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
        assert_eq!(
            **entry,
            Entry {
                context: Arc::new(ctx.context.clone()),
                sig: stxn.sig,
                auth_addr: Address::ZERO,
                lsig: None,
                msig: None,
                pqsig: None,
            }
        );
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
            let filler = Arc::new(Entry::new(Arc::new(test_context()), &test_stxn(0)));
            for i in 0..(MAX_PINNED_ENTRIES - 1) as u64 {
                let mut bytes = [0u8; 32];
                bytes[0..8].copy_from_slice(&i.to_be_bytes());
                inner.pinned.insert(Digest(bytes), filler.clone());
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

    /// Port of go's `TestSigVerifier` (`data/transactions/verify/
    /// txnBatch_test.go`): a single synchronous entry point that verifies a
    /// good group (succeeds, and the group becomes cache-covered so a
    /// resubmission is skipped) and a bad group (fails, and never becomes
    /// cache-covered). go's `SigVerifier` is a small synchronous wrapper
    /// around the same cache-consulting group-verify go's async
    /// `BatchVerifier` pool also uses; `verify_transaction_group_cached` is
    /// algod-rust's single synchronous entry point serving that same role
    /// (see its doc comment: "the single call site both the
    /// gossip/mempool-admission path ... and block verification ... should
    /// use").
    #[test]
    fn verify_transaction_group_cached_good_then_bad_mirrors_sig_verifier() {
        use ed25519_dalek::{Signer, SigningKey};

        let cache = VerifiedTransactionCache::new(100);
        let context = VerificationContext {
            spec_addrs: SpecialAddresses::default(),
            consensus_version: "future".to_string(),
        };
        let params = crate::rules::consensus_params_for_version("future")
            .expect("future consensus params must be registered");

        let build_signed_txn = |note: u64, key: &SigningKey| -> SignedTransaction {
            let pk = key.verifying_key();
            let sender = Address(pk.to_bytes());
            let txn = Transaction {
                txn_type: "pay".into(),
                sender,
                fee: 1000,
                first_valid: Round(1),
                last_valid: Round(1000),
                receiver: Address([0x42; 32]),
                amount: 1000,
                genesis_id: "test-v1".into(),
                genesis_hash: [0xAA; 32],
                note: serde_bytes::ByteBuf::from(note.to_be_bytes().to_vec()),
                ..Default::default()
            };
            let canonical = algo_codec::canonical_encode_transaction(&txn);
            let mut msg = Vec::with_capacity(2 + canonical.len());
            msg.extend_from_slice(b"TX");
            msg.extend_from_slice(&canonical);
            let sig = key.sign(&msg);
            SignedTransaction {
                txn,
                sig: sig.to_bytes(),
                ..Default::default()
            }
        };

        // Good group: valid ed25519 signature over the canonical encoding.
        let good_key = SigningKey::from_bytes(&[9u8; 32]);
        let good_group = vec![build_signed_txn(1, &good_key)];
        let ok = verify_transaction_group_cached(&good_group, &context, &params, &cache);
        assert!(
            ok.is_ok(),
            "a validly-signed group must verify successfully: {ok:?}"
        );

        // Once verified, the group must be cache-covered: a lookup for the
        // identical group under the identical context returns no unverified
        // groups (mirrors go's `TxnGroup` "already verified" skip path).
        let unverified =
            cache.get_unverified_transaction_groups(std::slice::from_ref(&good_group), &context);
        assert!(
            unverified.is_empty(),
            "a successfully-verified group must be fully cache-covered"
        );

        // Bad group: signed by a *different* key than the one whose pubkey
        // the sender address is derived from, so the signature check fails.
        let wrong_key = SigningKey::from_bytes(&[0xFFu8; 32]);
        let mut bad_stxn = build_signed_txn(2, &wrong_key);
        bad_stxn.txn.sender = Address(good_key.verifying_key().to_bytes());
        let bad_group = vec![bad_stxn];
        let err = verify_transaction_group_cached(&bad_group, &context, &params, &cache);
        assert!(
            err.is_err(),
            "a group with an invalid signature must fail verification"
        );

        // A failed group must never become cache-covered (so a later
        // resubmission with a corrected signature is verified for real).
        let still_unverified =
            cache.get_unverified_transaction_groups(std::slice::from_ref(&bad_group), &context);
        assert_eq!(
            still_unverified.len(),
            1,
            "a group that failed verification must not be cached as verified"
        );
    }

    /// Port of go's `TestTxnGroupCacheUpdateLogicWithMultiSig`
    /// (`data/transactions/verify/txn_test.go:1498`), pinning the specific
    /// combination `verifyGroup` exercises there that neither the plain
    /// delegated-multisig test (`verify_logicsig_delegated_multisig` in
    /// `signature.rs`) nor the cache tests above pin on their own: a
    /// LogicSig delegated via a 2-of-3 `MultisigSig` whose program itself
    /// evaluates a real condition (`sha256(arg0) == <fixed digest>`),
    /// driven through the cache-integrated `verify_transaction_group_cached`
    /// entry point (algod-rust's equivalent of go's `TxnGroup` +
    /// `VerifiedTransactionCache` pairing).
    ///
    /// Covers both of go's `verifyGroup` failure modes for this scenario:
    /// (1) a broken multisig subsig byte fails signature verification and
    /// the group is never cached, and (2) a correct signature but a
    /// tampered logic argument fails program evaluation (`"rejected by
    /// logic"` in go, `"transaction <txid>: rejected by logic"` here)
    /// -- also never cached. A subsequent verification with everything
    /// restored succeeds and the group becomes cache-covered.
    #[test]
    fn verify_transaction_group_cached_delegated_multisig_logicsig() {
        use algo_types::{LogicSig, MultisigSig, MultisigSubsig};
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::{Digest as Sha2Digest, Sha512_256};

        const PROGRAM_PREFIX: &[u8] = b"Program";
        const MSIG_ADDR_PREFIX: &[u8] = b"MultisigAddr";

        // `sha256(arg0) == byte base64 5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=`
        // -- the exact program and satisfying/breaking argument go's
        // TestTxnGroupCacheUpdateLogicWithMultiSig uses.
        let program = algo_avm::assemble_string(
            "arg 0\nsha256\nbyte base64 5rZMNsevs5sULO+54aN+OvU6lQ503z2X+SSYUABIx7E=\n==\n",
        )
        .expect("program must assemble")
        .program;
        let good_arg: Vec<u8> = vec![
            0x3D, 0x30, 0x97, 0x53, 0x85, 0x48, 0xE9, 0x91, 0x42, 0xFD, 0xDB, 0x3B, 0x31, 0xF5,
            0x5A, 0xAE, 0x63, 0x3F, 0xAE, 0xF2, 0x49, 0x93, 0x08, 0x12, 0x94, 0xAA, 0x7E, 0x06,
            0x08, 0x84, 0x39, 0x62,
        ];

        let keys: [SigningKey; 3] = [
            SigningKey::from_bytes(&[70u8; 32]),
            SigningKey::from_bytes(&[71u8; 32]),
            SigningKey::from_bytes(&[72u8; 32]),
        ];

        // Multisig contract-account address: SHA512/256("MultisigAddr" ||
        // version || threshold || pk1 || pk2 || pk3).
        let multisig_addr = {
            let mut hasher = Sha512_256::new();
            hasher.update(MSIG_ADDR_PREFIX);
            hasher.update([1u8]); // version
            hasher.update([2u8]); // threshold
            for key in &keys {
                hasher.update(key.verifying_key().to_bytes());
            }
            Address(hasher.finalize().into())
        };

        let sign_program = |key: &SigningKey, program: &[u8]| -> [u8; 64] {
            let mut msg = Vec::with_capacity(PROGRAM_PREFIX.len() + program.len());
            msg.extend_from_slice(PROGRAM_PREFIX);
            msg.extend_from_slice(program);
            key.sign(&msg).to_bytes()
        };

        // 2-of-3 multisig: keys 0 and 1 sign, key 2's subsig slot is blank.
        let build_lsig = |program: &[u8], arg: &[u8]| -> LogicSig {
            let subsigs: Vec<MultisigSubsig> = keys
                .iter()
                .enumerate()
                .map(|(i, key)| MultisigSubsig {
                    public_key: key.verifying_key().to_bytes(),
                    signature: if i < 2 {
                        sign_program(key, program)
                    } else {
                        [0u8; 64]
                    },
                })
                .collect();
            LogicSig {
                logic: serde_bytes::ByteBuf::from(program.to_vec()),
                args: Some(vec![Some(serde_bytes::ByteBuf::from(arg.to_vec()))]),
                msig: Some(MultisigSig {
                    version: 1,
                    threshold: 2,
                    subsigs,
                }),
                ..Default::default()
            }
        };

        let build_group = |lsig: LogicSig, note: u64| -> Vec<SignedTransaction> {
            vec![SignedTransaction {
                txn: Transaction {
                    sender: multisig_addr,
                    ..test_txn(note)
                },
                lsig: Some(lsig),
                ..Default::default()
            }]
        };

        // `LogicSigMsig` (classic, pre-v41 delegated multisig) is still
        // accepted under v40 -- see `crates/core/algo-types/src/
        // consensus.rs`'s v41 note ("retires LogicSigMsig in favor of
        // LogicSigLMsig"). Use v40 so this test exercises the same `Msig`
        // (not `LMsig`) field go's non-LMsig subtest does.
        let v40 = algo_types::consensus::CONSENSUS_V40;
        let context = VerificationContext {
            spec_addrs: SpecialAddresses::default(),
            consensus_version: v40.to_string(),
        };
        let params = crate::rules::consensus_params_for_version(v40)
            .expect("v40 consensus params must be registered");
        assert!(
            !params.logic_sig_lmsig,
            "sanity: v40 must still use the classic Msig delegation field"
        );

        let cache = VerifiedTransactionCache::new(100);

        // 1. A broken multisig subsig byte fails signature verification and
        //    is never cached.
        let mut broken_lsig = build_lsig(&program, &good_arg);
        broken_lsig.msig.as_mut().unwrap().subsigs[0].signature[0] ^= 1;
        let broken_group = build_group(broken_lsig, 1);
        let err = verify_transaction_group_cached(&broken_group, &context, &params, &cache)
            .expect_err("a broken multisig subsig byte must fail verification");
        assert!(
            err.to_string().to_lowercase().contains("sig")
                || err.to_string().to_lowercase().contains("multisig"),
            "expected a signature-related error, got: {err}"
        );
        let unverified =
            cache.get_unverified_transaction_groups(std::slice::from_ref(&broken_group), &context);
        assert_eq!(
            unverified.len(),
            1,
            "a group that failed signature verification must not be cached"
        );

        // 2. A correct signature but a tampered logic argument fails
        //    program evaluation and is also never cached.
        let mut bad_arg = good_arg.clone();
        bad_arg[0] ^= 1;
        let logic_fail_lsig = build_lsig(&program, &bad_arg);
        let logic_fail_group = build_group(logic_fail_lsig, 2);
        let err = verify_transaction_group_cached(&logic_fail_group, &context, &params, &cache)
            .expect_err("a tampered logic argument must be rejected by the LogicSig program");
        assert!(
            err.to_string().contains(": rejected by logic"),
            "expected a LogicSig-program-rejection error, got: {err}"
        );
        let unverified = cache
            .get_unverified_transaction_groups(std::slice::from_ref(&logic_fail_group), &context);
        assert_eq!(
            unverified.len(),
            1,
            "a group rejected by the LogicSig program must not be cached"
        );

        // 3. Everything correct: signature and logic both pass, and the
        //    group becomes cache-covered.
        let good_lsig = build_lsig(&program, &good_arg);
        let good_group = build_group(good_lsig, 3);
        let ok = verify_transaction_group_cached(&good_group, &context, &params, &cache);
        assert!(
            ok.is_ok(),
            "a correctly signed and logic-satisfying group must verify: {ok:?}"
        );
        let unverified =
            cache.get_unverified_transaction_groups(std::slice::from_ref(&good_group), &context);
        assert!(
            unverified.is_empty(),
            "a successfully-verified group must be fully cache-covered"
        );
    }

    // ── Issue #1253: EnableLogicSigCostPooling must gate group-wide
    // LogicSig budget pooling ──
    //
    // Port of go-algorand's `TestSigBudget`'s `EnableLogicSigCostPooling =
    // false` case (`data/transactions/logic/eval_test.go`): before protocol
    // v39, each LogicSig gets its own independent `LogicSigMaxCost` budget
    // (go: `eval.go`'s `remainingBudget()`, taken when
    // `PooledLogicSigBudget == nil`) -- an expensive LogicSig cannot borrow
    // unused budget from a cheap sibling in the same group. At and after
    // v39, budgets are pooled across the whole group
    // (`len(txgroup) * LogicSigMaxCost`), so the same expensive LogicSig
    // succeeds by drawing on the cheap sibling's unused share.

    /// A trivial `int 1` contract-account LogicSig program (cost 1) and its
    /// signed transaction, using the standard "authorizer == HashProgram"
    /// escrow-account dispatch (no delegated signature needed).
    fn contract_account_lsig_stxn(program: &[u8], note: u64) -> SignedTransaction {
        use algo_types::LogicSig;
        let addr = crate::signature::hash_program(program);
        SignedTransaction {
            txn: Transaction {
                sender: addr,
                ..test_txn(note)
            },
            lsig: Some(LogicSig {
                logic: serde_bytes::ByteBuf::from(program.to_vec()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// A backward-branch loop whose total opcode cost lands just over
    /// `LOGICSIG_BUDGET` (20,000) on its own: `iterations * 4` (`int 1`,
    /// `-`, `dup`, `bnz` each cost 1) plus 3 for the initial `int`, final
    /// `pop`, and final `int 1`. With `iterations = 5000` that's
    /// `1 + 5000*4 + 1 + 1 = 20003` -- enough to blow a single, independent
    /// 20,000-opcode budget, but trivially affordable pooled alongside a
    /// near-free sibling in a 2-member group (pool = 40,000).
    fn expensive_lsig_program() -> Vec<u8> {
        let src = "#pragma version 4\nint 5000\nloop:\nint 1\n-\ndup\nbnz loop\npop\nint 1\n";
        algo_avm::assemble_string(src)
            .expect("expensive lsig program must assemble")
            .program
    }

    /// The `int 1` (v4) program -- a near-free contract-account LogicSig.
    fn cheap_lsig_program() -> Vec<u8> {
        algo_avm::assemble_string("#pragma version 4\nint 1\n")
            .expect("cheap lsig program must assemble")
            .program
    }

    #[test]
    fn logicsig_cost_pooling_disabled_rejects_expensive_sibling_cheap_group_would_pool() {
        let cache = VerifiedTransactionCache::new(10);
        let context = test_context();

        let cheap = contract_account_lsig_stxn(&cheap_lsig_program(), 1);
        let expensive = contract_account_lsig_stxn(&expensive_lsig_program(), 2);
        let group = vec![cheap, expensive];

        // Pooling disabled (pre-v39 behavior): the expensive sibling can't
        // borrow the cheap sibling's unused budget, so its own program
        // alone (cost ~20003) blows its independent 20,000-opcode budget.
        let unpooled = ConsensusParams {
            enable_logicsig_cost_pooling: false,
            ..ConsensusParams::default()
        };
        let err = verify_transaction_group_cached(&group, &context, &unpooled, &cache)
            .expect_err("expensive LogicSig must exceed its own unpooled budget");
        assert!(
            err.to_string().contains("budget"),
            "expected a budget-exhaustion error, got: {err}"
        );
    }

    #[test]
    fn logicsig_cost_pooling_enabled_lets_expensive_sibling_borrow_cheap_groups_budget() {
        let cache = VerifiedTransactionCache::new(10);
        let context = test_context();

        let cheap = contract_account_lsig_stxn(&cheap_lsig_program(), 3);
        let expensive = contract_account_lsig_stxn(&expensive_lsig_program(), 4);
        let group = vec![cheap, expensive];

        // Pooling enabled (v39+, today's default consensus): the group's
        // combined 40,000-opcode pool easily covers the expensive
        // sibling's ~20,003 cost after the cheap sibling's near-zero spend.
        let pooled = ConsensusParams {
            enable_logicsig_cost_pooling: true,
            ..ConsensusParams::default()
        };
        verify_transaction_group_cached(&group, &context, &pooled, &cache)
            .expect("pooled group budget must cover the expensive LogicSig");
    }

    // ---- go v5.1.1 verified-cache behaviour (#2551) ----------------------

    use serde_bytes::ByteBuf;

    type TxnMutation = Box<dyn Fn(&mut SignedTransaction)>;
    type PqMutation = Box<dyn Fn(&mut SaltedKeySig)>;

    fn miss(cache: &VerifiedTransactionCache, probe: &SignedTransaction) -> bool {
        cache
            .get_unverified_transaction_groups(&[vec![probe.clone()]], &test_context())
            .len()
            == 1
    }

    fn hit(cache: &VerifiedTransactionCache, probe: &SignedTransaction) -> bool {
        !miss(cache, probe)
    }

    fn cached_with(stxn: &SignedTransaction) -> VerifiedTransactionCache {
        let cache = VerifiedTransactionCache::new(50);
        cache.add(group_ctx(vec![stxn.clone()]));
        assert!(hit(&cache, stxn), "the group as cached must hit");
        cache
    }

    fn lsig_txn(note: u64) -> SignedTransaction {
        let mut s = test_stxn(note);
        s.sig = [0u8; 64];
        s.lsig = Some(LogicSig {
            logic: ByteBuf::from(vec![0x06, 0x81, 0x01]),
            args: Some(vec![
                Some(ByteBuf::from(b"arg0".to_vec())),
                Some(ByteBuf::from(b"arg1".to_vec())),
            ]),
            ..Default::default()
        });
        s
    }

    /// go `TestGetUnverifiedTransactionGroupsAuthChanges`.
    #[test]
    fn altered_authorization_misses_the_cache() {
        let mut base = test_stxn(1);
        base.msig = Some(MultisigSig {
            version: 1,
            threshold: 1,
            subsigs: vec![],
        });
        base.sig = [0u8; 64];
        let cache = cached_with(&base);
        let mutate: Vec<(&str, TxnMutation)> = vec![
            ("sig", Box::new(|s| s.sig[0] ^= 1)),
            (
                "auth-addr",
                Box::new(|s| s.auth_addr = Some(Address([9u8; 32]))),
            ),
            (
                "msig-version",
                Box::new(|s| s.msig.as_mut().unwrap().version ^= 1),
            ),
            (
                "lsig-logic",
                Box::new(|s| {
                    s.lsig = Some(LogicSig {
                        logic: ByteBuf::from(vec![0x06, 0x81, 0x01]),
                        ..Default::default()
                    })
                }),
            ),
            (
                "lsig-args",
                Box::new(|s| {
                    s.lsig = Some(LogicSig {
                        args: Some(vec![Some(ByteBuf::from(b"arg".to_vec()))]),
                        ..Default::default()
                    })
                }),
            ),
        ];
        for (name, m) in mutate {
            let mut probe = base.clone();
            m(&mut probe);
            assert_eq!(compute_txn_id(&probe.txn), compute_txn_id(&base.txn));
            assert!(miss(&cache, &probe), "{name}: altered auth was accepted");
        }

        // lsig args: a changed and an appended-empty argument and a changed
        // delegation signature all miss
        let lsig = lsig_txn(2);
        let cache = cached_with(&lsig);
        let mut changed = lsig.clone();
        changed.lsig.as_mut().unwrap().args = Some(vec![Some(ByteBuf::from(b"x".to_vec()))]);
        assert!(miss(&cache, &changed), "lsig-args");
        let mut appended = lsig.clone();
        appended
            .lsig
            .as_mut()
            .unwrap()
            .args
            .as_mut()
            .unwrap()
            .push(Some(ByteBuf::new()));
        assert!(miss(&cache, &appended), "lsig-args-empty-appended");
        let mut delegated = lsig.clone();
        delegated.lsig.as_mut().unwrap().sig[0] ^= 1;
        assert!(miss(&cache, &delegated), "lsig-sig");
    }

    /// go `TestGetUnverifiedTransactionGroupsSaltedKeySigProofChanges` and
    /// `...LogicSigSaltedKeySigChanges` (the ls scheme keeps the program in
    /// `pk` and the encoded arguments in `sig`).
    #[test]
    fn altered_salted_key_sig_misses_the_cache() {
        let mut base = test_stxn(3);
        base.sig = [0u8; 64];
        base.pqsig = Some(SaltedKeySig {
            scheme: *b"f5",
            salt: algo_types::AddressSalt(4),
            public_key: ByteBuf::from(vec![1; 8]),
            signature: ByteBuf::from(vec![2; 8]),
        });
        let cache = cached_with(&base);
        let muts: Vec<PqMutation> = vec![
            Box::new(|p| p.signature[0] ^= 1),
            Box::new(|p| p.public_key[0] ^= 1),
            Box::new(|p| p.salt.0 ^= 1),
            Box::new(|p| p.scheme = *b"x1"),
            Box::new(|p| p.signature = ByteBuf::new()),
            Box::new(|p| p.public_key.push(0)),
        ];
        for m in muts {
            let mut probe = base.clone();
            m(probe.pqsig.as_mut().unwrap());
            assert!(miss(&cache, &probe));
        }
    }

    /// go `TestAddingToCacheBlankLsigNilVsEmpty`, in the one place Rust keeps
    /// go's nil/empty distinction: a nil argument is `None`, an empty one
    /// `Some(empty)`. An absent lsig and an all-zero one are the same thing.
    #[test]
    fn nil_and_empty_lsig_arguments_are_told_apart() {
        let mut cached = lsig_txn(4);
        cached.lsig.as_mut().unwrap().args = Some(vec![Some(ByteBuf::new())]);
        let cache = cached_with(&cached);
        let mut nil_arg = cached.clone();
        nil_arg.lsig.as_mut().unwrap().args = Some(vec![None]);
        assert!(miss(&cache, &nil_arg));

        // Equal() compares len(Args): a missing list equals an empty one
        let mut a = lsig_txn(5);
        a.lsig.as_mut().unwrap().args = None;
        let cache = cached_with(&a);
        let mut b = a.clone();
        b.lsig.as_mut().unwrap().args = Some(vec![]);
        assert!(hit(&cache, &b));

        // an lsig equal to the zero value is no lsig
        let plain = test_stxn(6);
        let cache = cached_with(&plain);
        let mut zero_lsig = plain.clone();
        zero_lsig.lsig = Some(LogicSig::default());
        assert!(hit(&cache, &zero_lsig));
        let mut blank_pq = plain.clone();
        blank_pq.pqsig = Some(SaltedKeySig::default());
        assert!(hit(&cache, &blank_pq));
    }

    /// go `TestAddingToCacheBlankMsigNilVsEmpty`: a non-nil empty `Subsigs`
    /// is stored out of line, so a nil one misses (the conservative way).
    #[test]
    fn empty_msig_is_not_the_absent_msig() {
        let mut cached = test_stxn(7);
        cached.msig = Some(MultisigSig::default());
        let cache = cached_with(&cached);
        let mut absent = cached.clone();
        absent.msig = None;
        assert!(miss(&cache, &absent));
        // and the other way: cached without, probed with
        let cache = cached_with(&absent);
        assert!(miss(&cache, &cached));
    }

    /// go `TestGetUnverifiedTransactionGroupsContextChanges`.
    #[test]
    fn changed_context_misses_and_leaves_the_entry_alone() {
        let stxn = test_stxn(8);
        let cache = cached_with(&stxn);
        let base = test_context();
        let mut fee = base.clone();
        fee.spec_addrs.fee_sink.0[0] += 1;
        let mut pool = base.clone();
        pool.spec_addrs.rewards_pool.0[0] += 1;
        let mut ver = base.clone();
        ver.consensus_version = "future".into();
        let mut all = fee.clone();
        all.spec_addrs.rewards_pool.0[0] += 1;
        all.consensus_version = "future".into();
        for ctx in [fee, pool, ver, all] {
            let r = cache.get_unverified_transaction_groups(&[vec![stxn.clone()]], &ctx);
            assert_eq!(r, vec![vec![stxn.clone()]]);
        }
        assert!(hit(&cache, &stxn));
    }

    /// go keeps one entry per transaction ID, so where a transaction sits in
    /// the group it is asked about does not matter.
    #[test]
    fn entries_are_per_transaction_not_per_group_position() {
        let (a, b) = (test_stxn(10), test_stxn(11));
        let cache = VerifiedTransactionCache::new(50);
        cache.add(group_ctx(vec![a.clone(), b.clone()]));
        assert!(hit(&cache, &b));
        assert!(hit(&cache, &a));
        let swapped = vec![b.clone(), a.clone()];
        assert!(cache
            .get_unverified_transaction_groups(&[swapped], &test_context())
            .is_empty());
    }

    /// go `add`: a re-verified transaction replaces its pinned entry, or the
    /// pool's copy would never be found verified again.
    #[test]
    fn add_replaces_a_pinned_entry() {
        let lsig = lsig_txn(12);
        let cache = cached_with(&lsig);
        cache.pin(std::slice::from_ref(&lsig)).unwrap();
        let mut other = lsig.clone();
        other.lsig.as_mut().unwrap().args = Some(vec![Some(ByteBuf::from(b"new".to_vec()))]);
        assert!(miss(&cache, &other));
        cache.add(group_ctx(vec![other.clone()]));
        assert!(hit(&cache, &other));
        assert!(miss(&cache, &lsig));
        // it stayed pinned: the bucket ring holds nothing for it
        let inner = cache.inner.lock().unwrap();
        assert!(inner.pinned.contains_key(&compute_txn_id(&lsig.txn)));
        assert!(inner.buckets.iter().all(|b| b.is_empty()));
        assert_eq!(inner.retained_bytes, 0);
    }

    /// go `add`/`Pin`: a bucket also rotates once its entries retain more
    /// than `bytesPerBucket`, but a group that is over the limit by itself
    /// still lands in an empty bucket.
    #[test]
    fn bucket_rotates_on_retained_bytes() {
        let cache = VerifiedTransactionCache::new(1000);
        cache.inner.lock().unwrap().bytes_per_bucket = 1000;
        let big = |note| {
            let mut s = lsig_txn(note);
            s.lsig.as_mut().unwrap().logic = ByteBuf::from(vec![0u8; 600]);
            s
        };
        let size = Entry::new(Arc::new(test_context()), &big(20)).retained_size();
        assert_eq!(size, 232 + 600 + 24 * 2 + 8);
        cache.add(group_ctx(vec![big(20)]));
        assert_eq!(cache.inner.lock().unwrap().base, 0);
        cache.add(group_ctx(vec![big(21)]));
        {
            let inner = cache.inner.lock().unwrap();
            assert_eq!(inner.base, 1, "second group overflows the byte limit");
            assert_eq!(inner.retained_bytes, size as isize);
        }
        // pinning from the current bucket releases its bytes
        cache.pin(&[big(21)]).unwrap();
        assert_eq!(cache.inner.lock().unwrap().retained_bytes, 0);
        // a group over the limit by itself goes in while the bucket is empty
        let huge = vec![big(22), big(23)];
        cache.add(group_ctx(huge));
        let inner = cache.inner.lock().unwrap();
        assert_eq!(inner.base, 1);
        assert_eq!(inner.retained_bytes, 2 * size as isize);
    }

    /// go `TestAddingToCacheOutOfLineSigs`: the entry keeps `lsig`, `msig`
    /// and `pqsig` only for a transaction that carries them (the entry owns
    /// its copy; Rust ownership makes aliasing the caller's data impossible).
    #[test]
    fn entry_keeps_out_of_line_auth_only_when_present() {
        let plain = test_stxn(30);
        let mut delegated = test_stxn(31);
        delegated.lsig = Some(LogicSig {
            logic: ByteBuf::from(vec![6, 0x81, 1]),
            pqsig: Some(SaltedKeySig {
                scheme: *b"f5",
                public_key: ByteBuf::from(vec![1; 4]),
                signature: ByteBuf::from(vec![2; 4]),
                ..Default::default()
            }),
            ..Default::default()
        });
        let mut salted = test_stxn(32);
        salted.pqsig = Some(SaltedKeySig {
            scheme: *b"ed",
            public_key: ByteBuf::from(vec![3; 4]),
            ..Default::default()
        });
        for (stxn, has_lsig, has_pq) in [
            (plain, false, false),
            (lsig_txn(33), true, false),
            (salted, false, true),
            (delegated, true, false),
        ] {
            let group = vec![stxn];
            let cache = VerifiedTransactionCache::new(500);
            cache.add(group_ctx(group.clone()));
            let id = compute_txn_id(&group[0].txn);
            let entry = {
                let inner = cache.inner.lock().unwrap();
                inner.buckets[inner.base][&id].clone()
            };
            assert_eq!(entry.lsig.is_some(), has_lsig);
            assert_eq!(entry.pqsig.is_some(), has_pq);
            assert!(entry.msig.is_none());
            assert_eq!(
                entry.lsig.as_ref(),
                group[0].lsig.as_ref().filter(|_| has_lsig)
            );
        }
    }

    /// A group that repeats a transaction ID replaces its own earlier entry
    /// before the group's bytes are counted; go's signed counter just dips,
    /// an unsigned one would panic with the cache mutex held.
    #[test]
    fn repeated_txid_in_one_group_does_not_underflow_the_byte_count() {
        let cache = VerifiedTransactionCache::new(50);
        let twice = vec![lsig_txn(40), lsig_txn(40)];
        cache.add(group_ctx(twice));
        let size = Entry::new(Arc::new(test_context()), &lsig_txn(40)).retained_size();
        assert_eq!(
            cache.inner.lock().unwrap().retained_bytes,
            size as isize,
            "two counted, one replaced"
        );
        assert!(hit(&cache, &lsig_txn(40)));
    }
}
