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

use std::collections::HashMap;

use algo_codec::{canonical_encode_signed_transaction, compute_txn_id, decode_signed_txn_stream};
use algo_types::{Digest, SignedTransaction};

/// What the cache keeps of a transaction that left the pool.
///
/// Mirrors go-algorand's `statusCacheEntry` (`data/pools/statusCache.go`),
/// which since v5.1.1 holds the transaction's encoding rather than the
/// decoded value, to keep the cache small.
#[derive(Debug, Clone)]
struct StatusEntry {
    /// The encoded `SignedTxn`.
    tx: Vec<u8>,
    /// The error string if the transaction was rejected, or empty if confirmed.
    txn_err: String,
}

/// A transaction's recorded status, as [`StatusCache::check`] returns it.
#[derive(Debug, Clone, PartialEq)]
pub struct TxnStatus {
    /// The transaction as it was cached.
    pub tx: SignedTransaction,
    /// The error string if the transaction was rejected, or empty if confirmed.
    pub txn_err: String,
}

/// A two-generation cache for transaction status, matching go-algorand's `statusCache`.
///
/// The cache maintains two hash maps (`cur` and `prev`). When `cur` reaches
/// capacity, it is rotated into `prev` and a fresh `cur` is allocated. Lookups
/// check `cur` first, then `prev`, giving recently-evicted entries a grace period.
///
/// Thread safety is handled at the pool level (the caller holds the lock),
/// so this type does not use internal synchronization.
#[derive(Debug)]
pub struct StatusCache {
    cur: HashMap<Digest, StatusEntry>,
    prev: Option<HashMap<Digest, StatusEntry>>,
    capacity: usize,
}

impl StatusCache {
    /// Create a new status cache with the given capacity per generation.
    ///
    /// Mirrors `makeStatusCache(sz)` in Go.
    pub fn new(capacity: usize) -> Self {
        let mut sc = StatusCache {
            cur: HashMap::new(),
            prev: None,
            capacity,
        };
        sc.reset();
        sc
    }

    /// Look up a transaction's status by its ID (digest).
    ///
    /// Returns the transaction and its error text if it is found in either
    /// `cur` or `prev`, `None` otherwise (a miss never fabricates a
    /// transaction). An entry that cannot be decoded reads as a miss, as in go.
    ///
    /// Mirrors `statusCache.check()` in Go.
    pub fn check(&self, txid: &Digest) -> Option<TxnStatus> {
        let entry = self
            .cur
            .get(txid)
            .or_else(|| self.prev.as_ref().and_then(|prev| prev.get(txid)))?;
        let mut txns = decode_signed_txn_stream(&entry.tx).ok()?;
        if txns.len() != 1 {
            return None;
        }
        Some(TxnStatus {
            tx: txns.remove(0),
            txn_err: entry.txn_err.clone(),
        })
    }

    /// Record a transaction's status (rejection reason) in the cache.
    ///
    /// If `cur` has reached capacity, it is rotated into `prev` before
    /// the new entry is inserted. This matches Go's `statusCache.put()`.
    pub fn put(&mut self, tx: &SignedTransaction, txn_err: String) {
        if self.cur.len() >= self.capacity {
            let old_cur = std::mem::replace(&mut self.cur, HashMap::with_capacity(self.capacity));
            self.prev = Some(old_cur);
        }

        self.cur.insert(
            compute_txn_id(&tx.txn),
            StatusEntry {
                tx: canonical_encode_signed_transaction(tx),
                txn_err,
            },
        );
    }

    /// Reset the cache, clearing both generations.
    ///
    /// Mirrors `statusCache.reset()` in Go.
    pub fn reset(&mut self) {
        self.cur = HashMap::with_capacity(self.capacity);
        self.prev = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::{Address, Round, Transaction};

    /// A distinct signed payment per `n` (go's `makeStatusCacheTxn`).
    fn txn(n: u8) -> SignedTransaction {
        SignedTransaction {
            txn: Transaction {
                txn_type: "pay".into(),
                sender: Address([n; 32]),
                receiver: Address([n.wrapping_add(1); 32]),
                fee: 1000,
                amount: n as u64 + 1,
                first_valid: Round(1),
                last_valid: Round(1000),
                note: serde_bytes::ByteBuf::from(vec![n; 3]),
                ..Default::default()
            },
            sig: [n; 64],
            ..Default::default()
        }
    }

    fn id(t: &SignedTransaction) -> Digest {
        compute_txn_id(&t.txn)
    }

    #[test]
    fn put_and_check() {
        let mut cache = StatusCache::new(10);
        let t = txn(1);

        assert!(cache.check(&id(&t)).is_none());

        cache.put(&t, "some error".to_string());

        let status = cache.check(&id(&t)).expect("should find entry");
        assert_eq!(status.txn_err, "some error");
    }

    /// go `TestStatusCacheRoundTrip`: what goes in comes back unchanged, and a
    /// miss reports itself as one without fabricating a transaction.
    #[test]
    fn status_cache_round_trip() {
        let mut cache = StatusCache::new(64);
        let mut t = txn(1);
        t.auth_addr = Some(Address([9; 32]));
        cache.put(&t, "some error".to_string());

        let got = cache.check(&id(&t)).expect("found");
        assert_eq!(got.txn_err, "some error");
        assert_eq!(got.tx, t);

        assert!(
            cache.check(&Digest([0xee; 32])).is_none(),
            "a transaction that was never cached must not be found"
        );
    }

    #[test]
    fn check_returns_none_for_missing() {
        let cache = StatusCache::new(10);
        assert!(cache.check(&Digest([42; 32])).is_none());
    }

    #[test]
    fn rotation_on_capacity() {
        // Capacity of 2: after inserting 2 entries, the 3rd triggers rotation.
        let mut cache = StatusCache::new(2);
        let (t1, t2, t3) = (txn(1), txn(2), txn(3));

        cache.put(&t1, "err1".to_string());
        cache.put(&t2, "err2".to_string());

        // cur is now full (2 entries). Next put rotates cur -> prev.
        cache.put(&t3, "err3".to_string());

        assert_eq!(cache.check(&id(&t3)).expect("t3 in cur").txn_err, "err3");
        assert_eq!(cache.check(&id(&t1)).expect("t1 in prev").txn_err, "err1");
        assert_eq!(cache.check(&id(&t2)).expect("t2 in prev").txn_err, "err2");
    }

    #[test]
    fn double_rotation_evicts_oldest() {
        let mut cache = StatusCache::new(1);
        let (t1, t2, t3) = (txn(1), txn(2), txn(3));

        cache.put(&t1, "err1".to_string());
        cache.put(&t2, "err2".to_string());
        assert!(cache.check(&id(&t1)).is_some());
        assert!(cache.check(&id(&t2)).is_some());

        cache.put(&t3, "err3".to_string());
        assert!(cache.check(&id(&t1)).is_none(), "t1 should be evicted");
        assert!(cache.check(&id(&t2)).is_some(), "t2 should be in prev");
        assert!(cache.check(&id(&t3)).is_some(), "t3 should be in cur");
    }

    #[test]
    fn reset_clears_everything() {
        let mut cache = StatusCache::new(10);
        let t = txn(1);
        cache.put(&t, "error".to_string());
        assert!(cache.check(&id(&t)).is_some());
        cache.reset();
        assert!(cache.check(&id(&t)).is_none());
    }

    #[test]
    fn reset_clears_prev_too() {
        let mut cache = StatusCache::new(1);
        let (t1, t2) = (txn(1), txn(2));
        cache.put(&t1, "err1".to_string());
        cache.put(&t2, "err2".to_string()); // rotates t1 to prev
        assert!(cache.check(&id(&t1)).is_some());
        assert!(cache.check(&id(&t2)).is_some());
        cache.reset();
        assert!(cache.check(&id(&t1)).is_none());
        assert!(cache.check(&id(&t2)).is_none());
    }

    #[test]
    fn empty_error_string_for_confirmed() {
        let mut cache = StatusCache::new(10);
        let t = txn(1);
        // An empty txn_err means the transaction was confirmed (not rejected).
        cache.put(&t, String::new());
        let status = cache.check(&id(&t)).expect("should find entry");
        assert!(status.txn_err.is_empty());
    }

    #[test]
    fn overwrite_existing_entry() {
        let mut cache = StatusCache::new(10);
        let t = txn(1);
        cache.put(&t, "first error".to_string());
        cache.put(&t, "second error".to_string());
        let status = cache.check(&id(&t)).expect("should find entry");
        assert_eq!(status.txn_err, "second error");
    }

    /// go logs and reports a miss for an entry it cannot decode.
    #[test]
    fn undecodable_entry_reads_as_a_miss() {
        let mut cache = StatusCache::new(10);
        let t = txn(1);
        cache.put(&t, "err".to_string());
        cache.cur.get_mut(&id(&t)).unwrap().tx = vec![0xc1];
        assert!(cache.check(&id(&t)).is_none());
    }

    /// Every authorization shape that can reach the pool survives the
    /// encode/decode the cache does (a transaction that did not would read as
    /// never seen).
    #[test]
    fn every_authorization_shape_round_trips() {
        use algo_types::{LogicSig, MultisigSig, SaltedKeySig};
        let mut cache = StatusCache::new(64);
        let mut shapes = Vec::new();
        shapes.push(txn(1));
        let mut m = txn(2);
        m.sig = [0; 64];
        m.msig = Some(MultisigSig {
            version: 1,
            threshold: 1,
            subsigs: vec![algo_types::MultisigSubsig {
                public_key: [5; 32],
                signature: [6; 64],
            }],
        });
        shapes.push(m);
        let mut l = txn(3);
        l.sig = [0; 64];
        l.lsig = Some(LogicSig {
            logic: serde_bytes::ByteBuf::from(vec![6, 0x81, 1]),
            args: Some(vec![Some(serde_bytes::ByteBuf::from(vec![1, 2])), None]),
            ..Default::default()
        });
        shapes.push(l);
        let mut p = txn(4);
        p.sig = [0; 64];
        p.pqsig = Some(SaltedKeySig {
            scheme: *b"f5",
            public_key: serde_bytes::ByteBuf::from(vec![1; 9]),
            signature: serde_bytes::ByteBuf::from(vec![2; 9]),
            ..Default::default()
        });
        shapes.push(p);
        let mut r = txn(5);
        r.auth_addr = Some(Address([8; 32]));
        shapes.push(r);
        for (i, t) in shapes.iter().enumerate() {
            cache.put(t, "e".to_string());
            let enc = canonical_encode_signed_transaction(t);
            let dec = decode_signed_txn_stream(&enc);
            assert!(dec.is_ok(), "shape {i}: {dec:?}");
            assert_eq!(&cache.check(&id(t)).expect("decodes").tx, t, "shape {i}");
        }
    }
}
