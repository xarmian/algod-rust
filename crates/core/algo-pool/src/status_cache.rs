use std::collections::HashMap;

use algo_types::Digest;

/// Status of a transaction that was previously in the pool.
///
/// Mirrors go-algorand's `statusCacheEntry` from `data/pools/statusCache.go`.
#[derive(Debug, Clone)]
pub struct TxnStatus {
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
    cur: HashMap<Digest, TxnStatus>,
    prev: Option<HashMap<Digest, TxnStatus>>,
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
    /// Returns `Some(TxnStatus)` if the transaction is found in either
    /// `cur` or `prev`, `None` otherwise.
    ///
    /// Mirrors `statusCache.check()` in Go.
    pub fn check(&self, txid: &Digest) -> Option<&TxnStatus> {
        if let Some(entry) = self.cur.get(txid) {
            return Some(entry);
        }
        if let Some(ref prev) = self.prev {
            if let Some(entry) = prev.get(txid) {
                return Some(entry);
            }
        }
        None
    }

    /// Record a transaction's status (rejection reason) in the cache.
    ///
    /// If `cur` has reached capacity, it is rotated into `prev` before
    /// the new entry is inserted. This matches Go's `statusCache.put()`.
    pub fn put(&mut self, txid: Digest, txn_err: String) {
        if self.cur.len() >= self.capacity {
            let old_cur = std::mem::replace(&mut self.cur, HashMap::with_capacity(self.capacity));
            self.prev = Some(old_cur);
        }

        self.cur.insert(txid, TxnStatus { txn_err });
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

    fn test_digest(byte: u8) -> Digest {
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        Digest(bytes)
    }

    #[test]
    fn put_and_check() {
        let mut cache = StatusCache::new(10);
        let txid = test_digest(1);

        assert!(cache.check(&txid).is_none());

        cache.put(txid, "some error".to_string());

        let status = cache.check(&txid).expect("should find entry");
        assert_eq!(status.txn_err, "some error");
    }

    #[test]
    fn check_returns_none_for_missing() {
        let cache = StatusCache::new(10);
        let txid = test_digest(42);
        assert!(cache.check(&txid).is_none());
    }

    #[test]
    fn rotation_on_capacity() {
        // Capacity of 2: after inserting 2 entries, the 3rd triggers rotation.
        let mut cache = StatusCache::new(2);

        let txid1 = test_digest(1);
        let txid2 = test_digest(2);
        let txid3 = test_digest(3);

        cache.put(txid1, "err1".to_string());
        cache.put(txid2, "err2".to_string());

        // cur is now full (2 entries). Next put rotates cur -> prev.
        cache.put(txid3, "err3".to_string());

        // txid3 should be in cur
        let s3 = cache.check(&txid3).expect("txid3 in cur");
        assert_eq!(s3.txn_err, "err3");

        // txid1 and txid2 should be in prev (still findable)
        let s1 = cache.check(&txid1).expect("txid1 in prev");
        assert_eq!(s1.txn_err, "err1");

        let s2 = cache.check(&txid2).expect("txid2 in prev");
        assert_eq!(s2.txn_err, "err2");
    }

    #[test]
    fn double_rotation_evicts_oldest() {
        let mut cache = StatusCache::new(1);

        let txid1 = test_digest(1);
        let txid2 = test_digest(2);
        let txid3 = test_digest(3);

        // Insert txid1 -> cur = {1}
        cache.put(txid1, "err1".to_string());

        // Insert txid2 -> rotation: prev = {1}, cur = {2}
        cache.put(txid2, "err2".to_string());

        // txid1 is now in prev, still findable
        assert!(cache.check(&txid1).is_some());
        assert!(cache.check(&txid2).is_some());

        // Insert txid3 -> rotation: prev = {2}, cur = {3}
        // txid1 is gone (was in old prev, which is dropped)
        cache.put(txid3, "err3".to_string());

        assert!(cache.check(&txid1).is_none(), "txid1 should be evicted");
        assert!(cache.check(&txid2).is_some(), "txid2 should be in prev");
        assert!(cache.check(&txid3).is_some(), "txid3 should be in cur");
    }

    #[test]
    fn reset_clears_everything() {
        let mut cache = StatusCache::new(10);
        let txid = test_digest(1);

        cache.put(txid, "error".to_string());
        assert!(cache.check(&txid).is_some());

        cache.reset();
        assert!(cache.check(&txid).is_none());
    }

    #[test]
    fn reset_clears_prev_too() {
        let mut cache = StatusCache::new(1);
        let txid1 = test_digest(1);
        let txid2 = test_digest(2);

        cache.put(txid1, "err1".to_string());
        cache.put(txid2, "err2".to_string()); // rotates txid1 to prev

        assert!(cache.check(&txid1).is_some());
        assert!(cache.check(&txid2).is_some());

        cache.reset();

        assert!(cache.check(&txid1).is_none());
        assert!(cache.check(&txid2).is_none());
    }

    #[test]
    fn empty_error_string_for_confirmed() {
        let mut cache = StatusCache::new(10);
        let txid = test_digest(1);

        // An empty txn_err means the transaction was confirmed (not rejected).
        cache.put(txid, String::new());

        let status = cache.check(&txid).expect("should find entry");
        assert!(status.txn_err.is_empty());
    }

    #[test]
    fn overwrite_existing_entry() {
        let mut cache = StatusCache::new(10);
        let txid = test_digest(1);

        cache.put(txid, "first error".to_string());
        cache.put(txid, "second error".to_string());

        let status = cache.check(&txid).expect("should find entry");
        assert_eq!(status.txn_err, "second error");
    }
}
