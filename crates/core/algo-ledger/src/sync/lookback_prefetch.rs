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

//! Best-effort concurrent prefetch for the lookback block download.
//!
//! The lookback phase fetches ~1001 blocks one at a time; on the gossip
//! backend each round trip costs ~0.4 s (379 s on the mainnet soak). A small
//! pool of worker threads fetches the window ahead of the (still strictly
//! sequential, strictly descending) consumer, which keeps its existing
//! store / retry / backoff behaviour:
//!
//! - results are only ever *consumed* in the consumer's order, so the stored
//!   data and the retry-budget accounting are unchanged;
//! - a failed prefetch never counts against the retry budget: the first
//!   worker error disables prefetching and the consumer simply falls back to
//!   its own direct fetch for that round and every later one;
//! - at most [`PREFETCH_WINDOW`] rounds are in flight or buffered ahead of
//!   the consumer.

use std::collections::HashMap;
use std::sync::{Condvar, Mutex};

use algo_error::AlgoError;

/// `(proto, header data, block data)` as returned by `fetch_block_raw`.
pub(crate) type RawBlock = (String, Vec<u8>, Vec<u8>);

/// Number of worker threads.
pub(crate) const PREFETCH_WORKERS: usize = 4;

/// How many rounds ahead of the consumer may be fetched / buffered.
const PREFETCH_WINDOW: u64 = 16;

struct Inner {
    results: HashMap<u64, RawBlock>,
    /// Next round a worker will claim (descending); `None` once every round
    /// of the range is claimed.
    next_claim: Option<u64>,
    /// Lowest round of the prefetch range.
    last: u64,
    /// Highest round of the prefetch range.
    first: u64,
    consumer_round: u64,
    /// Lowest round the consumer has asked for so far; asking again for it
    /// (or a higher round, e.g. a retry after a store failure) is never
    /// served from the buffer.
    taken_down_to: Option<u64>,
    stop: bool,
}

pub(crate) struct LookbackPrefetch {
    inner: Mutex<Inner>,
    cv: Condvar,
}

impl LookbackPrefetch {
    /// Prefetch rounds `first` down to `last` (inclusive, `first >= last`).
    pub(crate) fn new(first: u64, last: u64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                results: HashMap::new(),
                next_claim: (first >= last).then_some(first),
                last,
                first,
                consumer_round: first,
                taken_down_to: None,
                stop: false,
            }),
            cv: Condvar::new(),
        }
    }

    /// Worker loop; run on each worker thread until the range is exhausted
    /// or [`Self::shutdown`] is called.
    pub(crate) fn run_worker<F>(&self, fetch: &F)
    where
        F: Fn(u64) -> Result<RawBlock, AlgoError>,
    {
        loop {
            let round = {
                let mut g = self.inner.lock().unwrap();
                loop {
                    if g.stop {
                        return;
                    }
                    let Some(next) = g.next_claim else {
                        return;
                    };
                    if g.consumer_round.saturating_sub(next) < PREFETCH_WINDOW {
                        g.next_claim = if next > g.last { Some(next - 1) } else { None };
                        break next;
                    }
                    g = self.cv.wait(g).unwrap();
                }
            };
            match fetch(round) {
                Ok(block) => {
                    let mut g = self.inner.lock().unwrap();
                    g.results.insert(round, block);
                    self.cv.notify_all();
                }
                Err(_) => {
                    // Disable prefetching; the consumer falls back to its own
                    // (retrying) fetch.
                    self.shutdown();
                    return;
                }
            }
        }
    }

    /// The consumer is about to need `round`: return its prefetched block,
    /// waiting for an in-flight fetch of it, or `None` if it was never
    /// claimed / prefetching was disabled (fetch it directly then).
    pub(crate) fn take(&self, round: u64) -> Option<RawBlock> {
        let mut g = self.inner.lock().unwrap();
        if g.taken_down_to.is_some_and(|t| round >= t) {
            return None;
        }
        g.taken_down_to = Some(round);
        g.consumer_round = round;
        self.cv.notify_all();
        loop {
            if let Some(b) = g.results.remove(&round) {
                self.cv.notify_all();
                return Some(b);
            }
            if g.stop || round < g.last || round > g.first {
                return None;
            }
            let claimed = match g.next_claim {
                None => true,
                Some(next) => round > next,
            };
            if !claimed {
                return None;
            }
            g = self.cv.wait(g).unwrap();
        }
    }

    /// Stop all workers and wake everyone up.
    pub(crate) fn shutdown(&self) {
        let mut g = self.inner.lock().unwrap();
        g.stop = true;
        self.cv.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ShutdownOnDrop<'a>(&'a LookbackPrefetch);
    impl Drop for ShutdownOnDrop<'_> {
        fn drop(&mut self) {
            self.0.shutdown();
        }
    }

    fn blk(r: u64) -> RawBlock {
        ("p".to_string(), vec![], r.to_be_bytes().to_vec())
    }

    #[test]
    fn delivers_every_round_in_consumer_order_with_bounded_lookahead() {
        let in_flight = AtomicUsize::new(0);
        let max_seen = AtomicUsize::new(0);
        let fetch = |r: u64| -> Result<RawBlock, AlgoError> {
            let n = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            max_seen.fetch_max(n, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(2));
            in_flight.fetch_sub(1, Ordering::SeqCst);
            Ok(blk(r))
        };
        let pf = LookbackPrefetch::new(199, 100);
        let mut prefetched = 0;
        std::thread::scope(|s| {
            for _ in 0..PREFETCH_WORKERS {
                s.spawn(|| pf.run_worker(&fetch));
            }
            // Mirrors the production consumer: a `None` means "fetch it
            // yourself" (e.g. the worker has not claimed that round yet).
            let _guard = ShutdownOnDrop(&pf);
            for r in (100..=199u64).rev() {
                match pf.take(r) {
                    Some(got) => {
                        prefetched += 1;
                        assert_eq!(got, blk(r));
                    }
                    None => assert_eq!(fetch(r).unwrap(), blk(r)),
                }
            }
        });
        assert!(prefetched > 50, "prefetch served only {prefetched}/100");
        // workers plus the consumer's own direct fetches
        assert!(max_seen.load(Ordering::SeqCst) <= PREFETCH_WORKERS + 1);
        // Out-of-range / already-consumed rounds are not served.
        assert!(pf.take(99).is_none());
        // A re-take of an already-consumed round (store-failure retry) must
        // not block.
        assert!(pf.take(100).is_none());
    }

    #[test]
    fn first_error_disables_prefetch_and_consumer_falls_back() {
        let fetch = |r: u64| -> Result<RawBlock, AlgoError> {
            if r == 190 {
                Err(AlgoError::Network {
                    message: "boom".into(),
                })
            } else {
                Ok(blk(r))
            }
        };
        let pf = LookbackPrefetch::new(199, 100);
        std::thread::scope(|s| {
            for _ in 0..2 {
                s.spawn(|| pf.run_worker(&fetch));
            }
            let _guard = ShutdownOnDrop(&pf);
            // Whatever the interleaving, every take() returns (never hangs)
            // and anything it does return is the right block.
            for r in (100..=199u64).rev() {
                if let Some(b) = pf.take(r) {
                    assert_eq!(b, blk(r));
                }
            }
        });
    }

    #[test]
    fn unclaimed_round_returns_none_without_blocking() {
        let pf = LookbackPrefetch::new(50, 10);
        // No workers running: nothing claimed yet.
        assert!(pf.take(50).is_none());
    }
}
