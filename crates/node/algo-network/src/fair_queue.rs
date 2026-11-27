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

//! A bounded queue of values from many sources that serves the sources fairly.
//!
//! Port of go-algorand `util/fairqueue.go` (`FairQueue`), added in
//! `v5.1.1-stable` for the agreement proposal queue
//! (`agreement/gossip/network.go`).
//!
//! Two rules answer two different questions.
//!
//! Which source is served next: each source has its own queue, and
//! [`FairQueue::take`] takes one value from each source with values waiting in
//! turn. A source that starts or resumes waiting joins the end of the turn,
//! behind every source already waiting, so a value waits behind at most one
//! value from each other source. Within a source values are served in arrival
//! order.
//!
//! Which value is lost when the queue is full: [`FairQueue::offer`] makes room
//! by dropping the oldest value of the source with the most waiting. On a tie
//! with the arriving source, the arriving source's own oldest value is dropped.

use std::collections::{HashMap, VecDeque};
use std::sync::{Condvar, Mutex};

struct State<T> {
    /// The waiting values of each source with any, oldest first.
    by_source: HashMap<String, VecDeque<T>>,
    /// The same sources in the order they are served.
    order: Vec<String>,
    /// Index in `order` of the source served next.
    next: usize,
    waiting: usize,
    closed: bool,
}

/// See the module documentation. Safe for concurrent use, but
/// [`FairQueue::next`] expects a single caller at a time.
pub struct FairQueue<T> {
    capacity: usize,
    state: Mutex<State<T>>,
    ready: Condvar,
}

impl<T> FairQueue<T> {
    /// An empty queue that holds at most `capacity` values (one if `capacity`
    /// is less than 1).
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            state: Mutex::new(State {
                by_source: HashMap::new(),
                order: Vec::new(),
                next: 0,
                waiting: 0,
                closed: false,
            }),
            ready: Condvar::new(),
        }
    }

    /// Adds `m` from `source`, and reports whether that dropped another value
    /// to make room.
    pub fn offer(&self, source: &str, m: T) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut dropped = false;
        if st.waiting >= self.capacity {
            // A tie with the arriving source drops from the arriving source.
            // The capacity is at least 1, so a full queue always has a victim.
            // Among other sources holding the same (larger) count, go's map
            // iteration order picks one at random, so the choice is
            // unspecified there too.
            let mut victim = source.to_string();
            let mut victim_len = st.by_source.get(&victim).map_or(0, VecDeque::len);
            for (s, values) in &st.by_source {
                if values.len() > victim_len {
                    victim = s.clone();
                    victim_len = values.len();
                }
            }
            st.pop_oldest(&victim);
            dropped = true;
        }

        if !st.by_source.contains_key(source) {
            // Insert just before the source served next, which is the end of
            // the turn. Appending to `order` instead would let a source that
            // keeps emptying and refilling ahead of `next` hold `next` in
            // place, so the sources behind it would never be reached.
            let at = st.next;
            st.order.insert(at, source.to_string());
            st.next += 1;
            if st.next >= st.order.len() {
                st.next = 0;
            }
        }
        st.by_source
            .entry(source.to_string())
            .or_default()
            .push_back(m);
        st.waiting += 1;
        self.ready.notify_one();
        dropped
    }

    /// Removes and returns the oldest value of the source whose turn it is, or
    /// `None` if the queue is empty.
    pub fn take(&self) -> Option<T> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.take()
    }

    /// Waits for a value and takes it, or returns `None` once the queue is
    /// [closed](Self::close) with nothing waiting.
    pub fn next(&self) -> Option<T> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(m) = st.take() {
                return Some(m);
            }
            if st.closed {
                return None;
            }
            st = self.ready.wait(st).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// Makes [`Self::next`] return `None` once the queue is empty. Rust has no
    /// context to cancel, so this is the counterpart of go's `ctx.Done()`.
    pub fn close(&self) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.closed = true;
        self.ready.notify_all();
    }

    #[cfg(test)]
    fn invariants(&self) -> (usize, usize, usize) {
        let st = self.state.lock().unwrap();
        (st.waiting, st.by_source.len(), st.order.len())
    }
}

impl<T> State<T> {
    fn take(&mut self) -> Option<T> {
        if self.waiting == 0 {
            return None;
        }
        let source = self.order[self.next].clone();
        let (value, emptied) = self.pop_oldest(&source);
        // When the source emptied, `pop_oldest` already left `next` pointing
        // at the following source.
        if !emptied {
            self.next += 1;
        }
        if self.next >= self.order.len() {
            self.next = 0;
        }
        Some(value)
    }

    /// Drops the oldest value of `source`, which must have one. Reports
    /// whether that left `source` with none, in which case it is also removed
    /// from `order`.
    fn pop_oldest(&mut self, source: &str) -> (T, bool) {
        let values = self.by_source.get_mut(source).expect("source has values");
        let value = values.pop_front().expect("source has a value");
        self.waiting -= 1;
        if !values.is_empty() {
            return (value, false);
        }
        self.by_source.remove(source);
        if let Some(i) = self.order.iter().position(|s| s == source) {
            self.order.remove(i);
            if i < self.next {
                self.next -= 1;
            }
        }
        if self.next >= self.order.len() {
            self.next = 0;
        }
        (value, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    fn offer_from(q: &FairQueue<String>, source: &str, seq: u8) -> bool {
        q.offer(source, format!("{source}{seq}"))
    }

    fn take_all(q: &FairQueue<String>) -> Vec<String> {
        std::iter::from_fn(|| q.take()).collect()
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// go `TestFairQueueRoundRobin`.
    #[test]
    fn fair_queue_round_robin() {
        let q = FairQueue::new(50);
        for seq in 0..3 {
            offer_from(&q, "a", seq);
        }
        offer_from(&q, "b", 0);
        offer_from(&q, "c", 0);
        offer_from(&q, "c", 1);
        assert_eq!(take_all(&q), strs(&["a0", "b0", "c0", "a1", "c1", "a2"]));
        assert_eq!(q.invariants(), (0, 0, 0));

        // A source that comes back after emptying joins the end of the turn.
        offer_from(&q, "a", 0);
        offer_from(&q, "b", 0);
        assert_eq!(take_all(&q)[..1], strs(&["a0"])[..]);
        offer_from(&q, "a", 1);
        offer_from(&q, "b", 1);
        assert_eq!(take_all(&q), strs(&["a1", "b1"]));
    }

    /// go `TestFairQueueFull`.
    #[test]
    fn fair_queue_full() {
        let q = FairQueue::new(4);
        for seq in 0..4 {
            assert!(!offer_from(&q, "a", seq));
        }
        assert!(offer_from(&q, "b", 0));
        assert!(offer_from(&q, "c", 0));
        assert_eq!(q.invariants().0, 4);
        assert!(offer_from(&q, "a", 4));
        assert_eq!(take_all(&q), strs(&["a3", "b0", "c0", "a4"]));

        for s in ["a", "b", "c", "d"] {
            offer_from(&q, s, 0);
        }
        assert!(offer_from(&q, "b", 1));
        assert_eq!(take_all(&q), strs(&["a0", "c0", "d0", "b1"]));
    }

    /// go `TestFairQueueBoundedWait`.
    #[test]
    fn fair_queue_bounded_wait() {
        let q = FairQueue::new(50);
        offer_from(&q, "a", 0);
        offer_from(&q, "a", 1);
        offer_from(&q, "b", 0);
        offer_from(&q, "c", 0);
        assert_eq!(q.take().as_deref(), Some("a0"));
        let mut before = Vec::new();
        loop {
            let m = q.take().expect("queue not empty");
            if m == "a1" {
                break;
            }
            before.push(m.clone());
            assert!(before.len() <= 2, "a1 was not served within one turn");
            offer_from(&q, &m[..1], 1);
        }
        assert_eq!(before, strs(&["b0", "c0"]));

        let q = FairQueue::new(50);
        offer_from(&q, "a", 0);
        offer_from(&q, "b", 0);
        offer_from(&q, "c", 0);
        assert_eq!(q.take().as_deref(), Some("a0"));
        offer_from(&q, "d", 0);
        offer_from(&q, "a", 1);
        assert_eq!(take_all(&q), strs(&["b0", "c0", "d0", "a1"]));
    }

    /// go `TestFairQueueCapacityBelowOne` (a `usize` capacity cannot be -1).
    #[test]
    fn fair_queue_capacity_below_one() {
        let q = FairQueue::new(0);
        assert!(!offer_from(&q, "a", 0));
        assert!(offer_from(&q, "b", 0));
        assert_eq!(take_all(&q), strs(&["b0"]));
    }

    /// go `TestFairQueueEmptySource`.
    #[test]
    fn fair_queue_empty_source() {
        let q = FairQueue::new(4);
        q.offer("", "x0".to_string());
        offer_from(&q, "a", 0);
        q.offer("", "x1".to_string());
        assert_eq!(take_all(&q), strs(&["x0", "a0", "x1"]));
    }

    /// go `TestFairQueueNext`: `close` is the counterpart of `ctx.Done()`.
    #[test]
    fn fair_queue_next() {
        let q = Arc::new(FairQueue::new(4));
        let (tx, rx) = std::sync::mpsc::channel();
        let q2 = q.clone();
        std::thread::spawn(move || {
            if let Some(m) = q2.next() {
                tx.send(m).unwrap();
            }
        });
        offer_from(&q, "a", 0);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), "a0");

        // It returns None once closed, even when it was already waiting.
        let q3 = q.clone();
        let waiter = std::thread::spawn(move || q3.next());
        std::thread::sleep(Duration::from_millis(50));
        q.close();
        assert_eq!(waiter.join().unwrap(), None);
        assert_eq!(q.next(), None);
    }
}
