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

//! Lock-free, `const`-constructible histogram and counter for hot paths.
//!
//! [`crate::histogram::Histogram`] keeps its series in a `Mutex<HashMap>` (a
//! lock per observation, plus allocation for label canonicalisation) and is
//! not `const`-constructible, so it cannot be a plain `static` next to a
//! latency-critical call such as the SQLite commit. [`FixedHistogram`] and
//! [`FixedCounter`] are the lock-free equivalents: a handful of relaxed
//! atomic increments, fixed buckets, no labels, and the standard Prometheus
//! `histogram` / `counter` text exposition. Moved here from
//! `algo_ledger::follow_timing` (issue #1815) so the crate that owns metrics
//! owns both flavours.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Upper bounds (seconds) of the fixed histogram buckets; an implicit
/// `+Inf` bucket follows. Spans 1 ms to 30 s: sub-10 ms is a healthy block,
/// and the 1 s boundary matches the existing slow-stage warnings.
pub const BUCKET_BOUNDS_SECS: [f64; 14] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];
const N_BUCKETS: usize = BUCKET_BOUNDS_SECS.len();

/// A lock-free histogram with the fixed [`BUCKET_BOUNDS_SECS`] buckets.
///
/// See the module docs for how this differs from [`crate::histogram::Histogram`].
pub struct FixedHistogram {
    name: &'static str,
    help: &'static str,
    /// Non-cumulative per-bucket counts; the last slot is the `+Inf` bucket.
    buckets: [AtomicU64; N_BUCKETS + 1],
    sum_nanos: AtomicU64,
}

impl FixedHistogram {
    /// A histogram named `name` (no observations yet).
    pub const fn new(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            buckets: [const { AtomicU64::new(0) }; N_BUCKETS + 1],
            sum_nanos: AtomicU64::new(0),
        }
    }

    /// Records one observation.
    pub fn observe(&self, d: Duration) {
        let secs = d.as_secs_f64();
        let idx = BUCKET_BOUNDS_SECS
            .iter()
            .position(|&b| secs <= b)
            .unwrap_or(N_BUCKETS);
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        let nanos = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        self.sum_nanos.fetch_add(nanos, Ordering::Relaxed);
    }

    /// Total number of observations.
    pub fn count(&self) -> u64 {
        self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).sum()
    }

    /// Sum of all observations in seconds.
    pub fn sum_secs(&self) -> f64 {
        self.sum_nanos.load(Ordering::Relaxed) as f64 / 1e9
    }

    /// Appends the Prometheus text exposition (`histogram` type, cumulative
    /// buckets, `+Inf`, `_sum`, `_count`) to `out`.
    pub fn write_prometheus(&self, out: &mut String) {
        let counts: Vec<u64> = self
            .buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .collect();
        let total: u64 = counts.iter().sum();
        let _ = writeln!(out, "# HELP {} {}", self.name, self.help);
        let _ = writeln!(out, "# TYPE {} histogram", self.name);
        let mut cumulative = 0u64;
        for (bound, c) in BUCKET_BOUNDS_SECS.iter().zip(&counts) {
            cumulative += c;
            let _ = writeln!(
                out,
                "{}_bucket{{le=\"{}\"}} {}",
                self.name, bound, cumulative
            );
        }
        let _ = writeln!(out, "{}_bucket{{le=\"+Inf\"}} {}", self.name, total);
        let _ = writeln!(out, "{}_sum {}", self.name, self.sum_secs());
        let _ = writeln!(out, "{}_count {}", self.name, total);
    }
}

/// A monotonically increasing lock-free counter (`counter` text format).
pub struct FixedCounter {
    name: &'static str,
    help: &'static str,
    value: AtomicU64,
}

impl FixedCounter {
    /// A counter named `name` starting at zero.
    pub const fn new(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            value: AtomicU64::new(0),
        }
    }

    /// Adds one.
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    /// Current value.
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    /// Appends the Prometheus text exposition to `out`.
    pub fn write_prometheus(&self, out: &mut String) {
        let _ = writeln!(out, "# HELP {} {}", self.name, self.help);
        let _ = writeln!(out, "# TYPE {} counter", self.name);
        let _ = writeln!(out, "{} {}", self.name, self.get());
    }
}
