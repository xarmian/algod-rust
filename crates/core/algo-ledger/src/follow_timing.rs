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

//! Per-block timing of the follow path (issue #1678).
//!
//! Follow-phase lag spikes were unexplained because the only per-block
//! timing signal was a `WARN` for stages slower than one second. This module
//! keeps five fixed-bucket Prometheus histograms, exposed on `/metrics`:
//!
//! - `algod_rust_follow_block_apply_seconds`: wall time of the block apply
//!   (`apply_block_executing_app_calls`), which includes the AVM time.
//! - `algod_rust_follow_block_avm_seconds`: time spent inside top-level
//!   approval/clear-state program evaluation (inner app calls run inside it
//!   and are not counted twice); observed only for blocks that ran programs.
//! - `algod_rust_follow_block_commit_seconds`: the SQLite `COMMIT`
//!   (`commit_block`), including trie flush and `synchronous` fsyncs.
//! - `algod_rust_follow_block_wal_checkpoint_seconds`: each WAL checkpoint
//!   SQLite runs on the committing thread (observed through a WAL hook that
//!   reproduces SQLite's default auto-checkpoint, see
//!   [`install_wal_checkpoint_hook`]).
//! - `algod_rust_follow_block_ensure_block_seconds`: total
//!   `ensure_block` time from entry (including waiting for the ledger lock)
//!   to a successful commit.
//!
//! Recording is a handful of relaxed atomic increments; no lock is taken, so
//! nothing here can be held across the SQLite commit.

use std::cell::Cell;
use std::ffi::{c_char, c_int, c_void};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Upper bounds (seconds) of the fixed histogram buckets; an implicit
/// `+Inf` bucket follows. Spans 1 ms to 30 s: sub-10 ms is a healthy block,
/// and the 1 s boundary matches the existing slow-stage warnings.
pub const BUCKET_BOUNDS_SECS: [f64; 14] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];
const N_BUCKETS: usize = BUCKET_BOUNDS_SECS.len();

/// A lock-free histogram with the fixed [`BUCKET_BOUNDS_SECS`] buckets.
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

/// The five follow-path histograms.
pub struct FollowTiming {
    /// Block apply wall time.
    pub apply: FixedHistogram,
    /// Top-level AVM program evaluation time, per block that ran programs.
    pub avm: FixedHistogram,
    /// SQLite commit time.
    pub commit: FixedHistogram,
    /// WAL checkpoint time.
    pub wal_checkpoint: FixedHistogram,
    /// Total `ensure_block` time.
    pub ensure_block: FixedHistogram,
}

static FOLLOW_TIMING: FollowTiming = FollowTiming {
    apply: FixedHistogram::new(
        "algod_rust_follow_block_apply_seconds",
        "Wall time to apply one block on the follow path, including AVM execution.",
    ),
    avm: FixedHistogram::new(
        "algod_rust_follow_block_avm_seconds",
        "Time spent evaluating top-level AVM programs while applying one block (blocks with app calls only).",
    ),
    commit: FixedHistogram::new(
        "algod_rust_follow_block_commit_seconds",
        "Wall time of the SQLite commit of one block on the follow path.",
    ),
    wal_checkpoint: FixedHistogram::new(
        "algod_rust_follow_block_wal_checkpoint_seconds",
        "Wall time of each SQLite WAL checkpoint run on the committing thread.",
    ),
    ensure_block: FixedHistogram::new(
        "algod_rust_follow_block_ensure_block_seconds",
        "Total ensure_block time per committed block, including ledger lock wait.",
    ),
};

/// The process-wide follow-path histograms.
pub fn follow_timing() -> &'static FollowTiming {
    &FOLLOW_TIMING
}

/// Prometheus text exposition of all follow-path histograms.
pub fn follow_timing_prometheus_text() -> String {
    let t = follow_timing();
    let mut out = String::new();
    t.apply.write_prometheus(&mut out);
    t.avm.write_prometheus(&mut out);
    t.commit.write_prometheus(&mut out);
    t.wal_checkpoint.write_prometheus(&mut out);
    t.ensure_block.write_prometheus(&mut out);
    out
}

thread_local! {
    static AVM_NANOS: Cell<u64> = const { Cell::new(0) };
}

/// Clears this thread's AVM time accumulator (call before applying a block).
pub fn reset_avm_time() {
    AVM_NANOS.with(|c| c.set(0));
}

/// Returns and clears this thread's accumulated AVM time since the last
/// [`reset_avm_time`]; `None` when no program ran.
pub fn take_avm_time() -> Option<Duration> {
    let n = AVM_NANOS.with(|c| c.replace(0));
    (n > 0).then(|| Duration::from_nanos(n))
}

/// Adds the lifetime of this guard to the thread's AVM time accumulator.
pub struct AvmTimer(Instant);

impl AvmTimer {
    /// Starts timing a top-level program evaluation.
    pub fn start() -> Self {
        Self(Instant::now())
    }
}

impl Drop for AvmTimer {
    fn drop(&mut self) {
        let n = u64::try_from(self.0.elapsed().as_nanos()).unwrap_or(u64::MAX);
        AVM_NANOS.with(|c| c.set(c.get().saturating_add(n)));
    }
}

/// SQLite's default `wal_autocheckpoint` threshold, in WAL frames.
const DEFAULT_AUTOCHECKPOINT_FRAMES: c_int = 1000;

extern "C" fn wal_hook_cb(
    _ctx: *mut c_void,
    db: *mut rusqlite::ffi::sqlite3,
    name: *const c_char,
    n_frames: c_int,
) -> c_int {
    if n_frames >= DEFAULT_AUTOCHECKPOINT_FRAMES {
        let started = Instant::now();
        // SAFETY: SQLite passes the live connection handle and the schema
        // name; this is exactly what `sqlite3WalDefaultHook` does.
        unsafe { rusqlite::ffi::sqlite3_wal_checkpoint(db, name) };
        follow_timing().wal_checkpoint.observe(started.elapsed());
    }
    rusqlite::ffi::SQLITE_OK
}

/// Replaces SQLite's default auto-checkpoint hook with one that does the
/// same thing (a PASSIVE `sqlite3_wal_checkpoint` once the WAL reaches 1000
/// frames) but times it into
/// `algod_rust_follow_block_wal_checkpoint_seconds`. Call once per
/// connection after `journal_mode=WAL` is set.
pub fn install_wal_checkpoint_hook(conn: &rusqlite::Connection) {
    // SAFETY: `handle()` is the live connection; the callback is a plain
    // `extern "C"` function that ignores its context pointer.
    unsafe {
        rusqlite::ffi::sqlite3_wal_hook(conn.handle(), Some(wal_hook_cb), std::ptr::null_mut());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observations_land_in_cumulative_buckets() {
        let h = FixedHistogram::new("t_seconds", "test");
        h.observe(Duration::from_micros(500));
        h.observe(Duration::from_millis(7));
        h.observe(Duration::from_secs(60));
        let mut s = String::new();
        h.write_prometheus(&mut s);
        assert!(s.contains("t_seconds_bucket{le=\"0.001\"} 1\n"), "{s}");
        assert!(s.contains("t_seconds_bucket{le=\"0.01\"} 2\n"), "{s}");
        assert!(s.contains("t_seconds_bucket{le=\"30\"} 2\n"), "{s}");
        assert!(s.contains("t_seconds_bucket{le=\"+Inf\"} 3\n"), "{s}");
        assert!(s.contains("t_seconds_count 3\n"), "{s}");
        assert_eq!(h.count(), 3);
    }

    /// Strict text-format check: no leading whitespace, every line is a
    /// HELP/TYPE comment or `name[{le="x"}] value`, buckets are cumulative
    /// and `+Inf` equals `_count`.
    #[test]
    fn exposition_is_strictly_valid_text_format() {
        let t = follow_timing();
        t.apply.observe(Duration::from_millis(3));
        t.avm.observe(Duration::from_millis(30));
        t.commit.observe(Duration::from_millis(1200));
        t.wal_checkpoint.observe(Duration::from_millis(80));
        t.ensure_block.observe(Duration::from_millis(40));
        let text = follow_timing_prometheus_text();
        assert!(text.ends_with('\n'));
        let mut families = std::collections::BTreeMap::<String, Vec<(String, f64)>>::new();
        for line in text.lines() {
            assert!(!line.is_empty(), "blank line in exposition");
            assert!(
                !line.starts_with(char::is_whitespace),
                "leading ws: {line:?}"
            );
            if let Some(rest) = line.strip_prefix("# HELP ") {
                assert!(rest.split_once(' ').is_some(), "HELP needs text: {line:?}");
                continue;
            }
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                assert!(rest.ends_with(" histogram"), "TYPE: {line:?}");
                continue;
            }
            let (series, value) = line.rsplit_once(' ').expect("series value");
            let value: f64 = value.parse().unwrap_or_else(|_| panic!("value: {line:?}"));
            let (name, labels) = match series.split_once('{') {
                Some((n, l)) => {
                    assert!(l.ends_with('}'), "labels: {line:?}");
                    (n, &l[..l.len() - 1])
                }
                None => (series, ""),
            };
            assert!(
                name.starts_with("algod_rust_follow_block_")
                    && name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
                "name: {line:?}"
            );
            families
                .entry(name.to_string())
                .or_default()
                .push((labels.to_string(), value));
        }
        for base in ["apply", "avm", "commit", "wal_checkpoint", "ensure_block"] {
            let b = format!("algod_rust_follow_block_{base}_seconds");
            let buckets = &families[&format!("{b}_bucket")];
            assert_eq!(buckets.len(), BUCKET_BOUNDS_SECS.len() + 1);
            assert!(
                buckets.windows(2).all(|w| w[0].1 <= w[1].1),
                "{b} cumulative"
            );
            assert_eq!(buckets.last().unwrap().0, "le=\"+Inf\"");
            let count = families[&format!("{b}_count")][0].1;
            assert_eq!(buckets.last().unwrap().1, count);
            assert!(families.contains_key(&format!("{b}_sum")));
        }
    }

    #[test]
    fn avm_timer_accumulates_per_thread_and_resets() {
        reset_avm_time();
        assert!(take_avm_time().is_none());
        {
            let _g = AvmTimer::start();
            std::thread::sleep(Duration::from_millis(2));
        }
        {
            let _g = AvmTimer::start();
            std::thread::sleep(Duration::from_millis(2));
        }
        let d = take_avm_time().expect("two evaluations ran");
        assert!(d >= Duration::from_millis(4), "{d:?}");
        assert!(take_avm_time().is_none(), "take clears the accumulator");
    }

    #[test]
    fn wal_hook_times_checkpoints_and_keeps_default_behaviour() {
        let dir = std::env::temp_dir().join(format!("algod-wal-hook-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let conn = rusqlite::Connection::open(dir.join("t.sqlite")).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE t(a BLOB);")
            .unwrap();
        install_wal_checkpoint_hook(&conn);
        let before = follow_timing().wal_checkpoint.count();
        // 8 KiB rows: each commit adds a few frames; 1000+ frames trigger.
        for _ in 0..3000 {
            conn.execute("INSERT INTO t VALUES (zeroblob(8192))", [])
                .unwrap();
        }
        assert!(
            follow_timing().wal_checkpoint.count() > before,
            "auto-checkpoint must have been timed"
        );
        // The checkpoint really ran: the WAL is reset and reused instead of
        // growing to the ~24 MB written.
        let wal = std::fs::metadata(dir.join("t.sqlite-wal")).unwrap().len();
        assert!(wal < 16 * 1024 * 1024, "wal grew unbounded: {wal}");
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
