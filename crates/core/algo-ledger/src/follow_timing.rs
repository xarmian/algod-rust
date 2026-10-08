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
//! - `algod_rust_follow_block_ensure_block_seconds`: the *successful*
//!   `ensure_block` attempt: waiting for the ledger lock plus the commit.
//!   Earlier transient-failure attempts and their retry sleeps are excluded;
//!   they are counted by `..._ensure_block_retries_total`.
//! - `algod_rust_follow_block_apply_failed_seconds` and
//!   `algod_rust_follow_block_ensure_block_failed_seconds`: the same timings
//!   for applies / `ensure_block` calls that *failed*, so a slow failing
//!   apply is visible instead of silently missing from the success series.
//!   `..._ensure_block_already_committed_total` counts the idempotent early
//!   return (block already in the ledger).
//! - `algod_rust_follow_block_commit_failed_seconds`: the SQLite `COMMIT`
//!   (`commit_block`) when it returned an error (busy / I/O), which the
//!   `commit` series (successful commits only) never sees. Early returns of
//!   `ensure_block` that commit nothing because the ledger lock is
//!   poisoned are observed into the `ensure_block_failed` series; the routine
//!   "block is ahead of the ledger, needs catchup" skip is only counted by
//!   `..._ensure_block_skipped_ahead_total`.
//! - `algod_rust_process_start_time_seconds` (a gauge, see
//!   [`process_start_time_prometheus_text`]): process start as float Unix
//!   seconds with millisecond resolution, captured by
//!   [`init_process_start_time`] as the first thing `main` does, so a scraper
//!   can tell a restart from a counter delta even when the restarted node has
//!   since processed more blocks than the earlier baseline. Compare it for
//!   exact equality only.
//!
//! Sample populations differ: `apply`/`commit`/`ensure_block` are observed
//! for every committed block, `avm` only for blocks that ran a top-level
//! program (observed whether the apply then succeeded or failed).
//!
//! These cannot reuse `algo_metrics::Histogram`: that type keeps its series
//! in a `Mutex<HashMap>` (a lock per observation, plus allocation for label
//! canonicalisation), is not `const`-constructible so cannot be a plain
//! `static`, renders `_bucket` as `counter`, and `algo-ledger` does not
//! depend on `algo-metrics`. The follow path needs a branch-free atomic
//! increment next to the SQLite commit; this fixed-bucket variant is the
//! lock-free equivalent and emits the standard `histogram` text format.
//!
//! Recording is a handful of relaxed atomic increments; no lock is taken, so
//! nothing here can be held across the SQLite commit.

use std::cell::Cell;
use std::ffi::{c_char, c_int, c_void};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

/// Upper bounds (seconds) of the fixed histogram buckets; an implicit
/// `+Inf` bucket follows. Spans 1 ms to 30 s: sub-10 ms is a healthy block,
/// and the 1 s boundary matches the existing slow-stage warnings.
pub const BUCKET_BOUNDS_SECS: [f64; 14] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];
const N_BUCKETS: usize = BUCKET_BOUNDS_SECS.len();

/// A lock-free histogram with the fixed [`BUCKET_BOUNDS_SECS`] buckets.
///
/// See the module docs for why `algo_metrics::Histogram` is not reused.
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

/// The follow-path histograms and counters.
pub struct FollowTiming {
    /// Block apply wall time (successful applies).
    pub apply: FixedHistogram,
    /// Block apply wall time of applies that returned an error.
    pub apply_failed: FixedHistogram,
    /// Top-level AVM program evaluation time, per block that ran programs.
    pub avm: FixedHistogram,
    /// SQLite commit time.
    pub commit: FixedHistogram,
    /// SQLite commit time of commits that returned an error.
    pub commit_failed: FixedHistogram,
    /// WAL checkpoint time.
    pub wal_checkpoint: FixedHistogram,
    /// The successful `ensure_block` attempt (lock wait + commit).
    pub ensure_block: FixedHistogram,
    /// Total time of `ensure_block` calls that returned without committing
    /// because of an error (permanent failure or retries exhausted).
    pub ensure_block_failed: FixedHistogram,
    /// Transient-error retries inside `ensure_block`.
    pub ensure_block_retries: FixedCounter,
    /// `ensure_block` calls for a block the ledger already had.
    pub ensure_block_already_committed: FixedCounter,
    /// `ensure_block` calls skipped because the block is ahead of the ledger
    /// (routine: the catchup service will fetch the gap).
    pub ensure_block_skipped_ahead: FixedCounter,
}

static FOLLOW_TIMING: FollowTiming = FollowTiming {
    apply: FixedHistogram::new(
        "algod_rust_follow_block_apply_seconds",
        "Wall time to apply one block on the follow path, including AVM execution (successful applies).",
    ),
    apply_failed: FixedHistogram::new(
        "algod_rust_follow_block_apply_failed_seconds",
        "Wall time of block applies on the follow path that returned an error.",
    ),
    avm: FixedHistogram::new(
        "algod_rust_follow_block_avm_seconds",
        "Time spent evaluating top-level AVM programs while applying one block (blocks with app calls only; observed for failed applies too).",
    ),
    commit: FixedHistogram::new(
        "algod_rust_follow_block_commit_seconds",
        "Wall time of the SQLite commit of one block on the follow path.",
    ),
    commit_failed: FixedHistogram::new(
        "algod_rust_follow_block_commit_failed_seconds",
        "Wall time of SQLite commits of one block on the follow path that returned an error.",
    ),
    wal_checkpoint: FixedHistogram::new(
        "algod_rust_follow_block_wal_checkpoint_seconds",
        "Wall time of each SQLite WAL checkpoint run on the committing thread.",
    ),
    ensure_block: FixedHistogram::new(
        "algod_rust_follow_block_ensure_block_seconds",
        "Successful ensure_block attempt per committed block: ledger lock wait plus commit, excluding earlier failed attempts and retry sleeps.",
    ),
    ensure_block_failed: FixedHistogram::new(
        "algod_rust_follow_block_ensure_block_failed_seconds",
        "Total time of ensure_block calls that failed without committing, including retries and lock waits.",
    ),
    ensure_block_retries: FixedCounter::new(
        "algod_rust_follow_block_ensure_block_retries_total",
        "Transient-error retries performed inside ensure_block.",
    ),
    ensure_block_already_committed: FixedCounter::new(
        "algod_rust_follow_block_ensure_block_already_committed_total",
        "ensure_block calls for a block the ledger had already committed (idempotent early return).",
    ),
    ensure_block_skipped_ahead: FixedCounter::new(
        "algod_rust_follow_block_ensure_block_skipped_ahead_total",
        "ensure_block calls skipped because the block is ahead of the ledger (needs catchup; routine, not a failure).",
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
    t.apply_failed.write_prometheus(&mut out);
    t.avm.write_prometheus(&mut out);
    t.commit.write_prometheus(&mut out);
    t.commit_failed.write_prometheus(&mut out);
    t.wal_checkpoint.write_prometheus(&mut out);
    t.ensure_block.write_prometheus(&mut out);
    t.ensure_block_failed.write_prometheus(&mut out);
    t.ensure_block_retries.write_prometheus(&mut out);
    t.ensure_block_already_committed.write_prometheus(&mut out);
    t.ensure_block_skipped_ahead.write_prometheus(&mut out);
    out
}

/// Process start as Unix time in milliseconds. Fixed on the first call;
/// `main` calls [`init_process_start_time`] as its first statement, and the
/// accessor initialises lazily as a fallback (tests, other binaries).
fn process_start_unix_millis() -> u64 {
    static START: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *START.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    })
}

/// Captures the process start time. Call it first thing in `main`.
pub fn init_process_start_time() {
    let _ = process_start_unix_millis();
}

/// Process start, Unix seconds with millisecond resolution.
pub fn process_start_time_seconds() -> f64 {
    process_start_unix_millis() as f64 / 1000.0
}

/// Prometheus text exposition of `algod_rust_process_start_time_seconds`.
pub fn process_start_time_prometheus_text() -> String {
    format!(
        "# HELP algod_rust_process_start_time_seconds Process start as Unix time in seconds (millisecond resolution).\n\
         # TYPE algod_rust_process_start_time_seconds gauge\n\
         algod_rust_process_start_time_seconds {:.3}\n",
        process_start_time_seconds()
    )
}

thread_local! {
    /// Accumulated top-level AVM evaluation time of the block currently
    /// being applied *on this thread*. Single-thread assumption: block
    /// apply (and therefore every top-level program evaluation, including
    /// the inner transactions it spawns) runs synchronously on the one
    /// thread that holds the ledger lock, so a thread-local needs no
    /// synchronisation. Invariant: the only reset/take site is
    /// `try_commit_block`, which calls `reset_avm_time` immediately before
    /// and `take_avm_time` immediately after the apply; applies from other
    /// paths (catchup replay, simulation) merely accumulate into the
    /// accumulator, which the next reset discards.
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
///
/// Must be dropped on the thread that created it (debug-asserted): the
/// accumulator is thread-local, see the `AVM_NANOS` docs.
pub struct AvmTimer(Instant, ThreadId);

impl AvmTimer {
    /// Starts timing a top-level program evaluation.
    pub fn start() -> Self {
        Self(Instant::now(), std::thread::current().id())
    }
}

impl Drop for AvmTimer {
    fn drop(&mut self) {
        debug_assert_eq!(
            self.1,
            std::thread::current().id(),
            "AVM evaluation must start and finish on the apply thread"
        );
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
        let rc = unsafe { rusqlite::ffi::sqlite3_wal_checkpoint(db, name) };
        follow_timing().wal_checkpoint.observe(started.elapsed());
        if rc != rusqlite::ffi::SQLITE_OK {
            // SQLITE_BUSY etc. are normal for a PASSIVE checkpoint; the
            // default hook ignores the code as well.
            tracing::debug!(
                rc,
                n_frames,
                "follow_timing: WAL checkpoint returned non-OK"
            );
        }
    }
    rusqlite::ffi::SQLITE_OK
}

/// Replaces SQLite's default auto-checkpoint hook with one that does the
/// same thing (a PASSIVE `sqlite3_wal_checkpoint` once the WAL reaches 1000
/// frames, identical to `sqlite3WalDefaultHook` at the default
/// `wal_autocheckpoint`) but times it into
/// `algod_rust_follow_block_wal_checkpoint_seconds`. Call once per
/// connection after `journal_mode=WAL` is set.
///
/// Caveats: it applies to the connection it is installed on (the main ledger
/// connection, see `SqliteLedger::init`); other connections to the same
/// database keep SQLite's default hook and are not timed. A later
/// `PRAGMA wal_autocheckpoint = N` on that connection would silently replace
/// this hook (SQLite implements that pragma as `sqlite3_wal_autocheckpoint`,
/// which installs the default hook), so no code may issue it; the
/// `no_code_sets_wal_autocheckpoint` test guards that.
pub fn install_wal_checkpoint_hook(conn: &rusqlite::Connection) {
    // Fallback: normally `main` has already fixed the process start time.
    init_process_start_time();
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
        t.commit_failed.observe(Duration::from_millis(5));
        t.wal_checkpoint.observe(Duration::from_millis(80));
        t.ensure_block.observe(Duration::from_millis(40));
        t.apply_failed.observe(Duration::from_millis(3));
        t.ensure_block_failed.observe(Duration::from_millis(3));
        t.ensure_block_retries.inc();
        t.ensure_block_already_committed.inc();
        t.ensure_block_skipped_ahead.inc();
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
                assert!(
                    rest.ends_with(" histogram") || rest.ends_with(" counter"),
                    "TYPE: {line:?}"
                );
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
        for base in [
            "apply",
            "apply_failed",
            "avm",
            "commit",
            "commit_failed",
            "wal_checkpoint",
            "ensure_block",
            "ensure_block_failed",
        ] {
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
        for c in [
            "algod_rust_follow_block_ensure_block_retries_total",
            "algod_rust_follow_block_ensure_block_already_committed_total",
            "algod_rust_follow_block_ensure_block_skipped_ahead_total",
        ] {
            assert!(families[c][0].1 >= 1.0, "{c}");
        }
    }

    /// Strict text-format check of the process start time gauge: exactly
    /// HELP, TYPE gauge and one integer sample, no leading whitespace, and
    /// the value is stable within a process and a plausible Unix time.
    #[test]
    fn process_start_time_gauge_is_strictly_valid_text_format() {
        let text = process_start_time_prometheus_text();
        assert!(text.ends_with('\n'));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "{text:?}");
        assert!(lines[0].starts_with("# HELP algod_rust_process_start_time_seconds "));
        assert_eq!(
            lines[1],
            "# TYPE algod_rust_process_start_time_seconds gauge"
        );
        let (name, value) = lines[2].rsplit_once(' ').expect("series value");
        assert_eq!(name, "algod_rust_process_start_time_seconds");
        let (secs, millis) = value.split_once('.').expect("fractional seconds");
        assert_eq!(millis.len(), 3, "millisecond resolution: {value}");
        let value: f64 = value.parse().expect("float seconds");
        assert!(secs.parse::<u64>().is_ok());
        assert!(value > 1.6e9, "implausible start time {value}");
        assert!(lines.iter().all(|l| !l.starts_with(char::is_whitespace)));
        assert_eq!(text, process_start_time_prometheus_text());
    }

    /// The hook replaces SQLite's default auto-checkpoint; a later
    /// `PRAGMA wal_autocheckpoint` on the ledger connection would silently
    /// undo it, so no production source may issue that pragma.
    #[test]
    fn no_code_sets_wal_autocheckpoint() {
        fn walk(dir: &std::path::Path, hits: &mut Vec<String>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    walk(&p, hits);
                } else if p.extension().is_some_and(|x| x == "rs")
                    && !p.ends_with("follow_timing.rs")
                {
                    let text = std::fs::read_to_string(&p).unwrap().to_lowercase();
                    for pat in ["pragma wal_autocheckpoint", "sqlite3_wal_autocheckpoint"] {
                        if text.contains(pat) {
                            hits.push(format!("{}: {pat}", p.display()));
                        }
                    }
                }
            }
        }
        let mut hits = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut hits,
        );
        assert!(hits.is_empty(), "{hits:?}");
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
        // synchronous=OFF + batched inserts: fast on CI, same WAL behaviour.
        conn.execute_batch("PRAGMA synchronous=OFF;").unwrap();
        for _ in 0..6 {
            // ~500 x 8 KiB rows per commit => >1000 WAL frames per commit.
            conn.execute_batch("BEGIN;").unwrap();
            for _ in 0..500 {
                conn.execute("INSERT INTO t VALUES (zeroblob(8192))", [])
                    .unwrap();
            }
            conn.execute_batch("COMMIT;").unwrap();
        }
        assert!(
            follow_timing().wal_checkpoint.count() > before,
            "auto-checkpoint must have been timed"
        );
        // The checkpoint really ran: the WAL is reset and reused instead of
        // growing to the ~24 MB written (3000 rows x 8 KiB).
        let wal = std::fs::metadata(dir.join("t.sqlite-wal")).unwrap().len();
        assert!(wal < 16 * 1024 * 1024, "wal grew unbounded: {wal}");
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
