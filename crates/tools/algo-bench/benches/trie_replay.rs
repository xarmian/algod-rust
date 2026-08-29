// Copyright (c) 2026 Algod DAO
//
// SPDX-License-Identifier: MIT
// For the full license text, see LICENSE-MIT at the repository root.

//! Trie replay perf bench (TASK-145 / PLAN-144).
//!
//! Runs three measured phases against the Rust `MerkleTrie`:
//!
//! 1. **apply**  — sequence of `N` `trie.add()` calls on a fresh trie
//!    (in-memory mutations only; no commit).
//! 2. **commit** — one `trie.commit()` on a trie pre-populated with `N`
//!    elements; measures node serialization + page writes against
//!    [`InMemoryPageCommitter`].
//! 3. **cold-load** — one `MerkleTrie::load(&committer)` against a
//!    populated committer; measures the bytes → tree path.
//!
//! Each phase runs `SAMPLES` iterations (default 20). Per-iter durations
//! are reduced to median / p99 / mean / total and written as JSON to
//! `target/bench-results/trie_replay-rust.json`. The Go counterpart in
//! `tools/go-trie-replay-bench/` emits the same JSON shape; the
//! `trie_bench_compare` binary diff's them and updates `docs/PERF_TRIE.md`.
//!
//! Env vars (override the defaults without recompiling):
//!
//! - `TRIE_BENCH_N`       — working-set element count. Default 1000.
//! - `TRIE_BENCH_SAMPLES` — per-phase samples. Default 20.
//! - `TRIE_BENCH_OUT`     — output JSON path. Default
//!   `target/bench-results/trie_replay-rust.json`.
//!
//! Committer choice: [`InMemoryPageCommitter`] on both sides. Go's
//! `crypto/merkletrie` ships no SQLite-backed committer; the trackerdb
//! SQLite layer is out of scope for this bench (it's filesystem-dominated
//! and orthogonal to the trie's hot paths). See `docs/PERF_TRIE.md`
//! "Methodology → Out of scope" for the full reasoning.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use std::sync::Mutex;

use algo_bench::trie_replay::{
    generate_elements, hash_input_set, stats_from_durations, PhaseStats, TrieReplayResult,
    ELEMENT_SIZE,
};
use algo_error::AlgoError;
use algo_ledger::merkle_cache::{InMemoryPageCommitter, PageCommitter};
use algo_ledger::merkle_trie::MerkleTrie;

fn env_usize(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_path(var: &str, default: &str) -> PathBuf {
    std::env::var(var)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(default))
}

/// Workspace root, computed from `CARGO_MANIFEST_DIR`. The crate lives at
/// `crates/tools/algo-bench/`, so three `..`s reach the workspace root.
/// This makes the default JSON path stable regardless of where the user
/// invokes `cargo bench` from.
fn workspace_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).join("..").join("..").join("..")
}

/// Phase 1 — apply: build a fresh trie and `add()` every element.
/// Per sample we rebuild the trie so the measurement isn't polluted by
/// previous-sample state. The measurement region is exactly the `add`
/// loop; trie construction is excluded.
fn run_apply_phase(elements: &[[u8; ELEMENT_SIZE]], samples: usize) -> Vec<Duration> {
    let mut out = Vec::with_capacity(samples);
    for _ in 0..samples {
        let mut trie = MerkleTrie::new(ELEMENT_SIZE);
        let start = Instant::now();
        for e in elements {
            // unwrap is acceptable in bench code — any error here is a
            // test-data bug, not perf signal.
            let added = trie.add(e).expect("add");
            debug_assert!(added);
        }
        out.push(start.elapsed());
    }
    out
}

/// Phase 2 — commit: build + populate a fresh trie + committer per sample,
/// then time exactly the `commit()` call. The measurement excludes the
/// `add` loop and the committer construction.
fn run_commit_phase(elements: &[[u8; ELEMENT_SIZE]], samples: usize) -> Vec<Duration> {
    let mut out = Vec::with_capacity(samples);
    for _ in 0..samples {
        let mut trie = MerkleTrie::new(ELEMENT_SIZE);
        for e in elements {
            trie.add(e).expect("add");
        }
        let committer = InMemoryPageCommitter::new();
        let start = Instant::now();
        trie.commit(&committer).expect("commit");
        out.push(start.elapsed());
    }
    out
}

/// Phase 3 — cold-load: build a populated committer (out of the
/// measurement region), drop the trie, then time exactly the
/// `MerkleTrie::load(&committer)` call.
fn run_cold_load_phase(elements: &[[u8; ELEMENT_SIZE]], samples: usize) -> Vec<Duration> {
    let mut out = Vec::with_capacity(samples);
    for _ in 0..samples {
        let committer = InMemoryPageCommitter::new();
        {
            let mut trie = MerkleTrie::new(ELEMENT_SIZE);
            for e in elements {
                trie.add(e).expect("add");
            }
            trie.commit(&committer).expect("commit");
        }
        // Clone the committer into a Box so the trie owns its lazy
        // loader (PLAN-144 TASK-146); the original `committer` keeps a
        // shared handle via Arc for sample-loop reuse.
        let loader: Box<dyn algo_ledger::merkle_cache::PageCommitter + Send> =
            Box::new(committer.clone());
        let start = Instant::now();
        let restored = MerkleTrie::load(loader)
            .expect("load")
            .expect("load returned None after commit");
        let elapsed = start.elapsed();
        // Touch a load-time observable so the optimizer can't dead-code
        // the load call. With lazy load, `len()` only reflects in-memory
        // leaves — for the cold-load bench we only care that the call
        // returned a trie at all.
        let _ = restored.is_empty();
        out.push(elapsed);
    }
    out
}

/// `CountingCommitter` wraps an [`InMemoryPageCommitter`] and tallies
/// bytes written via `store_page` (including empty-payload deletes,
/// which count as 0). Used by the `add_then_commit_bytes_written`
/// measurement (PLAN-144 TASK-149) to compare write-amplification on a
/// single incremental commit before and after the refurbish refactor.
struct CountingCommitter {
    inner: InMemoryPageCommitter,
    bytes_written: Mutex<u64>,
    stores_called: Mutex<u64>,
}

impl CountingCommitter {
    fn new() -> Self {
        Self {
            inner: InMemoryPageCommitter::new(),
            bytes_written: Mutex::new(0),
            stores_called: Mutex::new(0),
        }
    }

    fn snapshot(&self) -> (u64, u64) {
        (
            *self.bytes_written.lock().unwrap(),
            *self.stores_called.lock().unwrap(),
        )
    }

    fn reset(&self) {
        *self.bytes_written.lock().unwrap() = 0;
        *self.stores_called.lock().unwrap() = 0;
    }
}

impl PageCommitter for CountingCommitter {
    fn load_page(&self, id: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        self.inner.load_page(id)
    }
    fn store_page(&self, id: u64, content: &[u8]) -> Result<(), AlgoError> {
        *self.stores_called.lock().unwrap() += 1;
        *self.bytes_written.lock().unwrap() += content.len() as u64;
        self.inner.store_page(id, content)
    }
}

/// Measure the byte cost of a SINGLE incremental commit — the
/// scenario refurbish is designed to optimize.
///
/// Sequence (per sample):
///   1. Build a fresh trie + commit `n_seed` elements (out of the
///      measured window).
///   2. Reset the counter.
///   3. Add ONE extra element.
///   4. Commit. Tally bytes written + store calls.
///
/// Returns (median bytes_written, median store_page calls) across
/// `samples` runs.
fn run_incremental_commit_bytes(
    elements: &[[u8; ELEMENT_SIZE]],
    extra: &[u8; ELEMENT_SIZE],
    samples: usize,
) -> (u64, u64) {
    let mut byte_samples: Vec<u64> = Vec::with_capacity(samples);
    let mut store_samples: Vec<u64> = Vec::with_capacity(samples);
    for _ in 0..samples {
        let committer = CountingCommitter::new();
        let mut trie = MerkleTrie::new(ELEMENT_SIZE);
        for e in elements {
            trie.add(e).expect("seed add");
        }
        trie.commit(&committer).expect("seed commit");
        committer.reset();

        // Add one element, commit; counter now reflects ONLY this
        // incremental commit.
        let _ = trie.add(extra).expect("incremental add");
        trie.commit(&committer).expect("incremental commit");
        let (bytes, stores) = committer.snapshot();
        byte_samples.push(bytes);
        store_samples.push(stores);
    }
    byte_samples.sort_unstable();
    store_samples.sort_unstable();
    let median_bytes = byte_samples[byte_samples.len() / 2];
    let median_stores = store_samples[store_samples.len() / 2];
    (median_bytes, median_stores)
}

fn print_summary(result: &TrieReplayResult, out_path: &std::path::Path) {
    eprintln!(
        "trie_replay (rust): n_elements={} input_hash={}",
        result.n_elements, result.input_hash_hex
    );
    for p in &result.phases {
        eprintln!(
            "  phase={:<10} samples={:>3}  median={:>10} ns  p99={:>10} ns  mean={:>10} ns  total={:>9.2} ms",
            p.phase, p.n_samples, p.median_ns, p.p99_ns, p.mean_ns, p.total_ms
        );
    }
    eprintln!("wrote {}", out_path.display());
}

fn main() {
    let n = env_usize("TRIE_BENCH_N", 1000);
    let samples = env_usize("TRIE_BENCH_SAMPLES", 20);
    // Default anchored on workspace root so the path is stable regardless
    // of whether the user invokes from the workspace root or the crate dir.
    let default_out = workspace_root().join("target/bench-results/trie_replay-rust.json");
    let out_path = env_path(
        "TRIE_BENCH_OUT",
        default_out.to_str().expect("workspace path utf8"),
    );

    let elements = generate_elements(n);
    let input_hash_hex = hash_input_set(&elements);

    // Brief warm-up — one full apply pass — to prime allocator caches and
    // the L2/L3 working set. Excluded from the measured samples.
    {
        let mut trie = MerkleTrie::new(ELEMENT_SIZE);
        for e in &elements {
            trie.add(e).expect("warm-up add");
        }
    }

    let apply_durs = run_apply_phase(&elements, samples);
    let commit_durs = run_commit_phase(&elements, samples);
    let load_durs = run_cold_load_phase(&elements, samples);

    // PLAN-144 TASK-149: incremental-commit byte measurement. Uses an
    // element OUTSIDE the seed set so the add is guaranteed
    // non-duplicate.
    let extra_element =
        algo_bench::trie_replay::make_element(u32::MAX, b"task-149 incremental commit probe");
    let (incremental_bytes, incremental_stores) =
        run_incremental_commit_bytes(&elements, &extra_element, samples);
    eprintln!(
        "incremental_commit (rust): bytes_written_median={} store_page_calls_median={}",
        incremental_bytes, incremental_stores,
    );

    let phases: Vec<PhaseStats> = vec![
        stats_from_durations("apply", n, &apply_durs),
        stats_from_durations("commit", n, &commit_durs),
        stats_from_durations("cold-load", n, &load_durs),
    ];

    let result = TrieReplayResult {
        implementation: "rust".to_string(),
        n_elements: n,
        input_hash_hex,
        phases,
    };

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|e| panic!("create dir {}: {}", parent.display(), e));
    }
    let json = serde_json::to_string_pretty(&result).expect("serialize JSON");
    std::fs::write(&out_path, json)
        .unwrap_or_else(|e| panic!("write {}: {}", out_path.display(), e));

    print_summary(&result, &out_path);
}
