//! Shared types + helpers for the `trie_replay` perf bench (TASK-145 / PLAN-144).
//!
//! This module is the Rust side of a deterministic Rust↔Go perf comparison
//! for go-algorand's `crypto/merkletrie` hot paths. It exposes:
//!
//! - [`generate_elements`] — deterministic 36-byte AccountHashBuilderV6
//!   inputs identical to the Go counterpart (`tools/go-trie-replay-bench`).
//! - [`PhaseStats`], [`TrieReplayResult`] — JSON shape consumed by the
//!   `trie_bench_compare` binary. The Go bench writes the same shape, so
//!   the two files are directly comparable.
//! - [`stats_from_durations`] — median/p99/mean/total reduction over a raw
//!   `Vec<Duration>`. Both Rust and Go reductions go through identical
//!   formulas (linear-interpolation percentile on sorted samples) so the
//!   ratios are not skewed by binning differences.
//!
//! Element generation mirrors `tools/merkle-trie-root-capture/main.go`'s
//! `makeElementSeq`: seed = LE 4 bytes of the index, affinity = BE u32 of
//! the index, payload bytes 5..32 = SHA512/256(seed)[1..32], kind = 0.
//! The Go bench reproduces this byte-for-byte so the input sets are
//! provably identical (`input_hash_hex` in the JSON is SHA512/256 over the
//! concatenated element bytes — both sides emit the same digest).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512_256};
use std::time::Duration;

/// Bytes per element. Matches go-algorand's `AccountHashBuilderV6` layout
/// (`ledger/store/trackerdb/hashing.go:64`).
pub const ELEMENT_SIZE: usize = 36;

/// Build a single 36-byte element. Byte-for-byte identical to
/// `tools/merkle-trie-root-capture/main.go::makeElement`.
pub fn make_element(affinity: u32, seed: &[u8]) -> [u8; ELEMENT_SIZE] {
    let mut hasher = Sha512_256::new();
    hasher.update(seed);
    let hash = hasher.finalize();
    let mut e = [0u8; ELEMENT_SIZE];
    e[0..4].copy_from_slice(&affinity.to_be_bytes());
    e[4] = 0; // HashKind::Account
    e[5..36].copy_from_slice(&hash[1..32]);
    e
}

/// Deterministic input set of `n` 36-byte elements.
///
/// Each element `i` is built with `affinity = i` (BE u32) and
/// `seed = [i as u8, (i >> 8) as u8, (i >> 16) as u8, (i >> 24) as u8]`.
/// This is byte-identical to the Go counterpart's `makeElementSeq(n)`.
pub fn generate_elements(n: usize) -> Vec<[u8; ELEMENT_SIZE]> {
    (0..n)
        .map(|i| {
            let i32_val = i as u32;
            let seed = [
                (i32_val & 0xff) as u8,
                ((i32_val >> 8) & 0xff) as u8,
                ((i32_val >> 16) & 0xff) as u8,
                ((i32_val >> 24) & 0xff) as u8,
            ];
            make_element(i32_val, &seed)
        })
        .collect()
}

/// SHA512/256 over the concatenated element bytes — a cheap verifier that
/// both implementations are running on the same input set. Hex-encoded for
/// the JSON output.
pub fn hash_input_set(elements: &[[u8; ELEMENT_SIZE]]) -> String {
    let mut hasher = Sha512_256::new();
    for e in elements {
        hasher.update(e);
    }
    hex::encode(hasher.finalize())
}

/// Per-phase descriptive stats. All durations in nanoseconds (integer); the
/// `total_ms` field is a convenience float for the human-readable report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PhaseStats {
    /// "apply" | "commit" | "cold-load".
    pub phase: String,
    /// 50th percentile per-iter duration, in nanoseconds.
    pub median_ns: u64,
    /// 99th percentile per-iter duration, in nanoseconds (linear interp).
    pub p99_ns: u64,
    /// Arithmetic mean per-iter duration, in nanoseconds.
    pub mean_ns: u64,
    /// Sum of all samples, in milliseconds (for quick "how long did the
    /// whole phase take" sanity-checks against wall clock).
    pub total_ms: f64,
    /// Number of timing samples collected for this phase.
    pub n_samples: usize,
    /// Per-sample workload size: for "apply" this is the number of
    /// `trie.add()` calls per sample; for "commit" / "cold-load" the
    /// per-sample workload is always one operation, but the WORKING SET
    /// is `n_elements` elements.
    pub n_elements: usize,
}

/// Full JSON shape written by each implementation. Both sides write to
/// disk, then [`trie_bench_compare`](../bin/trie_bench_compare/index.html)
/// reads and pairs them up.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrieReplayResult {
    /// "rust" or "go".
    pub implementation: String,
    /// Size of the working set (1000 elements is the canonical run).
    pub n_elements: usize,
    /// SHA512/256 of the concatenated input bytes; both implementations
    /// must emit the same digest for a meaningful comparison.
    pub input_hash_hex: String,
    /// Stats for each of the three phases ("apply", "commit", "cold-load").
    pub phases: Vec<PhaseStats>,
}

/// Reduce a `Vec<Duration>` to descriptive stats. The percentile is
/// linear-interpolation on a sorted copy. Empty input returns all-zero
/// fields except `n_samples` so JSON shape stays valid.
pub fn stats_from_durations(phase: &str, n_elements: usize, samples: &[Duration]) -> PhaseStats {
    if samples.is_empty() {
        return PhaseStats {
            phase: phase.to_string(),
            median_ns: 0,
            p99_ns: 0,
            mean_ns: 0,
            total_ms: 0.0,
            n_samples: 0,
            n_elements,
        };
    }

    let mut sorted_ns: Vec<u128> = samples.iter().map(|d| d.as_nanos()).collect();
    sorted_ns.sort_unstable();

    let total_ns: u128 = sorted_ns.iter().sum();
    let mean_ns = (total_ns / samples.len() as u128) as u64;

    let median_ns = percentile_ns(&sorted_ns, 0.50) as u64;
    let p99_ns = percentile_ns(&sorted_ns, 0.99) as u64;
    let total_ms = (total_ns as f64) / 1_000_000.0;

    PhaseStats {
        phase: phase.to_string(),
        median_ns,
        p99_ns,
        mean_ns,
        total_ms,
        n_samples: samples.len(),
        n_elements,
    }
}

/// Linear-interpolation percentile on a sorted slice. `p` is in `[0, 1]`.
fn percentile_ns(sorted: &[u128], p: f64) -> u128 {
    debug_assert!(!sorted.is_empty());
    debug_assert!((0.0..=1.0).contains(&p));
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = p * (sorted.len() as f64 - 1.0);
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        return sorted[lo];
    }
    let lo_v = sorted[lo] as f64;
    let hi_v = sorted[hi] as f64;
    let frac = rank - lo as f64;
    (lo_v + frac * (hi_v - lo_v)).round() as u128
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elements_are_deterministic_across_runs() {
        // The primary determinism gate: byte-identical input across runs.
        // Trivially true for a SHA-seeded generator, but pinning it as a
        // test means a future refactor that accidentally introduces
        // non-determinism (random affinity, time-based seed, etc.) fails
        // visibly.
        let a = generate_elements(256);
        let b = generate_elements(256);
        assert_eq!(a, b, "input set must be byte-identical across runs");
        assert_eq!(hash_input_set(&a), hash_input_set(&b));
    }

    #[test]
    fn element_layout_matches_account_hash_builder_v6() {
        // affinity goes in bytes 0..4 BE, kind byte at 4 is zero, payload
        // is hash[1..32]. Mirrors the Go capture tool — see
        // `tools/merkle-trie-root-capture/main.go::makeElement`.
        let e = make_element(0xAA_BB_CC_DD, &[0x01]);
        assert_eq!(&e[0..4], &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(e[4], 0);

        // Recompute the payload independently.
        let mut hasher = Sha512_256::new();
        hasher.update([0x01u8]);
        let h = hasher.finalize();
        assert_eq!(&e[5..36], &h[1..32]);
    }

    #[test]
    fn percentile_handles_single_and_multi_samples() {
        assert_eq!(percentile_ns(&[100], 0.5), 100);
        assert_eq!(percentile_ns(&[100], 0.99), 100);

        // 0..=99 → median ≈ 49.5 → rounds to 50; p99 ≈ 98.01 → rounds to 98.
        let s: Vec<u128> = (0..100).collect();
        assert_eq!(percentile_ns(&s, 0.50), 50);
        assert_eq!(percentile_ns(&s, 0.99), 98);
    }

    #[test]
    fn stats_from_durations_empty_input_returns_zeros() {
        let s = stats_from_durations("apply", 1000, &[]);
        assert_eq!(s.n_samples, 0);
        assert_eq!(s.median_ns, 0);
        assert_eq!(s.p99_ns, 0);
        assert_eq!(s.mean_ns, 0);
        assert_eq!(s.total_ms, 0.0);
    }

    #[test]
    fn stats_from_durations_single_sample() {
        let s = stats_from_durations("commit", 1000, &[Duration::from_nanos(1_000_000)]);
        assert_eq!(s.n_samples, 1);
        assert_eq!(s.median_ns, 1_000_000);
        assert_eq!(s.p99_ns, 1_000_000);
        assert_eq!(s.mean_ns, 1_000_000);
        assert!((s.total_ms - 1.0).abs() < 1e-9);
    }
}
