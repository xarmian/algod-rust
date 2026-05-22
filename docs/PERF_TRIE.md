# Merkle trie perf — Rust ↔ Go

Tracks the deterministic perf comparison between algod-rust's `MerkleTrie`
and go-algorand v4.5.1-stable's `crypto/merkletrie`. Established by
TASK-145 (PLAN-144); subsequent perf tasks in PLAN-144 update the
**Latest measurements** block below by re-running the bench.

The original perf target — TASK-137 in PLAN-130 — is **Rust wall-clock /
Go wall-clock ≤ 1.5×** on the canonical workload. The plan-level
acceptance gate in PLAN-144 enforces this number on close-out.

## Methodology

Three phases, run on identical input on both sides:

| Phase | What's measured |
|-------|-----------------|
| `apply` | `N` sequential `trie.add()` calls on a fresh in-memory trie. Excludes trie construction. |
| `commit` | One `trie.commit()` against an [`InMemoryCommitter`] after the trie is pre-populated with `N` elements. Excludes the add loop and committer construction. |
| `cold-load` | One `MerkleTrie::load(&committer)` / `MakeTrie(&committer, ...)` against a populated committer. Excludes committer construction. |

**Input set.** `N` 36-byte elements in the `AccountHashBuilderV6` layout
(affinity[4] || kind[1] || hash[1..32]), generated deterministically from
SHA512/256-seeded counters. Byte-for-byte identical on both sides — the
`input_hash_hex` field in the JSON output is the SHA512/256 of the
concatenated input bytes, and the comparison tool refuses to produce a
report unless both implementations emit the same digest.

**Sample size.** 20 per-phase samples by default; configurable via
`TRIE_BENCH_SAMPLES`. Reductions are linear-interpolation percentile on
sorted samples; both sides use the same formula so the median/p99 values
are directly comparable (no binning skew).

**Committer choice.** [`InMemoryPageCommitter`] on Rust, `InMemoryCommitter`
on Go. This isolates trie-perf (serialization, page layout, hash
accumulator, recompute path) from filesystem-dominated SQLite I/O.

### Out of scope

- **End-to-end SQLite I/O.** Go's `crypto/merkletrie` doesn't ship a
  SQLite-backed committer; the trackerdb SQLite layer is a separate
  concern. Including it would compare different code surfaces and obscure
  the trie-perf signal.
- **Cross-machine ratios.** The bench reports machine-local Rust↔Go
  ratios. Absolute wall-clock between dev machines is undefined; compare
  ratios, not nanoseconds.
- **`Delete` perf.** The block-apply phase exercises the trie's hot
  insertion path; `Delete` perf is dwarfed by `Commit` for our workload
  shapes and isn't on the critical path.

## Running the bench

### Prerequisites

- `go-algorand` checked out at `v4.5.1-stable` as a sibling of
  `algod-rust` (`../go-algorand`).
- Rust toolchain (workspace `rust-version`).
- Go 1.25+.

### One-shot — Rust + Go + comparison

```bash
# from the algod-rust repo root
cargo bench -p algo-bench --bench trie_replay
( cd tools/go-trie-replay-bench && go run . )
cargo run -p algo-bench --bin trie_bench_compare
```

The third command writes `docs/PERF_TRIE.md`'s **Latest measurements**
block (this file) and prints the terminal ratio table.

### Configuration

Both benches accept the same env vars:

| Env var              | Default                                                  | Meaning |
|----------------------|----------------------------------------------------------|---------|
| `TRIE_BENCH_N`       | `1000`                                                   | Working-set element count. |
| `TRIE_BENCH_SAMPLES` | `20`                                                     | Per-phase samples. |
| `TRIE_BENCH_OUT`     | (per side; see below)                                    | Output JSON path. |

Default output paths:

- Rust: `target/bench-results/trie_replay-rust.json`
- Go:   `tools/go-trie-replay-bench/bench-results/trie_replay-go.json`

`trie_bench_compare` accepts `--rust-json`, `--go-json`, `--doc-path` and
`--dry-run` overrides.

### Stability

On idle hardware, re-running the bench produces median ratios within
~5%. CI shared hardware is noisier; treat single CI runs as advisory and
prefer local reproduction when defending or attacking a perf claim. The
**input** is byte-identical across runs (asserted by
`crates/tools/algo-bench/src/trie_replay.rs::elements_are_deterministic_across_runs`);
only timing varies.

## Latest measurements

The block below is rewritten in place by `trie_bench_compare`. Hand edits
inside the markers will be lost.

### Interpreting the `cold-load` ratio

Both implementations now lazy-load pages on demand from a populated
committer — `cold-load` is therefore an apples-to-apples comparison:
each side reads only the metadata page (page 0) and defers node-page
reads to first use. Rust's [`MerkleTrie::load`] (PLAN-144 TASK-146)
installs an owned `Box<dyn PageCommitter + Send>` as the cache's
`lazy_loader`; subsequent `get` / `get_mut` calls fetch missing pages
through that committer.

All three phases (`apply`, `commit`, `cold-load`) directly compare the
same code surfaces between Rust and Go.

[`MerkleTrie::load`]: ../crates/core/algo-ledger/src/merkle_trie.rs

<!-- BEGIN BENCH RESULTS -->

_Generated by `cargo run -p algo-bench --bin trie_bench_compare`._

**Working set:** 1000 elements (36 bytes each).  
**Input hash:** `4db522fac595b7dee959efcaecebc1b0b7a4368e4a1b29fad3cf00f10c346730` (Rust = Go).

| Phase | Rust median (ns) | Go median (ns) | Rust/Go median | Rust p99 (ns) | Go p99 (ns) | Rust/Go p99 |
|-------|-----------------:|---------------:|---------------:|--------------:|------------:|------------:|
| `apply` |         2657212 |        2890365 |          0.92× |       3004758 |     4294475 |       0.70× |
| `cold-load` |             847 |           6943 |          0.12× |          1180 |      203061 |       0.01× |
| `commit` |          865162 |         859040 |          1.01× |       1035932 |     2037306 |       0.51× |

Rust samples per phase: 20. Go samples per phase: 20.

<!-- END BENCH RESULTS -->

## Change log

| Date | Phase | Median ratio (Rust/Go) | PR | Notes |
|------|-------|------------------------|----|-------|
| 2026-05-21 | apply | 0.30× | TASK-145 | Baseline. Rust ~3× faster on insertion. |
| 2026-05-21 | commit | 0.23× | TASK-145 | Baseline. Rust ~4× faster on commit + page serialization. |
| 2026-05-21 | cold-load | 20.71× | TASK-145 | Baseline; not apples-to-apples (Go is lazy). See note above; PLAN-144 Task 2 fixes. |
| 2026-05-22 | cold-load | 0.04× | TASK-146 | Lazy load lands. Rust now reads only metadata at load time; ~575× faster than the eager baseline and faster than Go in absolute terms. |
| 2026-05-22 | commit | 0.29× | TASK-147 | Active eviction wired into `SqliteLedger::commit_block`. Commit-phase wall clock unchanged within noise (eviction is amortized; the bench's commit phase doesn't install a loader, so `evict` is a no-op there). Bound on runtime cache memory enforced — verified by `trie_eviction_bound_test::long_replay_keeps_cache_below_target_and_preserves_root`. |
| 2026-05-22 | commit | 1.01× | TASK-148 | Page-packing heuristic ported (`reallocate_pending_pages` + helpers). Rust commit now does the same O(N) page-repack work Go does — wall-clock-equivalent. Trade-off: ~2× the prior Rust-without-heuristic CPU cost, in exchange for page-count parity. 1000-element trie now writes 10 node pages (matches Go), down from 44. |

Reproducer machine (baseline run): local dev; absolute nanoseconds vary,
ratios are the durable metric.

[`InMemoryCommitter`]: ../go-algorand/crypto/merkletrie/committer.go
[`InMemoryPageCommitter`]: ../crates/core/algo-ledger/src/merkle_cache.rs
