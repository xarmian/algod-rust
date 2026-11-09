# Phase 23 performance pass: hotspots, measurements and what is left

Epic [#2101](https://github.com/xarmian/algod-rust/issues/2101), issue
[#2110](https://github.com/xarmian/algod-rust/issues/2110). This document is
the ranked record of what the Phase 23 measurements found, what was changed
for each finding, with which before/after numbers and parity guard, and what is
still open. It is written from the measurements gathered while the phase ran
(issue and PR text, the published baseline in
[`BENCHMARK_RESULTS.md`](BENCHMARK_RESULTS.md), the DIV register); **no new
profiling pass was done for it**, and every number below says where it comes
from. Method and fairness rules: [`BENCHMARK_COMPARISON.md`](BENCHMARK_COMPARISON.md).
Evidence map per acceptance criterion: [`PHASE23_VALIDATION.md`](PHASE23_VALIDATION.md).

## How to read the numbers

- **Hosts differ between rows, and some rows are n = 1.** Each row says which
  host it ran on (the published baseline: an i7-13700 desktop, Ubuntu in WSL2,
  `RUNS=3`; the sync and WAL work: native Windows or WSL2 runs against the live
  betanet; the AVM row: native Windows, criterion). Only ratios measured on the
  same host in the same session are compared with each other.
- **A side is only called faster when the min-max ranges do not overlap**
  (n = 3 gives no confidence interval). Where noise was bimodal it is said.
- **Parity first.** An optimization that changes a verdict, a byte, an error
  text or a response is a bug however fast it is. Each row names its guard.
- **Where an optimization showed no gain it was not kept** (or not opened as a
  PR): rows 2 and 7 are measured "not worth it" results, recorded so nobody
  repeats them.

## Ranked hotspots

Ranked by the size of the effect that was measured (or, for the open rows, by
the size of the gap that is still measured). "Status" is the state of the work,
not of the issue.

| # | Hotspot | Measured (before to after) | Status | Issue / PR | Parity guard |
|---|---|---|---|---|---|
| 1 | Block replay after fast catchup | betanet live replay, algod-rust only: 21.3 to ~63 blocks/s after removing the 256-block pass cap and the 2 x 4 s idle between passes (n = 1 native runs; go 102 on the same host in the issue's measurement); then 54.1 to 86.7 blocks/s (+60 %, 3 alternating runs on the final head, two earlier sets 55.3 to 87.7 and 55.9 to 87.7) after a fetch window of 2x the concurrent fetches (profile: 11.1 of 16 fetches in flight on average, because a permit only returned when its round was applied). Original gap in the `catchup` tier, n = 1: 133 blocks/s go vs 22 algod-rust. | landed; gap to go not closed or reproduced | #2165 / PR #2203, #2204 / PR #2236 (DIV-010) | block-hash gate: hashes of five recent rounds equal to a public node after every run; `catchup_service` window/gate tests (`a_slow_round_does_not_idle_the_other_workers`, `sync_range_fetch_window_never_exceeds_the_parallel_budget`, tip-gate tests); fetch path and authentication untouched |
| 2 | Certificate authentication | `testnet-head` replay (20,000 rounds), Windows: 127 s to 44 s; Linux/WSL2: 143 s to 76 s against go's 38 s (Rust/Go wall ratio 3.8 to 2.0). Profile: authentication was 102 of 120 s, per vote 77 us OTS + 100 us VRF/sortition + 24 us membership. A second step, authenticating lookahead rounds concurrently (branch `perf/issue-2201-lookahead-auth`), measured 214.8/207.1/204.2 vs 203.5/209.8/206.1 blocks/s (n = 3 alternating): **no gain**, closed, branch kept. | landed (parallel votes); lookahead rejected | #2145 / PR #2202; #2201 (closed, no PR) | result-identical differential test against the kept reference implementation; replay final-state equality; accept/reject semantics of `cert.Authenticate` unchanged |
| 3 | Tracker SQLite WAL growth | betanet catchup + ~15 min replay, n = 1: 1,280 MB on disk vs go 126 MB, 2.04 GB vs 1.05 GB written to the block device. Cause: the pool evaluator keeps a `ReadSnapshot` alive across every commit, so the WAL is never restarted (~80 KB per block). Fix: checkpoint when opening a read snapshot (DIV-008), `journal_size_limit` 64 MiB on the writing connections. Native, 1500-round follow with a snapshot handover per block: 225 KB flat with the fix vs 3,263 to 23,356 KB without (about 16 KB per round); `wal_overlapping_reader_test`: 230 KB vs 2.7 MB over 200 rounds; unit-scale pinned-snapshot test: 7,045,232 B on disk after the snapshot ended without the limit, 262,144 B with it. Cost: about 0.8 ms per round (12.4 s vs 11.2 s for 1500 rounds) under the ledger lock. | landed; Docker `disk_mb`/`blockio_write_mb` n >= 3 and growth during a long export not measured | #2166 / PR #2208 (DIV-008), #2206 / PR #2240, #2209 / PR #2211 (DIV-009); open: #2205, #2206 | 15 `wal_overlapping_reader_test` tests including 120 randomized hard kills of a committing process; replay-corpus final-state equality; `Bench Ledger Replay` green |
| 4 | Redundant per-block hashing and txtail work in `checkDup` | Removed: re-hashing the payset in every scratch pass of block assembly (#2132), the pre-pass's second payset hash and second confirmed-set query (#2134), re-decoding every in-span txtail row on each lookup (#2134 span txid cache), the group's checkDup seed (#2131). **No wall-clock numbers were recorded**: the evidence is operation counts (payset hashed once, confirmed set loaded once, in-span rows decoded once per span). | landed; time effect unmeasured | #2131 / PR #2231, #2132 / PR #2232, #2134 / PR #2235 | `block_checkdup_oracle_test`, the new counter tests (`the_prepass_reuses_the_executions_txids_and_confirmed_set`, `in_span_txtail_rows_are_decoded_once_per_span`, `evaluate_payset_uses_the_supplied_txids_instead_of_rehashing`), verdicts and error texts unchanged (debug builds also assert the reused txids equal a rehash) |
| 5 | Catchup peak RSS | The issue's 701 MB (algod-rust) vs 396 MB (go) came from `docker stats` (counts page cache) and was **not reproduced natively**: peak VmHWM 183.7 / 188.3 / 180.2 / 195 MB over five betanet catchups, steady state at the head 88 to 113 MB. The peak is a 0.6 to 1.5 s transient of the catchpoint import (30,039 accounts, 67 chunks: anon 11 to 155 MB) plus ~13 MB of trie verify. Block replay contributes nothing (replay-corpus peak RSS 27 to 36 MB). Refuted: the importer's 256 MiB SQLite `cache_size` (lowered to 32 MiB, peak unchanged, n = 2). Candidate: glibc arenas (one 64 MiB; `MALLOC_ARENA_MAX=2` peak 161 MB, n = 1, so about 12 to 14 % of the peak and up to ~30 MB of steady state, not enough to ship). | attribution only, no reduction | #2207 / PR #2241 (tooling) | none needed (no production change) |
| 6 | Rust vs go on AVM micro pairs; the "AVM contexts clone `ConsensusParams`" hypothesis | Published baseline (WSL2 desktop, n = 3): `avm/lsig-arith-loop` go 126.6 us vs Rust 158.3 (1.25x), `avm/app-state-box` 8.9 vs 12.5 us (1.40x), `avm/lsig-bytes-ops` level, `avm/lsig-hash-loop` Rust 1.07x faster. **Hypothesis refuted** (#2114): `ConsensusParams` is 160 plain fields, its `approved_upgrades` map lives on `ConsensusParamsOverride`, so a clone is one ~1.3 KB copy: **~9 ns** (release, 200k clones) against evaluations of 29 us to 550 us. Criterion A/B on this host (native Windows, n = 5 alternating, nothing else running), medians in us with [min, max]: `app-state-box` 29.2 [28.7, 30.1] vs 28.9 [28.7, 30.0]; `lsig-arith-loop` 365.2 [355.8, 369.8] vs 363.4 [330.0, 367.9]; `lsig-bytes-ops` 554.9 [537.6, 579.7] vs 549.8 [539.9, 561.0]; `lsig-hash-loop` 83.5 [81.9, 85.9] vs 83.6 [82.2, 84.9]: all within the spread (at most 1 %). A run with other builds going in parallel was bimodal (`lsig-arith-loop` 242 / 235 / 485 us), so only the quiet set is quoted. | change built and verified (borrow instead of clone through `Cow`), **not pushed**: measured no gain | #2114 (closed, no PR; branch `perf/issue-2114-avm-context-borrow` local only) | `cargo test` for algo-avm/validate/ledger/bench-pairs, `avm_opcode_conformance`, clippy `-D warnings`; the real AVM gap is not the clone |
| 7 | Localnet commit latency: a fixed 200-transaction set took 18 rounds on an all-Rust cluster, 1 on all-Go | Smoke run, 1 CPU / 2 GB per container: Go commits in 1 round, Rust 17 to 19 rounds (about 11 txns per block), p95 latency ~3.6x. Root cause was a **bug, not a cost**: participation nodes never registered a `NodeInfo` with the WS/P2P transports, so `wantTXGossip` was always false and TX interest was dropped. After the fix 3 rounds (Go 2). | fixed | #2150 / PR #2153; live mixed-cluster check #2154 open | the localnet tier's txid-set equality gate; mixed-cluster conformance |
| 8 | `POST /v2/transactions/simulate` throughput | baseline `rest` smoke, concurrency 4: 1,112 vs 5,068 req/s (4.6x fewer), p50 3.7 vs 0.65 ms; concurrency 16 (issue measurement): ~1,290 vs ~4,470 req/s. Every other endpoint is level or faster in Rust. | **open, not profiled** | #2162 | the `rest` tier's response-equality gate (allowlist empty) and the simulate conformance tests |
| 9 | Codec and certificate/proposal decode in the micro pairs | Baseline, n = 3: go faster by 1.4x (block hash, large block decode, txid), 1.1x to 2.1x on encode, 2.7x (certificate) and 2.9x (proposal) on decode; Rust faster on Ed25519 (1.15x), VRF and credential verify (1.4x), sortition-select (45x). | **open, prime candidates, not profiled** | none filed | micro pairs' output-equivalence check (`cargo test -p algo-bench-pairs`), golden fixtures |

Where algod-rust is ahead in the published baseline (n = 3): peak RSS 5x to 7x
lower in replay and 6.5x lower on the localnet (1152 vs 178 MB), block-device
writes about 70x lower on the localnet (175.2 vs 2.5 MB), most REST read
endpoints 5 to 45 % more requests/s with lower tail latency.

## Findings that changed the work

- **The hot paths were not where the issue text guessed** twice: #2114 (the
  clone is nanoseconds) and #2207 (the RSS figure was page cache in Docker, the
  real peak is a one-second import transient). Both were found by measuring
  before changing code.
- **Two real optimizations were limited by one structural cap each** (the
  256-block catchup pass and the permit that only returned on apply); both were
  found with a per-fetch timeline, not a CPU profile.
- **The WAL problem looked like a SQLite setting and was a reader that never
  went away**; the setting-level suspects were checked and ruled out in the PR.
- **The benchmark gates found parity bugs as well as slow paths.** Beyond the
  optimizations above, the `replay`/`rest`/`localnet` equality gates and the
  corpus work surfaced consensus and API findings that were fixed under the
  same phase label (for example the rewards pool never debited, `checkDup` in
  validate mode, simulate round selection and response shape, `/v2/accounts`
  fields). They are listed in [`PHASE23_VALIDATION.md`](PHASE23_VALIDATION.md).

## Open items

| Issue | What is left | Why it is not done |
|---|---|---|
| #2204 | Docker `catchup` tier row (`replay_blocks_per_s`, n >= 3) and the comparison against go at the same window; the remaining gap is relay latency (the WS adds 50 to 120 ms over the TCP RTT) | needs the Docker daemon and a go build on the measuring host |
| #2205 | `disk_mb` / `blockio_write_mb` of the catchup tier before and after the WAL fix, n >= 3 | same |
| #2206 | WAL growth **during** a long export cannot be bounded (short of copying the database or versioned reads); not measured at mainnet scale | design limit; ~80 KB per block over a minutes-long export is tens of MB |
| #2207 | heap-level attribution of the ~140 MB import transient, a go-side measurement, a mainnet-sized state | no heap profiler on the measuring host; next step is a counting allocator or jemalloc in a throwaway build |
| #2162 | profile and fix simulate | not started |
| (none filed) | codec encode/decode/txid/commitment and certificate/proposal decode (rows 9) | not started; the baseline says where to look first |
| #2146 | replay corpus covering proposer payouts and state proofs (catchpoint start) | corpus work |
| #2151, #2167, #2169 | bench harness follow-ups (pool metrics in the localnet tier, the catchup tier's mock network) | tooling |

## Reproducing the numbers

- **Published baseline and any tier:** `make bench-compare TIERS=micro,replay,rest,localnet CORPUS=small RUNS=3`
  (commands, host and prerequisites in [`BENCHMARK_RESULTS.md`](BENCHMARK_RESULTS.md#environment-and-how-to-reproduce)).
  The baseline predates the optimizations in rows 1 to 4; **a post-optimization
  refresh of that report was not run for this document** (it needs the Docker
  daemon and quiet dedicated hardware) and is the first item to do before the
  epic is closed.
- **Criterion A/B (row 6):** `cargo bench -p algo-bench-pairs --bench pairs -- avm/`
  from a clean checkout of each side, alternating, n >= 3, nothing else running.
- **Live catchup replay (rows 1, 5):** `python3 scripts/bench/catchup_native.py --bin <algod-rust> --genesis docker/algod/genesis/betanet/genesis.json --follow-secs 60`
  (records `blocks/s`, the block-hash gate and, since #2241, per-phase memory);
  needs the public network and is not part of CI.
- **WAL (row 3):** `cargo test -p algo-ledger --test wal_overlapping_reader_test`.
- **Replay-corpus peak RSS (row 5):** `bench replay-corpus` on the `small`,
  `testnet-prefix50` and `testnet-head` corpora (`docs/BENCHMARK_COMPARISON.md`).
- **Per-optimization parity gates:** `cargo test -p algo-ledger -p algo-validate -p algo-avm`,
  `cargo test -p algo-conformance --test avm_opcode_conformance`,
  `python3 scripts/check_divergences.py`, `python3 scripts/phase17_parity_delta.py check`
  (fails only on the 3 known `partial` rows).
