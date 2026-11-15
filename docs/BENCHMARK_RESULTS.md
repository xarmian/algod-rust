# Go vs Rust benchmark results (baseline)

Published baseline of the Phase 23 comparison (epic #2101, issues #2109 and
#2322): go-algorand `v5.0.5-stable` against algod-rust `d263d969` (main after
the Phase 23 round-2 optimizations), same machine, same inputs, every macro
tier gated on Go/Rust final-state or response equality. Run on 2026-11-15; the
pre-optimization baseline of 2026-10-31 (go `v5.0.4-stable`, algod-rust
`561f7528`, n = 3) is in the git history of this file and
`benchmarks/baseline.json`. Method and fairness rules:
[BENCHMARK_COMPARISON.md](BENCHMARK_COMPARISON.md). Regenerate the blocks below
with `report.py --publish` (see [Regression detection](#regression-detection-and-ci)).

## Read this first

- **Indicative, not authoritative.** These numbers come from one developer
  machine (a desktop i7-13700 running Ubuntu in WSL2 with Docker inside the
  WSL VM), ten runs per row (`RUNS=10`), so every row carries a 95% confidence
  interval of the median; a side is marked faster only when the two intervals
  do not overlap. The host is virtualised, so noisy neighbours can skew
  results; CI-runner numbers (the weekly `bench-compare` workflow) are noisier
  still. Dedicated, quiet hardware is preferred for anything that becomes a
  decision.
- **Numbers where Rust is behind Go are shown as measured.** Nothing was
  tuned, filtered or re-run to improve a row. Every such row is listed with
  its owner under [Open findings](#open-findings-from-the-epic).
- **Smoke profiles.** `rest` ran its smoke profile (concurrency 4, one
  1-second step per endpoint) and `localnet` its smoke profile (200 fixed
  transactions plus one 10-second step at 50 TPS, 1 relay + 4 participation
  nodes, 2 CPUs / 3 GB per container). Round times are quantised (3 s vs
  3.33 s), so a few-percent `localnet` latency difference on a 10-second step
  is quantisation, not throughput. The full ladders are long runs for quiet
  hardware and are not in this baseline.
- **The 50-round testnet prefix is dominated by certificate authentication and
  startup.** `testnet-prefix50` replays 50 real blocks carrying one transaction;
  it proves that real certificates authenticate identically on both sides and
  says little about steady-state apply speed. It is also the one tier where Go
  is clearly ahead on wall clock (5x), see #2339.
- **Not in this baseline.** The `catchup` tier (public network, hours, not
  reproducible), the full `rest`/`localnet` ladders, and replay of the large
  (~1M transaction) corpus (the decision on how to publish it is pending). The
  small corpus is committed in the repository. The per-hotspot before/after
  measurements, with their hosts and n, are in [PERF_PHASE23.md](PERF_PHASE23.md).

## Headline

All tiers passed their equality gates on this run (replay final state equals
`corpus.json` on both sides; the REST responses are equal modulo the
issue-linked allowlist; both localnets confirmed the same txid set), so every
row below is a like-for-like measurement. The per-tier counts (paired, Rust
faster, Go faster, inconclusive) are generated in each block's "Summary by
tier" table; in words (figures are medians of the tables below):

- **micro**: Rust is faster on 20 of 27 rows (all the codec encode/decode and
  both payset commitments 1.2x to 1.9x, certificate decode 1.6x, AVM
  arithmetic/bytes/hash loops 1.2x to 1.3x, Ed25519/VRF/credential verify
  1.1x to 1.5x, sortition select 44x). Go is faster on three rows: `txid`
  1.19x and `sortition-select-f128` 1.18x (#2321) and `avm/app-state-box`
  1.26x (#2320).
- **replay, small corpus**: Go 1.29 s, Rust 1.41 s wall (Go 1.09x faster, down
  from 3.6x). Rust uses 2.9x less CPU time and 6.3x less peak RSS; it writes
  2.3x more bytes (154 vs 66 MB, #2316) into a 1.12x larger database.
- **replay, testnet-prefix50**: Go 0.11 s, Rust 0.56 s (5.1x slower); Rust CPU
  2.3x lower, peak RSS 4.4x lower. Owner: #2339.
- **rest (smoke, c4)**: Rust is ahead on most endpoints' latency/throughput
  rows and level on the rest; `simulate` (4.6x behind in the first baseline) is
  now level (4,858 vs 4,991 req/s, p99 1.9x lower). Go is 4% faster on
  `account_hot` and 4% to 8% on `simulate_app` (#2340).
- **localnet (smoke)**: level on throughput and round time; Rust peak RSS 5.9x
  lower and block-device writes 37x lower. The only Go-faster rows are the
  p95/p99 confirmation latencies of the 50 TPS step (6,035 vs 5,783 ms, 1.04x):
  one 250 ms sampling quantum of a 3 s round, with equal round time and 1.03x
  higher confirmed TPS in Rust, so a harness quantum, not a node cost.

## Environment and how to reproduce

| Item | Value |
|---|---|
| Machine | desktop, 13th Gen Intel Core i7-13700 (12 physical cores, 24 logical CPUs) |
| RAM | 31.2 GiB visible to the WSL2 VM |
| OS | Windows 11 host; Ubuntu 22.04.5 LTS in WSL2, kernel 6.18.54.1-microsoft-standard-WSL2 (hypervisor `Microsoft`, no CPU frequency governor exposed) |
| Docker | Docker Engine 28.2.1 inside the WSL2 distro; containers limited to 2 CPUs and 3 GB each (`BENCH_REST_CPUS`/`BENCH_LOCALNET_CPUS` and `_MEM` defaults), host has 24 CPUs |
| Toolchains | go 1.25.3, rustc 1.99.1 / cargo 1.99.1, Python 3.13.3 |
| go-algorand | `v5.0.4-stable`, commit `927ae0863cbb4cf29c6845c088a4ea4c439b10bb` (pin file `scripts/bench/go-algorand.pin`, checked by the run) |
| algod-rust | commit `561f7528d912ace27e71c06571b8d590c86ccc53` on the PR branch of #2109; its Rust sources are identical to `main` at `42b3818c` (the branch only adds harness, workflow and documentation files) |
| Runs | `RUNS=3` for every tier, one warm-up round where the tier has one |
| Date | 2026-10-31 |

Build prerequisites on a fresh Ubuntu: `autoconf automake libtool build-essential
pkg-config libssl-dev` (go-algorand's libsodium fork via `make libsodium`, and
the OpenSSL build of one Rust dependency), then:

```bash
BENCH_REST_PROFILE=smoke BENCH_LOCALNET_PROFILE=smoke \
BENCH_REST_RUST_IMAGE=algod-rust:bench-compare BENCH_LOCALNET_RUST_IMAGE=algod-rust:bench-compare \
BENCH_MICRO_GO_BENCHTIME=300ms BENCH_MICRO_CRITERION_ARGS="--warm-up-time 0.5 --measurement-time 1" \
make bench-compare TIERS=micro,replay,rest,localnet CORPUS=small RUNS=3 BENCH_RUN_DIR=bench-results/main
make bench-compare TIERS=replay CORPUS=testnet-prefix50 RUNS=3 BENCH_RUN_DIR=bench-results/testnet-prefix50
```

(`docker build -f docker/Dockerfile --target runtime -t algod-rust:bench-compare .`
builds the image the container tiers use.) Wall-clock cost of this run: build
196 s, micro 267 s, replay 32 s, rest 137 s, localnet 297 s.

## Published baseline

Both blocks below are generated by `report.py --publish` from the run
directories of the commands above. Spread is the min-max range (n = 3).

### Baseline `local-main`: micro, replay (small), rest, localnet

<!-- bench-baseline:begin local-main -->
Command: `make bench-compare TIERS=micro,replay,rest,localnet CORPUS=small RUNS=10 BENCH_REST_PROFILE=smoke BENCH_LOCALNET_PROFILE=smoke`

#### Summary by tier

| Tier | Paired rows | Rust faster | Go faster | Inconclusive |
|---|---|---|---|---|
| localnet | 28 | 4 | 2 | 22 |
| micro | 27 | 20 | 3 | 4 |
| replay | 7 | 2 | 5 | 0 |
| rest | 55 | 23 | 5 | 27 |

117 paired row(s) in total; 0 paired row(s) excluded from the baseline file (every paired row is kept, including rows whose Go or Rust median is 0). Counts come from the tables below.

Generated 2026-11-15T00:58:20Z. Methodology and fairness rules: [docs/BENCHMARK_COMPARISON.md](https://github.com/xarmian/algod-rust/blob/main/docs/BENCHMARK_COMPARISON.md).

**Status: OK.** 117 paired row(s): Rust faster 49, Go faster 15, inconclusive 53; 0 unpaired.

#### Builds

| | go-algorand | algod-rust |
|---|---|---|
| Commit | `31186e99a69e74483ad95e9ce872903b74758abf` | `d263d96974d9cf1d05e4467aa1bb78f4fdb32f76` |
| Describe | `v5.0.5-stable` | `d263d969` |
| Pin | expected `v5.0.5-stable`, matches | |
| Dirty tree | no | no |
| Binaries | go/algod, go/goal | rust/algod-rust |

#### Environment

| Item | Value |
|---|---|
| CPU model | 13th Gen Intel(R) Core(TM) i7-13700 |
| Sockets / physical cores / logical CPUs | 1 / 12 / 24 |
| Max MHz | 2112 |
| Frequency governor | n/a |
| Hypervisor | Microsoft |
| RAM | 31.2 GiB |
| OS | Ubuntu 22.04.5 LTS (x86_64) |
| Kernel | 6.18.58.1-microsoft-standard-WSL2 |
| rustc | rustc 1.99.1 (58cf8f9c3 2026-10-13) |
| go | go version go1.25.3 linux/amd64 |
| docker | 28.2.1 |
| python | 3.13.3 |
| CI runner | no |

Fairness warnings:

- virtualised CPU (Microsoft): noisy neighbours can skew results

#### Results

##### localnet

| Benchmark | Unit | Go median | Go spread | Rust median | Rust spread | Rust/Go | Faster |
|---|---|---|---|---|---|---|---|
| fixed/commit_rounds | rounds (lower is better) | 2 | [2, 3] 95% CI, n=10 | 3 | [3, 3] 95% CI, n=10 | 1.5 | inconclusive |
| fixed/commit_time_s | s (lower is better) | 6 | [6, 9] 95% CI, n=10 | 9 | [9, 9] 95% CI, n=10 | 1.5 | inconclusive |
| fixed/confirmed_tps | txn/s (higher is better) | 33.33 | [22.22, 33.33] 95% CI, n=10 | 22.22 | [22.22, 22.22] 95% CI, n=10 | 0.6667 | inconclusive |
| fixed/latency_p50_ms | ms (lower is better) | 4027 | [4023, 4029] 95% CI, n=10 | 4023 | [4021, 4027] 95% CI, n=10 | 0.999 | inconclusive |
| fixed/latency_p95_ms | ms (lower is better) | 5031 | [5030, 6037] 95% CI, n=10 | 6032 | [5027, 6037] 95% CI, n=10 | 1.199 | inconclusive |
| fixed/latency_p99_ms | ms (lower is better) | 5031 | [5030, 6037] 95% CI, n=10 | 6032 | [5027, 6037] 95% CI, n=10 | 1.199 | inconclusive |
| fixed/pool_rejected_check | txns (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| fixed/pool_rejected_remember | txns (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| fixed/pool_size_end | txns (lower is better) | 0 | [0, 190] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| fixed/rejected_groups | groups (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| fixed/round_time_s | s (lower is better) | 3 | [3, 3] 95% CI, n=10 | 3 | [3, 3] 95% CI, n=10 | 1 | inconclusive |
| fixed/set_tps | txn/s (higher is better) | 33.33 | [22.22, 33.33] 95% CI, n=10 | 22.22 | [22.22, 22.22] 95% CI, n=10 | 0.6667 | inconclusive |
| fixed/start_backlog_txns | txns (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| fixed/submit_tps | txn/s (higher is better) | 99.87 | [99.84, 99.9] 95% CI, n=10 | 99.88 | [99.81, 99.89] 95% CI, n=10 | 1 | inconclusive |
| ladder-50/blockio_write_mb | MB (lower is better) | 154.7 | [154.6, 155] 95% CI, n=10 | 4.148 | [2.708, 5.474] 95% CI, n=10 | 0.02682 | **Rust** 37.29x |
| ladder-50/confirmed_tps | txn/s (higher is better) | 25.89 | [25.56, 26.11] 95% CI, n=10 | 26.67 | [26.22, 26.67] 95% CI, n=10 | 1.03 | **Rust** 1.03x |
| ladder-50/cpu_cores | cores (lower is better) | 0.1434 | [0.1348, 0.305] 95% CI, n=10 | 0.4715 | [0.2008, 0.5126] 95% CI, n=10 | 3.289 | inconclusive |
| ladder-50/latency_p50_ms | ms (lower is better) | 4774 | [4773, 4777] 95% CI, n=10 | 4777 | [4774, 4780] 95% CI, n=10 | 1.001 | inconclusive |
| ladder-50/latency_p95_ms | ms (lower is better) | 5783 | [5781, 5785] 95% CI, n=10 | 6035 | [6033, 6037] 95% CI, n=10 | 1.044 | **Go** 1.044x |
| ladder-50/latency_p99_ms | ms (lower is better) | 5783 | [5781, 5785] 95% CI, n=10 | 6035 | [6033, 6037] 95% CI, n=10 | 1.044 | **Go** 1.044x |
| ladder-50/pool_rejected_check | txns (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| ladder-50/pool_rejected_remember | txns (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| ladder-50/pool_size_end | txns (lower is better) | 195.5 | [195, 295] 95% CI, n=10 | 109.5 | [105, 110] 95% CI, n=10 | 0.5601 | **Rust** 1.785x |
| ladder-50/rejected_groups | groups (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| ladder-50/round_time_s | s (lower is better) | 3 | [3, 3] 95% CI, n=10 | 3 | [3, 3] 95% CI, n=10 | 1 | inconclusive |
| ladder-50/rss_mb_peak | MB (lower is better) | 1137 | [1126, 1166] 95% CI, n=10 | 193 | [183.8, 195.8] 95% CI, n=10 | 0.1698 | **Rust** 5.889x |
| ladder-50/start_backlog_txns | txns (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| ladder-50/submit_tps | txn/s (higher is better) | 49.99 | [49.99, 49.99] 95% CI, n=10 | 49.99 | [49.99, 49.99] 95% CI, n=10 | 1 | inconclusive |

##### micro

| Benchmark | Unit | Go median | Go spread | Rust median | Rust spread | Rust/Go | Faster |
|---|---|---|---|---|---|---|---|
| agreement/credential-verify | ns/op (lower is better) | 141,409 | [138,323, 157,788] 95% CI, n=10 | 99,199 | [96,972, 105,362] 95% CI, n=10 | 0.7015 | **Rust** 1.426x |
| agreement/decode-cert | ns/op (lower is better) | 2978 | [2823, 3125] 95% CI, n=10 | 1846 | [1819, 1983] 95% CI, n=10 | 0.6197 | **Rust** 1.614x |
| agreement/decode-proposal | ns/op (lower is better) | 419 | [410.9, 428.6] 95% CI, n=10 | 411.5 | [406.8, 418.5] 95% CI, n=10 | 0.9822 | inconclusive |
| agreement/sortition-select | ns/op (lower is better) | 13,540 | [13,334, 14,387] 95% CI, n=10 | 309.5 | [303.4, 328.3] 95% CI, n=10 | 0.02286 | **Rust** 43.75x |
| agreement/sortition-select-f128 | ns/op (lower is better) | 759.5 | [731.7, 820.4] 95% CI, n=10 | 898.4 | [892.2, 929.7] 95% CI, n=10 | 1.183 | **Go** 1.183x |
| avm/app-state-box | ns/op (lower is better) | 8460 | [8398, 9251] 95% CI, n=10 | 10,645 | [10,484, 11,015] 95% CI, n=10 | 1.258 | **Go** 1.258x |
| avm/lsig-arith-loop | ns/op (lower is better) | 120,098 | [115,850, 133,778] 95% CI, n=10 | 95,065 | [92,307, 99,360] 95% CI, n=10 | 0.7916 | **Rust** 1.263x |
| avm/lsig-bytes-ops | ns/op (lower is better) | 176,848 | [173,990, 192,177] 95% CI, n=10 | 142,498 | [139,589, 148,738] 95% CI, n=10 | 0.8058 | **Rust** 1.241x |
| avm/lsig-hash-loop | ns/op (lower is better) | 44,613 | [42,286, 49,166] 95% CI, n=10 | 37,602 | [36,186, 38,240] 95% CI, n=10 | 0.8429 | **Rust** 1.186x |
| codec/block-hash | ns/op (lower is better) | 1146 | [1106, 1251] 95% CI, n=10 | 874.9 | [846.4, 924.8] 95% CI, n=10 | 0.7634 | **Rust** 1.31x |
| codec/decode-block-large | ns/op (lower is better) | 314,545 | [305,734, 325,989] 95% CI, n=10 | 316,390 | [309,275, 341,408] 95% CI, n=10 | 1.006 | inconclusive |
| codec/decode-block-small | ns/op (lower is better) | 998.5 | [985.8, 1140] 95% CI, n=10 | 803.2 | [781, 893.4] 95% CI, n=10 | 0.8044 | **Rust** 1.243x |
| codec/decode-stxn | ns/op (lower is better) | 658.7 | [646.6, 716.9] 95% CI, n=10 | 476.3 | [431.4, 524.8] 95% CI, n=10 | 0.7231 | **Rust** 1.383x |
| codec/encode-block-large | ns/op (lower is better) | 461,966 | [456,977, 510,444] 95% CI, n=10 | 270,743 | [263,161, 283,430] 95% CI, n=10 | 0.5861 | **Rust** 1.706x |
| codec/encode-block-small | ns/op (lower is better) | 1218 | [1185, 1310] 95% CI, n=10 | 835.4 | [815.8, 911] 95% CI, n=10 | 0.6859 | **Rust** 1.458x |
| codec/encode-stxn | ns/op (lower is better) | 673.7 | [650.8, 735.1] 95% CI, n=10 | 504.1 | [495.3, 541] 95% CI, n=10 | 0.7482 | **Rust** 1.336x |
| codec/txid | ns/op (lower is better) | 847.6 | [835, 921.4] 95% CI, n=10 | 1012 | [984.4, 1060] 95% CI, n=10 | 1.194 | **Go** 1.194x |
| commit/txn-merkle-sha512_256 | ns/op (lower is better) | 1,281,766 | [1,250,981, 1,380,625] 95% CI, n=10 | 803,517 | [777,022, 872,820] 95% CI, n=10 | 0.6269 | **Rust** 1.595x |
| commit/txn-vc-sha256 | ns/op (lower is better) | 1,280,500 | [1,256,308, 1,367,855] 95% CI, n=10 | 665,242 | [642,403, 697,355] 95% CI, n=10 | 0.5195 | **Rust** 1.925x |
| crypto/ed25519-batch-1024 | ns/op (lower is better) | 39,629,272 | [37,851,718, 41,176,651] 95% CI, n=10 | 33,380,427 | [32,472,202, 35,329,171] 95% CI, n=10 | 0.8423 | **Rust** 1.187x |
| crypto/ed25519-batch-64 | ns/op (lower is better) | 2,489,980 | [2,337,996, 2,561,907] 95% CI, n=10 | 2,057,834 | [1,999,861, 2,152,663] 95% CI, n=10 | 0.8264 | **Rust** 1.21x |
| crypto/ed25519-verify | ns/op (lower is better) | 37,078 | [35,857, 38,358] 95% CI, n=10 | 32,256 | [31,501, 33,476] 95% CI, n=10 | 0.87 | **Rust** 1.149x |
| crypto/falcon-verify | ns/op (lower is better) | 32,767 | [31,945, 35,268] 95% CI, n=10 | 32,190 | [30,717, 32,934] 95% CI, n=10 | 0.9824 | inconclusive |
| crypto/sha512_256-1KiB | ns/op (lower is better) | 1314 | [1261, 1439] 95% CI, n=10 | 1267 | [1241, 1294] 95% CI, n=10 | 0.9648 | inconclusive |
| crypto/sha512_256-32B | ns/op (lower is better) | 182.8 | [177.8, 200.9] 95% CI, n=10 | 166.9 | [162.7, 171] 95% CI, n=10 | 0.9131 | **Rust** 1.095x |
| crypto/sha512_256-64KiB | ns/op (lower is better) | 73,304 | [71,392, 75,499] 95% CI, n=10 | 70,381 | [68,012, 71,028] 95% CI, n=10 | 0.9601 | **Rust** 1.042x |
| crypto/vrf-verify | ns/op (lower is better) | 141,043 | [137,802, 146,038] 95% CI, n=10 | 96,677 | [95,559, 100,881] 95% CI, n=10 | 0.6854 | **Rust** 1.459x |

##### replay

| Benchmark | Unit | Go median | Go spread | Rust median | Rust spread | Rust/Go | Faster |
|---|---|---|---|---|---|---|---|
| small/blocks_per_s | block/s (higher is better) | 1549 | [1535, 1556] 95% CI, n=10 | 1423 | [1404, 1435] 95% CI, n=10 | 0.9189 | **Go** 1.088x |
| small/cpu_s | s (lower is better) | 2.777 | [2.77, 2.821] 95% CI, n=10 | 0.9449 | [0.9058, 0.9672] 95% CI, n=10 | 0.3402 | **Rust** 2.939x |
| small/db_mb | MB (lower is better) | 9.293 | [9.285, 9.301] 95% CI, n=10 | 10.4 | [10.4, 10.4] 95% CI, n=10 | 1.119 | **Go** 1.119x |
| small/peak_rss_mb | MB (lower is better) | 256.6 | [254.8, 257.9] 95% CI, n=10 | 40.76 | [40.35, 40.99] 95% CI, n=10 | 0.1588 | **Rust** 6.296x |
| small/txns_per_s | txn/s (higher is better) | 9549 | [9467, 9597] 95% CI, n=10 | 8775 | [8655, 8847] 95% CI, n=10 | 0.9189 | **Go** 1.088x |
| small/wall_s | s (lower is better) | 1.291 | [1.285, 1.303] 95% CI, n=10 | 1.405 | [1.394, 1.425] 95% CI, n=10 | 1.088 | **Go** 1.088x |
| small/write_mb | MB (lower is better) | 66.18 | [65.92, 66.47] 95% CI, n=10 | 154.5 | [154.5, 154.5] 95% CI, n=10 | 2.334 | **Go** 2.334x |

##### rest

| Benchmark | Unit | Go median | Go spread | Rust median | Rust spread | Rust/Go | Faster |
|---|---|---|---|---|---|---|---|
| account_assets/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| account_assets/c4/p50_ms | ms (lower is better) | 0.2881 | [0.282, 0.2959] 95% CI, n=10 | 0.2606 | [0.2563, 0.2689] 95% CI, n=10 | 0.9043 | **Rust** 1.106x |
| account_assets/c4/p95_ms | ms (lower is better) | 0.4486 | [0.4419, 0.4631] 95% CI, n=10 | 0.3785 | [0.372, 0.3913] 95% CI, n=10 | 0.8439 | **Rust** 1.185x |
| account_assets/c4/p99_ms | ms (lower is better) | 0.7208 | [0.6814, 0.8253] 95% CI, n=10 | 0.4691 | [0.4548, 0.4988] 95% CI, n=10 | 0.6507 | **Rust** 1.537x |
| account_assets/c4/rps | req/s (higher is better) | 13,254 | [12,905, 13,386] 95% CI, n=10 | 14,927 | [14,418, 15,093] 95% CI, n=10 | 1.126 | **Rust** 1.126x |
| account_cold/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| account_cold/c4/p50_ms | ms (lower is better) | 0.2525 | [0.2494, 0.256] 95% CI, n=10 | 0.2493 | [0.2488, 0.2519] 95% CI, n=10 | 0.9872 | inconclusive |
| account_cold/c4/p95_ms | ms (lower is better) | 0.364 | [0.3567, 0.374] 95% CI, n=10 | 0.3553 | [0.3524, 0.3622] 95% CI, n=10 | 0.9762 | inconclusive |
| account_cold/c4/p99_ms | ms (lower is better) | 0.4705 | [0.4581, 0.4925] 95% CI, n=10 | 0.4384 | [0.4327, 0.4522] 95% CI, n=10 | 0.9319 | **Rust** 1.073x |
| account_cold/c4/rps | req/s (higher is better) | 15,451 | [15,270, 15,737] 95% CI, n=10 | 15,668 | [15,532, 15,774] 95% CI, n=10 | 1.014 | inconclusive |
| account_hot/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| account_hot/c4/p50_ms | ms (lower is better) | 0.2782 | [0.2736, 0.2838] 95% CI, n=10 | 0.2907 | [0.2858, 0.2955] 95% CI, n=10 | 1.045 | **Go** 1.045x |
| account_hot/c4/p95_ms | ms (lower is better) | 0.4109 | [0.3971, 0.4169] 95% CI, n=10 | 0.4213 | [0.4173, 0.4399] 95% CI, n=10 | 1.025 | **Go** 1.025x |
| account_hot/c4/p99_ms | ms (lower is better) | 0.545 | [0.5085, 0.5749] 95% CI, n=10 | 0.503 | [0.4973, 0.5406] 95% CI, n=10 | 0.9228 | inconclusive |
| account_hot/c4/rps | req/s (higher is better) | 13,930 | [13,622, 14,228] 95% CI, n=10 | 13,392 | [12,992, 13,580] 95% CI, n=10 | 0.9614 | **Go** 1.04x |
| application/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| application/c4/p50_ms | ms (lower is better) | 0.2688 | [0.2675, 0.2734] 95% CI, n=10 | 0.2475 | [0.2441, 0.254] 95% CI, n=10 | 0.9206 | **Rust** 1.086x |
| application/c4/p95_ms | ms (lower is better) | 0.3891 | [0.3828, 0.4046] 95% CI, n=10 | 0.3562 | [0.3478, 0.3697] 95% CI, n=10 | 0.9152 | **Rust** 1.093x |
| application/c4/p99_ms | ms (lower is better) | 0.5144 | [0.5096, 0.5331] 95% CI, n=10 | 0.4406 | [0.4301, 0.4625] 95% CI, n=10 | 0.8565 | **Rust** 1.168x |
| application/c4/rps | req/s (higher is better) | 14,544 | [14,273, 14,625] 95% CI, n=10 | 15,820 | [15,361, 16,042] 95% CI, n=10 | 1.088 | **Rust** 1.088x |
| blocks_json/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| blocks_json/c4/p50_ms | ms (lower is better) | 0.4199 | [0.3973, 0.433] 95% CI, n=10 | 0.3024 | [0.2984, 0.3174] 95% CI, n=10 | 0.7203 | **Rust** 1.388x |
| blocks_json/c4/p95_ms | ms (lower is better) | 0.678 | [0.6503, 0.7061] 95% CI, n=10 | 0.4453 | [0.4373, 0.4956] 95% CI, n=10 | 0.6568 | **Rust** 1.523x |
| blocks_json/c4/p99_ms | ms (lower is better) | 1.287 | [1.137, 1.411] 95% CI, n=10 | 0.5411 | [0.5253, 0.6132] 95% CI, n=10 | 0.4204 | **Rust** 2.379x |
| blocks_json/c4/rps | req/s (higher is better) | 8752 | [8637, 9143] 95% CI, n=10 | 12,753 | [11,999, 12,927] 95% CI, n=10 | 1.457 | **Rust** 1.457x |
| blocks_msgpack/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| blocks_msgpack/c4/p50_ms | ms (lower is better) | 0.2924 | [0.2884, 0.2972] 95% CI, n=10 | 0.2431 | [0.2402, 0.2561] 95% CI, n=10 | 0.8313 | **Rust** 1.203x |
| blocks_msgpack/c4/p95_ms | ms (lower is better) | 0.435 | [0.4282, 0.4529] 95% CI, n=10 | 0.3522 | [0.3412, 0.3875] 95% CI, n=10 | 0.8097 | **Rust** 1.235x |
| blocks_msgpack/c4/p99_ms | ms (lower is better) | 0.5684 | [0.5391, 0.5974] 95% CI, n=10 | 0.4443 | [0.4264, 0.4992] 95% CI, n=10 | 0.7817 | **Rust** 1.279x |
| blocks_msgpack/c4/rps | req/s (higher is better) | 13,364 | [12,978, 13,501] 95% CI, n=10 | 16,029 | [15,111, 16,304] 95% CI, n=10 | 1.199 | **Rust** 1.199x |
| box/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| box/c4/p50_ms | ms (lower is better) | 0.2651 | [0.2637, 0.2889] 95% CI, n=10 | 0.2443 | [0.2361, 0.2478] 95% CI, n=10 | 0.9215 | **Rust** 1.085x |
| box/c4/p95_ms | ms (lower is better) | 0.3844 | [0.381, 0.4206] 95% CI, n=10 | 0.3454 | [0.334, 0.3577] 95% CI, n=10 | 0.8985 | **Rust** 1.113x |
| box/c4/p99_ms | ms (lower is better) | 0.5115 | [0.4891, 0.5452] 95% CI, n=10 | 0.4329 | [0.4245, 0.4571] 95% CI, n=10 | 0.8462 | **Rust** 1.182x |
| box/c4/rps | req/s (higher is better) | 14,751 | [13,366, 14,797] 95% CI, n=10 | 16,088 | [15,871, 16,622] 95% CI, n=10 | 1.091 | **Rust** 1.091x |
| simulate/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| simulate/c4/p50_ms | ms (lower is better) | 0.8154 | [0.5235, 0.8381] 95% CI, n=10 | 0.7613 | [0.7443, 0.8393] 95% CI, n=10 | 0.9337 | inconclusive |
| simulate/c4/p95_ms | ms (lower is better) | 1.13 | [1.106, 1.158] 95% CI, n=10 | 1.142 | [1.119, 1.222] 95% CI, n=10 | 1.011 | inconclusive |
| simulate/c4/p99_ms | ms (lower is better) | 2.437 | [2.266, 2.931] 95% CI, n=10 | 1.263 | [1.234, 1.368] 95% CI, n=10 | 0.5183 | **Rust** 1.929x |
| simulate/c4/rps | req/s (higher is better) | 4991 | [4657, 5625] 95% CI, n=10 | 4858 | [4647, 4965] 95% CI, n=10 | 0.9735 | inconclusive |
| simulate_app/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| simulate_app/c4/p50_ms | ms (lower is better) | 1.121 | [0.8166, 1.244] 95% CI, n=10 | 1.096 | [1.083, 1.126] 95% CI, n=10 | 0.9784 | inconclusive |
| simulate_app/c4/p95_ms | ms (lower is better) | 1.595 | [1.533, 1.669] 95% CI, n=10 | 1.727 | [1.702, 1.764] 95% CI, n=10 | 1.082 | **Go** 1.082x |
| simulate_app/c4/p99_ms | ms (lower is better) | 4.344 | [3.436, 5.163] 95% CI, n=10 | 1.955 | [1.885, 1.969] 95% CI, n=10 | 0.4501 | **Rust** 2.222x |
| simulate_app/c4/rps | req/s (higher is better) | 3314 | [3238, 3684] 95% CI, n=10 | 3177 | [3134, 3220] 95% CI, n=10 | 0.9586 | **Go** 1.043x |
| status/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| status/c4/p50_ms | ms (lower is better) | 0.243 | [0.2408, 0.248] 95% CI, n=10 | 0.2386 | [0.2356, 0.2457] 95% CI, n=10 | 0.982 | inconclusive |
| status/c4/p95_ms | ms (lower is better) | 0.3508 | [0.3417, 0.3571] 95% CI, n=10 | 0.3493 | [0.339, 0.3611] 95% CI, n=10 | 0.9958 | inconclusive |
| status/c4/p99_ms | ms (lower is better) | 0.4583 | [0.4486, 0.4676] 95% CI, n=10 | 0.4378 | [0.4196, 0.4531] 95% CI, n=10 | 0.9553 | inconclusive |
| status/c4/rps | req/s (higher is better) | 16,123 | [15,785, 16,197] 95% CI, n=10 | 16,280 | [15,817, 16,551] 95% CI, n=10 | 1.01 | inconclusive |
| tx_params/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| tx_params/c4/p50_ms | ms (lower is better) | 0.2449 | [0.2384, 0.2478] 95% CI, n=10 | 0.2464 | [0.2356, 0.2556] 95% CI, n=10 | 1.006 | inconclusive |
| tx_params/c4/p95_ms | ms (lower is better) | 0.352 | [0.3395, 0.3759] 95% CI, n=10 | 0.3598 | [0.3424, 0.3892] 95% CI, n=10 | 1.022 | inconclusive |
| tx_params/c4/p99_ms | ms (lower is better) | 0.4602 | [0.44, 0.4915] 95% CI, n=10 | 0.4521 | [0.4338, 0.5031] 95% CI, n=10 | 0.9823 | inconclusive |
| tx_params/c4/rps | req/s (higher is better) | 15,951 | [15,688, 16,362] 95% CI, n=10 | 15,768 | [15,002, 16,555] 95% CI, n=10 | 0.9885 | inconclusive |

Rust/Go is the ratio of the medians. For lower-is-better units a value below 1 means Rust is faster; for higher-is-better units a value above 1 means Rust is faster. A side is only marked faster when the two spreads (95% CI of the median for n >= 6, else min/max) do not overlap. Rows marked (synthetic) come from the selftest tier and measure the harness, not either node.

#### Tiers

| Tier | Exit | Duration (s) |
|---|---|---|
| build | 0 | 197.9 |
| micro | 0 | 3444 |
| replay | 0 | 35.05 |
| rest | 0 | 469.7 |
| localnet | 0 | 917.3 |
<!-- bench-baseline:end local-main -->

### Baseline `local-testnet-prefix50`: replay of real certificates

<!-- bench-baseline:begin local-testnet-prefix50 -->
Command: `make bench-compare TIERS=replay CORPUS=testnet-prefix50 RUNS=10`

#### Summary by tier

| Tier | Paired rows | Rust faster | Go faster | Inconclusive |
|---|---|---|---|---|
| replay | 7 | 2 | 5 | 0 |

7 paired row(s) in total; 0 paired row(s) excluded from the baseline file (every paired row is kept, including rows whose Go or Rust median is 0). Counts come from the tables below.

Generated 2026-11-15T00:58:36Z. Methodology and fairness rules: [docs/BENCHMARK_COMPARISON.md](https://github.com/xarmian/algod-rust/blob/main/docs/BENCHMARK_COMPARISON.md).

**Status: OK.** 7 paired row(s): Rust faster 2, Go faster 5, inconclusive 0; 0 unpaired.

#### Builds

| | go-algorand | algod-rust |
|---|---|---|
| Commit | `31186e99a69e74483ad95e9ce872903b74758abf` | `d263d96974d9cf1d05e4467aa1bb78f4fdb32f76` |
| Describe | `v5.0.5-stable` | `d263d969` |
| Pin | expected `v5.0.5-stable`, matches | |
| Dirty tree | no | no |
| Binaries | go/algod, go/goal | rust/algod-rust |

#### Environment

| Item | Value |
|---|---|
| CPU model | 13th Gen Intel(R) Core(TM) i7-13700 |
| Sockets / physical cores / logical CPUs | 1 / 12 / 24 |
| Max MHz | 2112 |
| Frequency governor | n/a |
| Hypervisor | Microsoft |
| RAM | 31.2 GiB |
| OS | Ubuntu 22.04.5 LTS (x86_64) |
| Kernel | 6.18.58.1-microsoft-standard-WSL2 |
| rustc | rustc 1.99.1 (58cf8f9c3 2026-10-13) |
| go | go version go1.25.3 linux/amd64 |
| docker | 28.2.1 |
| python | 3.13.3 |
| CI runner | no |

Fairness warnings:

- virtualised CPU (Microsoft): noisy neighbours can skew results

#### Results

##### replay

| Benchmark | Unit | Go median | Go spread | Rust median | Rust spread | Rust/Go | Faster |
|---|---|---|---|---|---|---|---|
| testnet-prefix50/blocks_per_s | block/s (higher is better) | 456.4 | [439, 477.7] 95% CI, n=10 | 90.05 | [89.16, 91] 95% CI, n=10 | 0.1973 | **Go** 5.068x |
| testnet-prefix50/cpu_s | s (lower is better) | 0.8628 | [0.8306, 0.9189] 95% CI, n=10 | 0.3783 | [0.3661, 0.4007] 95% CI, n=10 | 0.4385 | **Rust** 2.28x |
| testnet-prefix50/db_mb | MB (lower is better) | 0.8244 | [0.8244, 0.8244] 95% CI, n=10 | 2.029 | [2.029, 2.029] 95% CI, n=10 | 2.462 | **Go** 2.462x |
| testnet-prefix50/peak_rss_mb | MB (lower is better) | 141 | [138.3, 143.7] 95% CI, n=10 | 31.81 | [31.66, 32.09] 95% CI, n=10 | 0.2257 | **Rust** 4.431x |
| testnet-prefix50/txns_per_s | txn/s (higher is better) | 9.128 | [8.779, 9.555] 95% CI, n=10 | 1.801 | [1.783, 1.82] 95% CI, n=10 | 0.1973 | **Go** 5.068x |
| testnet-prefix50/wall_s | s (lower is better) | 0.1096 | [0.1047, 0.1139] 95% CI, n=10 | 0.5553 | [0.5494, 0.5608] 95% CI, n=10 | 5.068 | **Go** 5.068x |
| testnet-prefix50/write_mb | MB (lower is better) | 2.131 | [2.105, 2.145] 95% CI, n=10 | 3.527 | [3.527, 3.527] 95% CI, n=10 | 1.655 | **Go** 1.655x |

Rust/Go is the ratio of the medians. For lower-is-better units a value below 1 means Rust is faster; for higher-is-better units a value above 1 means Rust is faster. A side is only marked faster when the two spreads (95% CI of the median for n >= 6, else min/max) do not overlap. Rows marked (synthetic) come from the selftest tier and measure the harness, not either node.

#### Tiers

| Tier | Exit | Duration (s) |
|---|---|---|
| build | 0 | 2.848 |
| replay | 0 | 12.07 |
<!-- bench-baseline:end local-testnet-prefix50 -->

## Open findings from the epic

The comparison already paid for itself: the equality gates and the first
measurements produced these open issues. They are the explanation for the rows
where algod-rust is behind, and they feed the optimization pass #2110.

### Performance

Every row where Go is faster with non-overlapping ranges, and who owns it
(2026-11-15 re-run, `RUNS=10`):

| Row (Go faster) | Ratio | Owner / reason |
|---|---|---|
| `replay small` wall, blocks/s, txns/s | 1.09x | [#2316](https://github.com/xarmian/algod-rust/issues/2316): remaining cost is tracker WAL bytes and ext4 fsync, flat profile (see [PERF_PHASE23.md](PERF_PHASE23.md) row 12) |
| `replay small` `write_mb`, `db_mb` | 2.33x, 1.12x | [#2316](https://github.com/xarmian/algod-rust/issues/2316): the tracker WAL (about 140 of 154 MB) is written once and checkpointed; block-device writes in the `localnet` tier are 37x lower than go's |
| `replay testnet-prefix50` wall, blocks/s, `db_mb`, `write_mb` | 5.07x, 2.46x, 1.66x | [#2339](https://github.com/xarmian/algod-rust/issues/2339): certificate authentication and startup (Go uses about 8 cores for 0.11 s) |
| `micro avm/app-state-box` | 1.26x | [#2320](https://github.com/xarmian/algod-rust/issues/2320): per-call setup costs (bytecode parse, machine construction, allocation) |
| `micro agreement/sortition-select-f128` | 1.18x | [#2321](https://github.com/xarmian/algod-rust/issues/2321): software f128; measured, division is not the lever (PERF_PHASE23.md row 9) |
| `micro codec/txid` | 1.19x | [#2321](https://github.com/xarmian/algod-rust/issues/2321): one encode plus one SHA-512/256, 42% in the SHA block function |
| `rest account_hot`, `simulate_app` p95/rps | 1.03x to 1.08x | [#2340](https://github.com/xarmian/algod-rust/issues/2340) |
| `localnet ladder-50` p95/p99 latency | 1.04x | harness quantum (see Headline), no node cost |

The first baseline's findings are closed: #2145 (certificate authentication on
the large replay), #2162 (simulate), #2165/#2166 (catchup replay and WAL
growth), and the codec rows (PERF_PHASE23.md row 9). The profile-driven
optimization pass is #2110; the second round and this re-run are #2315 to
#2322.

Where algod-rust is ahead, as measured: peak RSS is 4x to 6x lower in replay
and 5.9x lower on the localnet, CPU time in replay 2.3x to 2.9x lower, most
REST read endpoints serve 9% to 46% more requests/s with lower tail latency,
`simulate` p99 is 1.9x to 2.2x lower, and the codec, payset commitment, AVM
loop, Ed25519, VRF and credential micro pairs are 1.1x to 1.9x faster.

### REST response differences (found by the `rest` tier's equality gate)

The `rest` tier serves one replayed ledger from both nodes and fails on any
response difference that is not on its issue-linked allowlist. The allowlist
is empty (the last entry, #2161, simulate `sender-rewards`, is fixed), so the
REST throughput rows compare nodes that answer the requests the gate sends
identically, apart from wall-clock-dependent fields. The gate's simulate
request is a payment: an app-call simulate (state deltas, logs, inner
transactions in `txn-result`) is not covered and still differs
([#2178](https://github.com/xarmian/algod-rust/issues/2178)).

## Regression detection and CI

`.github/workflows/bench-compare.yml` runs weekly and on dispatch (never as a
required PR check). It builds both implementations, runs the same
`make bench-compare` commands as above (`RUNS=3`, smoke profiles, the tiers'
default container limits of 2 CPUs / 3 GB), uploads each run
directory as an artifact and the reports as the job summary, and fails on any
equality-gate failure (`dry_run_gate_failure` proves that). It then compares
each report with the sections of [`benchmarks/baseline.json`](../benchmarks/baseline.json)
written by the publish step. For every paired row (a zero or undefined ratio is
kept and compared by its medians) a worsening of Rust of more than 25% is raised
as a warning annotation. The Rust/Go ratio, not the absolute time, is compared
because a CI runner moves both sides. A row only counts as a regression when it
was conclusive in the baseline or its Rust min-max range no longer overlaps the
baseline's (otherwise it is listed as `noise`), a move of one round on the
quantised `rounds` rows is not a change, and a jump from a zero baseline (an
error rate going from 0 to N) always counts. Each baseline section records its
host class (`dev-host` for the published laptop/desktop run, `ci-github-actions`
for a runner); memory, disk and CPU rows (units `MB`, `cores`) are only compared
within one host class and are `skipped-host` otherwise. The job fails (instead of
warning) only with `fail_on_regression`, and then also when a baseline section
or a baseline row is missing from the run, so a renamed section cannot disable
the gate silently. On shared runners ratios are still noisy, particularly tail
latencies of the 1-second REST steps, so a warning means "re-run on quiet
hardware", not "regression".

**CI-runner baseline.** The two sections above come from a desktop, and a
4-vCPU runner differs from it in more than speed. The first green
`workflow_dispatch` run of `bench-compare` should therefore be published as the
CI-runner baseline, with a distinct section name (for example `ci-runner-main`
and `ci-runner-testnet-prefix50`, after adding the matching marker pair to this
file), taken from the downloaded `bench-compare-results` artifact with
`report.py --publish`, and the workflow's regression step then pointed at those
sections. No CI-runner numbers are published yet.
Details: [BENCHMARK_COMPARISON.md, CI workflow and published baseline](BENCHMARK_COMPARISON.md#ci-workflow-and-published-baseline).

To refresh the baseline after a deliberate change (an optimization from #2110,
a pin bump), re-run the commands above on dedicated hardware and publish:

```bash
python3 scripts/bench/report.py bench-results/main --publish --section local-main \
  --doc docs/BENCHMARK_RESULTS.md --baseline benchmarks/baseline.json \
  --command "<the make command of the run>"
```
