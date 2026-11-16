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
  says little about steady-state apply speed. The Rust replay is bounded at the
  corpus's last round since #2342 (it used to spend about 0.5 s probing the tip
  after the last block, which go's bare apply loop has no counterpart of) and
  authenticates the next round's certificate on a helper thread while the
  current round is applied, as go does in its fetching goroutines (#2339);
  Rust is now 1.16x ahead on wall clock (0.0997 s vs 0.115 s, `RUNS=10`).
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

- **micro**: Rust is faster on 18 of 27 rows (all the codec encode/decode and
  both payset commitments 1.2x to 1.9x, certificate decode 1.6x, AVM
  arithmetic/bytes/hash loops 1.2x to 1.3x, Ed25519/VRF/credential verify
  1.1x to 1.5x, sortition select 44x). Go is faster on two rows:
  `sortition-select-f128` 1.22x (#2321) and `avm/app-state-box` 1.26x (#2320);
  `txid` is no longer one of them.
- **replay, small corpus** (`RUNS=10`, after #2342): Go 1.34 s, Rust 0.94 s
  wall (Rust 1.43x faster, was Go 3.6x faster in the first baseline). Rust
  uses 3.1x less CPU time and 6.2x less peak RSS; it writes 2.3x more bytes
  (154.5 vs 66 MB, #2316) into a 1.13x larger database.
- **replay, testnet-prefix50** (re-run after #2339, `RUNS=10`): Go 0.115 s, Rust
  0.0997 s (Rust 1.16x faster, was 5.1x slower); Rust CPU 2.5x lower, peak RSS
  4.2x lower. Go is ahead only on the fixed database/write overhead (`db_mb`
  3.8 vs 0.8 MB, `write_mb` 4.3 vs 2.2 MB, tiny absolute numbers).
- **rest (smoke, c4)**: Rust is ahead on most endpoints' latency/throughput
  rows and level on the rest; `simulate` (4.6x behind in the first baseline) is
  level. The only Go-faster row is `account_hot` p50 (0.288 vs 0.296 ms, 1.03x,
  #2340).
- **localnet (smoke)**: level on throughput and round time (3 s); Rust peak RSS
  5.9x lower and block-device writes 31x lower. The Go-faster rows are the
  confirmation-latency percentiles (`fixed` p95/p99 1.23x, `ladder-50`
  p50/p95/p99 1.05x to 1.07x). They are quantised by whole 3 s rounds: a
  200-transaction step commits in 2 or 3 rounds depending on where it lands
  relative to a round boundary, `commit_rounds` / `commit_time_s` intervals
  overlap ([2, 3]) and are inconclusive, confirmed TPS is level, and single-run
  A/B of the same Rust code flipped the `fixed` p95 direction (Rust faster
  before #2343, Go faster after, no change on the commit path), so this is
  round-boundary noise, not a node cost.

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
| localnet | 28 | 3 | 5 | 20 |
| micro | 27 | 18 | 2 | 7 |
| replay | 7 | 5 | 2 | 0 |
| rest | 55 | 23 | 1 | 31 |

117 paired row(s) in total; 0 paired row(s) excluded from the baseline file (every paired row is kept, including rows whose Go or Rust median is 0). Counts come from the tables below.

Generated 2026-11-16T11:29:03Z. Methodology and fairness rules: [docs/BENCHMARK_COMPARISON.md](https://github.com/xarmian/algod-rust/blob/main/docs/BENCHMARK_COMPARISON.md).

**Status: OK.** 117 paired row(s): Rust faster 49, Go faster 10, inconclusive 58; 0 unpaired.

#### Builds

| | go-algorand | algod-rust |
|---|---|---|
| Commit | `31186e99a69e74483ad95e9ce872903b74758abf` | `2f2570092a88e9169cc0039545d9d0ff797aaaf1` |
| Describe | `v5.0.5-stable` | `2f257009` |
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
| fixed/commit_rounds | rounds (lower is better) | 2 | [2, 3] 95% CI, n=10 | 3 | [2, 3] 95% CI, n=10 | 1.5 | inconclusive |
| fixed/commit_time_s | s (lower is better) | 6 | [6, 9] 95% CI, n=10 | 9 | [6, 9] 95% CI, n=10 | 1.5 | inconclusive |
| fixed/confirmed_tps | txn/s (higher is better) | 33.33 | [22.22, 33.33] 95% CI, n=10 | 22.22 | [22.22, 33.33] 95% CI, n=10 | 0.6667 | inconclusive |
| fixed/latency_p50_ms | ms (lower is better) | 4026 | [4022, 4029] 95% CI, n=10 | 4272 | [4023, 4279] 95% CI, n=10 | 1.061 | inconclusive |
| fixed/latency_p95_ms | ms (lower is better) | 5030 | [5029, 5033] 95% CI, n=10 | 6161 | [5282, 6290] 95% CI, n=10 | 1.225 | **Go** 1.225x |
| fixed/latency_p99_ms | ms (lower is better) | 5030 | [5029, 5033] 95% CI, n=10 | 6161 | [5282, 6290] 95% CI, n=10 | 1.225 | **Go** 1.225x |
| fixed/pool_rejected_check | txns (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| fixed/pool_rejected_remember | txns (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| fixed/pool_size_end | txns (lower is better) | 0 | [0, 10] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| fixed/rejected_groups | groups (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| fixed/round_time_s | s (lower is better) | 3 | [3, 3] 95% CI, n=10 | 3 | [3, 3] 95% CI, n=10 | 1 | inconclusive |
| fixed/set_tps | txn/s (higher is better) | 33.33 | [22.22, 33.33] 95% CI, n=10 | 22.22 | [22.22, 33.33] 95% CI, n=10 | 0.6667 | inconclusive |
| fixed/start_backlog_txns | txns (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| fixed/submit_tps | txn/s (higher is better) | 99.88 | [99.84, 99.91] 95% CI, n=10 | 99.89 | [99.87, 99.89] 95% CI, n=10 | 1 | inconclusive |
| ladder-50/blockio_write_mb | MB (lower is better) | 154.4 | [154.3, 154.4] 95% CI, n=10 | 4.897 | [2.756, 5.226] 95% CI, n=10 | 0.03172 | **Rust** 31.52x |
| ladder-50/confirmed_tps | txn/s (higher is better) | 26.11 | [25.56, 26.11] 95% CI, n=10 | 27.22 | [25, 27.78] 95% CI, n=10 | 1.043 | inconclusive |
| ladder-50/cpu_cores | cores (lower is better) | 0.1429 | [0.1397, 0.1708] 95% CI, n=10 | 0.1279 | [0.0736, 0.1472] 95% CI, n=10 | 0.8949 | inconclusive |
| ladder-50/latency_p50_ms | ms (lower is better) | 4773 | [4527, 4777] 95% CI, n=10 | 5026 | [5024, 5028] 95% CI, n=10 | 1.053 | **Go** 1.053x |
| ladder-50/latency_p95_ms | ms (lower is better) | 5784 | [5780, 5787] 95% CI, n=10 | 6161 | [6030, 6290] 95% CI, n=10 | 1.065 | **Go** 1.065x |
| ladder-50/latency_p99_ms | ms (lower is better) | 5784 | [5780, 5787] 95% CI, n=10 | 6161 | [6030, 6290] 95% CI, n=10 | 1.065 | **Go** 1.065x |
| ladder-50/pool_rejected_check | txns (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| ladder-50/pool_rejected_remember | txns (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| ladder-50/pool_size_end | txns (lower is better) | 195 | [195, 200] 95% CI, n=10 | 99.5 | [95, 105] 95% CI, n=10 | 0.5103 | **Rust** 1.96x |
| ladder-50/rejected_groups | groups (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| ladder-50/round_time_s | s (lower is better) | 3 | [3, 3] 95% CI, n=10 | 3 | [3, 3.333] 95% CI, n=10 | 1 | inconclusive |
| ladder-50/rss_mb_peak | MB (lower is better) | 1136 | [1123, 1152] 95% CI, n=10 | 192.8 | [180.5, 196.5] 95% CI, n=10 | 0.1697 | **Rust** 5.893x |
| ladder-50/start_backlog_txns | txns (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| ladder-50/submit_tps | txn/s (higher is better) | 49.99 | [49.99, 49.99] 95% CI, n=10 | 49.99 | [49.99, 49.99] 95% CI, n=10 | 1 | inconclusive |

##### micro

| Benchmark | Unit | Go median | Go spread | Rust median | Rust spread | Rust/Go | Faster |
|---|---|---|---|---|---|---|---|
| agreement/credential-verify | ns/op (lower is better) | 143,730 | [136,039, 161,158] 95% CI, n=10 | 105,270 | [99,201, 115,543] 95% CI, n=10 | 0.7324 | **Rust** 1.365x |
| agreement/decode-cert | ns/op (lower is better) | 3122 | [3007, 3479] 95% CI, n=10 | 2042 | [1937, 2170] 95% CI, n=10 | 0.6542 | **Rust** 1.529x |
| agreement/decode-proposal | ns/op (lower is better) | 438.9 | [412.9, 476.4] 95% CI, n=10 | 435.6 | [416.8, 454.1] 95% CI, n=10 | 0.9924 | inconclusive |
| agreement/sortition-select | ns/op (lower is better) | 14,624 | [13,118, 15,495] 95% CI, n=10 | 334.4 | [325.3, 359.3] 95% CI, n=10 | 0.02287 | **Rust** 43.73x |
| agreement/sortition-select-f128 | ns/op (lower is better) | 785.5 | [728.4, 880] 95% CI, n=10 | 958.3 | [905, 1026] 95% CI, n=10 | 1.22 | **Go** 1.22x |
| avm/app-state-box | ns/op (lower is better) | 9128 | [8440, 9582] 95% CI, n=10 | 11,461 | [10,720, 12,255] 95% CI, n=10 | 1.256 | **Go** 1.256x |
| avm/lsig-arith-loop | ns/op (lower is better) | 120,281 | [117,643, 132,143] 95% CI, n=10 | 105,597 | [103,903, 113,823] 95% CI, n=10 | 0.8779 | **Rust** 1.139x |
| avm/lsig-bytes-ops | ns/op (lower is better) | 188,887 | [171,598, 201,071] 95% CI, n=10 | 155,671 | [150,247, 162,982] 95% CI, n=10 | 0.8242 | **Rust** 1.213x |
| avm/lsig-hash-loop | ns/op (lower is better) | 47,091 | [43,069, 49,667] 95% CI, n=10 | 38,070 | [36,299, 42,230] 95% CI, n=10 | 0.8084 | **Rust** 1.237x |
| codec/block-hash | ns/op (lower is better) | 1196 | [1152, 1341] 95% CI, n=10 | 928.8 | [876.3, 981.2] 95% CI, n=10 | 0.7769 | **Rust** 1.287x |
| codec/decode-block-large | ns/op (lower is better) | 326,298 | [310,654, 370,098] 95% CI, n=10 | 334,152 | [320,130, 360,936] 95% CI, n=10 | 1.024 | inconclusive |
| codec/decode-block-small | ns/op (lower is better) | 1018 | [1001, 1206] 95% CI, n=10 | 806.9 | [788, 862.9] 95% CI, n=10 | 0.7931 | **Rust** 1.261x |
| codec/decode-stxn | ns/op (lower is better) | 662.5 | [650, 742.8] 95% CI, n=10 | 482.3 | [446.4, 528.9] 95% CI, n=10 | 0.728 | **Rust** 1.374x |
| codec/encode-block-large | ns/op (lower is better) | 480,712 | [469,856, 564,225] 95% CI, n=10 | 283,612 | [266,842, 337,420] 95% CI, n=10 | 0.59 | **Rust** 1.695x |
| codec/encode-block-small | ns/op (lower is better) | 1230 | [1169, 1576] 95% CI, n=10 | 854.1 | [825.5, 976.7] 95% CI, n=10 | 0.6947 | **Rust** 1.44x |
| codec/encode-stxn | ns/op (lower is better) | 694.6 | [664.6, 797.1] 95% CI, n=10 | 526.1 | [500.1, 560.9] 95% CI, n=10 | 0.7574 | **Rust** 1.32x |
| codec/txid | ns/op (lower is better) | 868 | [857.5, 1027] 95% CI, n=10 | 1066 | [1013, 1075] 95% CI, n=10 | 1.228 | inconclusive |
| commit/txn-merkle-sha512_256 | ns/op (lower is better) | 1,303,828 | [1,278,167, 1,415,198] 95% CI, n=10 | 840,549 | [813,205, 874,608] 95% CI, n=10 | 0.6447 | **Rust** 1.551x |
| commit/txn-vc-sha256 | ns/op (lower is better) | 1,291,572 | [1,271,388, 1,420,590] 95% CI, n=10 | 687,768 | [654,707, 701,027] 95% CI, n=10 | 0.5325 | **Rust** 1.878x |
| crypto/ed25519-batch-1024 | ns/op (lower is better) | 39,094,010 | [38,162,005, 44,460,770] 95% CI, n=10 | 29,449,045 | [28,467,061, 30,492,420] 95% CI, n=10 | 0.7533 | **Rust** 1.328x |
| crypto/ed25519-batch-64 | ns/op (lower is better) | 2,457,452 | [2,418,732, 2,828,724] 95% CI, n=10 | 1,833,556 | [1,765,206, 1,862,336] 95% CI, n=10 | 0.7461 | **Rust** 1.34x |
| crypto/ed25519-verify | ns/op (lower is better) | 37,196 | [36,473, 44,579] 95% CI, n=10 | 28,736 | [27,701, 29,397] 95% CI, n=10 | 0.7725 | **Rust** 1.294x |
| crypto/falcon-verify | ns/op (lower is better) | 33,773 | [32,809, 37,181] 95% CI, n=10 | 33,459 | [32,265, 35,714] 95% CI, n=10 | 0.9907 | inconclusive |
| crypto/sha512_256-1KiB | ns/op (lower is better) | 1346 | [1321, 1549] 95% CI, n=10 | 1315 | [1271, 1607] 95% CI, n=10 | 0.977 | inconclusive |
| crypto/sha512_256-32B | ns/op (lower is better) | 187.4 | [184.1, 212.6] 95% CI, n=10 | 178.2 | [167.4, 190.8] 95% CI, n=10 | 0.9513 | inconclusive |
| crypto/sha512_256-64KiB | ns/op (lower is better) | 75,434 | [73,193, 81,417] 95% CI, n=10 | 74,487 | [71,527, 107,594] 95% CI, n=10 | 0.9875 | inconclusive |
| crypto/vrf-verify | ns/op (lower is better) | 140,820 | [138,285, 157,759] 95% CI, n=10 | 102,295 | [99,012, 129,282] 95% CI, n=10 | 0.7264 | **Rust** 1.377x |

##### replay

| Benchmark | Unit | Go median | Go spread | Rust median | Rust spread | Rust/Go | Faster |
|---|---|---|---|---|---|---|---|
| small/blocks_per_s | block/s (higher is better) | 1488 | [1413, 1516] 95% CI, n=10 | 2120 | [1952, 2148] 95% CI, n=10 | 1.425 | **Rust** 1.425x |
| small/cpu_s | s (lower is better) | 2.916 | [2.828, 3.094] 95% CI, n=10 | 0.949 | [0.938, 1.049] 95% CI, n=10 | 0.3254 | **Rust** 3.073x |
| small/db_mb | MB (lower is better) | 9.289 | [9.285, 9.301] 95% CI, n=10 | 10.47 | [10.47, 10.47] 95% CI, n=10 | 1.127 | **Go** 1.127x |
| small/peak_rss_mb | MB (lower is better) | 256.5 | [255.4, 257.8] 95% CI, n=10 | 41.37 | [40.89, 41.77] 95% CI, n=10 | 0.1613 | **Rust** 6.199x |
| small/txns_per_s | txn/s (higher is better) | 9173 | [8712, 9350] 95% CI, n=10 | 13,071 | [12,037, 13,244] 95% CI, n=10 | 1.425 | **Rust** 1.425x |
| small/wall_s | s (lower is better) | 1.344 | [1.319, 1.415] 95% CI, n=10 | 0.9435 | [0.9311, 1.025] 95% CI, n=10 | 0.7018 | **Rust** 1.425x |
| small/write_mb | MB (lower is better) | 66.04 | [65.51, 66.73] 95% CI, n=10 | 154.5 | [154.5, 154.5] 95% CI, n=10 | 2.339 | **Go** 2.339x |

##### rest

| Benchmark | Unit | Go median | Go spread | Rust median | Rust spread | Rust/Go | Faster |
|---|---|---|---|---|---|---|---|
| account_assets/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| account_assets/c4/p50_ms | ms (lower is better) | 0.2987 | [0.2901, 0.3012] 95% CI, n=10 | 0.268 | [0.2634, 0.2734] 95% CI, n=10 | 0.8974 | **Rust** 1.114x |
| account_assets/c4/p95_ms | ms (lower is better) | 0.4725 | [0.4591, 0.4927] 95% CI, n=10 | 0.3861 | [0.3789, 0.4053] 95% CI, n=10 | 0.8172 | **Rust** 1.224x |
| account_assets/c4/p99_ms | ms (lower is better) | 0.7519 | [0.7173, 0.8118] 95% CI, n=10 | 0.4751 | [0.4596, 0.5117] 95% CI, n=10 | 0.6318 | **Rust** 1.583x |
| account_assets/c4/rps | req/s (higher is better) | 12,701 | [12,530, 13,090] 95% CI, n=10 | 14,563 | [14,074, 14,755] 95% CI, n=10 | 1.147 | **Rust** 1.147x |
| account_cold/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| account_cold/c4/p50_ms | ms (lower is better) | 0.2592 | [0.2567, 0.2667] 95% CI, n=10 | 0.2655 | [0.2567, 0.2767] 95% CI, n=10 | 1.024 | inconclusive |
| account_cold/c4/p95_ms | ms (lower is better) | 0.3746 | [0.3638, 0.3943] 95% CI, n=10 | 0.3921 | [0.369, 0.4125] 95% CI, n=10 | 1.047 | inconclusive |
| account_cold/c4/p99_ms | ms (lower is better) | 0.4878 | [0.4661, 0.5086] 95% CI, n=10 | 0.4908 | [0.4562, 0.5146] 95% CI, n=10 | 1.006 | inconclusive |
| account_cold/c4/rps | req/s (higher is better) | 15,079 | [14,564, 15,258] 95% CI, n=10 | 14,689 | [14,029, 15,247] 95% CI, n=10 | 0.9741 | inconclusive |
| account_hot/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| account_hot/c4/p50_ms | ms (lower is better) | 0.2879 | [0.2847, 0.2919] 95% CI, n=10 | 0.2956 | [0.2941, 0.3007] 95% CI, n=10 | 1.027 | **Go** 1.027x |
| account_hot/c4/p95_ms | ms (lower is better) | 0.4316 | [0.4206, 0.4468] 95% CI, n=10 | 0.4349 | [0.4275, 0.4492] 95% CI, n=10 | 1.008 | inconclusive |
| account_hot/c4/p99_ms | ms (lower is better) | 0.5711 | [0.5526, 0.5841] 95% CI, n=10 | 0.5282 | [0.517, 0.5458] 95% CI, n=10 | 0.9249 | **Rust** 1.081x |
| account_hot/c4/rps | req/s (higher is better) | 13,389 | [13,065, 13,633] 95% CI, n=10 | 13,091 | [12,850, 13,133] 95% CI, n=10 | 0.9777 | inconclusive |
| application/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| application/c4/p50_ms | ms (lower is better) | 0.2793 | [0.2756, 0.2895] 95% CI, n=10 | 0.2563 | [0.2534, 0.2611] 95% CI, n=10 | 0.9175 | **Rust** 1.09x |
| application/c4/p95_ms | ms (lower is better) | 0.4139 | [0.3982, 0.4541] 95% CI, n=10 | 0.3694 | [0.3641, 0.3835] 95% CI, n=10 | 0.8924 | **Rust** 1.121x |
| application/c4/p99_ms | ms (lower is better) | 0.5446 | [0.5199, 0.582] 95% CI, n=10 | 0.4673 | [0.4436, 0.4868] 95% CI, n=10 | 0.8581 | **Rust** 1.165x |
| application/c4/rps | req/s (higher is better) | 13,932 | [13,354, 14,155] 95% CI, n=10 | 15,235 | [14,890, 15,418] 95% CI, n=10 | 1.094 | **Rust** 1.094x |
| blocks_json/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| blocks_json/c4/p50_ms | ms (lower is better) | 0.4347 | [0.4164, 0.4459] 95% CI, n=10 | 0.314 | [0.3077, 0.3176] 95% CI, n=10 | 0.7224 | **Rust** 1.384x |
| blocks_json/c4/p95_ms | ms (lower is better) | 0.7077 | [0.6785, 0.7489] 95% CI, n=10 | 0.4593 | [0.4534, 0.4967] 95% CI, n=10 | 0.649 | **Rust** 1.541x |
| blocks_json/c4/p99_ms | ms (lower is better) | 1.409 | [1.325, 1.786] 95% CI, n=10 | 0.5535 | [0.547, 0.6759] 95% CI, n=10 | 0.3928 | **Rust** 2.546x |
| blocks_json/c4/rps | req/s (higher is better) | 8419 | [8162, 8923] 95% CI, n=10 | 12,308 | [11,896, 12,537] 95% CI, n=10 | 1.462 | **Rust** 1.462x |
| blocks_msgpack/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| blocks_msgpack/c4/p50_ms | ms (lower is better) | 0.2975 | [0.2869, 0.3166] 95% CI, n=10 | 0.2463 | [0.2417, 0.2597] 95% CI, n=10 | 0.8277 | **Rust** 1.208x |
| blocks_msgpack/c4/p95_ms | ms (lower is better) | 0.4463 | [0.431, 0.4967] 95% CI, n=10 | 0.3565 | [0.3514, 0.4036] 95% CI, n=10 | 0.7987 | **Rust** 1.252x |
| blocks_msgpack/c4/p99_ms | ms (lower is better) | 0.5975 | [0.5425, 0.6604] 95% CI, n=10 | 0.4563 | [0.4403, 0.5224] 95% CI, n=10 | 0.7637 | **Rust** 1.309x |
| blocks_msgpack/c4/rps | req/s (higher is better) | 13,104 | [12,148, 13,507] 95% CI, n=10 | 15,892 | [14,750, 16,148] 95% CI, n=10 | 1.213 | **Rust** 1.213x |
| box/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| box/c4/p50_ms | ms (lower is better) | 0.2769 | [0.2733, 0.284] 95% CI, n=10 | 0.2474 | [0.2448, 0.2508] 95% CI, n=10 | 0.8934 | **Rust** 1.119x |
| box/c4/p95_ms | ms (lower is better) | 0.4014 | [0.3934, 0.4411] 95% CI, n=10 | 0.3575 | [0.3482, 0.3664] 95% CI, n=10 | 0.8907 | **Rust** 1.123x |
| box/c4/p99_ms | ms (lower is better) | 0.5266 | [0.5098, 0.5606] 95% CI, n=10 | 0.4498 | [0.4369, 0.4652] 95% CI, n=10 | 0.8542 | **Rust** 1.171x |
| box/c4/rps | req/s (higher is better) | 14,114 | [13,456, 14,302] 95% CI, n=10 | 15,797 | [15,585, 15,976] 95% CI, n=10 | 1.119 | **Rust** 1.119x |
| simulate/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| simulate/c4/p50_ms | ms (lower is better) | 0.7561 | [0.5961, 0.8674] 95% CI, n=10 | 0.7823 | [0.7714, 0.7991] 95% CI, n=10 | 1.035 | inconclusive |
| simulate/c4/p95_ms | ms (lower is better) | 1.159 | [1.113, 1.279] 95% CI, n=10 | 1.142 | [1.124, 1.161] 95% CI, n=10 | 0.986 | inconclusive |
| simulate/c4/p99_ms | ms (lower is better) | 2.988 | [2.409, 3.256] 95% CI, n=10 | 1.265 | [1.255, 1.311] 95% CI, n=10 | 0.4232 | **Rust** 2.363x |
| simulate/c4/rps | req/s (higher is better) | 4863 | [4458, 5160] 95% CI, n=10 | 4872 | [4793, 4939] 95% CI, n=10 | 1.002 | inconclusive |
| simulate_app/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| simulate_app/c4/p50_ms | ms (lower is better) | 0.9389 | [0.8006, 1.218] 95% CI, n=10 | 1.106 | [1.086, 1.161] 95% CI, n=10 | 1.178 | inconclusive |
| simulate_app/c4/p95_ms | ms (lower is better) | 1.66 | [1.592, 1.765] 95% CI, n=10 | 1.735 | [1.72, 1.81] 95% CI, n=10 | 1.045 | inconclusive |
| simulate_app/c4/p99_ms | ms (lower is better) | 4.16 | [3.317, 5.56] 95% CI, n=10 | 1.945 | [1.92, 2.002] 95% CI, n=10 | 0.4676 | **Rust** 2.138x |
| simulate_app/c4/rps | req/s (higher is better) | 3484 | [3104, 3760] 95% CI, n=10 | 3168 | [3075, 3200] 95% CI, n=10 | 0.9092 | inconclusive |
| status/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| status/c4/p50_ms | ms (lower is better) | 0.2503 | [0.2467, 0.26] 95% CI, n=10 | 0.2448 | [0.2412, 0.2521] 95% CI, n=10 | 0.9781 | inconclusive |
| status/c4/p95_ms | ms (lower is better) | 0.3629 | [0.3552, 0.4011] 95% CI, n=10 | 0.3612 | [0.3521, 0.3779] 95% CI, n=10 | 0.9954 | inconclusive |
| status/c4/p99_ms | ms (lower is better) | 0.4645 | [0.4593, 0.5179] 95% CI, n=10 | 0.4517 | [0.4316, 0.4809] 95% CI, n=10 | 0.9725 | inconclusive |
| status/c4/rps | req/s (higher is better) | 15,613 | [14,770, 15,802] 95% CI, n=10 | 15,815 | [15,334, 16,122] 95% CI, n=10 | 1.013 | inconclusive |
| tx_params/c4/error_rate | ratio (lower is better) | 0 | [0, 0] 95% CI, n=10 | 0 | [0, 0] 95% CI, n=10 | n/a | inconclusive |
| tx_params/c4/p50_ms | ms (lower is better) | 0.2559 | [0.2479, 0.2787] 95% CI, n=10 | 0.2512 | [0.2427, 0.2621] 95% CI, n=10 | 0.9814 | inconclusive |
| tx_params/c4/p95_ms | ms (lower is better) | 0.3871 | [0.3572, 0.4271] 95% CI, n=10 | 0.3761 | [0.3515, 0.4103] 95% CI, n=10 | 0.9716 | inconclusive |
| tx_params/c4/p99_ms | ms (lower is better) | 0.5005 | [0.456, 0.5565] 95% CI, n=10 | 0.477 | [0.4334, 0.5629] 95% CI, n=10 | 0.953 | inconclusive |
| tx_params/c4/rps | req/s (higher is better) | 15,135 | [13,798, 15,775] 95% CI, n=10 | 15,361 | [14,623, 16,065] 95% CI, n=10 | 1.015 | inconclusive |

Rust/Go is the ratio of the medians. For lower-is-better units a value below 1 means Rust is faster; for higher-is-better units a value above 1 means Rust is faster. A side is only marked faster when the two spreads (95% CI of the median for n >= 6, else min/max) do not overlap. Rows marked (synthetic) come from the selftest tier and measure the harness, not either node.

#### Tiers

| Tier | Exit | Duration (s) |
|---|---|---|
| build | 0 | 226.1 |
| micro | 0 | 3511 |
| replay | 0 | 32.78 |
| rest | 0 | 448.7 |
| localnet | 0 | 914.7 |
<!-- bench-baseline:end local-main -->

### Baseline `local-testnet-prefix50`: replay of real certificates

<!-- bench-baseline:begin local-testnet-prefix50 -->
Command: `make bench-compare TIERS=replay CORPUS=testnet-prefix50 RUNS=10`

#### Summary by tier

| Tier | Paired rows | Rust faster | Go faster | Inconclusive |
|---|---|---|---|---|
| replay | 7 | 5 | 2 | 0 |

7 paired row(s) in total; 0 paired row(s) excluded from the baseline file (every paired row is kept, including rows whose Go or Rust median is 0). Counts come from the tables below.

Generated 2026-11-16T12:19:10Z. Methodology and fairness rules: [docs/BENCHMARK_COMPARISON.md](https://github.com/xarmian/algod-rust/blob/main/docs/BENCHMARK_COMPARISON.md).

**Status: OK.** 7 paired row(s): Rust faster 5, Go faster 2, inconclusive 0; 0 unpaired.

#### Builds

| | go-algorand | algod-rust |
|---|---|---|
| Commit | `31186e99a69e74483ad95e9ce872903b74758abf` | `e5325a98f62629aef4864f548c489fe2d49d2956` |
| Describe | `v5.0.5-stable` | `e5325a98` |
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
| testnet-prefix50/blocks_per_s | block/s (higher is better) | 434.1 | [426.5, 444.1] 95% CI, n=10 | 501.6 | [481.8, 507.4] 95% CI, n=10 | 1.156 | **Rust** 1.156x |
| testnet-prefix50/cpu_s | s (lower is better) | 0.9634 | [0.9129, 0.999] 95% CI, n=10 | 0.393 | [0.3809, 0.4084] 95% CI, n=10 | 0.408 | **Rust** 2.451x |
| testnet-prefix50/db_mb | MB (lower is better) | 0.8244 | [0.8244, 0.8244] 95% CI, n=10 | 3.842 | [3.842, 3.842] 95% CI, n=10 | 4.66 | **Go** 4.66x |
| testnet-prefix50/peak_rss_mb | MB (lower is better) | 140.3 | [139.3, 145.6] 95% CI, n=10 | 33.58 | [33.32, 33.95] 95% CI, n=10 | 0.2394 | **Rust** 4.178x |
| testnet-prefix50/txns_per_s | txn/s (higher is better) | 8.682 | [8.53, 8.882] 95% CI, n=10 | 10.03 | [9.637, 10.15] 95% CI, n=10 | 1.156 | **Rust** 1.156x |
| testnet-prefix50/wall_s | s (lower is better) | 0.1152 | [0.1126, 0.1172] 95% CI, n=10 | 0.09968 | [0.09854, 0.1038] 95% CI, n=10 | 0.8654 | **Rust** 1.156x |
| testnet-prefix50/write_mb | MB (lower is better) | 2.16 | [2.137, 2.18] 95% CI, n=10 | 4.297 | [4.297, 4.297] 95% CI, n=10 | 1.989 | **Go** 1.989x |

Rust/Go is the ratio of the medians. For lower-is-better units a value below 1 means Rust is faster; for higher-is-better units a value above 1 means Rust is faster. A side is only marked faster when the two spreads (95% CI of the median for n >= 6, else min/max) do not overlap. Rows marked (synthetic) come from the selftest tier and measure the harness, not either node.

#### Tiers

| Tier | Exit | Duration (s) |
|---|---|---|
| build | 0 | 158.7 |
| replay | 0 | 7.427 |
<!-- bench-baseline:end local-testnet-prefix50 -->

## Open findings from the epic

The comparison already paid for itself: the equality gates and the first
measurements produced these open issues. They are the explanation for the rows
where algod-rust is behind, and they feed the optimization pass #2110.

### Performance

Every row where Go is faster with non-overlapping ranges, and who owns it
(2026-11-16 re-run, `RUNS=10`):

| Row (Go faster) | Ratio | Owner / reason |
|---|---|---|
| `replay small` `write_mb`, `db_mb` | 2.34x, 1.13x | [#2316](https://github.com/xarmian/algod-rust/issues/2316): the tracker WAL (about 140 of 154 MB) is written once and checkpointed; block-device writes in the `localnet` tier are 37x lower than go's |
| `replay testnet-prefix50` `db_mb`, `write_mb` | 4.66x, 1.99x | [#2316](https://github.com/xarmian/algod-rust/issues/2316): fixed schema/index overhead of a 50-block database (3.8 vs 0.8 MB, 4.3 vs 2.2 MB); wall clock is no longer a Go-faster row (#2339) |
| `micro avm/app-state-box` | 1.26x | [#2320](https://github.com/xarmian/algod-rust/issues/2320): per-call setup costs (bytecode parse, machine construction, allocation) |
| `micro agreement/sortition-select-f128` | 1.22x | [#2321](https://github.com/xarmian/algod-rust/issues/2321): software f128; measured, division is not the lever (PERF_PHASE23.md row 9) |
| `rest account_hot` p50 | 1.03x | [#2340](https://github.com/xarmian/algod-rust/issues/2340) |
| `localnet` `fixed` p95/p99, `ladder-50` p50/p95/p99 latency | 1.23x, 1.05x to 1.07x | round-quantised noise (see Headline), no node cost |

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
