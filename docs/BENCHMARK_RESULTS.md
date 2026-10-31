# Go vs Rust benchmark results (baseline)

First published baseline of the Phase 23 comparison (epic #2101, issue #2109):
go-algorand `v5.0.4-stable` against algod-rust, same machine, same inputs,
every macro tier gated on Go/Rust final-state or response equality. Method
and fairness rules: [BENCHMARK_COMPARISON.md](BENCHMARK_COMPARISON.md).
Regenerate the blocks below with `report.py --publish` (see
[Regression detection](#regression-detection-and-ci)).

## Read this first

- **Indicative, not authoritative.** These numbers come from one developer
  machine (a desktop i7-13700 running Ubuntu in WSL2 with Docker inside the
  WSL VM), three runs per tier. With n = 3 there is no confidence interval,
  only the min-max range, and a side is marked faster only when the two ranges
  do not overlap. CI-runner numbers (the weekly `bench-compare` workflow) are
  noisier still; dedicated, quiet hardware is preferred for anything that
  becomes a decision.
- **Numbers where Rust is behind Go are shown as measured.** Nothing was
  tuned, filtered or re-run to improve a row. The open findings that explain
  the biggest gaps are listed [below](#open-findings-from-the-epic).
- **Smoke profiles.** `rest` ran its smoke profile (concurrency 4, one
  1-second step per endpoint) and `localnet` its smoke profile (200 fixed
  transactions plus one 10-second step at 50 TPS, 1 relay + 4 participation
  nodes, 2 CPUs / 3 GB per container). Round times are quantised (3 s vs
  3.33 s), so a 10% `localnet` difference on a 10-second step is quantisation,
  not throughput. The full ladders are long runs for quiet hardware and are not
  in this baseline.
- **The 50-round testnet prefix is startup-dominated.** `testnet-prefix50`
  replays 50 real blocks in about 0.1 s (Go) and 0.4 s (Rust); it proves that
  real certificates authenticate identically on both sides, and says almost
  nothing about steady-state speed.
- **Not in this baseline.** The `catchup` tier (public network, hours, not
  reproducible), the full `rest`/`localnet` ladders, and replay of the large
  (~1M transaction) corpus: the decision on how to publish the large corpus is
  pending, so it is not available as a release asset and no large-corpus numbers
  are reported. The small corpus is committed in the repository.
- Post-optimization numbers (epic acceptance criterion, issue #2110) are not
  here yet; they will be added next to this baseline.

## Headline

All four tiers passed their equality gates on this run (replay final state
equals `corpus.json` on both sides; the REST responses are equal modulo the
issue-linked allowlist; both localnets confirmed the same txid set), so every
row below is a like-for-like measurement.

The per-tier row counts (paired, Rust faster, Go faster, inconclusive) are
generated: each block below starts with a "Summary by tier" table counted from
the same rows as its result tables, and states how many paired rows were
excluded (none). What stands out, in words (the figures are medians of the
tables below):

- **micro**: Go is 1.1x to 2.1x faster on codec encode/decode, txid and the
  txn commitments; certificate and proposal decode are 2.7x and 2.9x slower in
  Rust. Rust is faster on Ed25519 (1.15x), VRF and credential verification
  (1.4x).
- **replay, small corpus**: Go replays in 1.3 s, Rust in 4.8 s (3.6x slower
  wall clock); Rust uses 1.9x less CPU time and 7.3x less peak RSS.
- **replay, testnet-prefix50**: Go 0.11 s, Rust 0.37 s (3.2x slower),
  startup-dominated; Rust peak RSS 5.2x lower.
- **rest (smoke, c4)**: Rust is ahead or level on every endpoint except
  `simulate`, where it serves 4.6x fewer requests/s (1,112 vs 5,068).
- **localnet (smoke)**: level on throughput and latency within round
  quantisation; Rust peak RSS 6.5x lower and block-device writes about 70x
  lower.

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
Command: `BENCH_REST_PROFILE=smoke BENCH_LOCALNET_PROFILE=smoke make bench-compare TIERS=micro,replay,rest,localnet CORPUS=small RUNS=3`

#### Summary by tier

| Tier | Paired rows | Rust faster | Go faster | Inconclusive |
|---|---|---|---|---|
| localnet | 22 | 4 | 4 | 14 |
| micro | 27 | 9 | 16 | 2 |
| replay | 6 | 2 | 4 | 0 |
| rest | 50 | 26 | 4 | 20 |

105 paired row(s) in total; 0 paired row(s) excluded from the baseline file (every paired row is kept, including rows whose Go or Rust median is 0). Counts come from the tables below.

Generated 2026-10-31T13:40:35Z. Methodology and fairness rules: [docs/BENCHMARK_COMPARISON.md](https://github.com/xarmian/algod-rust/blob/main/docs/BENCHMARK_COMPARISON.md).

**Status: OK.** 105 paired row(s): Rust faster 41, Go faster 28, inconclusive 36; 0 unpaired.

#### Builds

| | go-algorand | algod-rust |
|---|---|---|
| Commit | `927ae0863cbb4cf29c6845c088a4ea4c439b10bb` | `561f7528d912ace27e71c06571b8d590c86ccc53` |
| Describe | `v5.0.4-stable` | `561f7528` |
| Pin | expected `v5.0.4-stable`, matches | |
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
| Kernel | 6.18.54.1-microsoft-standard-WSL2 |
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
| fixed/commit_rounds | rounds (lower is better) | 3 | [3, 3] range, n=3 | 3 | [3, 3] range, n=3 | 1 | inconclusive |
| fixed/commit_time_s | s (lower is better) | 9 | [9, 9] range, n=3 | 10 | [10, 10] range, n=3 | 1.111 | **Go** 1.111x |
| fixed/confirmed_tps | txn/s (higher is better) | 22.22 | [22.22, 22.22] range, n=3 | 20 | [20, 20] range, n=3 | 0.9 | **Go** 1.111x |
| fixed/latency_p50_ms | ms (lower is better) | 4047 | [4022, 5031] range, n=3 | 4021 | [4020, 5030] range, n=3 | 0.9936 | inconclusive |
| fixed/latency_p95_ms | ms (lower is better) | 6060 | [6036, 6067] range, n=3 | 6035 | [5034, 6035] range, n=3 | 0.9959 | **Rust** 1.004x |
| fixed/latency_p99_ms | ms (lower is better) | 6060 | [6036, 6067] range, n=3 | 6035 | [5034, 6035] range, n=3 | 0.9959 | **Rust** 1.004x |
| fixed/rejected_groups | groups (lower is better) | 0 | [0, 0] range, n=3 | 0 | [0, 0] range, n=3 | n/a | inconclusive |
| fixed/round_time_s | s (lower is better) | 3 | [3, 3] range, n=3 | 3.333 | [3.333, 3.333] range, n=3 | 1.111 | **Go** 1.111x |
| fixed/set_tps | txn/s (higher is better) | 22.22 | [22.22, 22.22] range, n=3 | 20 | [20, 20] range, n=3 | 0.9 | **Go** 1.111x |
| fixed/start_backlog_txns | txns (lower is better) | 0 | [0, 0] range, n=3 | 0 | [0, 0] range, n=3 | n/a | inconclusive |
| fixed/submit_tps | txn/s (higher is better) | 99.88 | [99.83, 99.89] range, n=3 | 99.88 | [99.87, 99.9] range, n=3 | 1 | inconclusive |
| ladder-50/blockio_write_mb | MB (lower is better) | 175.2 | [152.7, 176.1] range, n=3 | 2.518 | [2.155, 3.529] range, n=3 | 0.01437 | **Rust** 69.6x |
| ladder-50/confirmed_tps | txn/s (higher is better) | 29.44 | [28.44, 30] range, n=3 | 26.11 | [24, 30.11] range, n=3 | 0.8868 | inconclusive |
| ladder-50/cpu_cores | cores (lower is better) | 0.2513 | [0.1852, 0.2762] range, n=3 | 0.08587 | [0.0728, 0.2155] range, n=3 | 0.3417 | inconclusive |
| ladder-50/latency_p50_ms | ms (lower is better) | 4526 | [4274, 4528] range, n=3 | 4524 | [4523, 4777] range, n=3 | 0.9996 | inconclusive |
| ladder-50/latency_p95_ms | ms (lower is better) | 5535 | [5286, 5537] range, n=3 | 5781 | [5530, 6046] range, n=3 | 1.044 | inconclusive |
| ladder-50/latency_p99_ms | ms (lower is better) | 5535 | [5286, 5537] range, n=3 | 5781 | [5530, 6046] range, n=3 | 1.044 | inconclusive |
| ladder-50/rejected_groups | groups (lower is better) | 0 | [0, 0] range, n=3 | 0 | [0, 0] range, n=3 | n/a | inconclusive |
| ladder-50/round_time_s | s (lower is better) | 3 | [3, 3] range, n=3 | 3 | [3, 3] range, n=3 | 1 | inconclusive |
| ladder-50/rss_mb_peak | MB (lower is better) | 1152 | [1134, 1158] range, n=3 | 178.3 | [172.2, 189.4] range, n=3 | 0.1547 | **Rust** 6.463x |
| ladder-50/start_backlog_txns | txns (lower is better) | 0 | [0, 0] range, n=3 | 0 | [0, 0] range, n=3 | n/a | inconclusive |
| ladder-50/submit_tps | txn/s (higher is better) | 49.99 | [49.99, 49.99] range, n=3 | 49.99 | [49.99, 49.99] range, n=3 | 1 | inconclusive |

##### micro

| Benchmark | Unit | Go median | Go spread | Rust median | Rust spread | Rust/Go | Faster |
|---|---|---|---|---|---|---|---|
| agreement/credential-verify | ns/op (lower is better) | 144,792 | [142,236, 148,686] range, n=3 | 101,633 | [100,511, 106,496] range, n=3 | 0.7019 | **Rust** 1.425x |
| agreement/decode-cert | ns/op (lower is better) | 3068 | [3033, 3156] range, n=3 | 8278 | [8040, 8848] range, n=3 | 2.698 | **Go** 2.698x |
| agreement/decode-proposal | ns/op (lower is better) | 420.1 | [400.6, 460.2] range, n=3 | 1236 | [1215, 1243] range, n=3 | 2.942 | **Go** 2.942x |
| agreement/sortition-select | ns/op (lower is better) | 14,388 | [13,259, 14,962] range, n=3 | 318.2 | [317.6, 318.3] range, n=3 | 0.02211 | **Rust** 45.22x |
| agreement/sortition-select-f128 | ns/op (lower is better) | 757.3 | [739.6, 772.3] range, n=3 | 956.3 | [916.2, 957.5] range, n=3 | 1.263 | **Go** 1.263x |
| avm/app-state-box | ns/op (lower is better) | 8943 | [8544, 10,590] range, n=3 | 12,485 | [12,235, 12,652] range, n=3 | 1.396 | **Go** 1.396x |
| avm/lsig-arith-loop | ns/op (lower is better) | 126,643 | [125,376, 131,531] range, n=3 | 158,308 | [155,352, 158,798] range, n=3 | 1.25 | **Go** 1.25x |
| avm/lsig-bytes-ops | ns/op (lower is better) | 186,051 | [175,464, 189,400] range, n=3 | 186,773 | [185,129, 187,325] range, n=3 | 1.004 | inconclusive |
| avm/lsig-hash-loop | ns/op (lower is better) | 44,947 | [43,917, 47,146] range, n=3 | 41,961 | [40,544, 42,057] range, n=3 | 0.9336 | **Rust** 1.071x |
| codec/block-hash | ns/op (lower is better) | 1204 | [1165, 1220] range, n=3 | 1707 | [1629, 1715] range, n=3 | 1.418 | **Go** 1.418x |
| codec/decode-block-large | ns/op (lower is better) | 321,206 | [309,677, 324,437] range, n=3 | 450,225 | [441,665, 475,009] range, n=3 | 1.402 | **Go** 1.402x |
| codec/decode-block-small | ns/op (lower is better) | 1038 | [992.9, 1039] range, n=3 | 1185 | [1157, 1198] range, n=3 | 1.141 | **Go** 1.141x |
| codec/decode-stxn | ns/op (lower is better) | 646.8 | [635.6, 657] range, n=3 | 463 | [440.5, 468.8] range, n=3 | 0.7158 | **Rust** 1.397x |
| codec/encode-block-large | ns/op (lower is better) | 473,256 | [454,393, 490,007] range, n=3 | 772,762 | [759,993, 784,282] range, n=3 | 1.633 | **Go** 1.633x |
| codec/encode-block-small | ns/op (lower is better) | 1208 | [1186, 1259] range, n=3 | 2095 | [2094, 2096] range, n=3 | 1.734 | **Go** 1.734x |
| codec/encode-stxn | ns/op (lower is better) | 711.6 | [642.9, 720.3] range, n=3 | 1152 | [1140, 1187] range, n=3 | 1.618 | **Go** 1.618x |
| codec/txid | ns/op (lower is better) | 920.3 | [905.6, 953.3] range, n=3 | 1822 | [1816, 1828] range, n=3 | 1.98 | **Go** 1.98x |
| commit/txn-merkle-sha512_256 | ns/op (lower is better) | 1,273,589 | [1,271,035, 1,285,803] range, n=3 | 2,673,341 | [2,617,843, 2,682,967] range, n=3 | 2.099 | **Go** 2.099x |
| commit/txn-vc-sha256 | ns/op (lower is better) | 1,295,904 | [1,294,804, 1,401,090] range, n=3 | 2,285,048 | [2,255,447, 2,345,166] range, n=3 | 1.763 | **Go** 1.763x |
| crypto/ed25519-batch-1024 | ns/op (lower is better) | 39,524,605 | [39,333,841, 40,437,423] range, n=3 | 34,495,942 | [34,068,897, 34,752,626] range, n=3 | 0.8728 | **Rust** 1.146x |
| crypto/ed25519-batch-64 | ns/op (lower is better) | 2,442,239 | [2,403,332, 2,468,163] range, n=3 | 2,168,229 | [2,145,172, 2,223,924] range, n=3 | 0.8878 | **Rust** 1.126x |
| crypto/ed25519-verify | ns/op (lower is better) | 40,001 | [38,187, 40,760] range, n=3 | 34,070 | [34,016, 34,809] range, n=3 | 0.8517 | **Rust** 1.174x |
| crypto/falcon-verify | ns/op (lower is better) | 32,863 | [32,502, 34,646] range, n=3 | 32,641 | [32,082, 33,002] range, n=3 | 0.9932 | inconclusive |
| crypto/sha512_256-1KiB | ns/op (lower is better) | 1322 | [1314, 1358] range, n=3 | 1509 | [1488, 1540] range, n=3 | 1.141 | **Go** 1.141x |
| crypto/sha512_256-32B | ns/op (lower is better) | 181.7 | [179.9, 185.3] range, n=3 | 176.3 | [174.3, 179.1] range, n=3 | 0.9701 | **Rust** 1.031x |
| crypto/sha512_256-64KiB | ns/op (lower is better) | 78,299 | [75,608, 80,225] range, n=3 | 88,653 | [88,047, 89,216] range, n=3 | 1.132 | **Go** 1.132x |
| crypto/vrf-verify | ns/op (lower is better) | 141,968 | [137,698, 143,642] range, n=3 | 101,635 | [99,751, 102,621] range, n=3 | 0.7159 | **Rust** 1.397x |

##### replay

| Benchmark | Unit | Go median | Go spread | Rust median | Rust spread | Rust/Go | Faster |
|---|---|---|---|---|---|---|---|
| small/blocks_per_s | block/s (higher is better) | 1522 | [1362, 1557] range, n=3 | 418 | [396.4, 420.8] range, n=3 | 0.2747 | **Go** 3.641x |
| small/cpu_s | s (lower is better) | 2.868 | [2.8, 3.181] range, n=3 | 1.482 | [1.434, 1.634] range, n=3 | 0.5169 | **Rust** 1.935x |
| small/db_mb | MB (lower is better) | 9.293 | [9.278, 9.297] range, n=3 | 9.969 | [9.969, 9.969] range, n=3 | 1.073 | **Go** 1.073x |
| small/peak_rss_mb | MB (lower is better) | 256.3 | [255.1, 257.4] range, n=3 | 35.11 | [35.07, 35.23] range, n=3 | 0.137 | **Rust** 7.3x |
| small/txns_per_s | txn/s (higher is better) | 9385 | [8398, 9599] range, n=3 | 2578 | [2444, 2595] range, n=3 | 0.2747 | **Go** 3.641x |
| small/wall_s | s (lower is better) | 1.314 | [1.285, 1.468] range, n=3 | 4.784 | [4.752, 5.046] range, n=3 | 3.641 | **Go** 3.641x |

##### rest

| Benchmark | Unit | Go median | Go spread | Rust median | Rust spread | Rust/Go | Faster |
|---|---|---|---|---|---|---|---|
| account_assets/c4/error_rate | ratio (lower is better) | 0 | [0, 0] range, n=3 | 0 | [0, 0] range, n=3 | n/a | inconclusive |
| account_assets/c4/p50_ms | ms (lower is better) | 0.3544 | [0.3213, 0.358] range, n=3 | 0.2825 | [0.2767, 0.2946] range, n=3 | 0.7971 | **Rust** 1.255x |
| account_assets/c4/p95_ms | ms (lower is better) | 0.6187 | [0.5289, 0.6573] range, n=3 | 0.4223 | [0.4215, 0.513] range, n=3 | 0.6826 | **Rust** 1.465x |
| account_assets/c4/p99_ms | ms (lower is better) | 0.9024 | [0.7991, 0.9342] range, n=3 | 0.5293 | [0.5239, 0.6657] range, n=3 | 0.5865 | **Rust** 1.705x |
| account_assets/c4/rps | req/s (higher is better) | 10,485 | [10,365, 11,714] range, n=3 | 13,669 | [12,670, 13,926] range, n=3 | 1.304 | **Rust** 1.304x |
| account_cold/c4/error_rate | ratio (lower is better) | 0 | [0, 0] range, n=3 | 0 | [0, 0] range, n=3 | n/a | inconclusive |
| account_cold/c4/p50_ms | ms (lower is better) | 0.2774 | [0.2728, 0.2825] range, n=3 | 0.2629 | [0.2565, 0.2676] range, n=3 | 0.9479 | **Rust** 1.055x |
| account_cold/c4/p95_ms | ms (lower is better) | 0.4217 | [0.4127, 0.4351] range, n=3 | 0.3974 | [0.3824, 0.3989] range, n=3 | 0.9424 | **Rust** 1.061x |
| account_cold/c4/p99_ms | ms (lower is better) | 0.5449 | [0.5321, 0.5664] range, n=3 | 0.5004 | [0.4787, 0.5026] range, n=3 | 0.9183 | **Rust** 1.089x |
| account_cold/c4/rps | req/s (higher is better) | 13,894 | [13,593, 14,140] range, n=3 | 14,736 | [14,497, 15,168] range, n=3 | 1.061 | **Rust** 1.061x |
| account_hot/c4/error_rate | ratio (lower is better) | 0 | [0, 0] range, n=3 | 0 | [0, 0] range, n=3 | n/a | inconclusive |
| account_hot/c4/p50_ms | ms (lower is better) | 0.3241 | [0.3236, 0.3323] range, n=3 | 0.2694 | [0.2632, 0.2788] range, n=3 | 0.8312 | **Rust** 1.203x |
| account_hot/c4/p95_ms | ms (lower is better) | 0.5197 | [0.5107, 0.5293] range, n=3 | 0.4116 | [0.3961, 0.4374] range, n=3 | 0.792 | **Rust** 1.263x |
| account_hot/c4/p99_ms | ms (lower is better) | 0.735 | [0.7127, 0.7469] range, n=3 | 0.5276 | [0.5018, 0.5704] range, n=3 | 0.7179 | **Rust** 1.393x |
| account_hot/c4/rps | req/s (higher is better) | 11,551 | [11,431, 11,842] range, n=3 | 14,322 | [13,766, 14,707] range, n=3 | 1.24 | **Rust** 1.24x |
| application/c4/error_rate | ratio (lower is better) | 0 | [0, 0] range, n=3 | 0 | [0, 0] range, n=3 | n/a | inconclusive |
| application/c4/p50_ms | ms (lower is better) | 0.2913 | [0.2839, 0.3034] range, n=3 | 0.2697 | [0.2646, 0.2708] range, n=3 | 0.9257 | **Rust** 1.08x |
| application/c4/p95_ms | ms (lower is better) | 0.4676 | [0.4189, 0.4749] range, n=3 | 0.4009 | [0.3937, 0.4045] range, n=3 | 0.8574 | **Rust** 1.166x |
| application/c4/p99_ms | ms (lower is better) | 0.6044 | [0.5255, 0.6377] range, n=3 | 0.5039 | [0.4928, 0.5126] range, n=3 | 0.8336 | **Rust** 1.2x |
| application/c4/rps | req/s (higher is better) | 13,035 | [12,711, 13,709] range, n=3 | 14,386 | [14,287, 14,680] range, n=3 | 1.104 | **Rust** 1.104x |
| blocks_json/c4/error_rate | ratio (lower is better) | 0 | [0, 0] range, n=3 | 0 | [0, 0] range, n=3 | n/a | inconclusive |
| blocks_json/c4/p50_ms | ms (lower is better) | 0.4409 | [0.4378, 0.4461] range, n=3 | 0.3235 | [0.3196, 0.3405] range, n=3 | 0.7336 | **Rust** 1.363x |
| blocks_json/c4/p95_ms | ms (lower is better) | 0.7394 | [0.733, 0.7821] range, n=3 | 0.4745 | [0.472, 0.5049] range, n=3 | 0.6416 | **Rust** 1.559x |
| blocks_json/c4/p99_ms | ms (lower is better) | 1.334 | [1.273, 1.472] range, n=3 | 0.587 | [0.5815, 0.6219] range, n=3 | 0.4399 | **Rust** 2.273x |
| blocks_json/c4/rps | req/s (higher is better) | 8184 | [8115, 8193] range, n=3 | 11,920 | [11,303, 12,028] range, n=3 | 1.457 | **Rust** 1.457x |
| blocks_msgpack/c4/error_rate | ratio (lower is better) | 0 | [0, 0] range, n=3 | 0 | [0, 0] range, n=3 | n/a | inconclusive |
| blocks_msgpack/c4/p50_ms | ms (lower is better) | 0.3246 | [0.3201, 0.3339] range, n=3 | 0.2585 | [0.2573, 0.2626] range, n=3 | 0.7964 | **Rust** 1.256x |
| blocks_msgpack/c4/p95_ms | ms (lower is better) | 0.5143 | [0.487, 0.5211] range, n=3 | 0.3928 | [0.3906, 0.3941] range, n=3 | 0.7638 | **Rust** 1.309x |
| blocks_msgpack/c4/p99_ms | ms (lower is better) | 0.6546 | [0.6474, 0.693] range, n=3 | 0.4999 | [0.4902, 0.5181] range, n=3 | 0.7637 | **Rust** 1.309x |
| blocks_msgpack/c4/rps | req/s (higher is better) | 11,828 | [11,496, 11,983] range, n=3 | 14,962 | [14,796, 15,011] range, n=3 | 1.265 | **Rust** 1.265x |
| box/c4/error_rate | ratio (lower is better) | 0 | [0, 0] range, n=3 | 0 | [0, 0] range, n=3 | n/a | inconclusive |
| box/c4/p50_ms | ms (lower is better) | 0.2935 | [0.2824, 0.3119] range, n=3 | 0.2703 | [0.2698, 0.2807] range, n=3 | 0.9209 | **Rust** 1.086x |
| box/c4/p95_ms | ms (lower is better) | 0.4398 | [0.4302, 0.5519] range, n=3 | 0.4639 | [0.4276, 0.4852] range, n=3 | 1.055 | inconclusive |
| box/c4/p99_ms | ms (lower is better) | 0.559 | [0.5508, 0.711] range, n=3 | 0.5993 | [0.5545, 0.631] range, n=3 | 1.072 | inconclusive |
| box/c4/rps | req/s (higher is better) | 13,240 | [11,993, 13,636] range, n=3 | 13,900 | [13,322, 14,174] range, n=3 | 1.05 | inconclusive |
| simulate/c4/error_rate | ratio (lower is better) | 0 | [0, 0] range, n=3 | 0 | [0, 0] range, n=3 | n/a | inconclusive |
| simulate/c4/p50_ms | ms (lower is better) | 0.6497 | [0.5054, 0.6716] range, n=3 | 3.702 | [3.09, 5.316] range, n=3 | 5.698 | **Go** 5.698x |
| simulate/c4/p95_ms | ms (lower is better) | 1.247 | [1.228, 1.278] range, n=3 | 6.201 | [4.512, 7.34] range, n=3 | 4.974 | **Go** 4.974x |
| simulate/c4/p99_ms | ms (lower is better) | 2.884 | [2.649, 3.772] range, n=3 | 7.411 | [5.799, 8.785] range, n=3 | 2.57 | **Go** 2.57x |
| simulate/c4/rps | req/s (higher is better) | 5068 | [4890, 6159] range, n=3 | 1112 | [813.7, 1242] range, n=3 | 0.2195 | **Go** 4.556x |
| status/c4/error_rate | ratio (lower is better) | 0 | [0, 0] range, n=3 | 0 | [0, 0] range, n=3 | n/a | inconclusive |
| status/c4/p50_ms | ms (lower is better) | 0.2734 | [0.2651, 0.274] range, n=3 | 0.2845 | [0.2516, 0.2877] range, n=3 | 1.04 | inconclusive |
| status/c4/p95_ms | ms (lower is better) | 0.4355 | [0.416, 0.491] range, n=3 | 0.4959 | [0.3916, 0.498] range, n=3 | 1.139 | inconclusive |
| status/c4/p99_ms | ms (lower is better) | 0.5698 | [0.5413, 0.6415] range, n=3 | 0.6451 | [0.4992, 0.6585] range, n=3 | 1.132 | inconclusive |
| status/c4/rps | req/s (higher is better) | 13,932 | [13,542, 14,471] range, n=3 | 13,149 | [13,006, 15,236] range, n=3 | 0.9438 | inconclusive |
| tx_params/c4/error_rate | ratio (lower is better) | 0 | [0, 0] range, n=3 | 0 | [0, 0] range, n=3 | n/a | inconclusive |
| tx_params/c4/p50_ms | ms (lower is better) | 0.2836 | [0.2811, 0.2849] range, n=3 | 0.2706 | [0.2581, 0.2775] range, n=3 | 0.9542 | **Rust** 1.048x |
| tx_params/c4/p95_ms | ms (lower is better) | 0.4913 | [0.4391, 0.5009] range, n=3 | 0.4209 | [0.3935, 0.4856] range, n=3 | 0.8568 | inconclusive |
| tx_params/c4/p99_ms | ms (lower is better) | 0.6399 | [0.5704, 0.6565] range, n=3 | 0.5444 | [0.4899, 0.6602] range, n=3 | 0.8508 | inconclusive |
| tx_params/c4/rps | req/s (higher is better) | 13,181 | [13,137, 13,656] range, n=3 | 14,186 | [13,430, 14,962] range, n=3 | 1.076 | inconclusive |

Rust/Go is the ratio of the medians. For lower-is-better units a value below 1 means Rust is faster; for higher-is-better units a value above 1 means Rust is faster. A side is only marked faster when the two spreads (95% CI of the median for n >= 6, else min/max) do not overlap. Rows marked (synthetic) come from the selftest tier and measure the harness, not either node.

#### Tiers

| Tier | Exit | Duration (s) |
|---|---|---|
| build | 0 | 196.2 |
| micro | 0 | 266.5 |
| replay | 0 | 31.52 |
| rest | 0 | 136.6 |
| localnet | 0 | 296.7 |
<!-- bench-baseline:end local-main -->

### Baseline `local-testnet-prefix50`: replay of real certificates

<!-- bench-baseline:begin local-testnet-prefix50 -->
Command: `make bench-compare TIERS=replay CORPUS=testnet-prefix50 RUNS=3`

#### Summary by tier

| Tier | Paired rows | Rust faster | Go faster | Inconclusive |
|---|---|---|---|---|
| replay | 6 | 2 | 4 | 0 |

6 paired row(s) in total; 0 paired row(s) excluded from the baseline file (every paired row is kept, including rows whose Go or Rust median is 0). Counts come from the tables below.

Generated 2026-10-31T13:40:47Z. Methodology and fairness rules: [docs/BENCHMARK_COMPARISON.md](https://github.com/xarmian/algod-rust/blob/main/docs/BENCHMARK_COMPARISON.md).

**Status: OK.** 6 paired row(s): Rust faster 2, Go faster 4, inconclusive 0; 0 unpaired.

#### Builds

| | go-algorand | algod-rust |
|---|---|---|
| Commit | `927ae0863cbb4cf29c6845c088a4ea4c439b10bb` | `561f7528d912ace27e71c06571b8d590c86ccc53` |
| Describe | `v5.0.4-stable` | `561f7528` |
| Pin | expected `v5.0.4-stable`, matches | |
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
| Kernel | 6.18.54.1-microsoft-standard-WSL2 |
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
| testnet-prefix50/blocks_per_s | block/s (higher is better) | 438.5 | [429.5, 467.9] range, n=3 | 135.1 | [125.1, 143.8] range, n=3 | 0.3081 | **Go** 3.246x |
| testnet-prefix50/cpu_s | s (lower is better) | 0.9958 | [0.8774, 1.058] range, n=3 | 0.2783 | [0.2674, 0.308] range, n=3 | 0.2795 | **Rust** 3.578x |
| testnet-prefix50/db_mb | MB (lower is better) | 0.8244 | [0.8244, 0.8244] range, n=3 | 2.353 | [2.353, 2.353] range, n=3 | 2.855 | **Go** 2.855x |
| testnet-prefix50/peak_rss_mb | MB (lower is better) | 151.2 | [140.2, 154.2] range, n=3 | 29.08 | [29.07, 29.21] range, n=3 | 0.1924 | **Rust** 5.198x |
| testnet-prefix50/txns_per_s | txn/s (higher is better) | 8.77 | [8.591, 9.358] range, n=3 | 2.702 | [2.502, 2.876] range, n=3 | 0.3081 | **Go** 3.246x |
| testnet-prefix50/wall_s | s (lower is better) | 0.114 | [0.1069, 0.1164] range, n=3 | 0.3701 | [0.3477, 0.3996] range, n=3 | 3.246 | **Go** 3.246x |

Rust/Go is the ratio of the medians. For lower-is-better units a value below 1 means Rust is faster; for higher-is-better units a value above 1 means Rust is faster. A side is only marked faster when the two spreads (95% CI of the median for n >= 6, else min/max) do not overlap. Rows marked (synthetic) come from the selftest tier and measure the harness, not either node.

#### Tiers

| Tier | Exit | Duration (s) |
|---|---|---|
| build | 0 | 4.278 |
| replay | 0 | 6.664 |
<!-- bench-baseline:end local-testnet-prefix50 -->

## Open findings from the epic

The comparison already paid for itself: the equality gates and the first
measurements produced these open issues. They are the explanation for the rows
where algod-rust is behind, and they feed the optimization pass #2110.

### Performance

| Issue | Finding | Where it shows |
|---|---|---|
| [#2145](https://github.com/xarmian/algod-rust/issues/2145) | Rust certificate authentication is about 6x slower than Go on a 20,000-round testnet replay (Go 40.5 s wall using all cores through `AsyncVoteVerifier`; algod-rust 266 s on a different host, so indicative). | `replay` rows: 3.2x to 3.6x slower wall clock here on the small and 50-round corpora (the large gap needs many certificates and cores). |
| [#2162](https://github.com/xarmian/algod-rust/issues/2162) | `POST /v2/transactions/simulate` serves about 3.5x fewer requests/s than Go (about 4,470 vs 1,290 req/s at concurrency 16, 2 CPUs). | `rest` `simulate/c4`: 1,112 vs 5,068 req/s, p50 3.7 ms vs 0.65 ms. Every other endpoint is level or faster in Rust. |
| [#2165](https://github.com/xarmian/algod-rust/issues/2165) | Block replay after fast catchup is about 6x slower than Go (22 vs 133 blocks/s on betanet, n = 1). | Not in this baseline (public-network `catchup` tier); consistent in direction with the replay rows. |
| [#2166](https://github.com/xarmian/algod-rust/issues/2166) | The tracker SQLite WAL grows without bound during catchup replay (1.28 GB vs Go 126 MB on betanet). | Not in this baseline; `replay` `db_mb` is 1.07x (small) and 2.9x (50 rounds) Go's file size. |
| [#2110](https://github.com/xarmian/algod-rust/issues/2110) | The profile-driven, parity-gated optimization pass that works these. | Before/after rows will be added here. |

Where algod-rust is ahead, as measured: peak RSS is 5x to 7x lower in replay
and 6.5x lower on the localnet, most REST read endpoints serve 5% to 45% more
requests/s with lower tail latency, and Ed25519, VRF and credential
verification are 1.15x to 1.4x faster in the micro pairs. The micro table also
shows what the macro rows imply: Rust is slower on codec work (encode, decode,
txid, transaction commitments) that every block replay exercises.

### REST response differences (found by the `rest` tier's equality gate)

The `rest` tier serves one replayed ledger from both nodes and fails on any
response difference that is not on its issue-linked allowlist. Each allowed
difference is an open parity bug, not an accepted divergence:

| Issue | Difference |
|---|---|
| [#2158](https://github.com/xarmian/algod-rust/issues/2158) | `GET /v2/transactions/params` reports `fee` = min-fee; Go reports the pool's fee per byte (0 when idle). |
| [#2159](https://github.com/xarmian/algod-rust/issues/2159) | `/v2/blocks/{round}?format=msgpack` re-encodes a certificate without a step field as step 2. |
| [#2160](https://github.com/xarmian/algod-rust/issues/2160) | Simulate JSON renders `gh` and other 32-byte digests as integer arrays; Go renders base64. |
| [#2161](https://github.com/xarmian/algod-rust/issues/2161) | Simulate omits `sender-rewards` when the sender has pending rewards. |

Because of these, the REST throughput rows compare nodes that answer a few
requests differently; the gate guarantees the differences are exactly the
listed ones and nothing else.

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
