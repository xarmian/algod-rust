# Go vs Rust benchmark comparison (`make bench-compare`)

This page explains how to compare the go-algorand `algod` (pinned at
`v5.0.4-stable`) with `algod-rust` on the same hardware and the same
workloads, and how to read the report you get. It is the methodology document
for Phase 23 (epic [#2101](https://github.com/xarmian/algod-rust/issues/2101),
plan in [`PHASE23_PROPOSAL.md`](PHASE23_PROPOSAL.md)). The older
single-purpose benchmarks (criterion suites, `bench-cluster`, `bench-stress`)
are described in [`BENCHMARKS.md`](BENCHMARKS.md).

One command builds both implementations at pinned commits, runs the selected
benchmark *tiers*, and writes one report with an environment fingerprint:

```bash
make bench-compare TIERS=selftest RUNS=5
# -> bench-results/<utc-timestamp>/report.md and report.json
```

## Contents

- [Quick start](#quick-start)
- [Methodology](#methodology)
- [Fairness rules](#fairness-rules)
- [Reading the report](#reading-the-report)
- [The run directory](#the-run-directory)
- [Tier contract (adding a tier)](#tier-contract-adding-a-tier)
- [Result schema v1](#result-schema-v1)
- [Pinned builds (`build_both.sh`)](#pinned-builds-build_bothsh)
- [Tiers](#tiers)

## Quick start

Requirements for a full run on a clean Linux box: `git`, `make`, `python3`
(3.8+, standard library only), Go (the version in go-algorand's `go.mod`),
Rust (stable, via rustup), the libsodium build tools
(`sudo apt-get install autoconf automake libtool build-essential`) and, for
the cluster tiers, Docker.

```bash
git clone https://github.com/xarmian/algod-rust
git clone --branch v5.0.4-stable https://github.com/algorand/go-algorand
cd algod-rust

make bench-compare-test                  # harness unit tests, a few seconds
make bench-compare TIERS=selftest        # harness end-to-end, no builds
make bench-compare TIERS=micro,replay RUNS=10   # real tiers (once they land)
```

Variables:

| Variable | Default | Meaning |
|---|---|---|
| `TIERS` | `selftest` | Comma-separated tiers to run, in order. Each tier is `scripts/bench/tiers/<tier>.py` or `<tier>.sh`. |
| `RUNS` | `5` | Measured runs per side for each benchmark (warm-up excluded). Use at least 6 to get a 95% confidence interval; 10 or more for publishable numbers. |
| `BENCH_BUILD` | `auto` | `auto` runs `build_both.sh` only when a selected tier needs binaries; `always` / `never` force it. |
| `BENCH_OUTPUT` | `bench-results` | Parent directory of the timestamped run directory. |
| `BENCH_RUN_DIR` | (unset) | Exact run directory instead of `<BENCH_OUTPUT>/<utc-ts>`. It must be empty or absent unless `BENCH_CLEAN=1`. |
| `BENCH_CLEAN` | (unset) | `1` clears a reused `BENCH_RUN_DIR`'s previous run artifacts first (`--clean`). |
| `GO_ALGORAND_DIR` | `../go-algorand` | go-algorand checkout. It must sit exactly on the pinned tag. |
| `GO_ALGORAND_REV` | `scripts/bench/go-algorand.pin` | Override the pinned tag. Only do this for experiments; the report records it. |
| `BENCH_BIN_DIR` | `target/bench-compare` | Where the built binaries go (`go/`, `rust/`). |

Without `make`, run the engine directly:
`python3 scripts/bench/run.py --tiers selftest --runs 5`.

## Methodology

The comparison follows four rules from the epic. Every tier must keep them.

1. **Same input, same work, same machine.** Both implementations read
   identical bytes: fixture files or a corpus with a sha256 manifest, never
   a live network fetch whose latency would dominate. Every macro tier checks
   that both sides ended in the **same final state** (block hashes,
   account-state root, app state). If they differ, the tier fails: that is a
   parity bug, not a benchmark result.
2. **Native harnesses on each side.** Go uses `testing.B` against the real
   go-algorand packages, preferring go-algorand's own `Benchmark*` functions
   where they exist. Rust uses `criterion` against the real crates. Macro
   tiers drive the real `algod` / `algod-rust` binaries. Nothing is
   re-implemented in a third language.
3. **One command, one report.** `make bench-compare` builds both
   implementations at pinned commits, runs the tiers and writes
   `report.{json,md}`. The report carries the environment fingerprint, the
   median with a confidence interval, and a Rust/Go ratio.
4. **Optimizations are measurement-driven and parity-gated.** An
   optimization PR cites the report row it improves, names the parity
   evidence that guards it (golden fixtures, conformance suites, the replay
   final-state gate, differential tests) and records before/after numbers.
   A deliberate structural difference goes in
   [`DIVERGENCES.md`](DIVERGENCES.md) with wire/consensus impact `none`.

### Statistics

- Each benchmark yields one **sample per measured run** for each side. A
  tier may itself take many iterations per run (criterion and `testing.B`
  do); the sample is that run's summary value, for example criterion's
  median estimate in ns/op.
- The report gives the **median** for each side.
- The **spread** is a distribution-free 95% confidence interval of the
  median when a side has n >= 6 samples. It uses order statistics: the
  interval `[x(r), x(n-r+1)]` with the largest `r` for which
  `P(Bin(n, 1/2) <= r-1) <= 0.025`, so it assumes nothing about the shape of
  the distribution. With n < 6 no order-statistic interval reaches 95%, so
  the report shows the **min/max range** and labels it `range`. The
  binomial tail is exact up to n = 1000; above that the report uses the
  normal approximation `N(n/2, n/4)`, which is accurate to well under a
  rank at that size.
- **Rust/Go** is the ratio of the two medians.
- **Faster** names a side only when the two spreads do not overlap, together
  with how many times faster it is (the larger median divided by the
  smaller). If the spreads overlap, the row is `inconclusive`. Run more
  runs, or accept that the two sides are within noise.

## Fairness rules

Before you trust or publish a number:

- **Same machine, same session.** Never compare a Go number from one
  machine with a Rust number from another. The report's fingerprint is
  there so you can see when someone did.
- **Fix the CPU frequency.** On Linux, set the governor to `performance`
  (`sudo cpupower frequency-set -g performance`, or write `performance` to
  `/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor`). If you can,
  disable turbo / boost as well, so thermal state doesn't favour whichever
  side runs first. The fingerprint records the governor and warns when it is
  not `performance`.
- **No other load.** Close browsers, IDE indexers and builds. Don't run two
  bench-compare runs at once. On laptops, plug in mains power.
- **Warm-up, then N runs.** Every tier discards at least one warm-up run
  (to fill the page cache, CPU caches and allocator pools) and then takes
  `RUNS` measured runs per side.
- **Interleave the sides.** Tiers alternate which implementation goes first
  in each run (Go, Rust, then Rust, Go, ...), so slow drift such as heat or
  background jobs hits both sides equally.
- **Pinned, clean builds.** `build_both.sh` refuses to build go-algorand
  unless the checkout's `HEAD` is the pinned tag's commit. The report shows both
  commits and flags uncommitted changes in either tree.
- **Release builds with each project's own flags.** go-algorand is built
  with the tags, buildmode and ldflags from its own Makefile. algod-rust is
  built with `cargo build --release --locked` (the workspace release
  profile).
- **CI runners and VMs are indicative only.** Shared runners have noisy
  neighbours. The fingerprint detects CI and hypervisors and puts a warning
  in the report. Published baselines say which kind of machine they came
  from.

## Reading the report

`report.md` has these sections:

1. **Status.** `OK`, or `FAILED` with the error count. A run fails when a
   tier exits non-zero, a result file fails schema validation, a pair uses
   two different units, or the build fails. The report is written either
   way, and `make bench-compare` then exits 1.
2. **Builds.** The go-algorand and algod-rust commits, `git describe`, whether
   the go-algorand pin matches, dirty-tree flags and (after a build) the
   binaries. When no selected tier needed a build, the commits come from the
   fingerprint and the report says so.
3. **Environment.** CPU model, sockets / cores / threads, max MHz, frequency
   governor, hypervisor, RAM, OS / kernel, toolchain versions, CI detection,
   followed by any **fairness warnings**.
4. **Results.** One table per tier:

   | Column | Meaning |
   |---|---|
   | Benchmark | Pairing key (with `tier`). `(synthetic)` marks selftest rows, which measure the harness and not either node. |
   | Unit | The unit, plus `lower is better` / `higher is better`. Units ending in `/s` default to higher-is-better; a tier can set `better` explicitly. |
   | Go / Rust median | Median of that side's samples. |
   | Go / Rust spread | `[low, high] 95% CI, n=N`, or `[min, max] range, n=N` when n < 6. |
   | Rust/Go | Ratio of medians. For lower-is-better units, below 1 means Rust is faster. For higher-is-better units, above 1 means Rust is faster. |
   | Faster | `**Rust** 1.8x`, `**Go** 1.2x`, `inconclusive` (spreads overlap), `go missing` / `rust missing` (unpaired row), or `unit mismatch`. |

5. **Tiers.** Exit status and duration of every tier, plus the build step if
   it ran.
6. **Errors.** Every validation or tier error, by file.

`report.json` (`"schema": "bench-report/v1"`) holds the same data in
machine-readable form: the fingerprint, the build info, per-row summaries
(`n`, `median`, `mean`, `min`, `max`, `stdev`, `spread_low/high`,
`spread_method`, `ci_coverage`), `ratio`, `faster`, `speedup`, and each
side's `metadata`. CI and the published baseline (#2109) consume it.

An **unpaired** row (only one side has results) is reported, not dropped.
It is how a tier shows a benchmark that exists on one side only, for example
a Rust-only criterion bench with no go-algorand counterpart yet. Unpaired
rows don't fail the run.

## The run directory

```
bench-results/20261028T084626Z/
  fingerprint.json      environment (scripts/bench/fingerprint.py)
  build-info.json       pinned builds + binary sha256s (only when built)
  tier-status.json      per-tier exit code + duration
  results/<tier>/*.json schema-v1 results written by each tier
  logs/<tier>.log       full stdout/stderr of each tier (logs/build.log)
  report.json           merged machine-readable report
  report.md             human-readable report
```

`bench-results/` is git-ignored. Regenerate the report from an existing run
directory with `python3 scripts/bench/report.py bench-results/<ts>`.

A run directory holds exactly one run. The runner refuses an existing,
non-empty `--run-dir` / `BENCH_RUN_DIR`, because `report.py` merges every
`results/**/*.json` it finds and would mix in an earlier run's results and
`build-info.json`. Pass `--clean` (make: `BENCH_CLEAN=1`) to delete the
previous run's artifacts (the entries listed above, and nothing else; it
refuses if the directory holds anything else).

The directory a result file sits in is authoritative. A result whose `tier`
field differs from its `results/<tier>/` directory, or a file directly under
`results/`, is dropped and reported as an error, so one tier cannot add
rows to another tier's table.

## Tier contract (adding a tier)

A tier is a single executable script, `scripts/bench/tiers/<tier>.py` (run
with the same Python as the runner) or `scripts/bench/tiers/<tier>.sh` (run
with `bash`). The file's basename is the tier name. It must match
`^[a-z][a-z0-9_-]*$`, and two files must not share a basename. To add a
tier you only add that script (plus any helpers or fixtures it uses). The
runner, schema and report need no changes.

**Declaring that it needs binaries.** Put
`# bench-tier-needs: build` within the first 30 lines. With the default
`BENCH_BUILD=auto`, the runner then runs `build_both.sh` before any tier.
If the build fails, or `BENCH_BUILD=never` is set, the tier is skipped and
reported as such.

**Inputs (environment variables).**

| Variable | Meaning |
|---|---|
| `BENCH_TIER` | The tier name. |
| `BENCH_RUNS` | Measured runs per side (>= 1). |
| `BENCH_OUT` | Directory for this tier's result files (`<run-dir>/results/<tier>/`, already created). |
| `BENCH_RUN_DIR` | The run directory (read `fingerprint.json` / `build-info.json` there if needed). |
| `BENCH_REPO_ROOT` | algod-rust checkout root; the tier's working directory. |
| `BENCH_GO_ALGORAND_DIR` | go-algorand checkout (on the pinned tag after a build). |
| `BENCH_BIN_DIR`, `BENCH_GO_BIN_DIR`, `BENCH_RUST_BIN_DIR` | Built binaries: `$BENCH_GO_BIN_DIR/{algod,goal}`, `$BENCH_RUST_BIN_DIR/algod-rust`. |
| `BENCH_BUILD_INFO` | Path of `build-info.json` (it may not exist when no build ran). |
| `BENCH_SCHEMA` | Path of `result-v1.json`. |

**Obligations.**

1. Write one or more `*.json` files into `$BENCH_OUT`. Each file holds a
   schema-v1 result object or an array of them (see below). Use the same
   `name` for the Go and the Rust half of a pair, and the same `unit`.
2. Follow the [fairness rules](#fairness-rules): discard a warm-up, take
   `BENCH_RUNS` samples per side, interleave the sides, feed both sides
   byte-identical inputs and record their sha256 in `metadata`.
3. Macro tiers compare the final state of both sides and **exit non-zero on
   divergence**. Record the compared hash in `metadata` (for example
   `final_state_sha256`).
4. Exit 0 on success. Any non-zero exit marks the tier failed, and the run
   fails too. Results already written are still reported.
5. Write progress to stdout or stderr. The runner tees it to the console
   and to `logs/<tier>.log`.
6. Carry the MIT header (tier scripts are tooling), unless the script ports
   go-algorand code, which makes it AGPL (see
   [`LICENSING_AUDIT.md`](LICENSING_AUDIT.md)).

Validate a tier's output while developing it with
`python3 scripts/bench/bench_schema.py <file.json>...`.
[`scripts/bench/tiers/selftest.py`](../scripts/bench/tiers/selftest.py) is
the reference implementation of this contract.

## Result schema v1

[`scripts/bench/schema/result-v1.json`](../scripts/bench/schema/result-v1.json)
(JSON Schema 2020-12) is the source of truth. `bench_schema.py` validates
against it using only the standard library.

```json
{
  "schema": "bench-result/v1",
  "tier": "micro",
  "name": "codec/decode-block-6",
  "impl": "rust",
  "unit": "ns/op",
  "better": "lower",
  "samples": [41210.5, 41188.0, 41302.9, 41190.1, 41250.7, 41222.3],
  "metadata": {"input": "crates/core/algo-codec/tests/fixtures/block_6.msgpack",
               "input_sha256": "...", "harness": "criterion"}
}
```

| Field | Required | Rule |
|---|---|---|
| `schema` | yes | Exactly `bench-result/v1`. A breaking change adds `result-v2.json`; it never edits v1. |
| `tier` | yes | The tier name. |
| `name` | yes | Pairing key within the tier, `^[A-Za-z0-9][A-Za-z0-9_./:+-]*$`. |
| `impl` | yes | `go` or `rust`. |
| `unit` | yes | For example `ns/op`, `s`, `MB/s`, `txn/s`, `bytes`. |
| `better` | no | `lower` or `higher`. Default: `higher` if `unit` ends in `/s`, else `lower`. |
| `samples` | yes | Non-empty array of finite, non-negative numbers, one per measured run. `NaN` / `Infinity` are rejected, and `report.json` is always strict JSON. |
| `metadata` | yes | Object (may be empty): provenance such as inputs, hashes, command lines and iteration counts; `synthetic: true` for selftest rows. |

No other top-level fields are allowed, so a typo fails validation instead of
being ignored. If several results share the same `tier`, `name` and `impl`,
their samples are merged.

## Pinned builds (`build_both.sh`)

`scripts/bench/build_both.sh` (run by the runner when needed, or by hand):

1. Reads the tag from `scripts/bench/go-algorand.pin` (`v5.0.4-stable`,
   swept with every other pin occurrence by `algod-version-upgrade`).
   `GO_ALGORAND_REV` overrides it.
2. Checks that the go-algorand checkout's `git rev-parse HEAD` equals
   `git rev-parse "$TAG^{commit}"`. If not, it exits 1 and prints the
   `git checkout` command to run. `git describe --tags` is recorded only as
   information, because it can name a different tag on the same commit.
   `--clone` clones the tag when no checkout exists.
3. Runs `make libsodium` (go-algorand links its vendored libsodium fork),
   then builds `cmd/algod` and `cmd/goal` with go-algorand's own release
   tags, buildmode and ldflags. It reads all three from go-algorand's
   Makefile in a single `make` parse.
4. Builds `algod-rust` with `cargo build --release --locked` and takes the
   binary's path from cargo's own JSON artifact message
   (`scripts/bench/cargo_artifact.py`), so `CARGO_TARGET_DIR`,
   `build.target-dir` and `--target` are honoured.
5. Copies the binaries to `$BENCH_BIN_DIR/{go,rust}/` and writes
   `build-info.json` (`bench-build-info/v1`): both commits, the tag commit,
   `describe`, dirty flags, toolchain versions and the sha256 of every
   binary.

CI: the `bench-build-both` job in `.github/workflows/harness-shell-tests.yml`
runs the go-algorand half for real (`--clone --skip-rust`) on Ubuntu
whenever `build_both.sh` or the pin file changes. It asserts
`built: true` and `pin_ok: true` and runs `algod -v`.

`--skip-go` / `--skip-rust` build only one side.

## Tiers

| Tier | Status | Measures |
|---|---|---|
| `selftest` | available (#2102) | The harness itself: both "sides" run the same Python sha256 workload. It checks the schema, pairing, statistics and report on any machine, and it is what CI runs. |
| `micro` | planned (#2103) | Paired Go `testing.B` / Rust criterion micro-benchmarks: codec, crypto, commitments, AVM, sortition. |
| `replay` | planned (#2104, #2105) | Offline ledger replay of a deterministic block corpus, with a final-state equality gate. |
| `localnet` | planned (#2106) | All-Go vs all-Rust homogeneous localnet throughput under the same load. |
| `rest` | planned (#2107) | REST API throughput against identical ledger state. |
| `catchup` | planned (#2108) | Public-network fast catchup and follow. |

The CI workflow and the published baseline (`docs/BENCHMARK_RESULTS.md`)
come with #2109.
