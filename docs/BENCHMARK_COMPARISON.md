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
- [The `micro` tier](#the-micro-tier)
- [Workload corpus](#workload-corpus)
- [The `replay` tier](#the-replay-tier)
- [The `localnet` tier](#the-localnet-tier)

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
make bench-compare TIERS=micro,replay RUNS=10   # real tiers
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
| `micro` | available (#2103) | Paired Go `testing.B` / Rust criterion micro-benchmarks on identical fixture bytes: codec, crypto, commitments, AVM, agreement. See [The `micro` tier](#the-micro-tier). |
| `replay` | available (#2105) | Offline ledger replay of the deterministic block corpus (#2104) through go-algorand's ledger and algod-rust's production catchup path, with a final-state equality gate. See [The `replay` tier](#the-replay-tier). |
| `localnet` | available (#2106) | All-Go vs all-Rust homogeneous localnet throughput and latency under the same load, with a same-txid-set gate. See [The `localnet` tier](#the-localnet-tier). |
| `rest` | planned (#2107) | REST API throughput against identical ledger state. |
| `catchup` | planned (#2108) | Public-network fast catchup and follow. |

The CI workflow and the published baseline (`docs/BENCHMARK_RESULTS.md`)
come with #2109.

## The `micro` tier

```bash
make bench-compare TIERS=micro RUNS=10
# a quicker, noisier look:
BENCH_MICRO_GO_BENCHTIME=300ms BENCH_MICRO_CRITERION_ARGS="--warm-up-time 0.5 --measurement-time 1" \
  make bench-compare TIERS=micro RUNS=3
make bench-micro-equiv        # only the Go/Rust output-equivalence check
```

The tier compares one go-algorand function with its algod-rust counterpart
per **pair**, both run on the same input bytes. It needs `go` (the version
in go-algorand's `go.mod`), `cargo`, a go-algorand checkout on the pinned tag
(`GO_ALGORAND_DIR`, default `../go-algorand`) and the libsodium build tools.
It builds no `algod` binaries, so it does not declare
`bench-tier-needs: build`.

### How it works

| Piece | Path | Role |
|---|---|---|
| Registry | [`benchmarks/pairs.toml`](../benchmarks/pairs.toml) | One `[[pair]]` per comparison: `id`, `unit`, the Go `go_package` + `go_bench`, the Rust `rust_bench` (always equal to `id`), the production function of each side (`go_api`, `rust_api`), the `fixture` file and its `fixture_sha256`. |
| Fixtures | `benchmarks/fixtures/micro/` | The shared inputs. They are committed and checked out byte-exact (`.gitattributes`: `-text`). |
| Fixture generator | `benchmarks/go-micro/cmd/genfixtures` | Writes every fixture deterministically (fixed seeds, no clock, no RNG) with go-algorand itself: msgpack encodings, ed25519 / VRF / Falcon signatures, assembled TEAL. The small block, the certificate and the proposal are re-encodings of fixtures already in the repo. |
| Go side | `benchmarks/go-micro` (AGPL, links go-algorand) | `micro/cases.go` has one case per pair id. `micro_test.go` has one `Benchmark*` per pair (`go_bench`). `cmd/equiv` prints every pair's output digest. |
| Rust side | `crates/tools/algo-bench-pairs` (AGPL) | `src/lib.rs` has one case per pair id. `benches/pairs.rs` is one criterion benchmark per id, named `<group>/<name>`. The `micro-equiv` binary prints every pair's output digest. |
| Tier | `scripts/bench/tiers/micro.py` | Runs the steps below and writes `results/micro/micro.json`. |
| Converters | `scripts/bench/micro_convert.py` | Parse `go test -bench -benchmem` output and criterion's `new/sample.json` / `estimates.json`, load the registry. Unit-tested on captured outputs of both frameworks (`scripts/bench/test_micro_convert.py`, `scripts/bench/testdata/micro/`). |
| Equivalence | `scripts/bench/micro_equiv.py` | Runs `cmd/equiv` and `micro-equiv` and compares them pair by pair. |

A case on either side is two functions that share one implementation of the
operation: `Op` / `run` is the measured body (setup such as reading and
decoding the fixture is done once, outside the timer), and `Digest` /
`digest` runs the operation once and describes its output in a canonical
text form that is the same in both languages. Examples:
`sha256:<hex>` of the re-encoded bytes for codec pairs, `hex:<digest>` for
hashes, `valid:<n>/<n>` for signature verification,
`pass:true;cost:12014` for logicsigs, `weight:16;vrfout:<hex>` for a
credential, and `pass:..;cost:..;pre:..;gdelta:..;logs:..` for the app call.

The tier then:

1. Checks every fixture's sha256 against the registry.
2. **Output equivalence.** Runs every pair once on both sides and requires
   identical digests. A pair whose digests differ means the two sides did
   not do the same work on the same bytes, or one of them is wrong, so the
   tier stops before timing anything. The same check also runs in
   `cargo test`: `crates/tools/algo-bench-pairs/tests/equivalence.rs`
   compares the Rust digests with `benchmarks/fixtures/micro/go-digests.json`,
   which `go run ./cmd/equiv -write` recorded from go-algorand, and the Go
   test `TestDigestsMatchRecorded` keeps that file in step with the Go side.
3. Runs `BENCH_MICRO_WARMUP` (default 1) discarded warm-up rounds, then
   `RUNS` measured rounds, alternating which side goes first. A Go round is
   `go test -run '^$' -bench '<every go_bench>' -benchmem -count=1`, which
   gives one ns/op per pair. A Rust round is one
   `cargo bench -p algo-bench-pairs --bench pairs -- --noplot`. Its sample
   for a pair is criterion's **mean** time per iteration over the whole run,
   `sum(times) / sum(iters)` from `new/sample.json` (read through each
   benchmark's `new/benchmark.json` `full_id`). That is the same statistic
   as Go's ns/op, which is the total timed duration divided by `b.N`, so a
   round of either side reports a mean. Without a usable `sample.json` the
   converter falls back to `estimates.json`'s mean point estimate, warns,
   and records the source in `metadata.sample_source`. The tier fails if a
   pair's rounds came from different sources. Each side therefore
   contributes `RUNS` per-round means, one per interleaved round, which the
   report turns into the median, the CI and the Rust/Go ratio. The Go B/op
   and allocs/op, criterion's per-sample median, the sample counts, both
   commands, the fixture and its sha256 and the output digest go to each
   result's `metadata`.

**Stateful pairs.** `avm/app-state-box` writes global state and a box into
its in-memory ledger on both sides. Its case therefore has a reset that
restores the starting state (empty global state, a zeroed box), and every
benchmark iteration on both sides is reset followed by the operation
(`BenchIteration` / `bench_iteration`). The reset stays inside the timed
region on purpose. It is tiny next to the app call: about 30 ns for an
8-entry map clear and a 64-byte zero, against about 15 µs for the call.
Go's only way to exclude it, `b.StopTimer` / `b.StartTimer` with
`ReportAllocs`, runs `runtime.ReadMemStats` twice per iteration, which
inflated the measured call by about 10-25% and has no criterion
counterpart. Both sides' app digests include the starting state and the
global-state delta (`pre:globals=0,box=…;gdelta:…`). Both equivalence checks
(`cmd/equiv`, `micro-equiv`, `TestDigestsMatchRecorded` and
`tests/equivalence.rs`) also run every pair three more times and require an
unchanged digest, so a pair whose iterations drift apart fails the tier.

Knobs: `BENCH_MICRO_FILTER` (a regex on pair ids, for example `^crypto/`),
`BENCH_MICRO_GO_BENCHTIME` (Go `-benchtime`, default 1s),
`BENCH_MICRO_CRITERION_ARGS` (extra criterion arguments, default criterion
settings), `BENCH_MICRO_WARMUP`, and `BENCH_MICRO_ALLOW_UNPINNED=1` to accept
a go-algorand checkout that is not on the pinned tag (the report's
fingerprint still flags it).

### Why not go-algorand's own `Benchmark*` functions

The epic prefers go-algorand's own benchmarks where they measure the same
thing on the same input. We reviewed `crypto.BenchmarkHash`,
`BenchmarkVerify25519`, `BenchmarkBatchVerifier*`, the `logic` package's
`benchmarkOperation` family and the generated `BenchmarkUnmarshal*`. Each one
generates its input inside the benchmark (`crypto.RandBytes`,
`protocol.RandomizeObject`, inline TEAL), so the Rust side cannot read the
same bytes. The pairs therefore use thin `testing.B` wrappers that call the
same go-algorand APIs on the shared fixtures.

### Pairs

| Pair | Fixture | go-algorand | algod-rust |
|---|---|---|---|
| `codec/decode-block-small` | `block-small.msgpack` (round 6 of `algo-codec`'s `block_6.msgpack`, 1 app call) | `protocol.Decode(&bookkeeping.Block)` | `algo_codec::decode_block` |
| `codec/decode-block-large` | `block-large.msgpack` (1025 txns) | `protocol.Decode(&bookkeeping.Block)` | `algo_codec::decode_block` |
| `codec/encode-block-small` / `-large` | same | `protocol.Encode(&block)` | `algo_codec::canonical_encode_block` |
| `codec/decode-stxn` / `encode-stxn` | `stxn-appl.msgpack` (signed app call) | `protocol.Decode` / `Encode` of `transactions.SignedTxn` | `SignedTransaction::decode_from_reader` (one object, the gossip and payset decoder) / `canonical_encode_signed_transaction` |
| `codec/txid` | `stxn-appl.msgpack` | `Transaction.ID` | `compute_txn_id` |
| `codec/block-hash` | `block-large.msgpack` | `BlockHeader.Hash` | `compute_block_digest` |
| `crypto/sha512_256-32B` / `-1KiB` / `-64KiB` | `bytes-*.bin` | `crypto.Hash` | `sha2::Sha512_256` |
| `crypto/ed25519-verify` | `stxn-appl.msgpack` | `SignatureVerifier.Verify(txn, sig)` | `algo_validate::verify_single_sig` |
| `crypto/ed25519-batch-64` / `-1024` | `stxns-64.msgpack`, `stxns-1024.msgpack` | `crypto.BatchVerifier` | `verify_single_sig` per signature (no Rust batch verifier yet) |
| `crypto/vrf-verify` | `vrf.frames` (pk, proof, selector bytes) | `VrfPubkey.Verify` | `algo_consensus_crypto::vrf::vrf_verify` |
| `crypto/falcon-verify` | `falcon.frames` | `FalconVerifier.VerifyBytes` (C) | `algo_falcon::falcon_verify`, default pure-Rust backend ([DIV-001](DIVERGENCES.md)) |
| `commit/txn-merkle-sha512_256` | `block-large.msgpack` | `Block.TxnMerkleTree().Root()` | `compute_payset_merkle_root` |
| `commit/txn-vc-sha256` | `block-large.msgpack` | `Block.TxnMerkleTreeSHA256().Root()` | `compute_vector_commitment(Sha256)` |
| `avm/lsig-arith-loop` | `avm-arith.bin` (500-iteration `mulw`/`addw`/`%` loop) | `NewSigEvalParams` + `EvalSignature` | `LogicSigAvmContext` + `run_logicsig_program` |
| `avm/lsig-hash-loop` | `avm-hash.bin` (60 x `sha256`/`sha512_256`/`keccak256`) | same | same |
| `avm/lsig-bytes-ops` | `avm-bytes.bin` (250 x `b^`/`extract`/`b+`/`b\|`/`replace2`) | same | same |
| `avm/app-state-box` | `avm-app.bin` (8 global puts/gets, `box_put`/`box_get`, `log`) | `NewAppEvalParams` + `EvalContract`, in-memory `LedgerForLogic` | `LedgerAvmContext<LedgerState>` + `run_approval_program` |
| `agreement/sortition-select` | `sortition.json` | `sortition.Select` (pre-v42 float path) | `sortition::select` |
| `agreement/sortition-select-f128` | `sortition.json` | `sortition.SelectF128` (v42+) | `sortition::select_f128` |
| `agreement/credential-verify` | `credential.json` (soft-vote selector) | `UnauthenticatedCredential.Verify` | `UnauthenticatedCredential::verify` |
| `agreement/decode-cert` | `cert-20.msgpack` (20-vote certificate) | `protocol.Decode(&agreement.Certificate)` | `codec::decode_bundle` |
| `agreement/decode-proposal` | `proposal.msgpack` (transmitted payload) | `protocol.Decode(&agreement.TransmittedPayload)` | `codec::decode_compound_message` |

Notes on the pairs:

- The logicsig programs check their own result. The generator first runs
  each program in go-algorand, reads the result from scratch slot 0, and
  then embeds it in a final `load 0; push <value>; ==`. The committed
  program therefore only approves if the evaluator computes exactly
  go-algorand's value. The digest also carries the opcode cost.
- A single agreement vote cannot be decoded outside go-algorand's
  `agreement` package (`unauthenticatedVote` is unexported). The exported
  `Certificate` (a bundle of 20 votes) covers the vote decoding path. For
  the same reason the credential pair uses a copy of the unexported
  `agreement.selector` (`benchmarks/go-micro/micro/selector.go`) whose
  `ToBeHashed` is the generated msgp encoder.
- go-algorand's `logic.NewLedger` mock lives in a `_test.go` file, so the
  app pair uses a minimal in-memory `LedgerForLogic`
  (`benchmarks/go-micro/micro/ledger.go`). It is the counterpart of the Rust
  side's in-memory `LedgerState`.

### Adding a pair

1. Pick an id `<group>/<name>` and the production function on each side.
2. If it needs a new input, add it to `cmd/genfixtures`, then regenerate
   the fixtures from `benchmarks/go-micro` (Linux, go-algorand checkout with
   `make libsodium` done, `GOWORK` pointing at a `go.work` that replaces
   `github.com/algorand/go-algorand` with that checkout):
   `go run ./cmd/genfixtures -repo ../.. -out ../fixtures/micro`.
3. Go: add the case to `builders` in `micro/cases.go` and a
   `func BenchmarkX(b *testing.B) { run(b, "<id>") }` to `micro_test.go`.
4. Rust: add the id to `IDS` (sorted) and a `build()` arm in
   `crates/tools/algo-bench-pairs/src/lib.rs`. Use the same digest format
   as the Go case.
5. Record the Go digests with `go run ./cmd/equiv -write ../fixtures/micro/go-digests.json`.
6. Add the `[[pair]]` to `benchmarks/pairs.toml` with the fixture's sha256
   (`sha256sum benchmarks/fixtures/micro/<file>`).
7. Run `python3 scripts/bench/test_pairs.py` (registry against both sides,
   sha256s), `cargo test -p algo-bench-pairs` (Rust digests against Go's)
   and `make bench-micro-equiv`.

CI: the `bench-compare-harness` job in `harness-shell-tests.yml` runs the
static registry checks. `.github/workflows/bench-micro.yml` (Linux, triggered
by changes to `benchmarks/**`, the micro scripts or `algo-bench-pairs`)
clones the pinned go-algorand, runs `go test -list`, the recorded-digest
tests, the live equivalence check and `make bench-compare TIERS=micro RUNS=3`
with short criterion settings, and appends `report.md` to the job summary.
It also triggers on changes to the production crates the pairs measure
(`algo-codec`, `algo-avm`, `algo-ledger`, `algo-agreement`,
`algo-consensus-crypto`, `algo-validate`, `algo-falcon`, `algo-types`,
`Cargo.lock`) and on the go-algorand pin. For a PR that touches only those,
it runs the equivalence steps and skips the timing tier.
CI runners are shared and noisy, so treat those ratios as indicative only.

## Workload corpus

The `replay` tier (#2105) needs a realistic block stream that is **fixed**:
both implementations replay the same bytes offline, and the result can be
checked against a known final state. Live networks are not reproducible and
the localnet stress scripts send random load, so issue #2104 added a
deterministic corpus generator and two corpora:

| Corpus | Rounds | Txns (top-level / inner) | Size | Where |
|---|---:|---:|---:|---|
| `small` | 2,000 | 10,735 / 1,597 | 4.2 MB | committed: `benchmarks/corpus/small/` |
| `large` | 50,000 | 1,017,999 / 150,394 | 300 MB (151 MB as `.tar.gz`) | release asset, `make bench-corpus-fetch` |

```bash
make bench-corpus-fetch     # download + verify large into benchmarks/corpus/large/
make bench-corpus-small     # regenerate small (Linux; byte-identical to the committed one)
                            # (--force: generated beside --out, swapped in only after it verifies)
make bench-corpus-large     # generate large locally instead of fetching (~35 min)
python3 scripts/bench/corpus/corpus_tool.py verify benchmarks/corpus/small
python3 scripts/bench/corpus/corpus_tool.py summary benchmarks/corpus/small
```

### How it is generated

`scripts/bench/corpus/generate.py` (MIT) orchestrates;
`benchmarks/go-corpus` (`corpusgen`, AGPL: it links go-algorand) does the
work against the pinned go-algorand:

1. `corpusgen genesis` writes a **DevMode** genesis and a fixed node
   `config.json`. It does not use `goal network create`, which stamps the wall
   clock into the genesis (CLAUDE.md, issue #1590). Every key comes from
   `SHA-512/256("algod-rust/bench-corpus/v1|<seed>|<label>|<index>")`:
   the workload accounts, the fee sink and rewards pool, four online
   "validator" accounts, and the participation keys of genesis and keyreg
   registrations. Nothing reads `crypto/rand`. The genesis timestamp is pinned
   to `1767225600` (2026-01-01T00:00:00Z) and the protocol is the pinned
   go-algorand's `ConsensusCurrentVersion` (v43 at `v5.0.4-stable`).
2. `generate.py` starts the pinned go-algorand `algod` on that data dir
   (`target/bench-compare/go/algod` from `build_both.sh --skip-rust`).
3. `corpusgen drive` sets the DevMode block timestamp step
   (`POST /v2/devmode/blocks/offset/3`), then builds every round from a
   seeded PCG generator over a model of the ledger state. A round is a list
   of groups: all but the last go to `POST /v2/transactions/async` (pool
   only), and the generator waits until the pool holds each one before it
   sends the next, which keeps the pool in plan order. Before each round it
   also waits for the pool to drop the previous block's txns: the pool hears
   about a committed block from the ledger's notifier goroutine, after the
   synchronous submit has already returned. The last group goes to
   the synchronous `POST /v2/transactions`, which in DevMode assembles and
   commits the block. Pool waits poll with a 1 to 8 ms backoff. Each txn has `FirstValid` = its round, `LastValid` =
   round + 1000 and a unique 10-byte note `"bc" || u64 counter`.
4. After each round the generator fetches the raw
   `/v2/blocks/{r}?format=msgpack` bytes, decodes them with go-algorand's own
   codec, checks that the payset is exactly the planned txids in planned
   order and that `prev` is the previous block's hash, and appends the bytes
   to `blocks.bin`. Created asset/app ids are read from the block's ApplyData.
5. At the end it writes `corpus.json` (with the final state from
   `/v2/ledger/supply` and `/v2/accounts`), copies `genesis.json` and the node
   config, dumps the protocol's `ConsensusParams`, and `generate.py` writes
   `MANIFEST.sha256` and verifies the corpus with both `corpusgen verify` and
   `corpus_tool.py verify`.

The workload covers payments and account close-outs, ASA create /
reconfigure / destroy / opt-in / transfer / clawback / freeze / unfreeze /
holding close, app create / call / opt-in / close-out / clear / update /
delete with global, local and box state (box put and delete), atomic groups
of 2 to 5 mixed txns, an app method that issues inner pay + axfer + appl
(a call of a second app), rekey-to, txns signed by the rekeyed authorizer,
rekey back, and keyreg online/offline. Multi-round lifecycles (rekey, freeze,
close-out, keyreg, throwaway apps and assets) are scheduled into later rounds
and reserve their accounts meanwhile. The presets:

| Preset | `--rounds` | `--accounts` | `--txns-per-round` | Use |
|---|---:|---:|---:|---|
| `tiny` | 100 | 32 | 6 | CI determinism check |
| `small` | 2000 | 64 | 5 | committed corpus (size cap 5 MB) |
| `large` | 50000 | 1000 | 20 | release asset (~1M txns) |

Any other size: `generate.py --rounds N --accounts A --txns-per-round K
--seed S --out DIR`. Generation is client-bound at 500 to 530 txn/s (25 to 26
rounds/s with 20 txns per round) on a 24-thread WSL2 box, because each async
group waits for the pool. The large preset takes 33 to 35 minutes.

### Layout

| File | Content |
|---|---|
| `blocks.bin` | `ACRPBLK1` magic, then one record per round `0..=N`: `round` (u64 big-endian), `len` (u32 big-endian), then `len` bytes that are exactly the `/v2/blocks/{round}?format=msgpack` response body: msgpack map `{"block": Block, "cert": Certificate}`. Round 0 is the genesis block (empty cert). Uncompressed. |
| `genesis.json` | The genesis the node ran (go-algorand `protocol.EncodeJSON`). |
| `node-config.json` | The node's `config.json` (non-default values only). |
| `consensus.json` | `{"version", "params"}`: the full `ConsensusParams` of the genesis protocol. |
| `corpus.json` | Schema `algod-corpus/v1`: name, generator (version, seed, accounts, txns per round, timestamp step), go-algorand tag and commit, network (genesis id and hash, consensus version, devmode, genesis timestamp), file names, rounds, `txns`, `txids_sha256`, `histogram` and `final_state`. |
| `MANIFEST.sha256` | `sha256sum` format (`<hex>  <name>`), every other file, sorted. |

`histogram` counts top-level txns by `types` and `type.subtype`
(`subtypes`), inner txns by type at every nesting level
(`inner_types`), and `features` (groups, grouped, rekey and
rekeyed-signer txns, inner txns, app global/local deltas, box refs).
The kinds every corpus must contain are listed once, in
`benchmarks/corpus/coverage.json`, which both `corpus_tool.py verify`
and the Rust corpus test read. The definitions are in
`benchmarks/go-corpus/record.go` and are mirrored in
`crates/tools/algo-bench/src/corpus.rs`. `txids_sha256` is the sha256 of
every top-level TxID (32 raw bytes each) in block order. `final_state` holds
the last round, its block hash (`blk-...`), its txn counter, total and online
money, and `accounts_sha256` over the sorted `"<address> <amount>\n"` lines of
every account the generator knows (REST `amount`, so pending rewards are
included).

The repository's `.gitattributes` marks `benchmarks/corpus/**` as `-text`,
so a Windows checkout never rewrites a byte. The manifest pins
`corpus.json` and `genesis.json` too, and the Python and Rust checkers
reject a manifest that contains CR.

Census of both corpora (generator v1, seed `algod-rust-bench-corpus`):

| kind | small | large |
|---|---:|---:|
| acfg.create | 83 | 8,328 |
| acfg.destroy | 82 | 8,327 |
| acfg.reconfigure | 82 | 8,327 |
| afrz.freeze | 83 | 8,271 |
| afrz.unfreeze | 83 | 8,271 |
| appl.call | 3,084 | 294,353 |
| appl.clear | 87 | 8,355 |
| appl.closeout | 64 | 8,470 |
| appl.create | 98 | 8,193 |
| appl.delete | 96 | 8,190 |
| appl.optin | 214 | 17,799 |
| appl.update | 96 | 8,190 |
| axfer.clawback | 169 | 16,547 |
| axfer.close | 94 | 8,372 |
| axfer.optin | 157 | 9,372 |
| axfer.transfer | 2,121 | 203,345 |
| keyreg.offline | 67 | 8,194 |
| keyreg.online | 67 | 8,196 |
| pay.close | 94 | 8,372 |
| pay.payment | 3,814 | 360,527 |
| inner appl | 532 | 50,131 |
| inner axfer | 533 | 50,132 |
| inner pay | 532 | 50,131 |
| app_box_ref_txns | 752 | 75,000 |
| app_global_delta_txns | 1,992 | 185,602 |
| app_local_delta_txns | 1,917 | 178,829 |
| auth_addr_txns | 192 | 16,817 |
| grouped_txns | 2,448 | 233,673 |
| groups | 695 | 66,849 |
| inner_txns | 1,597 | 150,394 |
| rekey_txns | 191 | 16,807 |
| **top-level txns** | **10,735** | **1,017,999** |

### Determinism

Same seed, same parameters, same generator version and the same go-algorand
build give a **byte-identical corpus**: every file, every block hash and
every txid. Exact txid equality is therefore expected, with nothing masked.
These are the inputs that would vary in a naive localnet run, and how each
is pinned:

| Would vary | Pinned by |
|---|---|
| Genesis timestamp (`goal network create` uses the wall clock) | `corpusgen genesis` writes the genesis itself, with `timestamp` = 1767225600. |
| Account and participation keys (random) | Derived from the seed. |
| Genesis hash, and with it every txid's `gh` | Follows from the two rows above. |
| Block timestamps (wall clock) | DevMode timestamp offset: `ts` = previous `ts` + 3. |
| Block seed | DevMode sets `seed` = `committee.Seed(prev.Hash())`. |
| Which txns land in which block, and their order | No agreement: one block per synchronous submit, with the pool order held by waiting on each async group. Every block is checked against the plan. |
| `FirstValid` / `LastValid` / notes | Fixed per round and txn counter, not read from "current round" at run time. |
| Created asset/app ids | Follow from the deterministic txn counter. |
| State-proof / heartbeat txns from the node | None. The node holds no participation keys, so it injects nothing into the pool. |

Things that do change the bytes, on purpose: a different seed or parameters,
a new generator version (bump `generatorVersion` in `main.go`; the pinned
key-derivation test fails first), and a different go-algorand tag (protocol
version, encodings, node config defaults). Build `corpusgen` with the Go
toolchain from go-algorand's `go.mod` (what `generate.py` and CI use): the
workload draws from `math/rand/v2`'s PCG, and Go does not promise that the
stream of helpers like `IntN` stays the same across releases. The release tarball is not
byte-reproducible across Python/zlib versions, so `large.ref` pins the
sha256 of `MANIFEST.sha256`, not the tarball's.

Evidence:

- Locally (WSL2 Ubuntu, go1.25.3, go-algorand `v5.0.4-stable`): `tiny`
  twice and `small` twice from fresh nodes, `corpus_tool.py compare`
  reported byte-identical each time. The committed `small` is one of those
  runs. `large` was also generated twice (about 33 minutes each), and both
  runs were byte-identical. The second run used a freshly built `corpusgen`.
  Their MANIFEST sha256 is the one pinned in `benchmarks/corpus/large.ref`.
- CI (`.github/workflows/bench-corpus.yml`, Linux, path-filtered to the
  generator, the corpus and the pin): gofmt, vet and `go test` of the
  generator; `corpusgen verify` of the committed small corpus; `tiny`
  generated twice and compared; and `small` regenerated and compared byte
  for byte with `benchmarks/corpus/small`.

### What DevMode means for replay

The corpus comes from a single-node DevMode network. This keeps it
deterministic and fast, but the replay tier has to account for it:

- **Certificates are degenerate.** Each is `{"rnd": r}` with no votes, so the
  corpus cannot benchmark certificate verification. Replay through the
  ledger's block-apply path. go-algorand's `Ledger.AddBlock` does not check
  the certificate. algod-rust needs `SqliteLedger::set_devmode_chain(true)`,
  as `algod-rust node` sets for a `devmode` genesis.
- **No proposer**, so no proposer payouts or absenteeism. Fees still go to
  the fee sink and rewards still accrue from the rewards pool.
- **No state proofs.** No node holds participation keys. Keyreg state-proof
  keys are derived 64-byte values (go-algorand checks that they are present,
  not what they commit to).

`crates/tools/algo-bench/tests/corpus_small.rs` runs in the default `cargo
test` (unit-tests CI). It verifies the manifest, decodes every block + cert
with `algo_codec::decode_block_response` (and checks that the fast decoder
agrees), checks `prev` / `prev512` against `algo_codec`'s header digests of
the previous block, and recomputes the histogram, `txids_sha256`, final
block hash and txn counter. It then replays all 2,000 blocks through
algod-rust's `SqliteLedger` from its own genesis loader (same round-0 block
hash as go served) to the recorded txn counter and total money, in about 8 s
in a debug build. The Python tooling tests (`scripts/bench/test_corpus.py`:
manifest, corpus.json arithmetic and coverage, compare, deterministic pack,
`fetch_corpus.sh`) run in the `bench-compare-harness` job. The manifest
parsers in Python (`corpus_tool.py`), Rust (`algo_bench::corpus`) and
`fetch_corpus.sh` follow one rule set:
- each line is a lowercase 64-hex digest, two spaces, then a file name;
- the name is a plain name in the corpus directory, with no `/` or `\`,
  not `.` or `..`, and not the manifest itself;
- no duplicate entries.

The Python and Rust parsers both run the shared vectors in
`scripts/bench/testdata/corpus/manifest_vectors.json`. The shell check
matches names exactly, never as patterns.

### Fetching and publishing the large corpus

`scripts/bench/fetch_corpus.sh` (`make bench-corpus-fetch`) downloads the
asset named in `benchmarks/corpus/large.ref` (override with `--url` or
`CORPUS_URL`, or install a local tarball with `--from FILE`). It extracts the
asset and checks the sha256 of `MANIFEST.sha256` against the pin, every
listed file against the manifest, and that no unlisted file came along. Only
then does it install the corpus into `benchmarks/corpus/large/`, which git
ignores. If the asset does not exist yet (HTTP 404 or unreachable), it exits
3 and prints the commands that generate the corpus locally.

Publishing is a manual step for a maintainer. No workflow creates releases:

```bash
bash scripts/bench/build_both.sh --skip-rust
python3 scripts/bench/corpus/generate.py --preset large --out /tmp/corpus-large-v1
sha256sum /tmp/corpus-large-v1/MANIFEST.sha256      # must equal large.ref's pin
python3 scripts/bench/corpus/corpus_tool.py pack /tmp/corpus-large-v1 corpus-large-v1.tar.gz
gh release create bench-corpus-large-v1 corpus-large-v1.tar.gz \
  --title "Benchmark workload corpus: large (generator v1, go-algorand v5.0.4-stable)" \
  --notes "Deterministic replay corpus, issue #2104. Verify with scripts/bench/fetch_corpus.sh."
```

After a generator or go-algorand pin change, regenerate both corpora,
commit the new `small`, update `manifest_sha256` (and the tag/URL) in
`large.ref`, and publish the new asset under a new tag.

## The `replay` tier

```bash
make bench-compare TIERS=replay RUNS=3                 # small corpus (committed)
make bench-compare TIERS=replay CORPUS=large RUNS=3    # large corpus (fetched)
make bench-compare TIERS=replay CORPUS=testnet-head RUNS=3    # real certificates (fetched once)
make bench-compare TIERS=replay CORPUS=testnet-prefix50 RUNS=3  # 50 real rounds (committed)
BENCH_CORPUS_DIR=/path/to/corpus make bench-compare TIERS=replay RUNS=3
```

`CORPUS` picks the corpus by name. An exported `BENCH_CORPUS` is used when
`CORPUS` is not given, and `BENCH_CORPUS_DIR` (an explicit directory) overrides
both.

The tier (issue #2105) replays a [workload corpus](#workload-corpus)
offline through go-algorand's ledger and through algod-rust's production
catchup path. Both start from a fresh on-disk ledger and read the same bytes.
The tier reports throughput and resource use with Rust/Go ratios, and it
**fails if the two final states differ**, or if either state differs from the
one go-algorand reported when it generated the corpus. It declares
`bench-tier-needs: build`, so the runner builds `algod-rust` (release) with
`build_both.sh` first. The Go harness is built against `GO_ALGORAND_DIR`
(pinned tag enforced, libsodium built when missing) through a generated
`go.work`. It needs Linux or macOS: the Go side links go-algorand's vendored
libsodium.

### What each side runs

| | go-algorand | algod-rust |
|---|---|---|
| Harness | `benchmarks/go-replay` (`goreplay`, AGPL: it links go-algorand) | `algod-rust bench replay-corpus` (`bin/algod-rust/src/commands/bench_replay.rs`) |
| Data directory | `config.json` (the corpus's `node-config.json`), `cfg.EnsureAndResolveGenesisDirs` and `data.LoadLedger`, as `node.MakeFull` does | `config.json`, then `participate`'s `open_and_configure_participate_ledger` and `seed_ledger_from_genesis_str`, plus `set_devmode_chain` for a devmode genesis (as `algod-rust node` does) |
| Per block | The body of `catchup/service.go` `fetchAndWrite`: `processBlockBytes` (decode, round checks), `ContentsMatchHeader`, the certificate check, the `MaxBalLookback` backpressure wait, then `AddBlock` (default `CatchupBlockValidateMode` 0) or `Validate` + `AddValidatedBlock` | The catchup service's own sync pass, `CatchupService::sync_range` (`crates/core/algo-ledger/src/catchup_service.rs`). It runs parallel fetch workers, then in round order `authenticate_block`, `algo_validate::contents_match_header` and `AgreementLedgerBridge::ensure_block` (store the block and cert, apply, commit) |
| Block source | `blocks.bin`, read record by record from the file | `CorpusBlockFetcher`, a `BlockFetcher` that reads `blocks.bin` per round and builds the `FetchedBlockCert` the way the gossip fetcher does (`decode_block_response`, raw payset blobs, `participate::fetched_certificate`) |
| End of the timed section | `WaitForCommit(last)` (every block durable), then `Close()` (waits for an in-flight tracker commit and stops the writers) | the last commit (algod-rust commits each block synchronously), then the ledger is dropped |
| Final state | read from the **reopened** ledger | read from the **reopened** ledger |

Nothing on the Rust side is a benchmark-only shortcut. The only corpus-specific
pieces are the block source and the DevMode certificate check (below). The
unit test `small_corpus_replays_to_the_go_final_state` (in
`bench_replay.rs`) runs this exact code in default CI and requires the Go
state.

**DevMode certificates.** A DevMode corpus certificate holds only its round
(no votes, no proposal), so neither side can authenticate it.
- go would call `cert.Authenticate`. `goreplay` instead requires the
  degenerate form: the right round and no votes.
- algod-rust's `CorpusCatchupLedger` delegates everything to the production
  `AgreementLedgerBridge`, except `authenticate_block`, which runs the same
  check (`check_devmode_certificate`).
- A non-DevMode corpus is authenticated for real on both sides: go's
  `cert.Authenticate` with an `AsyncVoteVerifier`, the bridge's
  `Certificate::authenticate`. The
  [`testnet-head` corpus](#the-testnet-head-corpus-real-certificates) is
  one: it is what benchmarks that path.

**DevMode payouts.** go's catchup `AddBlock` evaluates with
`validate = false`, and `validateForPayouts` runs only inside `endOfBlock`'s
`if eval.validate` (`ledger/eval/eval.go` L1551-L1571), so go never holds a
fetched proposer-less DevMode block to the payout rules. algod-rust's
catchup commit checks payouts (issue #1803) except on a devmode chain
(`SqliteLedger::is_devmode_chain`, `apply_devmode_block_executing_app_calls`),
the same rule its follow path already had.

### What is measured

The timed section starts after setup and ends as described in the table.
Setup covers genesis seeding, an untimed pre-pass that indexes `blocks.bin`
and counts the work, and the final-state computation.

| Row | Unit | Definition |
|---|---|---|
| `<corpus>/blocks_per_s` | block/s | blocks replayed / wall time |
| `<corpus>/txns_per_s` | txn/s | top-level + inner txns / wall time |
| `<corpus>/wall_s` | s | wall time of the timed section |
| `<corpus>/peak_rss_mb` | MB | `VmHWM` from `/proc/self/status` (process lifetime peak; the pre-pass streams the corpus, it never holds it in memory) |
| `<corpus>/cpu_s` | s | `getrusage(RUSAGE_SELF)` user + sys over the timed section |
| `<corpus>/write_mb` | MB | `/proc/self/io` `write_bytes` over the timed section; omitted where the kernel has no per-task I/O accounting (WSL2) |
| `<corpus>/db_mb` | MB | size of the data directory after the close |

Each run uses a fresh temporary data directory. The tier discards
`BENCH_REPLAY_WARMUP` (default 1) warm-up rounds, then runs `RUNS` measured
rounds and alternates which side goes first. Every result's `metadata`
carries the corpus manifest sha256, `final_state_sha256` (canonical JSON of
the final state), the final block hash, both commands and each side's
effective config.

### Config parity and the differences that remain

Both sides run the corpus's `node-config.json` on top of their defaults:
`Archival: true`, and the default `CatchupBlockValidateMode` 0,
`CatchupParallelBlocks` 16, `MaxAcctLookback` 4, `LedgerSynchronousMode` 2
and `CatchpointInterval` 10000. Each result's `config` lists the values it
ran with. These differences remain, and they are part of what is measured:

- **Write strategy.** go queues blocks in its block queue and flushes account
  deltas to the tracker DB in batches, at most every ~5 s
  (`balancesFlushInterval`). Up to that much state stays in memory and is
  rebuilt from the blocks on restart. algod-rust commits block and state in
  one SQLite transaction per block.
- **Payout validation.** go's `AddBlock` skips `validateForPayouts`.
  algod-rust's catchup checks it on non-devmode chains (#1803); the corpus is
  devmode, so it is skipped here too.
- **`MaxAcctLookback`.** go keeps 4 rounds of deltas. algod-rust's delta
  cache never goes below 320 rounds (`set_delta_cache_window`).
- **Catchpoints.** Neither side writes catchpoint files: algod-rust needs a
  `CatchpointDir`, which the config leaves empty. go maintains its catchpoint
  trie on archival nodes, and algod-rust maintains its account trie.
- **Fetch pipeline.** go's harness writes blocks in order from one goroutine,
  as `fetchAndWrite` does once the previous round is written; it does not run
  go's network fetch pipeline. algod-rust runs its real sync pass, including
  its fetch worker threads (`CatchupParallelBlocks`).

### The final-state equality gate

Both harnesses compute the same canonical document
(`benchmarks/go-replay/state.go`, `crates/tools/algo-bench/src/replay_state.rs`;
the line formats must stay identical). Every digest is the hex sha256 of the
lines described below.

| Field | Content |
|---|---|
| `round`, `block_hash`, `txn_counter` | the last block |
| `total_money`, `online_money`, `totals` | the ledger's `AccountTotals` (online / offline / not-participating money and reward units, rewards level) |
| `known_accounts` | `corpus.json`'s digest: `"<address> <amount>\n"` over the sorted account set the generator tracked, amounts with pending rewards (REST `amount`). The set is rebuilt from the corpus: the genesis allocations, every top-level payment receiver, and the accounts of the first two apps created |
| `all_accounts` | every non-empty account: its stored base record (status, balance, rewards base, auth, totals, voting keys), then its asset holdings, created assets, app local states and created apps, including TEAL key/value state and program hashes |
| `kv` | every box: `"<hex key> <hex value>\n"` sorted by key |

The tier fails when any of these holds:
- a run's Go and Rust states differ (the report names each differing field);
- the runs disagree with each other;
- a full replay's state differs from `corpus.json`'s `final_state` on round,
  block hash, txn counter, money, account count or `accounts_sha256`.

Each harness also checks `corpus.json` itself and exits 3 on a mismatch.
`--dump-state DIR` (Rust) and `-dump-state DIR` (Go) write the digested lines,
so a divergence can be diffed line by line. `--rounds N` / `-rounds N`
(tier: `BENCH_REPLAY_ROUNDS`) replay a prefix, for bisecting the first
diverging round. The gate's first finding was #2116: the rewards pool was
never debited for accrued rewards. The first divergence was at round 3.

**Recorded Go state.** `benchmarks/go-replay/testdata/small-final-state.json`
is the Go harness's full final state on the `small` corpus. Two tests hold it
in step: Go's `TestSmallCorpusFinalStateMatchesRecorded` and algod-rust's
`small_corpus_replays_to_the_go_final_state`. So default `cargo test` checks
the Rust state against Go's without Go installed. The `algo-bench` test
`corpus_small.rs` additionally checks go-algorand's numbers along the way
(round 3's not-participating money, the round-2000 pool balance and
`corpus.json`'s `accounts_sha256`) through the follow path.

**Negative tests.**
- `BENCH_REPLAY_CORRUPT=txn` replays a copy of the corpus with one byte of a
  txn note flipped. Both replays stop at that block (payset commitment
  mismatch).
- `BENCH_REPLAY_CORRUPT=expected` alters the expected `accounts_sha256`. Both
  replays succeed, and the gate rejects the state.
- `BENCH_REPLAY_CORRUPT=vote` (corpora with real certificates only, such as
  `testnet-prefix50`) flips one bit of the last byte of the last vote's
  signature (`cert.vote[-1].sig.s`) in the last record, located by parsing the
  record's msgpack (`corpus_tool.corrupt_vote`). Both replays stop at that
  round, at certificate authentication (go: `cert did not authenticate
  block`; Rust: `replay stopped at round N: ... ; last authentication error: round N: ...`). A DevMode corpus has no
  votes, so the tier refuses to build this corpus from one. The Go and Rust
  tests do the same flip on their side and decode the record before and after
  to assert that exactly that signature byte changed.
- In all cases the manifest is re-hashed, so the corpus still verifies.
- Each must fail the tier. CI runs all three. The Go tests
  `TestCorruptedTxnFailsTheReplay` / `TestWrongExpectedStateExits3` /
  `TestTestnetPrefixTamperedVoteFailsAuthentication`, the Rust tests
  `corrupted_txn_fails_the_replay` /
  `testnet_prefix_tampered_vote_fails_authentication` and
  `scripts/bench/test_replay.py` / `test_testnet_corpus.py` cover the same
  paths per side.

### The `testnet-head` corpus (real certificates)

```bash
make bench-compare TIERS=replay CORPUS=testnet-head RUNS=3
python3 scripts/bench/corpus/fetch_testnet.py fetch    # only the fetch
```

The DevMode corpora cannot benchmark certificate verification: their
certificates hold only the round. `testnet-head` (issue #2119) is the first
20,000 rounds of the public testnet, blocks and certificates verbatim, with
`devmode: false` in `corpus.json`. Both harnesses then take their
non-DevMode branch and authenticate **every** certificate: go's
`cert.Authenticate` with an `AsyncVoteVerifier`, and algod-rust's
`Certificate::authenticate` through `AgreementLedgerBridge::authenticate_block`
(the catchup service's own check). Votes are verified against the online
stake at the round's balance-lookback round, so the tier measures the vote
signature, VRF-credential and committee-sortition work a node pays during
catchup.

| | |
|---|---|
| Source | an archival algod, default `https://testnet-api.algonode.cloud` (`endpoint=` in `benchmarks/corpus/testnet-head.ref`, override with `TESTNET_ENDPOINT` or `--endpoint`): `GET /v2/blocks/{r}?format=msgpack` for rounds 0..20000, the response bodies stored unchanged as `ACRPBLK1` records, plus `GET /genesis` stored byte for byte as served (`benchmarks/corpus/**` is `-text`, so no checkout rewrites it) |
| Checks while fetching | every block body must parse as a msgpack `{block, cert}` response for the requested round (an HTML error page, an empty body or another round's block aborts the fetch); the genesis must hash (go's `Genesis.Hash`, ported from `canonical_encode_genesis`) to the endpoint's `genesis-hash` **and** to the `genesis_hash=` the ref pins (testnet's), so an endpoint of another network is refused ("wrong network"); the final state must agree with the endpoint's block hash and txn counter. A body cut short mid-transfer, a reset or a timeout is retried with backoff (exit 3 when exhausted). Nothing is installed on any failure, and `--force` replaces an existing corpus only at the very end (the old one is untouched until the new one is complete and verified) |
| Cost | about 20,000 requests (a few minutes with 16-32 workers) and 258 MB on disk, fetched once. The replay then needs no network. Go replays it in about 40 s and 270 MB RSS on a 24-core Linux box (the vote checks run in parallel) |
| Cache and pin | `benchmarks/corpus/testnet-head/` (git-ignored). `testnet-head.ref` pins the sha256 of its `MANIFEST.sha256`; a fetch whose bytes differ is discarded, so every run reads identical bytes (two independent fetches gave the same manifest). The tier checks an existing cache against the pin too and refuses a foreign or stale one (delete it, or `fetch --force`) |
| Tier | `CORPUS=testnet-head` fetches the corpus when it is missing (exit 3 and a message when the endpoint is unreachable; `BENCH_CORPUS_DIR` then works with a copy) |
| Committed slice | `benchmarks/corpus/testnet-prefix50/` holds rounds 0..50 (650 kB) with its final state. The default test suites replay it with every certificate authenticated: the Rust tests `testnet_prefix_authenticates_every_certificate` / `testnet_prefix_tampered_vote_fails_authentication`, the Go tests `TestTestnetPrefixAuthenticatesEveryCertificate` / `TestTestnetPrefixTamperedVoteFailsAuthentication`, and CI's `CORPUS=testnet-prefix50` tier run. Its own ref, `benchmarks/corpus/testnet-prefix50.ref`, pins its manifest and holds its final state; rebuild it as shown below |

The committed slice is rebuilt, from the same endpoint and byte for byte, with:

```bash
python3 scripts/bench/corpus/fetch_testnet.py fetch --ref benchmarks/corpus/testnet-prefix50.ref --name testnet-prefix50 --dest benchmarks/corpus/testnet-prefix50 --force
```

A ref describes one range: `--rounds N` selects another and then ignores the
ref's `final_state` and `manifest_sha256` (pass `--final-state` to give one).
`scripts/bench/test_testnet_corpus.py` runs the command above, exactly as
printed here, against a local mock endpoint.

**Final state.** `corpus.json`'s `final_state` is defined as for the other
corpora. `round`, `block_hash` and `txn_counter` are the endpoint's
(`GET /v2/blocks/N/hash`, the header's `tc`; testnet's first blocks carry no
txn counter, so it is 0). `total_money`, `online_money`, `accounts`,
`accounts_microalgos` and `accounts_sha256` describe the balances at round N,
which an algod serves only for the current round, never for a past one, so
they cannot come from the endpoint. They are the state go-algorand's own
ledger reaches replaying this very stream
(`benchmarks/corpus/testnet-head.final.json`, derived with
`fetch_testnet.py finalize` from a `goreplay` result). `finalize` refuses a
replay whose round, block hash or txn counter differs from the endpoint's,
and the fetch checks the committed file against the endpoint again. So the Go
state is anchored to the chain by the block hash (which commits to the
payset and the rewards state), and Rust is held to Go by the usual gate.

**`known_accounts`.** The set is rebuilt from the corpus as for the DevMode
corpora: every genesis allocation, every top-level payment receiver and the
accounts of the first two apps the corpus creates (none exist in this range,
so the set is the genesis accounts plus the payment receivers: 195 at round
20,000).

**What it does not cover.** The first 20,000 rounds hold 425 transactions,
no applications, no boxes, no proposer
payouts and no state proofs: those arrived in later consensus versions, and a
node cannot start there without a catchpoint. This corpus benchmarks
certificate authentication and the per-round ledger overhead of an almost
empty chain. Payouts and state-proof transactions need a corpus that starts
from a catchpoint-restored ledger (see the follow-up issue linked from
#2119).

**Go harness note.** go's `accountUpdates.lookupKeysByPrefix` learns the
database round from the `kvstore` rows its query returns, so on a ledger
that never created a box it reports `StaleDatabaseRoundError` (database round
0) although nothing is stale. The Go harness's box scan (`boxKeys` in
`benchmarks/go-replay/state.go`) treats exactly that case as "no committed
boxes" and takes the live ones from the in-memory deltas, but only after
counting the rows of the tracker database's `kvstore` table (`kvstoreRows`):
if any row is committed, the stale round is a real inconsistency and the
harness fails instead of dropping boxes. go logs one `level=error` line for the
benign case; that line is harmless. Covered: the no-row case end to end
(`testnet-prefix50`, `-rounds 20`), the row count itself
(`TestKvstoreRowsCountsTheCommittedRows`), and the unchanged path of a ledger
with boxes (the `small` corpus). Not covered: the loud-failure branch of
`boxKeys` itself, because go cannot be made to report a stale round with
committed KV rows.

### CI

`.github/workflows/bench-replay.yml` (Linux) runs on changes to the harnesses,
the corpus, the tier and the production ledger, validation and codec crates.
It runs:
- gofmt, vet and `go test` of `benchmarks/go-replay`;
- the tier's Python tests;
- `make bench-compare TIERS=replay CORPUS=small RUNS=3`, with `report.md`
  appended to the job summary;
- both negative tests;
- `make bench-compare TIERS=replay CORPUS=testnet-prefix50 RUNS=1` (50 real
  rounds, every certificate authenticated on both sides) and the `vote`
  negative test. The 20,000-round `testnet-head` corpus needs the public
  endpoint and is not fetched in CI.

CI runners are noisy, so treat their ratios as indicative only.

### Running it by hand

```bash
# Go side (Linux; GOWORK replacing go-algorand with the pinned checkout):
go build -o goreplay ./benchmarks/go-replay
./goreplay -corpus benchmarks/corpus/small -data /tmp/g -out /tmp/g.json
# Rust side:
algod-rust bench replay-corpus --corpus benchmarks/corpus/small --data-dir /tmp/r --output /tmp/r.json
```

## The `localnet` tier

```bash
make bench-compare TIERS=localnet RUNS=3                       # the full ladder
make bench-compare TIERS=localnet RUNS=1 BENCH_LOCALNET_PROFILE=smoke   # a few minutes
```

The tier answers "how much does an all-Rust network commit, and how quickly,
compared with an all-Go network, on the same host under the same load?". It
needs Docker with Compose v2 and network access to pull
`algorand/algod:<pinned tag>` (once). It builds the algod-rust image from
`docker/Dockerfile` (`--target runtime`, cached after the first build); it
does not use `build_both.sh`, because both implementations run inside
containers.

### Why not a mixed cluster

`make bench-stress` and `make bench-cluster` run **mixed** clusters (Go and
Rust nodes in one network). They are good for **interoperability**: do the
two implementations agree, gossip and certify together. They cannot say
which implementation is faster. Every round's block is proposed by whichever
node wins the sortition, every vote needs both halves, and a slow Rust node
slows the Go nodes' round and the other way round. CPU, RSS and latency in
such a run are therefore confounded, and the same goes for TPS. Their numbers
are **interop** numbers, not a comparison. Use this tier for comparison.

### Topology and limits

Two clusters, run one after the other on one host, with the same shape:

```text
            relay  (gossip listener 4161, REST 8080)
          /  |  |  \
      part1 part2 part3 part4     one online wallet each, 25% of the stake
```

| | `go` | `rust` |
|---|---|---|
| Image | `algorand/algod:<tag from scripts/bench/go-algorand.pin>` (the official image of the pinned release) | `algod-rust:bench-localnet`, built from this checkout |
| Process | the image entrypoint (`algod`) | `algod-rust participate` |
| Relay | `NetAddress 0.0.0.0:4161` | `--listen-address 0.0.0.0:4161 --relay-messages`, no keys |
| Participation node | dials `relay:4161`, key from its node directory | `--peers relay:4161 --import-partkey <the same .partkey>` |

What is identical by construction (`scripts/bench/localnet_lib.py`,
`topology`; `ll.shape` and the unit tests pin it):

- **Genesis.** One `goal network create` per run, then copied into a private
  tree for each cluster. Both clusters therefore share the genesis hash, the
  four participation keys and the consensus version (`future`). The 16
  deterministic load accounts are funded **in the genesis** (as
  NotParticipating accounts: they never accrue rewards, so a balance depends
  only on the transactions applied), so no funding transaction differs between
  the clusters. The tier asserts the two genesis hashes are equal.
- **Fresh genesis every run.** `goal network create` stamps the genesis with its
  creation time and both nodes clamp block timestamps to `prev.ts + 25 s`
  (CLAUDE.md, "Mixed-cluster soaks must start from a fresh genesis"). The tier
  never reuses a network between runs or between the two clusters' runs.
- **Resource limits.** Every container of both clusters gets the same
  `cpus` and `mem_limit` (`BENCH_LOCALNET_CPUS`, default 2;
  `BENCH_LOCALNET_MEM`, default 3g), no restart policy, and its own bridge
  network. The load generator is **not** limited and not part of either
  cluster.
- **Node-local config.** The pool and queue sizes and the 500 ms proposal
  assembly window of `docker/scripts/stress-bootstrap.sh` are written into every
  node's `config.json`. algod-rust reads the subset it implements, so the same
  file is a like-for-like input rather than proof that every key took effect.
- **Load generator.** One binary, `algod-rust loadgen`, run in a container on the
  cluster's network, spreading submissions round-robin over all five REST
  endpoints. It is the same binary and the same flags for both clusters.

The tier alternates which cluster runs first in successive runs, like the other
tiers, and records both image ids, the limits and the load commands in each
row's metadata.

### Steps

| Step | Offered load | What it shows |
|---|---|---|
| `fixed` | exactly `BENCH_LOCALNET_FIXED_COUNT` deterministic payments (`--fixed-count`) at `BENCH_LOCALNET_FIXED_TPS` | The correctness gate, plus the time to commit a known set. |
| `ladder-<tps>` | `BENCH_LOCALNET_LADDER` (`100,500,1000,2000`) for `BENCH_LOCALNET_STEP_SECS` (60) each | Throughput and latency at fixed offered rates. |
| `max` | an unbounded offer (target 1,000,000 TPS, 32 submitters per endpoint) for the same time | The maximum sustained TPS. Its `rejected_groups` is not reported: an unbounded offer rejects by design. |

Between steps the tier waits (up to 120 s) for the relay's pool to drain. If it
does not, the step is **not** failed (after an unbounded `max` step a large
backlog legitimately outlasts the wait) but **flagged**: the row
`<step>/start_backlog_txns` records the transactions still pooled when the step
started (0 on a clean start) and a warning is logged, so a dirty start is
visible in the report instead of silently measuring the previous step's tail.

Per step, the rows `<step>/<metric>`:

| Metric | Unit | How |
|---|---|---|
| `confirmed_tps` | txn/s | `tc` (transaction counter) and `ts` of the block headers at the start and the end of the **submission interval**, read from the relay: transactions committed between the two over their chain time. The generator reports the rounds (and wall-clock instants) at which it started and stopped submitting, so container start-up, its confirmation tail and the pool drain are not in the window. |
| `submit_tps` | txn/s | The generator's accepted submissions per second of wall time. |
| `latency_p50_ms`, `_p95_ms`, `_p99_ms` | ms | Submit to in-block time of every Nth transaction (the generator polls `/v2/transactions/pending/{txid}` every 250 ms, so its resolution is 250 ms). |
| `round_time_s` | s | Chain seconds per round over the same window. Block timestamps have one-second resolution, so very short steps are coarse. |
| `rejected_groups` | groups | Groups a node refused (pool full, fee below the floor) or the generator could not hand to a submitter. The reasons are in the generator's report. |
| `cpu_cores` | cores | Sum over the five containers of the mean CPU% / 100 (`docker stats`, sampled about every 2 s) over the same submission interval. |
| `rss_mb_peak` | MB | Sum of every container's peak memory usage. |
| `blockio_write_mb` | MB | Block-device bytes written by the five containers in the step. |

The `fixed` step also reports how fast the whole set was committed, measured on
the chain and not by polling: `commit_rounds` and `commit_time_s` are the rounds
and block-header seconds from the block before the first submission to the block
holding the last transaction (one-second timestamp resolution), and `set_tps` is
the set size over that time. `commit_rounds` is the most robust of the three.

The raw generator reports, the stats samples (`*-samples.jsonl`) and, on a
failure, each node's last 3,000 log lines land in `logs/localnet/` of the run
directory. `/metrics` is not used: the two implementations expose different
metric sets, so a per-node counter would not be a pair. Pool rejections come
from the generator's own error tallies instead.

### The same-txid-set gate

The fixed-count step is deterministic: transaction `seq` has the sender at ring
position `seq * group_size + i` of the load accounts, a note derived from
`(seq, i)`, a fixed fee and the validity window `[first_valid, first_valid+999]`
(Ed25519 signatures are deterministic too). The generator enforces `--duration-secs` in this mode too: the scheduler stops
handing out jobs at the deadline, retries give up there, and a dead endpoint is
rotated away from after 5 consecutive failures. Failed attempts are counted as
`retries` per endpoint; `failed_groups` counts groups. REST reads of the tier
itself retry briefly unreachable nodes (reset, timeout, 5xx) with backoff and a
loadgen container that times out is force-removed. If a later run fails the
gate, the rows of the runs that completed are still written to `localnet.json`
(marked `incomplete`, naming `failed_run`) and the tier exits non-zero.

A submission a node reports as already known (go's
"transaction already in ledger", algod-rust's "transaction already in the pool")
counts as accepted; lease conflicts do not. The tier passes `--group-size 1`
explicitly and the gate expects `fixed_count * group_size` transactions, and
checks the generator reports the same number. Two clusters sharing a genesis and a
key file are therefore fed **byte-identical transactions**, and the gate fails
the tier, naming the difference, unless for every run:

- both clusters accepted exactly N transactions and **confirmed every one of
  them** (the generator polls each txid until it is in a block);
- the sha256 of the submitted txid set equals that of the confirmed set on each
  cluster, and **the two clusters' sets are equal**;
- each chain committed exactly N transactions during the step (the `tc` delta
  between the block before the first submission and the last block), so
  nothing else was committed;
- the load accounts end with **the same balances** on both;
- the genesis hashes are equal;
- the five nodes of each cluster agree on the block hash at the lowest common
  round (no fork);
- no node restarted or was OOM-killed (`RestartCount`, `OOMKilled`).

A divergence is a parity bug, not a benchmark result. The sorted txids of every
fixed step are kept as `logs/localnet/<impl>-run<N>-fixed-txids.txt`.

### Limits of the numbers

- Everything runs on one host, so the generator, the Docker daemon and ten
  containers (not simultaneously: the clusters run one after the other) share
  its cores. Read the Rust/Go ratio, not an absolute TPS, and give the host at
  least `5 x cpus` free cores for the full ladder.
- The offered load comes from one machine and is submitted over REST. A
  cluster that is slower at the REST ingress shows up as slower here, which is
  what a user would see.
- Docker's CPU accounting is per container and sampled, so a short step has few
  samples.
- `blockio_write_mb` is whatever the Docker engine reports for the container's
  block device. Docker Desktop on Windows/macOS can report 0 for one side; the
  report then shows no ratio for that row (read it on a Linux host).
- The tier measures what it is given. If the Rust cluster commits a fixed set
  over many more rounds than the Go cluster, that is a result about algod-rust
  (for example transaction gossip between nodes), not a harness artefact: the
  generator submitted the same bytes to the same five endpoints.

### CI

`.github/workflows/bench-localnet.yml` runs the unit tests of the aggregation,
topology and gate logic (`scripts/bench/test_localnet.py`) and a **smoke** of the
tier (`BENCH_LOCALNET_PROFILE=smoke`: 200 fixed transactions and a single
10-second ladder step at 50 TPS, one run, 1 CPU and 2 GB per container). It
asserts the gate passed and that the report carries a Rust/Go ratio for the
fixed step. It is a check that the tier works, not a benchmark: shared runners
are too noisy for the ratios to mean anything.

### Running it by hand

```bash
# 3 runs of the full ladder, on a quiet host with docker, cpus >= 12
BENCH_LOCALNET_CPUS=2 make bench-compare TIERS=localnet RUNS=3
# one cluster's tooling, e.g. to debug the load generator against a running network:
algod-rust loadgen gen-accounts --deterministic --count 16 --out keys.json
algod-rust loadgen run --algod-urls http://127.0.0.1:4300 --keys keys.json \
  --fixed-count 200 --target-tps 100 --duration-secs 120 --txids-out txids.txt
```
