# TEAL corpus parity: statistics, history and benchmark

Phase 25 (epic #2364) compares algod-rust's TEAL assembler and disassembler with
go-algorand's on every program of the public ARC56Registry. This page is the
published report of issue #2371: what the corpus looks like, how far the two
implementations agree, how that changes over time, and how fast each side is.
The stage definitions are in the issues #2365 (corpus), #2366 (drivers), #2367
(disassemble), #2368 (reassemble), #2369 (original sources).

## First full-corpus run

| Item | Value |
|---|---|
| Date | 2026-11-17 |
| Registry | `ARC56Registry` at `e75e509cf2452fea5b0726e064f7445dedbeac07` (a fresh clone by `make teal-corpus-fetch`, fetched 2026-11-17T13:51:14Z) |
| go-algorand | `v5.0.5-stable`, `31186e99a69e74483ad95e9ce872903b74758abf` |
| algod-rust | `8af88af31996caccf70ef8f4f7d6145f378ffed1` (this PR's branch before the docs commit; the Rust sources are those of `main` plus the `--timings` flag) |
| Machine | desktop, Intel Core i7-13700 (12 cores / 24 threads), 31.2 GiB, Windows 11 host, Ubuntu 22.04.5 in WSL2 (kernel 6.18.58.1-microsoft-standard-WSL2), go 1.25.3, rustc 1.99.1 |

The raw `stats.json` of this run is [teal-corpus/latest-stats.json](teal-corpus/latest-stats.json).

### Corpus

| | |
|---|---|
| Programs (de-duplicated by sha256) | 3,692 (3,669 approval, 21 clear, 2 shared) |
| Distinct sources | 3,687 |
| Total bytes | 3,145,695 |
| Size min / p50 / p90 / p99 / max (bytes) | 1 / 335 / 1,900 / 7,446 / 38,414 |
| AVM versions | v1: 1, v8: 4, v10: 2,482, v11: 1,166, v12: 24, v13: 15 |
| Registry file name equals sha256 of the program | 3,692 of 3,692 |
| Opcodes seen vs. go's opcode table (`logic.OpSpecs`) | 188 of 198 (94.9%) |
| Never seen in the corpus | `arg`, `arg_0`, `arg_1`, `arg_2`, `arg_3`, `args` (LogicSig-only), `gaid`, `gtxna`, `gtxnas`, `sumhash512` |

The never-seen list is the part of `opcodes.go` that real contracts do not
exercise; the synthetic corpora (`gen_synthetic*.py`, run in the
`teal-corpus-drivers` workflow) cover those opcodes instead.

### Agreement, per stage

| Stage | Compared | Identical | Identical error | Mismatched | Panics | Timeouts |
|---|---|---|---|---|---|---|
| disassemble | 3,692 | 3,691 | 1 | 0 | 0 | 0 |
| reassemble (go's disassembly assembled by both) | 3,691 | 3,666 | 25 | 0 | 0 | 0 |
| source (original ARC-56 sources) | 3,687 | 3,524 | 163 | 0 | 0 | 0 |

"Identical error" is the number of inputs that both implementations reject with
exactly the same ordered error list. The REST sample stage (#2370) is written by
`live_teal_corpus_parity` when `TEAL_CORPUS_REST_OUT` names the output directory
(one row per node-vs-node comparison, #2372); `stats.py` reports it as soon as
`rest_sample.{go,rust}.jsonl` exist there, and omits it otherwise (it is omitted
here; the nightly workflow runs it and requires it).

| Rate | Go | Rust |
|---|---|---|
| Fixed point `assemble(disassemble(P)) == P` (3,666 of 3,691 disassemblable programs) | 99.32% | 99.32% (the same 3,666) |
| `sha256(assemble(disassemble(P)))` equals the registry hash, among the fixed-point programs | 100% | 100% |

Both implementations leave the same 25 programs off the fixed point with the
same bytes (stage `reassemble`, gate 2: `rust.assemble(rust.disassemble(P))` equals
`go.assemble(go.disassemble(P))` on every program).

Error classes both sides reject identically (numbers and names masked): the
one undisassemblable program is `illegal opcode 0xN`; the 163 sources are 80
`bytecblock arg did not parse: X` and 79 `strconv.ParseUint: parsing "X": invalid syntax`
(template variables, `TMPL_*`, plus `PRFX_*` sources, which need substituting before
they assemble) and 4 others; the 25 non-reassembling disassemblies are go's
static type errors (`... arg N wanted type ... got ...`, 23) and 2 others. The full
histogram is in `error_classes` of the stats file.

## Statistics: `stats.json`

`make teal-corpus-stats` (after `make teal-corpus-parity`) writes
`teal-corpus-work/out/stats.json` with `scripts/teal-corpus/stats.py build`. The
schema, `teal-corpus-stats/v1`, is documented in the module docstring of
`scripts/teal-corpus/stats.py`: `run`, `corpus`, `avm_versions`, `opcodes`,
`stages`, `fixed_point`, `error_classes`. The output is deterministic (sorted
keys, LF, no timestamp), and is tested against hand-built fixtures in
`scripts/teal-corpus/test_stats.py` (also run by the `harness-shell-tests`
workflow).

The opcode table is the Go driver's `teal-corpus opcodes`, i.e. go-algorand's
own `logic.OpSpecs`; the opcode histogram counts the first token of every
instruction in go's disassembly.

## History

`docs/teal-corpus/history.csv` has one row per recorded run (date, registry
SHA, algod-rust commit, go tag, corpus shape, opcode coverage, per-stage
compared/mismatched, panics, timeouts, fixed-point and registry-hash rates).
It is a file in the repository, not a workflow artifact or a branch, because it
is diffable in review, needs no extra permissions, and does not expire with
artifact retention. The update path:

```bash
make teal-corpus-fetch && make teal-corpus-parity   # network; fresh registry clone
make teal-corpus-history                            # appends (or replaces the same day/registry/commit row)
```

and commit the CSV (and, if wanted, `latest-stats.json`) with the change that
motivates the run. A scheduled run that cannot push to `main` uploads its
`stats.json` as a workflow artifact and the row is appended by the next commit
that records a run (`.github/workflows/teal-corpus-parity.yml`, issue #2372).

## Benchmark: `make bench-compare TIERS=teal-corpus`

The `teal-corpus` tier (`scripts/bench/tiers/teal-corpus.py`) runs the Go and
Rust batch drivers over the same corpus with `--jobs 1` (single thread per
side), one process per run, a discarded warm-up pair and `RUNS` measured pairs
that alternate which side goes first. Workloads:

| Workload | Input |
|---|---|
| `disassemble/all` | every program |
| `assemble-disassembled/all` | go's disassembly of every program |
| `assemble-sources/all` | every original ARC-56 source |
| `disassemble/top20`, `assemble-sources/top20` | the 20 largest programs / sources (stable micro rows, `BENCH_TEAL_TOPN`) |

Per workload and side: `wall_s`, `programs_per_s`, `MB_per_s`, and the
per-program `p50_us` / `p99_us` (timed inside the worker around the operation
itself). The equality gate runs after every run: the two JSONL outputs must be
byte-identical (header aside) and neither may record a timeout or an unmirrored
panic; otherwise the workload's timings are withheld (no result row is written
for it) and the tier exits 1. `BENCH_TEAL_CORRUPT=1` is the negative test.
Reproduce (needs the corpus, a go-algorand checkout at the pin with libsodium,
cargo):

```bash
make teal-corpus-fetch
make bench-compare TIERS=teal-corpus RUNS=10 BENCH_CLEAN=1 BENCH_RUN_DIR=bench-results/teal-corpus
```

Results (`RUNS=10`, medians, 95% CI of the median in `report.md`; the gate
passed on every run of every workload), 2026-11-20, i7-13700 WSL2 desktop, go
`v5.0.5-stable`, algod-rust `b3195d75` (issue #2410), the 2026-11-17 run
(`73317092`, issue #2411) in brackets:

| Workload | Metric | Go | Rust | Faster |
|---|---|---|---|---|
| `disassemble/all` | wall | 0.464 s | 0.108 s | Rust 4.30x (Rust 4.34x) |
| | MB/s | 6.78 | 29.16 | Rust 4.30x (Rust 4.34x) |
| | p50 / p99 per program | 42.7 / 1,047 us | 10.0 / 281 us | Rust 4.27x / Rust 3.72x (Rust 4.33x / Rust 3.70x) |
| `assemble-disassembled/all` | wall | 1.027 s | 0.359 s | Rust 2.86x (Go 1.05x) |
| | MB/s | 20.26 | 58.02 | Rust 2.86x (Go 1.05x) |
| | p50 / p99 per program | 103.3 / 2,351 us | 41.1 / 848 us | Rust 2.52x / Rust 2.77x (Go 1.11x / Go 1.14x) |
| `assemble-sources/all` | wall | 1.072 s | 0.404 s | Rust 2.65x (inconclusive) |
| | MB/s | 52.89 | 140.4 | Rust 2.65x (inconclusive) |
| | p50 / p99 per program | 108.0 / 2,599 us | 46.3 / 954 us | Rust 2.33x / Rust 2.73x (Go 1.13x / Go 1.09x) |
| `disassemble/top20` | wall | 40.4 ms | 12.5 ms | Rust 3.24x (Rust 3.24x) |
| | p50 / p99 per program | 1,533 / 5,021 us | 316 / 2,208 us | Rust 4.85x / Rust 2.27x (Rust 4.69x / Rust 2.31x) |
| `assemble-sources/top20` | wall | 79.5 ms | 28.2 ms | Rust 2.82x (Rust 1.05x) |
| | p50 / p99 per program | 3,217 / 11,336 us | 1,183 / 3,541 us | Rust 2.72x / Rust 3.20x (inconclusive / Rust 1.07x) |

`wall_s` includes each driver's own per-input dispatch (go: a goroutine and a
timer per input; Rust: long-lived workers that claim their own inputs under a
per-job deadline supervisor). Before #2411 the Rust driver handed every input
to its worker over a channel, 30 us per input against go's 11 us, which was
the whole `disassemble/all` gap: the disassembler itself was already faster.
`wall_s - sum(per-program)` measures it; the split is in
[BENCHMARK_RESULTS.md](BENCHMARK_RESULTS.md#teal-corpus-tier-phase-25-2371).
Assembling was 1.11x to 1.13x slower per program (p50) until
[#2410](https://github.com/xarmian/algod-rust/issues/2410) removed the
assembler's per-instruction fixed costs (opcode-name lookups, per-token and
per-instruction allocations, the SipHash offset-to-source map; profile and
split in [BENCHMARK_RESULTS.md](BENCHMARK_RESULTS.md#teal-corpus-tier-phase-25-2371));
the corpus parity stays at zero mismatches.
The run is one WSL2 desktop, so it is indicative, not a fixed reference.
