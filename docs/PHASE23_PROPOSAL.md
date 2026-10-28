# Phase 23 Proposal — reproducible Go vs Rust benchmark, then parity-safe optimization

Phase 23 gives anyone one reproducible, documented way to compare the
go-algorand `algod` build (pinned `v5.0.4-stable`) with `algod-rust` on the
same hardware and workloads. It publishes the numbers, then uses them to
make algod-rust faster **without giving up byte- or consensus-level parity**
with go-algorand.

Tracking epic: [#2101](https://github.com/xarmian/algod-rust/issues/2101).
Methodology: [`docs/BENCHMARK_COMPARISON.md`](BENCHMARK_COMPARISON.md).

## Motivation

Epic 37 (#96) built the first pieces: `crates/tools/algo-bench`,
`make benchmark`, `bench-cluster.sh`, `bench-stress.sh` and
`benchmarks/go-decode`. Together they don't yet make a comparison an
outsider can trust:

- `docs/BENCHMARKS.md` still referenced `v4.5.1-stable` (fixed in #2102).
- The Go side covers only block decode. The Rust criterion suites cover
  codec, validate, AVM, ledger and Falcon, but nothing is paired, so most
  hot paths have no Go/Rust ratio.
- `bench-cluster` / `bench-stress` run **mixed** clusters, where Rust and Go
  nodes share consensus and load, so per-implementation throughput is
  confounded.
- `bench replay` / `bench decode` fetch over HTTP, and network latency
  dominates. Their own docs say not to use them for comparison.
- Nothing recorded the environment (CPU, OS, toolchains, commits), so
  numbers from two machines couldn't be compared, and no CI job produced a
  canonical report.

## Design principles (every child issue)

1. **Same input, same work, same machine.** Both implementations read
   identical bytes (fixtures or a corpus with a sha256 manifest). Every
   macro run checks that both ended in the **same final state**. A run that
   diverges is a parity bug, not a result.
2. **Native harnesses on each side.** Go uses `testing.B` against the real
   go-algorand packages, preferring its existing `Benchmark*` functions.
   Rust uses `criterion` against the real crates. Macro runs use the real
   `algod` binaries. Nothing is re-implemented in a third language.
3. **One command and one report.** `make bench-compare` builds both at
   pinned commits, runs the selected tiers and writes
   `bench-results/<ts>/report.{json,md}`, with the environment fingerprint,
   the median and a confidence interval, and a Rust/Go ratio column.
4. **Optimizations are measurement-driven and parity-gated.** Each one
   cites a report row, names its parity guard (golden fixtures, conformance
   suites, the replay final-state equality, differential/oracle tests) and
   records before/after numbers. A deliberate structural difference is
   registered in `docs/DIVERGENCES.md` with wire/consensus impact `none`.

## Scope

The children land strictly in order, one PR at a time. Each later tier only
adds a script under `scripts/bench/tiers/` that emits schema-v1 JSON (the
tier contract in `BENCHMARK_COMPARISON.md`).

| # | Issue | Deliverable | Tier |
|---|---|---|---|
| 1 | #2102 | Harness: `make bench-compare` (`TIERS=`, `RUNS=`), pinned `build_both.sh` (HEAD == tag commit check, `make libsodium`), `fingerprint.py`, `report.py`, result schema v1, built-in `selftest` tier, this proposal and the methodology doc. | `selftest` |
| 2 | #2103 | Paired Go/Rust micro-benchmark suite (codec, crypto, commitments, AVM, sortition) with a pair registry mapping each Go `Benchmark*` to its criterion bench. | `micro` |
| 3 | #2104 | Deterministic workload block corpus (pay / ASA / app / groups / inner txns) with a sha256 manifest. | (input for `replay`) |
| 4 | #2105 | Offline ledger-replay macro benchmark (Go ledger vs algod-rust) with a final-state equality gate. | `replay` |
| 5 | #2106 | Homogeneous localnet throughput: an all-Go cluster vs an all-Rust cluster under the same load. | `localnet` |
| 6 | #2107 | REST API throughput against identical ledger state. | `rest` |
| 7 | #2108 | Public-network fast-catchup and follow benchmark (testnet). | `catchup` |
| 8 | #2109 | `bench-compare` CI workflow, plus a published baseline in `docs/BENCHMARK_RESULTS.md` with its fingerprint. | all |
| 9 | #2110 | Profile-driven optimization pass: a baseline profile, then one issue per hotspot, each parity-gated. | — |

### Architecture (from #2102)

```
make bench-compare TIERS=a,b RUNS=N
  └─ scripts/bench/run.py            tier runner
       ├─ fingerprint.py             -> fingerprint.json
       ├─ build_both.sh              -> build-info.json, target/bench-compare/{go,rust}/
       │    (only when a tier declares `# bench-tier-needs: build`)
       ├─ tiers/<tier>.{py,sh}       -> results/<tier>/*.json  (schema/result-v1.json)
       └─ report.py                  -> report.json + report.md
```

## Success criteria

- [ ] Every child issue (#2102 to #2110) closed with its PR merged and CI green.
- [ ] A person with a clean Linux box, Docker, Go and Rust can run
      `make bench-compare` by following `docs/BENCHMARK_COMPARISON.md` alone
      and get a `report.md` comparable to the published baseline.
- [ ] Every macro tier asserts Go/Rust final-state equality and fails loudly
      on divergence.
- [ ] `docs/BENCHMARK_RESULTS.md` publishes a baseline (with its
      environment fingerprint) and the post-optimization numbers.
- [ ] Every merged optimization cites before/after report rows and its
      parity guard. All existing conformance, golden and parity suites stay
      green, and `python3 scripts/check_divergences.py` passes.
- [ ] `docs/PHASE23_VALIDATION.md` (evidence map) written at close-out, and
      the `CLAUDE.md` phase list updated.
- [ ] `gh issue list --label "phase:23" --state open` is empty before the
      epic closes.

## Non-goals

- Mixed Go+Rust clusters as a *performance* measure. They stay the
  consensus-interop harness (`bench-cluster`, `bench-stress` and the soaks).
- HTTP-fetch benchmarks against public endpoints (`bench replay` /
  `bench decode` / `bench-go`). They stay single-implementation profiling
  tools.
- Any optimization that changes wire bytes, consensus results or REST
  output. Such a change is a parity bug, however fast it is.
- Changing go-algorand. We measure the pinned tag as released.
