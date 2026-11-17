# Phase 25 Validation — TEAL corpus parity (ARC56Registry)

_Written 2026-11-17 with the nightly workflow (issue #2372)._

Evidence map for epic [#2364](https://github.com/xarmian/algod-rust/issues/2364):
algod-rust's TEAL **disassembler** and **assembler** are in exact parity with
go-algorand `v5.0.5-stable` on every distinct program and original source of the
public [ARC56Registry](https://github.com/scholtz/ARC56Registry), and a nightly
job keeps proving it. Phase 25 changes no protocol rule, no go-algorand pin and
**adds no divergence** (`docs/DIVERGENCES.md` is unchanged; the Go side is the
oracle and every mismatch class found was fixed in algod-rust). The published
numbers are in [`docs/TEAL_CORPUS_PARITY.md`](TEAL_CORPUS_PARITY.md); this file
maps each criterion to the test, tool or workflow that proves it and says what is
not yet met.

## Criteria and evidence

| Criterion | Status | Evidence |
|---|---|---|
| Every sub-issue of the epic closed | **met when the #2372 PR merges** | #2365 PR #2373 (fetch + extract, `scripts/teal-corpus/fetch.py`, `extract.py`); #2366 PR #2374 (Go driver `tools/teal-corpus`, Rust driver `crates/tools/teal-corpus`, JSONL schema, `diff`); #2367 PR #2376 (disassembly parity); #2368 PR #2383 (reassembly parity); #2369 PR #2384 (original-source parity); #2370 PR #2389 (REST tier, `goal clerk compile`); #2371 PR #2412 (statistics, history, benchmark tier); #2372 (this change). |
| 1. Disassembly parity: `go.Disassemble(P)` and `rust.disassemble(P)` byte-identical or the same error, on every program | **met** | Stage `disassemble` of `make teal-corpus-parity` (`scripts/teal-corpus/run_drivers.sh`): 3,692 programs, 0 mismatches, 0 panics, 0 timeouts (`docs/teal-corpus/latest-stats.json`); Rust ports in `crates/core/algo-avm/src/disassembler.rs`, regression cases `crates/core/algo-avm/tests/disassemble_go_parity.rs` + `fixtures/disasm_go_parity.jsonl` (kept fresh by `scripts/teal-corpus/disasm_fixtures.py --check` in `teal-corpus-drivers.yml`), `pc_details_go_parity.rs`. |
| 2. Reassembly parity: the disassembled TEAL assembles identically in go and rust | **met** | Stage `reassemble` (`scripts/teal-corpus/reassemble.py`): 3,691 compared, 0 mismatches, plus the cross-check `rust.assemble(rust.disassemble(P)) == go.assemble(go.disassemble(P))`; type tracking port in `crates/core/algo-avm/src/type_track.rs` (`AVM Type Tracking Table Is Generated` CI check); synthetic adversarial corpora (`gen_synthetic*.py`) in `teal-corpus-drivers.yml`. |
| 3. Original-source parity: bytecode, source map, warnings and ordered errors from `source.approval/clear` | **met** | Stage `source` (`scripts/teal-corpus/source_stats.py`): 3,687 compared, 0 mismatches; assembler front end port `crates/core/algo-avm/src/assembler.rs`, `assemble_go_parity.rs` + `fixtures/asm_go_parity.jsonl` (`asm_fixtures.py --check`), 20,000+20,000+20,000 syntax/byte mutations in `teal-corpus-drivers.yml`. |
| 4. REST-surface parity: `POST /v2/teal/disassemble`, `/v2/teal/compile[?sourcemap=true]` on a sample, real handlers of both nodes | **met** | `bin/algod-rust/tests/live_teal_corpus_parity.rs` (`teal_corpus_rest_matches_go_and_offline`), run by `validate-api.yml` on every code change and by the nightly with the sample size of its dispatch input (default 300); `goal clerk compile -D` parity in `teal-corpus-drivers.yml` (`goal-clerk-compile-parity`). Since #2372 the test writes `rest_sample.{go,rust}.jsonl` (`TEAL_CORPUS_REST_OUT`) so the stage is part of `stats.json` and of the gate. |
| Neither harness may panic, hang or exhaust memory on any input | **met** | Per-input timeout and panic capture in both drivers (`crates/tools/teal-corpus`, `tools/teal-corpus`); `panics` and `timeouts` are gate counters in `gate.py` (zero required); go's assembler scratch-index panic (#2381) is mirrored as a typed condition and counted as `identical_panic_mirrored`, never as a failure to hide. |
| The Go side is the oracle; no new divergence | **met** | `python3 scripts/check_divergences.py` unchanged (DIV-001 to DIV-010); no `DIVERGENCE` marker added in this phase. |
| The corpus is untrusted third-party input; not committed wholesale | **met** | `fetch.py` fetches shallow at a recorded SHA into an empty directory, never executes it; only minimal reproducers live in the fixtures; the workflow caches the checkout by registry SHA and uploads reproducer bundles only for mismatching programs (`gate.py bundle`, at most 50). |
| Go binaries build through go-algorand's own entry points | **met** | The workflow checks out go-algorand at the pin (env `GO_ALGORAND_REV`, `v5.0.5-stable`) as a sibling directory, runs `make -C ../go-algorand libsodium`, then `tools/teal-corpus/build.sh` (inside `make teal-corpus-parity`); `scripts/teal-corpus/test_workflow.py` fails on an ad-hoc `go build`. |
| The nightly is green only on exact parity (zero mismatches, no allow-list) | **met** (demonstrated, below) | `.github/workflows/teal-corpus-parity.yml` + `scripts/teal-corpus/gate.py`. Every gate step is a hard failure; the only `continue-on-error` steps are the informational benchmark and the Docker Hub login (`test_workflow.py::test_no_gate_is_soft`). |
| Every mismatch class found along the way has its own issue, a fix with a regression test, and is closed | **met** | Found and fixed during the phase: #2375 (pcDetails), #2377 to #2381 (reassembly, scratch-index panic), #2388 and #2390 (non-UTF-8 sources, `clerk compile -D`), the same `clerk` decode work (#2393, #2391); each with its regression case in the fixtures above. `gh issue list --label phase:25 --state open` lists no parity mismatch: #2416 (below) and the two performance rows #2410 (assemble 1.24x slower than go) and #2411 (disassemble 1.08x slower), which are speed findings of the benchmark tier, not parity gaps; the other open goal/consensus issues are not Phase 25 parity work. |
| The nightly workflow has passed on the full registry corpus for 3 consecutive nights | **not met, moved to #2416** | Calendar-bound: needs three scheduled runs after the workflow is on `main`. #2416 collects the run URLs and links them from the epic. |
| `docs/PHASE25_VALIDATION.md` written; `CLAUDE.md` and `docs/PROJECT_SCOPE.md` mention the phase | **met** | This file; the Phase 25 entry in `CLAUDE.md`; the Phase 25 paragraph in `docs/PROJECT_SCOPE.md`; the local-run section in `docs/DEV_WORKFLOW.md`. |

## Criteria of #2372 (the nightly workflow)

| Criterion | Status | Evidence |
|---|---|---|
| Workflow exists, path-filtered for PRs, nightly, manually dispatchable | **met** | `.github/workflows/teal-corpus-parity.yml`: `schedule` (01:27 UTC), `workflow_dispatch` (inputs `registry_ref`, `go_ref`, `rest_sample_size`), `pull_request` with the assembler/disassembler/sourcemap sources, the drivers and `scripts/teal-corpus/**`; PR runs use the pinned `PR_REGISTRY_SHA`; `actionlint` clean; structure pinned by `scripts/teal-corpus/test_workflow.py`. |
| go-algorand built through `make libsodium` and the repo pin | **met** | See above; libsodium build cached by go-algorand commit. |
| A deliberately seeded mismatch turns the job red and uploads the reproducer; reverting turns it green | **met** | Throwaway PR #2414 (the disassembler rewrote `intc_0` as `intc 0`): run <https://github.com/xarmian/algod-rust/actions/runs/44109036343> is **red** (`diff disassemble: 3692 rows compared, 411 identical, 1 both-error-identical, 3280 mismatches`; step "Offline parity stages" and the verdict fail) and its artifact `teal-corpus-parity-44109036343` holds `out/*.mismatches.jsonl` and 150 files of reproducer bundles (50 programs). After a revert commit (plus a comment touch so the path filter starts the run) the run <https://github.com/xarmian/algod-rust/actions/runs/44110521002> is **green**. A third throwaway PR (#2417) ran the live REST sample (40 programs, 879 comparisons, 0 mismatches; stage `rest_sample` present in `stats.json`): <https://github.com/xarmian/algod-rust/actions/runs/44110177113>. The unseeded baseline of the real PR is also green: <https://github.com/xarmian/algod-rust/actions/runs/44104023091>. |
| An empty/failed extraction turns the job red | **met** | Throwaway PR #2415 (registry directory names no longer match): run <https://github.com/xarmian/algod-rust/actions/runs/44109050025> is **red** at "Extraction sanity gate" (`FAIL extraction: only 0 programs extracted (need at least 1000); the registry layout may have changed`) and at the verdict; unit tests `test_gate.py::ExtractionGate`. |
| Job summary: registry SHA, go pin, algod-rust commit, per-stage counts, benchmark table | **met** | `gate.py summary` appended to `$GITHUB_STEP_SUMMARY` (`test_gate.py::Reports`); the benchmark table is `gate.py bench-table` of the informational `scripts/bench/tiers/teal-corpus.py` tier. |
| Failure opens/updates one tracking issue; a later green run resolves it | **met** (tested with a fake `gh`, and live against this repo: two failures gave one issue plus comments, a green call closed it; issues #2418 and #2419 are those exercises, closed) | `scripts/teal-corpus/tracking_issue.py` (`test_tracking_issue.py`): first failure creates one issue (labels `conformance`, `avm`, `bug`, `ci`, `phase:25`, `team:a`), later failures comment on it, the first green run comments and closes it. Only scheduled/dispatched runs on `main` call it, never PR runs. |
| 3 consecutive green nightly runs | **moved to #2416** | See above. |
| Docs, license headers, fmt/clippy/suite | **met** | This file, `CLAUDE.md`, `PROJECT_SCOPE.md`, `DEV_WORKFLOW.md`; new files carry the MIT header (tooling with no go-algorand derivation); the one Rust change is in a test file (`cargo clippy -p algod-rust --test live_teal_corpus_parity -- -D warnings` clean, `rustfmt --check` clean). |

## Known limitations

- **History row.** The job computes the row (`stats.py history`) and uploads the
  updated `history.csv` and `stats.json` as artifacts, but does not push to
  `main` (branch protection, no extra permissions); the next commit that records
  a run copies the row into `docs/teal-corpus/history.csv`.
- **REST sample on PRs.** PR runs skip the live REST tier (the docker dual-node
  harness is heavy and `validate-api.yml` already runs the same test on every
  code change); the nightly and manual dispatch run it.
- **Registry growth.** The nightly follows the registry at `main`, so a new
  contract can surface a new mismatch class on any night; that is the purpose of
  the job. The extraction thresholds (`TEAL_CORPUS_MIN_PROGRAMS`, default 1000;
  `TEAL_CORPUS_MAX_SKIP_RATIO`, default 0.05) are environment-tunable in
  `gate.py`.
