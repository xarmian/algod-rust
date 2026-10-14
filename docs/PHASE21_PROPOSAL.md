# Phase 21 Proposal — pure-Rust Falcon-1024 `det1024` port (first intended divergence)

Phase 21 ports `crates/core/algo-falcon` from the vendored C library
(`github.com/algorand/falcon` v0.1.0) to pure Rust, bit-identically, keeps
the C library as a runtime-selectable backend, benchmarks both, introduces
Go-generated sample vectors as the parity oracle, and — because this is the
**first deliberate divergence from go-algorand** — introduces the
divergence register `docs/DIVERGENCES.md` and its tooling so that every
future parity sweep treats it as intended.

Tracking epic: [#1926](https://github.com/xarmian/algod-rust/issues/1926)
(`docs/epics/Epic-31-Falcon-Rust-Port.md`). Register entry: `DIV-001`.

## Motivation

- `algo-falcon` is a thin FFI wrapper over ≈18.6k lines of vendored C: the
  only non-Rust code on the consensus path (state-proof keys/signatures via
  `algo-consensus-crypto::merklesig`, native PQ accounts via `pq_scheme`,
  the AVM `falcon_verify` opcode, `algokey-rust`). It needs a C toolchain
  to build and cannot be reasoned about with Rust's tooling.
- The C build uses emulated floating point (`FALCON_FPEMU=1`); a Rust port
  on native IEEE-754 doubles should be faster on the FFT-heavy sign/keygen
  paths.
- There is no byte-level known-answer test against go-algorand today; the
  port needs — and leaves behind — a permanent oracle.
- algod-rust will diverge from go-algorand in more places over time. The
  project needs one register, one marker grammar and one checker so that
  the `algod-version-upgrade` skill, Phase 17 audits and human reviewers
  never mistake an intended difference for a parity bug, and so go-algorand
  maintainers can read and port what changed.

## Scope

### Facts that shape the design (verified in `crates/core/algo-falcon/falcon-c/`)

- `config.h:232` sets `FALCON_KG_CHACHA20 1`: keygen samples f, g through
  the ChaCha20 `prng` (rng.c) seeded from SHAKE256 — `rng.rs` is a
  prerequisite for both sign and keygen.
- `FALCON_FPEMU=1`. The emulated FP equals strict IEEE-754 binary64
  round-to-nearest-even for `add/sub/mul/div/sqrt/rint/floor/trunc/of/
  scaled/lt`, **but `fpr_expm_p63` (`fpr.c:1287`) is a 64-bit fixed-point
  routine that differs from the FPNATIVE double Horner form** — the Rust port
  must use the integer `expm_p63` on its native-f64 path.
- keygen/sign internals are `static` in C; per-function differential tests
  need a test-only shim translation unit (`falcon-c-test/shims.c`, feature
  `c-internals-test`).
- Go is not installed on the Windows development machine; the Go vector
  tool runs in CI, the vendored C is the local stand-in generator, and CI
  proves C == Go.

### Decisions

- Default backend: **Rust**. C stays available behind the default-on cargo
  feature `c-backend` and the `config.json` field `FalconBackend: "c"`.
- The option lives in `config.json` (`algo_config::Local`), as the first
  algod-rust-only field (single `(0, default)` `VersionedDefault` entry).
- Native `f64` only (no port of the integer-emulated FP).
- Staged PRs, one sub-issue per stage, one open PR at a time.

### Stages

| Stage | Issue | Deliverable |
|---|---|---|
| 1 | #1927 | `docs/DIVERGENCES.md`, `DIVERGENCE DIV-NNN` markers, `scripts/check_divergences.py` (+ test, CI, `make lint`), CLAUDE.md rule, this proposal, Epic-31 |
| 2 | #1928 | Vector corpus `tests/fixtures/falcon/vectors.jsonl`, `examples/gen_vectors.rs`, `tools/falcon-vector-capture` (Go), `falcon-vectors.yml`, `conformance-parity.yml` step, `tests/falcon_vectors.rs` |
| 3 | #1929 | `FalconBackend` enum + write-once global + `*_with` API, `c-backend` feature, `Local.FalconBackend`, startup wiring, `algokey-rust --falcon-backend` |
| 4 | #1930 | `src/rs/shake256.rs` |
| 5 | #1931 | `src/rs/codec.rs` |
| 6 | #1932 | `src/rs/fpr.rs` + `falcon-c-test/shims.c` (`c-internals-test`) |
| 7 | #1933 | `src/rs/fft.rs` |
| 8 | #1934 | `src/rs/vrfy.rs`, `src/rs/common.rs` |
| 9 | #1935 | verify path + `det1024` verify/convert/salt — **Milestone A** (Rust verifies the corpus); fuzz target |
| 10 | #1936 | `src/rs/rng.rs`, `src/rs/sign.rs`, `sign_dyn_finish`, `det1024` sign — **Milestone B** (byte-identical signatures) |
| 11 | #1937 | `src/rs/keygen.rs`, default flipped to Rust — **Milestone C** (full parity) |
| 12 | #1938 | criterion benchmarks, `docs/BENCHMARKS.md`, optimisation pass |
| 13 | #1939 | `docs/falcon/FALCON_RUST_PORT.md`, DIV-001 finalised, `PHASE21_VALIDATION.md`, Phase 17 rows, licensing audit rows |

### Porting rules

- Keep the C structure and names (`logn` parameters, `tmp` arenas with
  explicit offsets) so the Rust can be diffed side by side with the C.
- All C unsigned arithmetic becomes `wrapping_*` / explicit casts;
  `clippy::arithmetic_side_effects` is denied on `src/rs/`.
- Same numeric error codes as C inside the existing `FalconError` variants.
- Floating point: only `+ - * / sqrt` on `f64`, `rint` as the FPNATIVE
  integer trick, integer `expm_p63`, constants as `u64` bit patterns.
- Secret-dependent code keeps the C constant-time constructs.
- Every new Rust file: AGPL header with the third-party attribution comment
  (Falcon Project 2017–2019 MIT; Algorand, Inc. `det1024` MIT) on top.

## Success criteria

- [ ] All stage issues #1927–#1939 closed.
- [ ] Corpus byte-identical when generated by go-algorand (CI
      `falcon-vectors.yml`), by the vendored C, and by the Rust port.
- [ ] `cargo test -p algo-falcon` green with default features,
      `--no-default-features`, and `--features c-internals-test`;
      workspace suite, `clippy -D warnings`, `fmt`, MSRV check green.
- [ ] Node starts with `FalconBackend` unset (rust) and `"c"`; fails loudly
      on an unknown value.
- [ ] `cargo bench -p algo-falcon` table published in
      `docs/falcon/FALCON_RUST_PORT.md` and `docs/BENCHMARKS.md`.
- [ ] `python3 scripts/check_divergences.py` passes with DIV-001 `landed`.
- [ ] `docs/PHASE21_VALIDATION.md` evidence map written; Phase 17 falcon rows
      point at the new tests; `python3 scripts/phase17_parity_delta.py check`
      exits 0.
- [ ] `gh issue list --label "phase:21" --state open` empty before the epic
      closes.

## Non-goals

- Changing anything on the wire or in consensus: keys, signatures, headers,
  salt versions and error codes stay byte-identical (proven, not assumed).
- Falcon-512 or non-deterministic Falcon: only `det1024` is used on-chain.
- A port of the integer-emulated floating point (`FALCON_FPEMU`); the
  native-`f64` path is proven equal by the corpus and differential tests.
- Constant-time *guarantees* beyond what the C offers (the C constructs are
  kept; determinism is the tested property).
