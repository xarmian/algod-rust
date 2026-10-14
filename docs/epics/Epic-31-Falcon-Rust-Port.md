# Epic: Phase 21 — pure-Rust Falcon-1024 `det1024` port (DIV-001)

Tracks porting `crates/core/algo-falcon` from the vendored C library to pure
Rust with a runtime-selectable C backend, Go-generated parity vectors,
benchmarks, and the divergence register that records this as algod-rust's
first intended difference from go-algorand. GitHub epic issue:
[#1926](https://github.com/xarmian/algod-rust/issues/1926). Proposal:
`docs/PHASE21_PROPOSAL.md`. Register entry: `DIV-001` in
`docs/DIVERGENCES.md`.

## Stages (dependency order; one PR each)

- [ ] #1927 — stage 1: divergence register, markers, `check_divergences.py`, CLAUDE.md rule, proposal + this epic
- [ ] #1928 — stage 2: `det1024` vector corpus (Go tool in CI + C generator), `falcon_vectors.rs`, CI diff job
- [ ] #1929 — stage 3: `FalconBackend` abstraction, `c-backend` feature, `Local.FalconBackend`, startup wiring, algokey flag
- [ ] #1930 — stage 4: `src/rs/shake256.rs`
- [ ] #1931 — stage 5: `src/rs/codec.rs`
- [ ] #1932 — stage 6: `src/rs/fpr.rs` + test-only C shim (`c-internals-test`)
- [ ] #1933 — stage 7: `src/rs/fft.rs`
- [ ] #1934 — stage 8: `src/rs/vrfy.rs` + `src/rs/common.rs`
- [ ] #1935 — stage 9: verify path — Milestone A
- [ ] #1936 — stage 10: `src/rs/rng.rs` + `src/rs/sign.rs` — Milestone B
- [ ] #1937 — stage 11: `src/rs/keygen.rs` + default flipped to Rust — Milestone C
- [ ] #1938 — stage 12: benchmarks + optimisation pass
- [ ] #1939 — stage 13: docs close-out

## Epic-level acceptance criteria

- [ ] All stage issues closed.
- [ ] Corpus byte-identical from go-algorand (CI), vendored C, and Rust.
- [ ] `cargo test -p algo-falcon` green under default features,
      `--no-default-features`, `--features c-internals-test`; workspace
      gate green.
- [ ] Node honours `FalconBackend` (`rust` default, `c`), fails loudly on
      unknown values.
- [ ] Benchmarks published; `check_divergences.py` green with DIV-001
      `landed`; `docs/PHASE21_VALIDATION.md` written.
- [ ] Hard gate: `gh issue list --label "phase:21" --state open` empty before
      close.
