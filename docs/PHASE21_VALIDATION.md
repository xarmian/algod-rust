# Phase 21 Validation — pure-Rust Falcon-1024 `det1024` port (DIV-001)

_Completed: 2026-10-14_

Phase 21 replaced the cgo-style FFI wrapper around the vendored Falcon C
library with a pure-Rust implementation, kept the C as a runtime-selectable
backend, introduced a go-algorand-generated vector corpus as the permanent
parity oracle, and created the divergence register that records this as
algod-rust's first intended difference from go-algorand.

Evidence map for [`docs/PHASE21_PROPOSAL.md`](PHASE21_PROPOSAL.md) and
[`docs/epics/Epic-31-Falcon-Rust-Port.md`](epics/Epic-31-Falcon-Rust-Port.md).
Tracking epic: [#1926](https://github.com/xarmian/algod-rust/issues/1926).
Register entry: `DIV-001` in [`docs/DIVERGENCES.md`](DIVERGENCES.md).
Engineering notes for go-algorand developers:
[`docs/falcon/FALCON_RUST_PORT.md`](falcon/FALCON_RUST_PORT.md).

## Criteria and evidence

| Criterion | Evidence |
|---|---|
| Corpus byte-identical from go-algorand, the vendored C and the Rust port | `crates/core/algo-falcon/tests/fixtures/falcon/vectors.jsonl` (113 records). `.github/workflows/falcon-vectors.yml` regenerates it with `tools/falcon-vector-capture` (Go, go-algorand `crypto` at `v5.0.3-stable`, `make libsodium`) and `git diff --exit-code`s it — green on PRs #1941, #1942, #1944. `cargo run -p algo-falcon --example gen_vectors -- --backend c` and `--backend rust` both reproduce the file byte for byte (`fc /b`). |
| Keys, signatures, CT forms, verify decisions identical on every backend | `tests/falcon_vectors.rs` (6 tests × every backend; `conformance-parity.yml` step θ); `all_backends_agree_on_keygen_sign_verify`; the go-algorand hard-coded `falcon_verify` vector (`data/transactions/logic/crypto_test.go`) in the corpus. |
| Every ported module bit-identical to the C it replaces | `cargo test -p algo-falcon --features c-internals-test`: 66 lib tests incl. differential tests for SHAKE256, every codec, 200k fpr operations (+ shimmed `rint/floor/trunc/…` over the full double range), FFT/poly ops, NTT/verify/compute_public/complete_private, hash_to_point, is_short, ChaCha20 PRNG, samplers, `sign_dyn` on real keys, and every NTRU-solver level with the arena compared after each step (`keygen_steps_match_c`), `falcon_inner_keygen` for logn 1..=9 and 1024. |
| Pure-Rust build needs no C compiler | `cargo test -p algo-falcon --no-default-features` (42 lib + 6 corpus tests) and `cargo check -p algo-falcon --no-default-features`. |
| Backend selectable at runtime | `config.json` `FalconBackend` (`"rust"` default, `"c"`), applied by `bin/algod-rust/src/falcon_backend.rs` after every config load, failing startup on unknown values; `algokey-rust --falcon-backend`; `algo_falcon::set_falcon_backend` write-once semantics (`set_falcon_backend_is_write_once_and_idempotent`). |
| Bit-parity beyond the corpus (#1948) | `tests/backend_parity.rs` + `falcon-parity.yml`. Heavy run on the final code, 2026-10-14, `--release`, 202 s: **1,200 seeds** (keys, and signatures / CT forms / salt versions for 10 message lengths each — 12,000 signatures — all byte-identical between the Rust and C backends), keygen for 15 seed lengths, **1,500,000 mutated verify inputs** with the full `Result<bool, FalconError>` identical on both backends (29,112 accepts; 1,220,473 plain rejects; 167,031 signature-size errors; 83,384 public-key-size errors), **300,000** random-byte strings through CT conversion and salt-version extraction identical (including every error code), and malformed private keys failing identically. |
| Live mixed-cluster state-proof soak (#1948) | `ops/mixed-cluster/scripts/stateproof-soak.sh` (3 go-algorand + 1 algod-rust node, fresh genesis, `FalconBackend` unset = `rust`), 2026-10-14. The first state proof (round 512) was committed in block 560, which carries one `stpf` transaction on all four nodes with **byte-identical block bytes**. Block hashes for rounds 512..568 (57 rounds) are identical on all four nodes, and header `spt.n` advanced to 768 identically. The Rust node accepted 2 Falcon signatures from go-algorand peers (verified by the Rust backend), signed its own state-proof message with the Falcon key imported from `goal`, and built and submitted a StateProofTx. 0 Falcon errors in its log. The 3 Go nodes serve one identical `/v2/stateproofs/512` payload. The 4 Go warnings are benign: genesis-era `lookback round 0` voters and a duplicate-in-pool broadcast. Known gap: algod-rust returns 404 on `/v2/stateproofs/{round}` although it holds the committed proof (not a Falcon issue, tracked in #1952). Raw data: `docs/falcon/soak-data/`. |
| Consumers unchanged | `cargo test -p algo-config -p algo-consensus-crypto -p algo-avm -p algo-validate -p algod-rust -p algokey-rust` and `algo-ledger --test pq_falcon_e2e_test` green on the Rust default. |
| Benchmarks published | `cargo bench -p algo-falcon` (`benches/falcon_bench.rs`); clean comparison on two platforms with raw data in `docs/falcon/BENCHMARK_RUST_VS_C.md` (sign ~15–16× and keygen ~1.9–2.2× faster in Rust; verify at parity, compiler-dependent); `scripts/falcon_bench_report.py` regenerates the tables; row in `docs/BENCHMARKS.md`. |
| Divergence register in force | `docs/DIVERGENCES.md` (DIV-001 `landed`), `DIVERGENCE DIV-001:` markers at every site, `scripts/check_divergences.py` in `license-compliance.yml` (`divergence-register` job) and `make lint`; CLAUDE.md + skill rules. |
| Phase 17 map still complete | Falcon rows in `docs/phase17/parity_crypto.md` / `parity_txn_logic.md` link the corpus tests; `python3 scripts/phase17_parity_delta.py check` exits 0. |
| Licensing | `docs/LICENSING_AUDIT.md` / `docs/LICENSING.md` rows for `src/rs/*`, `falcon-c-test/`, generators; `check-license-headers.py` green. |

## Findings worth recording

- `FALCON_KG_CHACHA20` is **disabled** in the vendored `config.h` (the
  `#define` is inside a comment): key generation samples from SHAKE256
  directly. An early design note had it enabled; the step-level
  differential test against `mkgauss` caught the discrepancy immediately.
- The C's emulated `fpr_expm_p63` is not bit-identical to its own
  native-double branch, and the emulated `trunc(2^63)` is 0; both are
  ported from the emulated branch (see `rs/fpr.rs`).
- Compressed-mode signing and verification hash the message with
  `hash_to_point_vartime`; the constant-time variant is used only for CT
  signatures.

## Known limitations / sign-offs

- Constant-time properties are inherited from the C's constructs and not
  separately audited; determinism/bit-identity is the tested property.
- The expanded-key signing path, padded/CT signing and the OS entropy
  source are not ported (unreachable from `det1024`).
- A live mixed-cluster run with state proofs / PQ transactions on the Rust
  default is tracked by #1937's consensus-critical criterion and the
  nightly soak workflows.
