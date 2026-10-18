# Falcon-1024 `det1024` in Rust — port notes (DIV-001)

Written for go-algorand developers and for anyone auditing parity. It
describes exactly how algod-rust's pure-Rust deterministic Falcon-1024
differs from — and stays byte-identical to — the C library go-algorand links
through cgo (`github.com/algorand/falcon` v0.1.0, `crypto/falconWrapper.go`),
how that identity is proven, how to regenerate the evidence, and how to port
the result to Go if you want it. Register entry: `DIV-001` in
[`docs/DIVERGENCES.md`](../DIVERGENCES.md); epic #1926 (Phase 21).

## What changed, in one paragraph

Nothing on the wire. Keys derived from a seed, compressed signatures, CT
(constant-time-decodable) signature forms, the salt-version byte, every
accept/reject decision for malformed input, and the numeric error codes are
all identical to the C library's. What changed is the implementation
language: `crates/core/algo-falcon/src/rs/` is a module-for-module port of
the vendored C (`crates/core/algo-falcon/falcon-c/`), and it is the default
backend. The C stays in the crate behind the default-on cargo feature
`c-backend` and is selectable at runtime by the algod-rust-only
`config.json` key `FalconBackend` (`"rust"` default, `"c"`) and
`algokey-rust --falcon-backend`.

## Module map

| C file (vendored) | Rust module | What it holds |
|---|---|---|
| `shake.c` | `rs/shake256.rs` | SHAKE256 with Falcon's inject/flip/extract context semantics |
| `codec.c` | `rs/codec.rs` | modq / trim_i8 / trim_i16 / comp encoders and decoders, bit-width tables |
| `fpr.h`, `fpr.c` | `rs/fpr.rs`, `rs/fpr_tables.rs` | floating-point layer (see below), FFT constant tables as bit patterns |
| `fft.c` | `rs/fft.rs` | FFT/iFFT and polynomial operations in FFT representation |
| `vrfy.c` | `rs/vrfy.rs`, `rs/ntt_tables.rs` | arithmetic mod q = 12289, NTT, verify_raw, compute_public, complete_private |
| `common.c` | `rs/common.rs` | hash_to_point (vartime and ct), is_short, is_short_half |
| `rng.c` | `rs/rng.rs` | the ChaCha20 PRNG used by the signing sampler |
| `sign.c` | `rs/sign.rs` | Gaussian samplers, dynamic-tree ffSampling, sign_dyn |
| `keygen.c` | `rs/keygen.rs`, `rs/keygen_tables.rs` | f/g sampling, big-integer RNS tower, NTRU solver |
| `falcon.c` | `rs/falcon.rs` | key encoding, sign_dyn_finish (compressed), verify (compressed), error codes |
| `deterministic.c` | `rs/det1024.rs` | Algorand's deterministic layer: seeded keygen, fixed salt, 0xBA/0xDA formats, CT conversion |
| (FFI) | `backend/c.rs` | the original cgo-equivalent bindings, now one of two backends |

Only what `det1024` reaches is ported: the expanded-key signing path
(`expand_privkey`, `sign_tree`), padded and CT-format *signing*, and the
OS entropy source are not reachable from the deterministic API and were
left out. The C function names, loop shapes and operation order are kept so
the two can be read side by side; the Rust spells out every place the C
relies on unsigned wraparound (`wrapping_*`) or truncating casts.

## Floating point: why it is bit-identical

The vendored C is built with `FALCON_FPEMU=1`, Pornin's integer emulation of
IEEE-754 binary64 with round-to-nearest-even. The Rust uses native `f64`.
These agree because:

- Rust's `+ - * /` and `f64::sqrt` are correctly rounded on every target,
  Rust never contracts `a*b + c` into a fused multiply-add, and x86-64 uses
  SSE2 (no x87 extended precision). Falcon never reaches subnormals,
  infinities or NaNs. This is exactly the discipline the C's own
  `FALCON_FPNATIVE` branch assumes.
- **Three things are deliberately *not* taken from the native branch**, each
  proven by the differential tests:
  1. `fpr_expm_p63` (the exponential feeding the Gaussian sampler) is the
     emulated 64-bit fixed-point evaluation from `fpr.c`. The native
     branch's double Horner form is **not** bit-identical, and a one-bit
     difference there changes signatures.
  2. `fpr_rint`, `fpr_floor`, `fpr_trunc` are the emulated bit-level
     algorithms, so they agree with the C on every input including values
     outside the `i64` range, where a native cast is
     implementation-defined (and `expm_p63(x, 1.0)` relies on
     `trunc(2^63) == 0`).
  3. Every constant and both FFT tables are `f64::from_bits` of the
     emulated branch's bit patterns, never decimal literals.

A Go port would need the same three rules. Go's `float64` arithmetic is
strict IEEE-754 (the compiler may fuse `x*y + z` on some architectures
**unless** the intermediate is explicitly converted: write `float64(x*y) + z`
or keep operands in separate statements), `math.Sqrt` is correctly rounded,
and `math.Float64frombits` gives the constants.

### Where the two are *not* bit-identical, and why it cannot matter

An adversarial hunt (issue #2016, `src/rs/fpr_adversarial.rs`, run with
`--features c-internals-test`) feeds the Rust `fpr` layer and the emulated C
about 2.5 million operand pairs built to hit what random operands never do:
exact round-to-nearest-even ties (half-ulp additions, 54-bit products,
exact and near-exact quotients), perfect squares and their neighbours, huge
exponent gaps (sticky bits), mantissa patterns around the round bit, the
`i64` boundaries through `fpr_of`, and exponents from the subnormal edge to
the infinity encoding. Result:

- **Every operation on normal finite operands with a normal finite result is
  bit-identical** (add, sub, mul, div, sqrt, sqr, inv, half, double, neg, lt,
  rint, floor, trunc, of). No in-domain mismatch exists; the test fails if one
  ever does.
- The mismatches that exist all lie **outside** that domain, and
  `tests/fixtures/falcon/fpr_divergences.jsonl` records 198 of them as test data
  (operands, Rust result, C result, class); `committed_divergences_are_still_divergent_and_out_of_domain`
  replays them so a change on either side is noticed:

  | class | Rust (native `f64`) | C (`FALCON_FPEMU`) |
  |---|---|---|
  | underflow | subnormal result | flushed to zero |
  | subnormal operand | treated as the tiny number it is | treated as zero (flush) |
  | overflow | `+-inf` | an out-of-range exponent (the emulation has no infinity) |
  | non-finite operand | `inf`/`NaN` propagation | the encoding is just a huge number |
  | zero sign | `fpr_div(0, negative) = -0`, `fpr_half(-0) = -0` | `+0` |

- **Falcon cannot reach them.** `falcon_keygen_and_signing_stay_inside_the_bit_identical_domain`
  instruments every arithmetic call in a debug build and runs keygen and
  signing: across ~10^9 operations there is no subnormal and no non-finite value,
  no `fpr_div(0, negative)` and no `fpr_half(-0)`, and the exponents span about
  2^-572 .. 2^+572 (keygen's big-integer to floating-point conversions),
  roughly 450 binades short of both limits (2^-1022, 2^1023), so neither
  flush-to-zero nor the missing infinity can be triggered.

This is an empirical argument over keys and messages, not a proof; the
signature-level differential tests (`backend_parity.rs`, scalable through
`FALCON_PARITY_*`) and the go-algorand-generated corpus cover the whole
algorithm end to end.

## Key generation randomness

`FALCON_KG_CHACHA20` is **off** in the vendored `config.h` (the `#define` is
inside a comment). Key generation therefore draws its Gaussian samples
directly from the SHAKE256 context seeded with the 32-byte seed, 8
little-endian bytes per draw. Only the signing sampler uses the ChaCha20
PRNG (`prng_init` from 56 SHAKE bytes, 8 blocks per refill). Getting this
wrong changes every key derived from a seed; the port's step-by-step tests
caught exactly that during development.

## Scratch memory

`keygen.c` works over one `uint32_t` arena with pointer arithmetic,
`memmove`s regions over each other and reinterprets dead integer regions
as floating point. The Rust keeps the same arena and the same offsets for
every integer region (so the big-integer data flow, including every move,
is the C's) and gives the floating-point vectors and the `k` vector their
own allocations, which the C's data flow permits (those regions are never
read back through a different type). `sign.c`'s `fpr` arena is replaced by
one allocation per named buffer with the C's copies replicated. Verification
allocates its small scratch per call. None of this changes any computed
value.

## How identity is proven

1. **Corpus** — `crates/core/algo-falcon/tests/fixtures/falcon/vectors.jsonl`:
   12 seeds → keys; 6 messages per seed → compressed and CT signatures and
   salt version; 28 negative cases (bad header, CT header on the compressed
   path, cleared salted bit, wrong salt version, flipped body byte,
   truncations, trailing byte, empty, header-only, oversized, all-zero
   body, wrong key, wrong message) that must be rejected; and the signature
   go-algorand hard-codes in `data/transactions/logic/crypto_test.go`. Three
   generators define it verbatim and must agree byte for byte:
   `tools/falcon-vector-capture` (Go, linking go-algorand's `crypto`
   package — run in CI by `.github/workflows/falcon-vectors.yml` against a
   fresh `v5.0.3-stable` clone and `git diff --exit-code`'d),
   `cargo run -p algo-falcon --example gen_vectors -- --backend c`, and
   `--backend rust`. `tests/falcon_vectors.rs` runs the corpus against
   every compiled backend (`conformance-parity.yml` step θ).
2. **Per-module differential tests** against the C internals
   (`cargo test -p algo-falcon --features c-internals-test`): random and
   adversarial inputs through the Rust and the C (`falcon_inner_*`
   symbols, plus `static` functions re-exported by the test-only shim
   translation units in `falcon-c-test/`), compared bit for bit — SHAKE
   streams, every codec, 200k floating-point operations, every FFT and
   NTT routine, hash_to_point, the samplers, `sign_dyn` on real keys, and
   every level of the NTRU solver with the arena contents compared after
   each step.
3. **Backend agreement** — `all_backends_agree_on_keygen_sign_verify` and
   the existing go-algorand-ported unit tests run on the default backend;
   `algokey-rust` end-to-end tests cover the CLI.

## Benchmarks

Full methodology, both platforms, raw data and interpretation:
[`BENCHMARK_RUST_VS_C.md`](BENCHMARK_RUST_VS_C.md). In short (Criterion
medians, `cargo bench -p algo-falcon`):

| Operation | Windows / MSVC | Linux / gcc |
|---|---|---|
| sign (32 B / 1000 B) | Rust **16.5× / 16.3×** faster | Rust **15.2× / 14.7×** faster |
| keygen | Rust **2.20×** faster | Rust **1.85×** faster |
| verify (32 B / 1000 B) | Rust 1.32× / 1.26× faster | **C 7% / 8% faster** (essentially parity) |
| compressed → CT | C 12% faster (~0.5 µs) | Rust 4% faster |

The signing/keygen gain is the emulated floating point in the C; verification
is pure integer work, so there the winner is decided by the C compiler.

## Regenerating the evidence

```bash
# corpus from the vendored C / the Rust port (no Go needed)
cargo run -p algo-falcon --example gen_vectors -- --backend c
cargo run -p algo-falcon --example gen_vectors -- --backend rust
# corpus from go-algorand (Linux; `make libsodium` in ../go-algorand first)
cd tools/falcon-vector-capture && go run .
# differential tests
cargo test -p algo-falcon --features c-internals-test
# pure-Rust build (no C compiler at all)
cargo test -p algo-falcon --no-default-features
```

## Switching backends

- Node: `"FalconBackend": "c"` in `config.json` (requires a build with the
  default `falcon-c-backend` feature). The value is applied once, right
  after `config.json` is loaded, before any Falcon operation; an unknown
  value or a backend missing from the build is a startup error.
- `algokey-rust --falcon-backend c`.
- Library: `algo_falcon::set_falcon_backend` (write-once) or the
  `*_with(backend, …)` variants.

## Porting this to Go

The Rust modules follow the C one function at a time, so a Go port can be
reviewed against either. The corpus is the acceptance test: a port is
correct when `go run .` in `tools/falcon-vector-capture` — pointed at the
new implementation — produces the committed file byte for byte, and the
differential approach (compare each module with the C through cgo while
porting) is what made this port converge quickly. Mind the three
floating-point rules above and the keygen randomness source; everything
else is integer arithmetic with explicit wraparound.
