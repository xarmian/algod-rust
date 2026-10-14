# Intended divergences from go-algorand

algod-rust's premise is byte-level, behaviour-level parity with go-algorand
at the pinned reference version. This file is the **single register of the
places where algod-rust deliberately differs** from go-algorand — in how it
is built, implemented or configured — while staying wire- and
consensus-compatible. It exists for three readers:

1. **Parity sweeps, version-upgrade passes and Phase 17 test-parity audits**
   (human or AI): a difference listed here is *intended*. Do not file it as
   a bug, do not "fix" it back to the go-algorand shape, and do not classify
   its tests as gaps. If an upstream change touches an area listed here,
   re-verify the entry's "How parity is proven" evidence instead.
2. **algod-rust developers** adding a new deliberate difference: add a row
   and a section here **in the same PR**, put a `DIVERGENCE DIV-NNN: <why>`
   marker comment at every code site that embodies it, and keep
   `python3 scripts/check_divergences.py` green (it runs in CI and
   `make lint`).
3. **go-algorand maintainers**: each `### DIV-NNN` section below is written
   so that you can see exactly what changed relative to your tree, what
   stayed identical, which test proves it, and how you could port it if you
   like it.

## Rules

- **Scope.** A divergence is any place where algod-rust, *on purpose*, is
  not a straight translation of go-algorand: a different implementation of
  the same algorithm, an algod-rust-only configuration field, a different
  build/dependency choice with observable consequences, a deliberately
  different operational default. Bugs, not-yet-ported features and
  out-of-scope subsystems are **not** divergences — those are tracked as
  issues and in `docs/PHASE17_TEST_PARITY.md`.
- **Wire and consensus compatibility is not negotiable.** A divergence must
  not change what goes on the wire, what a block hashes to, or what a
  transaction/program evaluates to. The "Wire / consensus impact" column
  must say `none` and the section must say how that is proven.
- **IDs** are `DIV-001`, `DIV-002`, … allocated sequentially and never
  reused. A row may be added as `reserved` before the code lands.
- **Status** is one of `reserved` (id allocated, nothing landed),
  `in-progress` (partially landed), `landed`, `retired` (no longer differs;
  keep the row for history).
- **Marker grammar.** `DIVERGENCE DIV-NNN: <one line>` inside any comment
  (`//`, `///`, `#`, `/* */`, …). `grep -rn "DIVERGENCE DIV-"` lists every
  site. `scripts/check_divergences.py` asserts that every marker has a
  register entry, every non-`reserved` entry has at least one marker, ids are
  sequential, and every marker has a description.
- **Each section** answers, for a go-algorand reader: what changed, what is
  identical, why, how parity is proven (tests, fixtures, CI jobs), how to
  switch back (if there is a switch), and how to port it to go-algorand.

## Register

| ID | Title | Area | Status | Since | Wire / consensus impact | algod-rust files | Upstream files | Proof |
|---|---|---|---|---|---|---|---|---|
| DIV-001 | Falcon-1024 `det1024` implemented in pure Rust; vendored C kept as a runtime-selectable backend (`config.json` `FalconBackend`) | crypto / state proofs / PQ accounts / AVM `falcon_verify` | landed | 2026-10-14 | none (bit-identical keys, signatures, verify decisions, CT conversion) | `crates/core/algo-falcon/`, `crates/node/algo-config/src/lib.rs` (`FalconBackend`), `bin/algod-rust/src/commands/node.rs`, `crates/tools/algokey-rust` | `crypto/falconWrapper.go`, module `github.com/algorand/falcon` v0.1.0 (`falcon.go`, `deterministic.c`, Pornin's reference C) | Go-generated vector corpus diffed in CI, per-function differential tests vs the vendored C, fuzz target (epic #1926) |

## Entries

### DIV-001 — Falcon-1024 `det1024` in pure Rust, C kept as a selectable backend

**Status:** landed — the pure-Rust backend is the default since Phase 21
stage 11 (#1937); epic
[#1926](https://github.com/xarmian/algod-rust/issues/1926),
`docs/PHASE21_PROPOSAL.md`. Long-form engineering notes:
`docs/falcon/FALCON_RUST_PORT.md`.

**What go-algorand does.** `crypto/falconWrapper.go` wraps the Go module
`github.com/algorand/falcon` v0.1.0, which is Thomas Pornin's reference
Falcon C implementation plus Algorand's deterministic `det1024` layer
(`deterministic.c`: seed-derived keygen via SHAKE256, deterministic signing
with a 1-byte salt version instead of a 40-byte random salt, header `0xBA`
for compressed and `0xDA` for CT signatures, `FALCON_FPEMU=1` emulated
floating point; `FALCON_KG_CHACHA20` is left disabled so key generation
samples directly from SHAKE256). The C is called through cgo.

**What algod-rust does instead.** The same `det1024` algorithm is
implemented in Rust (`crates/core/algo-falcon/src/rs/`), module for module
after the C files (`shake.c`, `codec.c`, `fpr.h/.c`, `fft.c`, `vrfy.c`,
`common.c`, `rng.c`, `sign.c`, `keygen.c`, `falcon.c`, `deterministic.c`).
The vendored C stays in the crate behind the cargo feature `c-backend`
(default on) and is selectable at runtime through the algod-rust-only
`config.json` field `FalconBackend` (`"rust"`, the default, or `"c"`), the
first configuration key that has no go-algorand counterpart.

**What is identical.** Every byte: public/private key encoding, the
compressed and CT signature encodings, the salt-version scheme, the accept
and reject decisions (including every malformed-input rejection) and the
numeric error codes. Floating point uses native IEEE-754 binary64 for
`+ - * / sqrt` (which Falcon's emulated FP is designed to match bit for bit)
and the C library's own 64-bit fixed-point `fpr_expm_p63` (the one routine
whose native-double variant is *not* bit-identical).

**Why.** Remove the only non-Rust code from the consensus path (no C
toolchain or cgo-equivalent needed to build a node), make the signing path
faster than emulated-FP C, and give the port a permanent oracle.

**How parity is proven.** (1) A vector corpus
(`crates/core/algo-falcon/tests/fixtures/falcon/vectors.jsonl`: seeds →
keys, messages → compressed + CT signatures, negative cases, and
go-algorand's own hard-coded `falcon_verify` vector) generated by a Go tool
that links go-algorand's `crypto` package (`tools/falcon-vector-capture`),
regenerated and `git diff --exit-code`-ed in CI; the same corpus is
reproduced byte-for-byte by the vendored C and by the Rust port. (2)
Per-function differential tests of every ported module against the C
internals (feature `c-internals-test`). (3) A differential fuzz target for
`falcon_verify`. (4) The existing go-algorand-ported unit tests run under
both backends.

**How to switch back.** `"FalconBackend": "c"` in `config.json`
(requires a build with the default `c-backend` feature). `algokey-rust
--falcon-backend c`.

**How go-algorand could port it.** The Rust modules keep the C function
names and structure, so a Go port can be reviewed side by side against
`github.com/algorand/falcon`'s C. The corpus is the acceptance test; the
one trap is floating point: Go's `float64` is strict IEEE-754 for
`+ - * / sqrt` (no FMA contraction on amd64/arm64 when written as separate
statements), `math.Sqrt` is correctly rounded, and `expm_p63` must be the
fixed-point integer version. See `docs/falcon/FALCON_RUST_PORT.md` once it
lands.
