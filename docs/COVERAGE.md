# Test Coverage

How coverage is measured, reported, and gated in algod-rust, and the practices
we expect from contributors. Introduced by issue #440.

## Why we measure coverage

algod-rust is consensus-critical software. An untested branch in the AVM
interpreter, ledger apply logic, or transaction validation is not just an
ordinary bug risk — it is a potential chain fork. Coverage does **not** prove
correctness (the conformance harness against go-algorand does that); it proves
that the test suite actually *reaches* the code. The two are complementary:

- **Fixtures / conformance** — prove behavior matches go-algorand
  byte-for-byte for the inputs we have.
- **Coverage** — exposes which code paths no fixture or unit test exercises,
  so we know where conformance evidence is missing and can prioritize fixture
  generation in `algo-fixtures`.

## Tooling

We use [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) —
source-based LLVM instrumentation, the current best practice for Rust. It is
accurate at region (branch) granularity, covers unit, integration, and doc
tests, and works on both Linux and Windows. We deliberately do not use
ptrace-based tools (e.g. older `tarpaulin` modes): they are Linux-only and
less accurate.

### Running locally

```bash
cargo install cargo-llvm-cov          # one-time; also: rustup component add llvm-tools-preview
make coverage                          # HTML report, opens in browser
make coverage-lcov                     # lcov.info for editor integrations (e.g. Coverage Gutters)
```

Both targets instrument the default `cargo test --workspace` targets — the
Docker-backed e2e suites (localnet, mixed-cluster, relay) are feature/env-gated
and excluded, so no go-algorand binaries or libsodium are needed.

**Windows note:** run from a shell where `cargo` is on PATH (the MSVC
developer environment via `vcvarsall.bat` if your setup requires it). Golden
fixture tests require LF checkouts — see `.gitattributes`; a CRLF-mangled
checkout fails `block_json_test` regardless of coverage tooling.

## CI pipeline

`.github/workflows/coverage.yml` runs on every PR and push to `main`:

1. `cargo llvm-cov --workspace --release` produces `lcov.info` (test/bench
   source files are excluded from the report — they are scaffolding, not
   shipped code).
2. The LCOV file and a browsable HTML report are attached as workflow
   artifacts (14-day retention), so coverage is inspectable even without
   Codecov.
3. The LCOV file is uploaded to [Codecov](https://codecov.io), which posts a
   PR comment with the coverage diff (patch coverage, per-component breakdown,
   changed files) and drives the status checks below.

> **Setup:** the repository needs a `CODECOV_TOKEN` Actions secret (Codecov
> requires a token for non-fork uploads). Until it is configured, the workflow
> still runs and publishes artifacts; only the Codecov comment/checks are
> skipped.

## Thresholds and gating (`codecov.yml`)

| Check | Scope | Rule |
|---|---|---|
| `project` | `crates/core`, `crates/node`, `bin` | overall coverage may not drop more than **0.5%** |
| `patch` | `crates/core`, `crates/node`, `bin` | new/changed lines must be **≥ 80%** covered |
| `tooling` | `crates/tools` | reported, **informational only** (never blocks) |

Components (`core`, `node`, `bin`, `tools`) give a per-area breakdown in the
PR comment and the Codecov UI.

### Why not 100%?

100% line coverage is not the goal and chasing it produces low-value tests
that ossify implementation details. The goals, in order:

1. **Consensus-critical crates high** — `algo-avm`, `algo-ledger`,
   `algo-validate`, `algo-codec`, `algo-agreement`, `algo-consensus-crypto`
   should trend toward **≥ 85–90%** line coverage, with both success *and*
   rejection paths of every rule exercised.
2. **Patch coverage protected** — every PR's new code is at least 80% covered,
   so debt never grows silently.
3. **Glue can be lower** — CLI argument plumbing, error `Display` impls, and
   tooling do not warrant the same rigor.

## Best practices for contributors

- **Every new opcode, REST handler, or ledger rule lands with tests for both
  the success path and the rejection/error paths.** For AVM work, cover the
  version-gating boundary (opcode available at vN, rejected at vN−1).
- **Prefer conformance fixtures over hand-written expectations** where
  go-algorand output can be captured — coverage tells you *where* a fixture is
  missing; `make fixtures` / `algo-fixtures` produce it.
- **Read the region (branch) numbers, not just line coverage** — a line with a
  `?`/`match`/short-circuit can be "covered" while half its branches never
  ran. The HTML report shows uncovered regions inline.
- **Coverage exclusions are exceptional.** Use
  `#[cfg_attr(coverage_nightly, coverage(off))]` (or an entry in
  `codecov.yml` `ignore`) only for genuinely unreachable/uninstrumentable code
  (e.g. `unreachable!` arms mandated by exhaustiveness), and justify every
  exclusion in review.
- **Don't write tests to move the number.** If a threshold blocks a PR, the
  right fix is a test that pins real behavior (ideally against a go-algorand
  fixture), not a test that merely executes lines.
- **A dropped threshold is a conversation, not a workaround.** If gating is
  wrong for a legitimate change (e.g. large generated code), adjust
  `codecov.yml` in the same PR with a rationale in the description.
