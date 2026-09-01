# algod-rust

Full Rust reimplementation of go-algorand — a production-grade Algorand node. Phases 0–6 are complete (conformance harness, block sync, AVM execution, ledger apply, validation, REST API, consensus participation). Phases 9–14 (go-algorand version-upgrade parity sweeps — `v4.6.0-stable` → `v4.7.0-stable` plus a new libp2p P2P transport, then `v4.7.0-stable` → `v4.7.2-stable`, then `v4.7.2-stable` → `v4.7.3-stable`, then `v4.7.3-stable` → `v4.7.4-stable`, then `v4.7.4-stable` → `v5.0.0-stable`) are also complete — see epics #650 and #678. Phase 15 (licensing and legal-framework compliance — AGPL-3.0-or-later as a whole with MIT-eligible files, `Algod DAO` as the legal entity) is also complete — see epic #732 and `docs/PHASE15_VALIDATION.md`. Phase 16 (node configuration and consensus-parameter parity audit — a from-scratch field-by-field audit of `config.json`/`ConsensusParams` against go-algorand, independent of any version-delta sweep) is also complete — see epic #745 and `docs/PHASE16_VALIDATION.md`. Phase 17 (go-algorand ↔ algod-rust **test parity** audit — every go-algorand test mapped to its algod-rust equivalent or explained as a gap, independent of any version-delta sweep) is in progress — see epic #830 and `docs/PHASE17_TEST_PARITY.md`. The reference pin is `v5.0.0-stable`. See `docs/PROJECT_SCOPE.md` for full scope, `docs/PHASE6_VALIDATION.md` for the Layer-9 consensus evidence map, `docs/PHASE10_VALIDATION.md` for the v4.7.0-stable version-upgrade/P2P-transport evidence map, `docs/PHASE11_VALIDATION.md` for the v4.7.2-stable sweep evidence map, `docs/PHASE12_VALIDATION.md` for the v4.7.3-stable sweep evidence map, `docs/PHASE13_VALIDATION.md` for the v4.7.4-stable sweep evidence map, `docs/PHASE14_VALIDATION.md` for the v5.0.0-stable sweep evidence map, `docs/PHASE15_VALIDATION.md` for the licensing-compliance evidence map, `docs/PHASE16_VALIDATION.md` for the configuration/consensus-parameter parity evidence map (which test/tool proves which criterion), and `docs/PHASE17_TEST_PARITY.md` for the full go-algorand↔algod-rust test-parity map.

## Shell Environment

- `cargo` and `go` are both in PATH.

## Reference Implementation

- **go-algorand source** is at `../go-algorand`, pinned to `v5.0.0-stable` (detached HEAD)
- Use this as the authoritative reference for AVM opcodes, consensus params, field indices, and protocol semantics
- Key reference files:
  - `data/transactions/logic/opcodes.go` — opcode table, version gating
  - `data/transactions/logic/eval.go` — opcode implementations (opTxn, opGlobal, opAppLocalGet, etc.)
  - `data/transactions/logic/resources.go` — reference resolution, resource tracking
  - `config/consensus.go` — consensus params per version (LogicSigVersion, MinTxnFee, etc.)
  - `protocol/consensus.go` — consensus version constants (ConsensusCurrentVersion = V41)
  - `ledger/simulation/simulator.go` — simulation engine (Simulator, check, evaluate)
  - `daemon/algod/api/server/v2/handlers.go` — REST API handlers

## CI Workflows (.github/workflows)

- **Building go-algorand binaries in CI requires the vendored libsodium fork.**
  go-algorand's `crypto` package links `crypto/libs/<os>/<arch>/lib/libsodium.a`
  via cgo. A plain `go build ./cmd/<tool>` fails with
  `sodium.h: No such file or directory`. Always run `make libsodium` in the
  go-algorand checkout first (needs `autoconf automake libtool build-essential`
  on the runner) before building any go-algorand command.
- **Path-filtered workflows fire on any commit touching their paths**, including
  unrelated lint/fmt sweeps. A red check on a PR may come from a workflow the
  feature never touched — read the failing job's logs before assuming the
  feature implementation is at fault, and fix the workflow itself if that is
  the actual failure.
- When adding a CI step, prefer the reference repo's own build entry points
  (Makefile targets, scripts/) over ad-hoc `go build`/`go test` invocations —
  they encode required native-dependency setup.

## Golden Fixtures

- Fixture files under `crates/**/fixtures/` are compared byte-for-byte against
  go-algorand output. `.gitattributes` pins them to LF checkout; on Windows
  checkouts made before that file existed, golden tests (e.g.
  `block_json_test`) fail on CRLF only — re-checkout the fixtures rather than
  "fixing" the encoder. Never let editors or autocrlf rewrite fixture bytes.

## Simulation EvalDelta-on-Error Semantics

- go-algorand's simulate endpoint reports a **partial** EvalDelta for a
  transaction that rejects/errors only when that failure genuinely fails the
  outer transaction (approval program reject/error → `evalError != nil` at
  `AfterTxn` → the tracer's `saveEvalDelta`/`omitEvalDelta` substitutes the
  per-opcode-saved delta for the real, empty `ApplyData.EvalDelta`).
- **ClearState is the exception**: go-algorand swallows a ClearState
  program's `logic.EvalError` and never fails the outer transaction for it
  (`ledger/apply/application.go`) — clearing out is always allowed — so a
  rejected/erroring ClearState program's `ApplyData.EvalDelta` stays empty in
  the real ledger *and* in simulate, unlike approval programs. Don't
  "fix" `run_clear_state_program`'s empty-on-error result by analogy with
  `run_approval_program` — it's already correct.

## Licensing

- algod-rust as a whole is a modified work based on go-algorand, licensed
  **AGPL-3.0-or-later** (preserving go-algorand's section 7e Additional
  Terms), with individual MIT-eligible files additionally available under
  MIT. See `docs/LICENSING.md` for the rationale and `docs/LICENSING_AUDIT.md`
  for the file/directory-level classification.
- The legal entity for every copyright/attribution statement in this repo
  is **Algod DAO**.
- **Every new source file created in this repo must carry the correct
  license header at creation time.** Default to the AGPL header (mirroring
  the format already used across `crates/core/*`/`crates/node/*`/`bin/*`/
  `crates/tools/*`/`tools/*.go` — see `crates/core/algo-types/src/consensus.rs`
  for the canonical template to copy) whenever the new file ports,
  translates, or is structurally derived from go-algorand (or the AGPL
  `sortition`/`falcon` Go modules) — this is the default for essentially
  all consensus/protocol/API/wire-format work in this repo, per
  `docs/LICENSING_AUDIT.md`'s "when in doubt, AGPL" rule. Use the MIT
  header (see `docs/LICENSING_AUDIT.md`'s MIT template, e.g.
  `crates/tools/algo-bench`) only for genuinely original files with no
  AGPL derivation (repo tooling/CI/ops scripts not embedding ported
  logic). If a new file ports from a third-party source (e.g.
  gnark-crypto, go-sumhash), add the localized third-party attribution
  comment on top of the AGPL/MIT header, following the pattern in
  `crates/core/algo-avm/src/ops/crypto.rs` (poseidon2) and
  `crates/core/algo-consensus-crypto/src/sumhash.rs` (go-sumhash).
- Prose Markdown docs (README, `CLAUDE.md` itself, `docs/*.md`) are
  deliberately exempt from per-file headers — see `docs/LICENSING_AUDIT.md`'s
  explicit note on this.

## Bash Tool Constraints

- Do NOT chain test runs hoping for different results. If a test fails, diagnose the issue first.

## Phase 17 test-parity tracking (docs/PHASE17_TEST_PARITY.md)

- `docs/PHASE17_TEST_PARITY.md` (index/aggregate table) and the 15 per-area
  files under `docs/phase17/parity_*.md` (one row per go-algorand test,
  classified `matched-1:1` / `matched-1:many` / `matched-many:1` / `partial`
  / `missing-test` / `not-implemented` / `out-of-scope`) are the live,
  authoritative record of go-algorand↔algod-rust test parity — not a
  point-in-time snapshot. Whenever a Phase 17 issue (or any fix that adds a
  test proving parity with a go-algorand test named in these files) is
  merged, update the corresponding row(s) in the relevant
  `docs/phase17/parity_<area>.md` file to reflect the new status (typically
  `missing-test`/`not-implemented` → `matched-1:1`/`matched-1:many`/
  `partial`, with a working link to the new Rust test), then refresh
  `docs/PHASE17_TEST_PARITY.md`'s aggregate/per-area status-count table to
  match. This is part of finishing the fix, not a separate follow-up —
  include it in the same PR (or a same-day docs commit) so the tracking
  file never drifts from what main actually has test coverage for.
- `scripts/list_go_tests.sh` and `scripts/list_rust_tests.sh` regenerate the
  raw inputs (`docs/phase17/go_tests.tsv`, `docs/phase17/rust_tests.tsv`) if
  a fuller re-sweep is ever needed — re-run after a future go-algorand
  version bump, or whenever the counts look stale.
- `docs/epics/Epic-27-Test-Parity-Audit.md` and epic issue #830 track
  which of the 22 Phase 17 sub-issues are open/closed — check that box too
  when a sub-issue's PR merges.

## Autonomous merge authorization (algod-issue-fix / algod-version-upgrade)

- The user has explicitly pre-authorized merging PRs opened by the
  `algod-issue-fix` and `algod-version-upgrade` skills **without** an
  `AskUserQuestion` confirmation per PR, so that a batch of issues can be
  driven end-to-end unattended. This is a durable, standing authorization —
  do not re-ask "should I merge?" for PRs meeting the bar below.
- The authorization is conditional, not blanket. Auto-merge a PR only when
  ALL of the following hold; if any is unmet, fall back to the skills'
  default behavior (ask via `AskUserQuestion` before merging):
  - Every CI check is green (no pending/failed checks).
  - The self-review step (step 5/6 of the skill) found nothing left
    unresolved.
  - The issue's acceptance-criteria audit (step 9) shows every item
    checked, struck-with-comment, or moved-with-comment — no silently
    unaddressed item.
  - The PR does not touch anything outside this repo (no cross-repo,
    infra/deploy, or credentials/secrets changes).
- This authorization covers merges performed *by these two skills' own
  workflow*. It does not extend to other destructive/shared-state actions
  (force-push, branch deletion outside a completed PR's own branch,
  `--no-verify`, etc.), and it does not extend to merges requested ad hoc
  outside these skills' flow — those still confirm as normal.

## Common Commands

```bash
cargo build --workspace
cargo test --workspace
cargo test --test digest_test
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

## Project Structure

See `docs/DEV_WORKFLOW.md` for fixture generation, localnet, and testing workflows.
See `docs/CRATE_ARCHITECTURE.md` for detailed crate design and dependency rationale.

Workspace crates:

### Core (consensus-critical)
- `crates/core/algo-error` — error types
- `crates/core/algo-types` — Block, BlockHeader, Transaction, SignedTransaction, AccountData, etc.
- `crates/core/algo-codec` — canonical msgpack encode/decode
- `crates/core/algo-avm` — AVM (TEAL) interpreter, opcodes, logic evaluation
- `crates/core/algo-ledger` — ledger state, block apply, simulation engine, catchpoint sync
- `crates/core/algo-validate` — transaction validation, signature verification, block validation
- `crates/core/algo-agreement` — agreement protocol types and verification
- `crates/core/algo-consensus-crypto` — VRF, one-time signatures, Falcon post-quantum sigs
- `crates/core/algo-falcon` — Falcon-512 signature scheme
- `crates/core/algo-pool` — transaction pool

### Node
- `crates/node/algo-rest-api` — REST API v2 server (axum), handlers, models, NodeInterface trait
- `crates/node/algo-rest-client` — REST API client, parallel block fetching
- `crates/node/algo-network` — P2P networking

### Tools
- `crates/tools/algo-fixtures` — fixture capture from go-algorand
- `crates/tools/algo-conformance` — conformance comparison (Rust vs Go)
- `crates/tools/algo-bench` — benchmarks

### Binary
- `bin/algod-rust` — CLI binary (sync, serve, etc.)
