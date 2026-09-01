# Phase 17 Proposal — go-algorand ↔ algod-rust Test Parity Audit

Phase 17 audits algod-rust's test suite against go-algorand's, test by
test, across the entire pinned `v5.0.0-stable` reference — not scoped
to any single subsystem or version delta — and closes the real gaps it
finds.

Tracking epic: see `docs/PHASE17_TEST_PARITY.md` for the full evidence
map; the epic issue number is recorded there once filed.

## Motivation

Phases 0–16 built and hardened algod-rust subsystem by subsystem and
version-delta by version-delta, each phase scoped to a specific area
(AVM, ledger, networking, config, etc.) or a specific upstream diff.
None of them asked the blunt, exhaustive question this phase asks:
*for every test go-algorand actually has, does algod-rust have one that
proves the same behavior?* A gap that predates every prior phase, or
that falls between two phases' scopes, would never surface any other
way.

## Methodology

1. Enumerate every `func TestXxx` in the go-algorand reference checkout
   (`scripts/list_go_tests.sh`) and every `#[test]`/`#[tokio::test]` in
   algod-rust (`scripts/list_rust_tests.sh`).
2. Split the go-algorand list into 15 package-area batches and, for
   each, cross-reference every test against the full Rust test list by
   keyword and, where ambiguous, by reading both implementations —
   producing `docs/phase17/parity_<area>.md`.
3. Classify each go-algorand test as `matched-1:1`, `matched-1:many`,
   `matched-many:1`, `partial`, `missing-test` (feature implemented,
   untested), `not-implemented` (feature absent), or `out-of-scope`.
4. Roll the 15 area files up into `docs/PHASE17_TEST_PARITY.md`, and
   group every `not-implemented`/`missing-test` finding into a small
   number of tracked issues by theme (this document, below).

Full results: [`docs/PHASE17_TEST_PARITY.md`](PHASE17_TEST_PARITY.md).

## Headline findings (research pass, 2026-09-01, against go-algorand v5.0.0-stable)

Of 3,177 go-algorand tests: 472 `matched-1:1`, 443 `matched-1:many`, 200
`matched-many:1`, 721 `partial`, 430 `missing-test`, 578
`not-implemented`, 333 `out-of-scope`. **1,115 rows are real, actionable
gaps.**

The most consequential findings, roughly in priority order:

1. **AVM transaction-group resource-availability enforcement does not
   exist.** `is_asset_available`/`is_app_available`
   (`crates/core/algo-ledger/src/avm_context.rs`) only check the
   *current* transaction's own foreign-array fields, never sibling
   transactions in the group; raw account addresses supplied to
   opcodes (rather than via a foreign-array index) pass through with
   **zero** availability check at all; asset-holding and local-state
   reads/writes have no "unavailable" gate; and `tx.Access`
   (`ResourceRef`/`LocalsRef`/`HoldingRef`) is fully modeled and
   statically validated but never consulted at AVM execution time. v8
   and v9+/v10+ execution behave identically today. This is the single
   largest correctness gap surfaced by this audit.
2. **Several other real AVM/ledger-apply correctness bugs**: the
   inner-app-call reentrancy guard only blocks *direct* self-recursion,
   not an indirect A→B→A cycle; `app_local_put`/`app_local_del` never
   check that the target account is a writable reference; app-version
   downgrade is never rejected; `StateSchema` write-limit enforcement
   is missing from `app_global_put`/`app_local_put`; and
   `computeMinAvmVersion` (RekeyTo/ApplicationCall raising the minimum
   AVM version) has no implementation anywhere.
3. **Per-field version gating is missing for 5 AVM opcodes**
   (`global`, `txn`/`gtxn`, `asset_params_get`, `acct_params_get`,
   `block`) — only whole-opcode version gates exist, so a program using
   a future-version *field* of an already-available opcode would
   succeed in algod-rust where go-algorand rejects it. (`itxn_field`
   and `app_params_get`/`app_params_set` do implement real per-field
   gating.)
4. **Per-type `WellFormed()` mempool-admission validation is missing**
   for payment, asset transfer/config/freeze, keyreg, and state-proof
   transactions (only application-call and heartbeat have it) — a
   malformed transaction of these types that go-algorand rejects at
   mempool admission may not be caught until much later, or at all.
5. **A state-proof signing/proving worker daemon does not exist.**
   algod-rust only applies/verifies state proofs already committed to
   a block; it never collects partial signatures, caches prover state,
   or constructs/submits a state-proof transaction itself.
6. **`crypto/stateproof`'s block-generation-side absentee/suspension
   computation, `FirstValidTime`, and several REST-boundary PQ/curve
   compliance checks** (`SkipPqAddressCheck`, on-curve escrow-LogicSig
   rejection) are also absent.
7. **Networking**: the `network/vpack` vote-compression codec is
   entirely unimplemented (peer-feature bits are negotiated but never
   used); the libp2p stream manager (`algo-p2p::streams`) is an
   explicit stub with no request/response protocol; there is no
   `IdentityTracker` connection-dedup mechanism; and libp2p
   connection-limit/pubsub-parameter derivation uses library defaults
   only.
8. **Catchup has no peer-selection/ranking layer** — block/catchpoint
   fetching is round-robin/single-source with no historical
   per-peer-performance tracking, accounting for the large majority of
   the catchup-area gaps.
9. **A handful of CLI/operator-tooling and subsystem-level gaps**:
   `algokey pq` (standalone post-quantum key CLI), an autonomous
   heartbeat-sending service, `libgoal` app-call resource resolution,
   and the application-call excessive-rate-limiter (ERL) subsystem.
10. **`crypto/merklearray` proof-concatenation and decode-time
    allocbound enforcement are absent**, and several `merklesignature`
    tamper-vector tests (corrupted round/proof/signature/index/key)
    have no Rust analogue despite `verify_bytes` being implemented.
    **A parameter-set question was also flagged and should be
    double-checked**: `algo-falcon`'s test names suggest Falcon-512
    while go-algorand's state-proof PQ scheme is Falcon-1024 — likely a
    naming/documentation mismatch rather than a real algorithm bug
    (state-proof participation-key generation already appears to use
    the right parameters elsewhere), but worth a quick, explicit
    reconciliation pass before assuming either way.
11. **A large volume of `missing-test` findings** across AVM/assembler
    edge cases, ledger app-call/resource/catchpoint scenarios,
    agreement player-state-machine and service-level scenarios, crypto
    KAT/randomized-encoding coverage, and REST/kmd/multi-node-cluster
    negative paths — features that already work but aren't pinned by a
    test.

Findings *not* re-filed here: `config.Local` field/behavior gaps beyond
what Phase 16 already tracks (the `IsListenServer` state matrix,
`AdjustConnectionLimits`, `ValidateP2PHybridConfig`, genesis/log-path
resolution) are Phase-16-lineage and referenced from the relevant
sub-issue rather than duplicated.

Large swaths of `out-of-scope` findings are **not** gaps: go-algorand's
custom `logrus`-based logging/telemetry pipeline (algod-rust uses
`tracing` + Prometheus `/metrics`), its reflection-based
struct-completeness/codegen tests (Rust's compiler enforces this
structurally), its typed LRU read-through cache layer and prefetcher
(algod-rust commits synchronously to sqlite instead), and its own
CLI/deployment/dev tooling (`goal`, `netdeploy`, `block-generator`,
`algofix`) are deliberate architectural substitutions per this repo's
design, not missing functionality.

## Issue plan

The 1,115 real gaps are grouped into a bounded set of tracked issues by
theme rather than filed one per test — see the epic issue for the
current list and status. Correctness bugs (items 1–6 above) are
prioritized ahead of missing-test-only findings; large net-new
subsystems (state-proof worker, vpack codec, libp2p streams,
peer-selection) are tracked but may be scoped down to their most
consequential slice rather than a full port in the first pass.
