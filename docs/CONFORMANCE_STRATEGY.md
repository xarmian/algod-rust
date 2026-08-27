# CONFORMANCE_STRATEGY.md — Algod-Rust Protocol Conformance Strategy

_Last updated: 2026-03-04T02:04:22.827977Z_

This document describes the strategy for guaranteeing that **algod-rust remains fully compatible with go-algorand** at every stage of development.

Because consensus software is extremely sensitive to subtle differences in encoding, hashing, and execution behavior, the Rust node must be validated continuously against the Go implementation.

The conformance system acts as a **permanent differential testing harness** between the two implementations.

---

# 1. Core Philosophy

The conformance strategy follows three guiding principles:

1. **Differential Testing**
   - Every behavior of the Rust node should be compared against go-algorand.

2. **Deterministic Fixtures**
   - Historical blocks, transactions, and state transitions must be replayable deterministically.

3. **Incremental Validation**
   - Each subsystem must be validated independently before integration.

---

# 2. Layers of Conformance

Conformance testing is organized into layers from simplest to most complex.

```
Layer 1: Encoding / Decoding
Layer 2: Hashing and Canonicalization
Layer 3: Transaction Validation
Layer 4: Block Validation
Layer 5: Ledger State Transitions
Layer 6: AVM Execution
Layer 7: Catchup and Sync
Layer 8: Network Message Compatibility
Layer 9: Consensus Behavior
```

Each layer must pass before progressing to the next.

---

# 3. Layer 1 — Encoding / Decoding

Goal:

Ensure Rust decodes Algorand message formats exactly the same as Go.

Test strategy:

1. Capture raw msgpack blocks from go-algorand.
2. Decode using Rust codec.
3. Re-encode canonically.
4. Verify byte equivalence.

Test command example:

```
algod-rust-conform codec-test fixtures/block_100.msgpack
```

Failures here usually indicate:

- incorrect field ordering
- msgpack encoding differences
- integer size issues

---

# 4. Layer 2 — Hashing and Canonicalization

Goal:

Ensure all cryptographic digests match the Go implementation.

Tests include:

- transaction ID
- block hash
- payset hash
- state proof hashes

Validation process:

1. Compute hashes in Go.
2. Compute hashes in Rust.
3. Compare outputs.

Mismatch artifacts should include:

- canonical bytes
- decoded structure
- expected vs actual hash

---

# 5. Layer 3 — Transaction Validation

Goal:

Verify Rust correctly validates individual transactions.

Test scenarios:

- signature validation
- group size rules
- fee requirements
- asset rules
- application call constraints

Differential approach:

```
for each test_tx:
    go_result = go_algod.validate(tx)
    rust_result = rust_validator.validate(tx)

    assert(go_result == rust_result)
```

---

# 6. Layer 4 — Block Validation

Goal:

Ensure Rust accepts or rejects blocks exactly the same as Go.

Tests include:

- payset validation
- signature checks
- protocol rule enforcement
- timestamp validation

Replay strategy:

```
for block in historical_chain:
    go_valid = go_algod.validate_block(block)
    rust_valid = rust_algod.validate_block(block)

    assert(go_valid == rust_valid)
```

---

# 7. Layer 5 — Ledger State Transitions

Goal:

Ensure state updates are identical.

Procedure:

1. Start from the same genesis state.
2. Replay blocks sequentially.
3. Compare state roots after each block.

Validation points:

- account balances
- asset states
- application state
- participation state

Mismatch debugging should produce:

- full state diff
- transaction group responsible
- ledger snapshot

---

# 8. Layer 6 — AVM Execution

Goal:

Ensure TEAL execution produces identical results.

Tests include:

- opcode execution
- stack operations
- cost accounting
- state reads/writes

Testing methods:

1. Official TEAL test vectors.
2. Randomized contract execution.
3. Historical block replay.

Each execution should produce identical:

- return values
- state changes
- gas costs

---

# 9. Layer 7 — Catchup and Sync

Goal:

Ensure Rust node reconstructs the ledger identically.

Testing process:

1. Start with empty database.
2. Sync from peers or fixtures.
3. Compare resulting ledger root with Go node.

Key metrics:

- catchup speed
- state root equality
- snapshot correctness

## 9.1. Phase B writer-side acceptance (PLAN-36 / TASK-127)

PLAN-36 ("DB Interchange — Phase B: Writer Side") makes algod-rust's
trackerdb + block DB on-disk format byte-compatible with what
go-algorand reads on startup. The end-to-end acceptance gate is the
**Rust-writer → Go-resumer handoff**:

1. A 3-node go-algorand cluster produces N blocks.
2. `algod-rust sync` consumes those blocks via REST against one of the
   Go nodes and writes them into a fresh ledger prefix using only the
   canonical encoders (`canonical_encode_base_account_data`,
   `canonical_encode_base_online_account_data`,
   `canonical_encode_resources_data`,
   `canonical_encode_online_round_params_data`,
   `canonical_encode_txtail_round`,
   `canonical_encode_state_proof_verification_context`,
   `canonical_encode_certificate`).
3. The Rust-produced `<prefix>.tracker.sqlite` and `<prefix>.block.sqlite`
   are staged into a Go-shaped data dir.
4. A clean go-algorand v4.7.2-stable container boots against that data
   dir and must:
   - start with zero ERROR / FATAL log lines
   - report `last-round >= N` via `/v2/status`
   - serve `/v2/blocks/N` from the Rust-written rows
   - leave no Rust-only tables in the trackerdb
     (`state_deltas`, `merkle_trie`, `catchpoint_import_state`,
     `algod_rust_meta` must all be absent)

How to run:

```bash
# Bash orchestration directly (reproducible by hand):
bash ops/mixed-cluster/scripts/handoff-rust-to-go.sh

# Or wrapped as a gated cargo test:
MIXED_CLUSTER=1 cargo test -p algo-network --test rust_writer_go_resume \
    -- --ignored --nocapture
```

Interpreting results:

- **PASS** = the Phase B writer-side contract holds. The Rust node
  produces an on-disk shape that go-algorand can mount and read
  without migration.
- **FAIL with Rust-only tables present** = a writer path is still
  emitting non-canonical schema. Grep `crates/core/algo-ledger/src/`
  for `CREATE TABLE` to find the offender.
- **FAIL with Go ERROR lines on startup** = canonical encoding for at
  least one BLOB type drifted. Run the targeted unit tests
  (`cargo test -p algo-codec trackerdb_canonical`) and inspect which
  fixture round-trip diverged.
- **FAIL with /v2/blocks/N empty** = the block DB row layout
  (round / cert / blkdata column tuple) doesn't match what Go's
  `blockdb` package expects. Verify `algo_codec::
  canonical_encode_certificate` and the `blocks` table schema.

The script preserves the working directory (`$HANDOFF_DIR`) on failure
so the produced SQLite files + Go container logs can be inspected
side-by-side. Out of scope for Phase B (deferred to Phase C / PLAN-37):
bidirectional handoff where Go advances atop Rust-written state and
Rust then verifies the resulting blocks.

---

# 10. Layer 8 — Network Message Compatibility

Goal:

Ensure Rust node understands all gossip messages.

Tests include:

- handshake messages
- block propagation
- vote messages
- proposal messages

Strategy:

Run mixed clusters of:

- Go nodes
- Rust nodes

Verify interoperability.

---

# 11. Layer 9 — Consensus Behavior

Goal:

Ensure Rust consensus decisions match Go nodes.

Testing environment:

A private mixed Go/Rust cluster under `ops/mixed-cluster/`
(`docker-compose.yml` + `template.json`, bootstrapped by
`scripts/start.sh`):

```
Cluster (shipped, Phase 6):

3 x algorand/algod:4.7.2-stable   relay + proposer, 30% online stake each
1 x algod-rust participate        10% online stake, voting + proposing

Deferred to Phase 7: 3 Go + 3 Rust, 1000+ round soaks.
```

Validation checks and where each one lives:

| Check | Harness entry point | Tooling |
|---|---|---|
| Committee selection (VRF + sortition) matches Go | `cargo test -p algo-consensus-crypto` | `crates/core/algo-consensus-crypto/tests/vrf_parity.rs`, `tests/sortition_parity.rs`, `crates/core/algo-agreement/tests/lookback_boundary.rs` |
| Go accepts Rust's votes | `make consensus-cluster-smoke`, `make consensus-cluster-test` | `scripts/participation-smoke.sh`, `scripts/consensus-conformance.sh` checks `go_accepts_rust_votes` + `no_go_side_rejections` (read off the Go nodes' own `VoteAccepted` telemetry) |
| Block proposals accepted | `make consensus-cluster-test` | `scripts/analyze.py::proposer_share_check` — Rust account's share of committed proposers inside a two-sided binomial bound, never zero; the gate itself is unit-tested by `scripts/analyze_test.py` (`make consensus-cluster-analyzer`) |
| Rust verifies Go's certificates | `make consensus-cluster-test` | `crates/tools/algo-cert-crossverify` via `scripts/verify-soak.sh` (check `certs_authenticate_rust`) |
| Go verifies certificates from a Rust-participating chain | `make consensus-cluster-test` | `tools/cert-authenticate/` — a real go-algorand v4.7.2-stable binary running `agreement.Certificate.Authenticate` over ledger facts exported from the **Rust** ledger (check `certs_authenticate_go`) |
| Fork resolution / final block agreement | `make consensus-cluster-test` | `crates/tools/algo-fork-detector` over every round (check `fork_free`); `scripts/analyze.py::cadence_check` for block cadence; `scripts/status.sh` for per-node lockstep |
| Period advancement | `make consensus-cluster-test` | `consensus-conformance.sh` pauses a Go relay to force period > 0, then requires a return to lockstep (`period_advancement_recovery`) |
| Restart / rejoin mid-round, no equivocation | `make consensus-cluster-restart` | `scripts/restart-rejoin.sh` (graceful / SIGKILL / killed-as-proposer) + `scripts/equivocation.py`, cross-checked against Go's own `voteTracker` equivocation detector |
| Malformed messages rejected | `make consensus-cluster-negative` | `crates/tools/algo-agreement-fuzz` + `scripts/negative-conformance.sh` — bad VRF proof, zero committee weight, wrong OTS domain, corrupted proposal payload |
| Participation observability | `make consensus-cluster-status` | `GET /v2/participation/status` and `GET /metrics` on the Rust node (`crates/core/algo-agreement/src/metrics.rs`), scraped by `scripts/metrics.py` |

`docs/PHASE6_VALIDATION.md` is the full evidence map: it walks each of
`docs/PHASE6_PROPOSAL.md`'s seven success criteria to the specific test
or tool that verifies it, records the four consensus bugs this layer
found, and states the honest scope limits (notably why the Rust node's
cert vote does not appear *inside* certificates at a 30/30/30/10 stake
split). `ops/mixed-cluster/README.md` is the operational runbook.

Layer 9 is **not** run in CI: a container build plus a Rust release
build plus a 200-round soak is far too slow for per-PR CI. Every
cluster test is `#[ignore]`d and gated on `MIXED_CLUSTER=1`, so
`cargo test --workspace` never touches Docker. See
`docs/MIXED_CLUSTER_HARNESS.md` §3.

---

# 12. Fixture Infrastructure

Fixtures are critical to reproducibility.

Fixtures should include:

- raw block bytes
- decoded JSON
- expected hashes
- expected ledger state root

Fixture storage example:

```
fixtures/
    blocks/
    txns/
    ledger/
    avm/
```

---

# 13. Automated Conformance Runner

Create a dedicated tool:

```
algod-rust-conform
```

Capabilities:

- capture fixtures from Go node
- replay historical blocks
- compare results
- generate mismatch reports

Report example:

```
reports/conformance.json
```

Includes:

- rounds tested
- mismatches found
- stack traces
- reproduction instructions

---

# 14. Continuous Integration

CI automatically runs every parity dimension on every PR. Failures
block merges.

## 14.1 PR workflow — `.github/workflows/conformance-parity.yml`

Byte-level differential suite vs go-algorand `v4.7.2-stable`. Target
wall time: ≤ 8 min on a warm cache. Exercises the PLAN-30 gap
dimensions (Greek letters match the gap memo):

| Step | Test | Corpus |
|------|------|--------|
| **β** VRF parity | `cargo test --release -p algo-consensus-crypto --test vrf_parity` | `crates/core/algo-consensus-crypto/tests/fixtures/vrf/vectors.jsonl` |
| **γ** Sortition parity | `cargo test --release -p algo-consensus-crypto --test sortition_parity` | `crates/core/algo-consensus-crypto/tests/fixtures/sortition/vectors.jsonl` |
| **ε** Codec roundtrip | `cargo test --release -p algo-agreement --test codec_roundtrip` | `crates/core/algo-agreement/tests/fixtures/wire/**` |
| **ζ** Canonical-encoding proptest | `PROPTEST_CASES=1000000 cargo test --release -p algo-agreement --test codec_proptest` | generated (no fixture) |
| **η** Lookback boundary | `cargo test --release -p algo-agreement --test lookback_boundary` | `crates/core/algo-agreement/tests/fixtures/lookback/lookback_boundaries.json` |

The workflow runs a single job that reuses one `target/` across all
five steps (via `Swatinem/rust-cache@v2`), keeping compile cost
amortized.

## 14.2 Nightly workflow — `.github/workflows/nightly-fuzz.yml`

Extends **ζ** with `PROPTEST_CASES=10_000_000` (~30 min wall time, ≈5×
the PR budget). Schedule: 03:17 UTC daily, plus `workflow_dispatch`
with an overridable `proptest_cases` input. If proptest finds a new
counter-example:

1. The failing seed is written to
   `crates/core/algo-agreement/tests/proptest-regressions/` by
   proptest itself.
2. The workflow uploads that directory as a 30-day retained artifact
   (`proptest-regressions-<run-id>`).
3. The workflow opens a PR against `main` with the new seed committed,
   labeled `fuzz-finding` + `conformance`, so the next CI run replays
   the regression automatically once merged.

## 14.3 Baseline test job

`cargo test --workspace` continues to run in the project's default
test job and covers the non-parity corpus (codec unit tests, AVM
opcode tests, ledger apply tests, REST API handler tests). The
parity workflow is additive, not a replacement.

## 14.4 Refreshing fixtures

`docs/DEV_WORKFLOW.md` §"Conformance Fixture Refresh" is the runbook
for bumping go-algorand and regenerating the corpora in this section.
Read it before the first refresh on a new machine — each capture tool
has prerequisites (libsodium for VRF, C++ toolchain for sortition).

## 14.5 vFuture coverage (issue #548)

Every dimension above exercises go-algorand at the network's *current*
consensus version (`CONSENSUS_CURRENT_VERSION`, V41 as of this
writing). Nothing exercised `vFuture` ("future" — `protocol.
ConsensusFuture`, go-algorand's perpetual staging protocol for
not-yet-released consensus changes) until #548, so a `vFuture`-only
field like the `Load`/`CongestionTax` ("ld"/"ct") header fields added
in #534/PR #547 had only Rust-side unit tests pinned to go-algorand's
*Go test source* (`TestNextCongestionTax`'s oracle table), not a
byte-exact fixture captured from a real go-algorand `vFuture` binary.

**The harness now closes that gap:**

- `docker/docker-compose.vfuture.yml` stands up a single-node,
  100%-own-stake go-algorand `4.7.2-stable` private network pinned to
  `future` (`docker/config/vfuture-template.json`,
  `docker/scripts/vfuture-entrypoint.sh`) — the same official image
  used by every other Docker capture target in this repo, just with a
  different genesis template.
- `docker/config/vfuture-consensus.json` overrides only
  `MaxTxnBytesPerBlock` for `future` (down to a few KiB) via
  go-algorand's own `consensus.json` configurable-protocols mechanism
  (`config.ConfigurableConsensusProtocolsFilename`), regenerated by
  `tools/vfuture-consensus-override/`. This makes `Load` (block
  byte-fullness) and — one round later — `CongestionTax` (which only
  goes non-zero once `Load` exceeds 50%, per `NextCongestionTax`)
  reachable with a few dozen payment transactions instead of the
  megabytes the real 5 MiB default would require.
- `docker/scripts/capture-vfuture-fixtures.sh` drives the network,
  floods it with transactions, scans for the rounds where `Load` and
  `CongestionTax` first go non-zero, and captures them through the
  **same** generic `algod-rust capture` pipeline (`crates/tools/
  algo-fixtures`) every other block fixture in this repo uses — no
  vFuture-specific capture code was needed, only a vFuture-reachable
  target.
- The captured fixtures live at `crates/core/algo-ledger/tests/
  fixtures/vfuture/` and are replayed byte-exactly by
  `crates/core/algo-ledger/tests/vfuture_load_fixture.rs`, which also
  cross-checks the decoded `Load`/`CongestionTax` values against
  Rust's own `compute_load`/`next_congestion_tax` — so a regression in
  either the arithmetic or the encoding shape fails this test, not
  just the pre-existing oracle-table unit tests.

See `docs/DEV_WORKFLOW.md` §"vFuture Fixture Capture" for the
regeneration runbook.

---

# 15. Historical Replay Testing

The strongest validation is **replaying historical mainnet blocks**.

Procedure:

1. Export historical blocks from Go node.
2. Replay blocks through Rust ledger engine.
3. Compare resulting ledger state roots.

Testing ranges:

- first 10k blocks
- random mid-chain segments
- recent blocks

---

# 16. Fuzz Testing

Critical components should be fuzzed:

Targets:

- msgpack decoder
- transaction parser
- AVM opcode execution
- block validator

Example:

```
cargo fuzz run block_decode
```

---

# 17. Failure Debugging Tools

When mismatches occur, the system should generate:

- decoded object diff
- canonical byte diff
- hash comparison
- ledger state diff

These artifacts drastically reduce debugging time.

---

# 18. Long-Term Validation

Even after mainnet launch, conformance testing should continue.

Examples:

- replay last 1000 blocks daily
- cross-compare ledger roots
- fuzz new protocol features

---

# Final Principle

The Rust node should **never trust itself**.

Every behavior must be verified against the reference implementation until the Rust implementation becomes equally trusted.
