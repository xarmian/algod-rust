# Phase 16 Proposal — Node Configuration and Consensus-Parameter Parity

Phase 16 audits algod-rust's node-configuration surface (`config.json`
equivalent) and consensus-parameter struct against go-algorand's, field
by field, and closes every real divergence found.

Tracking epic: [#745](https://github.com/xarmian/algod-rust/issues/745).

## Motivation

Phases 9–14 tracked *version-delta* parity (what changed between two
go-algorand pins). They were never scoped to re-audit the **absolute**
shape of `config.Local`/`config.ConsensusParams` against algod-rust's
current implementation from scratch — so a gap present since the
original phase 0–3 port, untouched by any later version delta, would
never surface through that process. This phase does that full audit.

## Audit findings (research pass, 2026-08-30, against go-algorand v5.0.0-stable)

### 1. Node configuration (`config.Local` / `config.json`)

**algod-rust has no `config.json` ingestion mechanism at all.** go-algorand
reads `<data-dir>/config.json`, overlays it onto version-tagged defaults,
and migrates old-version files forward (`config/config.go`,
`config/localTemplate.go`). algod-rust only reads an optional
`algod-rust.toml` with two sections (`[rest]`, `[p2p]`); everything else
is either a narrow per-subcommand CLI flag, hardcoded, or absent.

Of go-algorand's ~97 real (non-deprecated) `Local` fields: ~9 are
implemented matching, ~20 are implemented with a materially different
default/semantics/CLI shape, ~10 are genuinely not applicable (Go-runtime
or telemetry-subsystem specifics), and **~58 have no equivalent at all**.

### 2. Consensus parameters (`config.ConsensusParams`)

algod-rust's `crates/core/algo-types/src/consensus.rs` is a strong,
deliberately-maintained port covering ~118 of go-algorand's 141 struct
fields, correct per-version back to v7. **23 fields are absent**: 8 are
self-documented as `(not modeled)` in version-boundary comments; **15 are
silently missing** with no implementation anywhere. Of the silent gaps,
several are **historical-replay-correctness risks** — bugfix-activation
flags (`PendingResidueRewards`, `InitialRewardsRateCalculation`,
`RewardsCalculationFix`, `UnifyInnerTxIDs`, `UnfundedSenders`,
`EnablePrecheckECDSACurve`, `AppForbidLowResources`) that, if applied
unconditionally rather than version-gated, would compute wrong results
for blocks predating each fix's real activation round. `StateProofTopVoters`
(bounding the state-proof voter set) is also absent and directly affects
state-proof formation/verification.

All 23 originate in go-algorand well before v4.6.0-stable (2019–2021-era
commits) — baseline gaps in the original port, not something the
version-delta sweeps had a reason to catch.

### 3. Custom consensus.json support

**Does not exist.** go-algorand's `LoadConfigurableConsensusProtocols`/
`SaveConfigurableConsensus` (`config/config.go`) reads/writes
`<data-dir>/consensus.json`, merging overrides onto the built-in version
table. algod-rust has no equivalent loader; its vFuture consensus values
are hardcoded directly in `consensus.rs`. A real go-algorand-authored
consensus.json (`docker/config/vfuture-consensus.json`) already exists in
the repo and is field-shape-compatible — it's just never parsed by any
Rust code path (it's fed only to a go-algorand sibling container for
fixture capture).

## Scope

See epic issue for the full dependency-ordered sub-issue list. Grouped
by area:

- **Consensus-critical param gaps** (highest priority — historical-replay
  and live-acceptance-rule correctness).
- **Custom consensus.json load/merge/save mechanism.**
- **config.json load/migration mechanism** (the foundational plumbing:
  `Version` field, partial overlay onto defaults, `migrate()`).
- **Per-area config field gaps**, once the plumbing exists: networking,
  storage/data-dirs, REST/API, catchup/sync, agreement queues, telemetry
  (some of which may be honestly dispositioned as out-of-scope given
  algod-rust's architecture, e.g. no remote-telemetry subsystem exists or
  is wanted).
- **Dead-file cleanup**: `docker/localnet-rust/data/config.json` is
  currently decorative (nothing reads it).

Each sub-issue records the earliest go-algorand tag its gap traces to
(via the `go-algorand-version-lookup` skill), even where that's much
older than the current `v5.0.0-stable` pin — these are backfill gaps, not
new parity work, and should be labeled accordingly (see epic for the
labeling convention used).

## Non-goals

- Go-runtime-specific knobs with no Rust analogue (`GoMemLimit`,
  `DeadlockDetection`, `RunHosted`) are documented as not-applicable, not
  silently dropped.
- A pluggable storage-backend abstraction (`StorageEngine` sqlite vs.
  pebbledb) is out of scope — algod-rust has its own fixed storage
  design; this is recorded as a deliberate architectural difference, not
  a gap to close.
- Adding a remote telemetry-reporting subsystem from scratch is treated
  as a judgment call for whoever picks up that sub-issue, not mandated —
  see the sub-issue for the specific disposition reasoning.

## Success criteria

- Every sub-issue merged (or honestly disposed per this repo's
  issue-disposition rules).
- `docs/PHASE16_VALIDATION.md` written at close-out.
- Hard gate: `gh issue list --label "phase:16" --state open` empty before
  the epic closes.
