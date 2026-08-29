# Epic: Node configuration and consensus-parameter parity audit

Tracks auditing algod-rust's node-configuration surface and
consensus-parameter struct against go-algorand's, field by field, and
closing every real divergence found. GitHub epic issue:
[#745](https://github.com/xarmian/algod-rust/issues/745). Full scope and
audit findings: [`docs/PHASE16_PROPOSAL.md`](../PHASE16_PROPOSAL.md).

## Why this phase exists

Phases 9–14 tracked *version-delta* parity — what changed between two
go-algorand pins. They were never scoped to re-audit the **absolute**
shape of `config.Local`/`config.ConsensusParams` from scratch, so a gap
present since the original phase 0–3 port, untouched by any later
version delta, would never surface through that process.

## Headline findings

1. **No `config.json` ingestion mechanism at all** — algod-rust reads
   only a small `algod-rust.toml` (two sections); go-algorand's ~97 real
   `Local` fields are ~9 matching, ~20 different, ~10 not-applicable, and
   **~58 with no equivalent**.
2. **23 consensus-parameter fields absent** from `consensus.rs` (which
   otherwise correctly covers ~118 of 141 fields back to v7) — 8
   self-documented as skipped, **15 silently missing**, several of which
   are historical-replay-correctness risks (unconditional-vs-version-gated
   bugfix-activation flags).
3. **No custom consensus.json load/merge/save mechanism** — a real
   go-algorand-authored file already sits unused in the repo
   (`docker/config/vfuture-consensus.json`).

All three predate the version-delta sweeps.

## Sub-issues (dependency order, priority-first)

- [ ] #747 — consensus: add missing historical-replay-correctness ConsensusParams fields (`PendingResidueRewards`, `InitialRewardsRateCalculation`, `RewardsCalculationFix`, `UnifyInnerTxIDs`, `UnfundedSenders`, `EnablePrecheckECDSACurve`, `AppForbidLowResources`, `StateProofTopVoters`) — **highest priority**, independent of the rest
- [ ] #750 — consensus: implement custom consensus.json load/merge/save (`LoadConfigurableConsensusProtocols` equivalent) — independent
- [ ] #752 — consensus: add remaining missing ConsensusParams fields (`LogicSigMsig`/`LogicSigLMsig`, `EnableBareBudgetError`, `StateProofMaxRecoveryIntervals`, `CatchpointLookback`, `EnableLedgerDataUpdateRound`, `StateProofUseTrackerVerification`, catchpoint file-version interop) — independent
- [ ] #754 — config: implement config.json loading and version migration (`config.Local` equivalent) — **foundational plumbing**, everything below depends on this
- [ ] #748 — config: networking config field gaps (depends on #754)
- [ ] #749 — config: storage/data-directory config field gaps (depends on #754)
- [ ] #751 — config: REST/API config field gaps, including the `EndpointAddress` default-on divergence (depends on #754)
- [ ] #753 — config: catchup/sync config field gaps (depends on #754)
- [ ] #755 — config: agreement-protocol config field gaps — also contains 2 live bugs (stale queue-length constants, delta-cache lookback window 80x too large) fixable independent of #754 (depends on #754 for the config-wiring half only)
- [ ] #756 — config: telemetry/metrics/logging config fields — remote telemetry disposed as a deliberate non-goal (privacy/trust reasons); Prometheus `/metrics` always-on confirmed NOT a bug (matches go-algorand's own unconditional route) (depends on #754)
- [ ] #757 — config: wire up or remove the decorative `docker/localnet-rust/data/config.json` (depends on #754)

## Epic-level acceptance criteria

- [ ] All sub-issues above closed (merged or honestly disposed).
- [ ] `docs/PHASE16_PROPOSAL.md`, this doc, `docs/PROJECT_SCOPE.md` updated.
- [ ] Full gate green on `main`.
- [ ] `docs/PHASE16_VALIDATION.md` evidence map written at close-out.
- [ ] Hard gate: `gh issue list --label "phase:16" --state open` empty
      before this epic closes.
