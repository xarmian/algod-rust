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

- [x] #747 — consensus: add missing historical-replay-correctness ConsensusParams fields (`PendingResidueRewards`, `InitialRewardsRateCalculation`, `RewardsCalculationFix`, `UnifyInnerTxIDs`, `UnfundedSenders`, `EnablePrecheckECDSACurve`, `AppForbidLowResources`, `StateProofTopVoters`) — **highest priority**, independent of the rest — merged via PR #759. `StateProofTopVoters` moved to #758; verification-depth gaps moved to #760.
- [x] #750 — consensus: implement custom consensus.json load/merge/save (`LoadConfigurableConsensusProtocols` equivalent) — independent — merged via PR #761.
- [x] #752 — consensus: add remaining missing ConsensusParams fields (`LogicSigMsig`/`LogicSigLMsig`, `EnableBareBudgetError`, `StateProofMaxRecoveryIntervals`, `CatchpointLookback`, `EnableLedgerDataUpdateRound`, `StateProofUseTrackerVerification`, catchpoint file-version interop) — independent — merged via PR #765.
- [x] #754 — config: implement config.json loading and version migration (`config.Local` equivalent) — **foundational plumbing**, everything below depends on this — merged via PR #767.
- [x] #748 — config: networking config field gaps (depends on #754) — merged via PR #769. Remaining fields split off to #768.
- [x] #749 — config: storage/data-directory config field gaps (depends on #754) — merged via PR #771. Automatic catchpoint generation wiring split off to #770.
- [x] #751 — config: REST/API config field gaps, including the `EndpointAddress` default-on divergence (depends on #754) — merged via PR #772.
- [x] #753 — config: catchup/sync config field gaps (depends on #754) — merged via PR #773. TxSyncer live-wiring split off to #774.
- [x] #774 — sync: wire TxSyncer into the live node (transaction sync loop never runs) — discovered while working #753; merged via PR #791. Bloom-filter wire-protocol follow-up moved to #792.
- [x] #792 — sync: TxSyncer HTTP pull protocol doesn't match go-algorand's Bloom-filter wire format — split off from #774; merged via PR #800. Misbehaving-peer defense gap moved to #801.
- [x] #801 — sync: TxSyncer never checks whether a peer's returned group was entirely already in our Bloom filter — split off from #792; merged via PR #805.
- [x] #755 — config: agreement-protocol config field gaps — also contains 2 live bugs (stale queue-length constants, delta-cache lookback window 80x too large) fixable independent of #754 (depends on #754 for the config-wiring half only) — merged via PR #775.
- [x] #756 — config: telemetry/metrics/logging config fields — remote telemetry disposed as a deliberate non-goal (privacy/trust reasons); Prometheus `/metrics` always-on confirmed NOT a bug (matches go-algorand's own unconditional route) — merged via PR #777. `EnableRuntimeMetrics`/`EnableNetDevMetrics` moved to #776.
- [x] #776 — metrics: add Go-runtime and network-interface counters to gate with `EnableRuntimeMetrics`/`EnableNetDevMetrics` — split off from #756; merged via PR #795.
- [x] #757 — config: wire up or remove the decorative `docker/localnet-rust/data/config.json` (depends on #754) — merged via PR #778.
- [x] #758 — consensus/state-proof: implement independent voter-set formation/verification (`StateProofTopVoters` had no code path) — split off from #747; merged via PR #781.
- [x] #780 — consensus/state-proof: wire voter-set selection into block production/validation (votersTracker + onlineTotalsEx) — merged via PR #782, live/byte-level gaps closed via PR #783.
- [x] #760 — consensus: close verification-depth gaps from #747 (live mixed-cluster + oracle fixtures) — split off from #747; merged via PR #784.
- [x] #762 — consensus: thread custom consensus.json overrides through `consensus_params_for_version` (previously only one startup call site) — merged via PR #763.
- [x] #764 — consensus: live-node verification that consensus.json overrides are enforced over the wire — merged via PR #785.
- [x] #766 — catchpoint: implement V6 file-format producer/consumer support — merged via PR #787. A second bug found in the same PR (V7 export using the V8 label maker) filed and fixed inline as #786.
- [x] #786 — catchpoint writer: V7 export label used the V8 label maker, not V7's — found and fixed inline during #766's PR #787.
- [x] #768 — config: close remaining networking config.json field gaps (PublicAddress/hybrid validation, message filters, DNS security, Relay config.json loading, etc.) — split off from #748; merged via PR #790. `NetAddress` unification moved to #788; message-filter wiring gap moved to #789.
- [x] #788 — networking: full `enrichNetworkingConfig`-style `NetAddress` unification (relay `--bind-address` / participate `--listen-address`) — split off from #768; merged via PR #799.
- [x] #789 — networking: wire MessageFilter into real peer connections (`incoming_filter`/`outgoing_filter` never populated) — discovered while implementing #768; merged via PR #797. Broadcast-side notification gap moved to #798.
- [x] #798 — networking: send `MsgDigestSkip` notifications to peers (outgoing filter's broadcast-side notification is unwired) — discovered while implementing #789; merged via PR #802. Per-connection state bug moved to #803.
- [x] #803 — networking: `outgoing_message_filter` shared across all peer connections instead of per-peer, causing over-suppression — discovered while implementing #798; merged via PR #804.
- [x] #770 — ledger: wire automatic catchpoint generation into the live apply loop (`CatchpointInterval`/`CatchpointTracking`) — split off from #749; merged via PR #793. Graceful-shutdown/atomicity follow-up moved to #794.
- [x] #794 — ledger: automatic catchpoint export needs graceful-shutdown wait and atomic file write — split off from #770; merged via PR #806.
- [x] #779 — node start: DNSBootstrapID (config.json) has no peer-discovery consumer — merged via PR #796 (formally dispositioned out of scope by design).

## Epic-level acceptance criteria

- [x] All sub-issues above closed (merged or honestly disposed per this repo's issue-disposition rules) — 30 sub-issues total (12 originally scoped, 18 follow-ups), none disposed as unreachable/deferred.
- [x] `docs/PHASE16_PROPOSAL.md`, this epic doc, `docs/PROJECT_SCOPE.md` updated.
- [x] Full gate green on `main` — `cargo fmt --all -- --check` (clean except the pre-existing, unrelated `assembler.rs` rustfmt-drift diff documented in `docs/PHASE15_VALIDATION.md`), `cargo clippy --workspace --all-targets -- -D warnings` (clean), `cargo test --workspace` (clean except the documented pre-existing `algo-network` doctest flake).
- [x] `docs/PHASE16_VALIDATION.md` evidence map written at close-out.
- [x] Hard gate: `gh issue list --label "phase:16" --state open` empty
      (returns only this epic issue itself) before this epic closes.
