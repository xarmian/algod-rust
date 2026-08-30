# Phase 16 Validation — Node Configuration and Consensus-Parameter Parity

_Completed: 2026-08-30_

Phase 16 audited algod-rust's node-configuration surface
(`config.json`/CLI flags) and consensus-parameter struct
(`ConsensusParams`) against go-algorand's, field by field, and closed
every real divergence found. Unlike Phases 9–14 (which tracked only
*version-delta* parity — what changed between two go-algorand pins),
this phase re-audited the **absolute** shape of `config.Local`/
`config.ConsensusParams` from scratch, surfacing gaps present since the
original Phase 0–3 port that no version-delta sweep would ever have
caught.

This document is the evidence map for
[`docs/PHASE16_PROPOSAL.md`](PHASE16_PROPOSAL.md) and
[`docs/epics/Epic-26-Configuration-Consensus-Parity.md`](epics/Epic-26-Configuration-Consensus-Parity.md).
Every claim below cites a specific issue/PR/commit/test in this repo.

Tracking epic: [#745](https://github.com/xarmian/algod-rust/issues/745).

---

## Completeness re-check (Stage 7 mandatory re-run)

This phase never moved the go-algorand version pin, so the re-check is
lighter than Phases 9–14's:

- `git -C ../go-algorand describe --tags` still reports `v5.0.0-stable`
  (detached HEAD) — unchanged since the phase began.
- `gh issue list --repo xarmian/algod-rust --label "phase:16" --state open`
  returns **only** the epic issue [#745](https://github.com/xarmian/algod-rust/issues/745)
  itself, confirmed 2026-08-30 immediately before this document was
  written — no missed sub-issue exists under the label.

## Headline findings (from `docs/PHASE16_PROPOSAL.md`'s research pass)

1. algod-rust had **no `config.json` ingestion mechanism at all** — only
   an optional `algod-rust.toml` with two sections existed. Of
   go-algorand's ~97 real `Local` fields: ~9 were implemented-matching,
   ~20 implemented-different, ~10 not-applicable, and **~58 had no
   equivalent**.
2. **23 consensus-parameter fields were absent** from
   `crates/core/algo-types/src/consensus.rs` (which otherwise correctly
   modeled ~118 of 141 fields back to v7). 8 were self-documented as
   skipped; **15 were silently missing**, several of which are
   historical-replay-correctness risks (bugfix-activation flags that
   must be version-gated, not unconditional).
3. **No custom consensus.json load/merge/save mechanism existed.** A
   real go-algorand-authored `consensus.json` already sat in the repo
   (`docker/config/vfuture-consensus.json`) but was never parsed by any
   Rust code — algod-rust's vFuture params were hardcoded instead.

All three findings predated the version-delta-scoped Phase 9–14 sweeps —
baseline gaps in the original port, not artifacts of any later upgrade.

## Sub-issue disposition

30 sub-issues closed in total: the 12 issues originally scoped in the
epic, plus 18 follow-up issues filed and worked as gaps surfaced during
implementation (this repo's standing "every open topic becomes a worked
sub-issue" rule). None were disposed as unreachable/deferred — every
real gap that surfaced was implemented and merged.

### Group A — consensus-critical gaps

| Sub-issue | PR(s) / commit(s) | Evidence |
|---|---|---|
| [#747](https://github.com/xarmian/algod-rust/issues/747) missing historical-replay-correctness `ConsensusParams` fields (`PendingResidueRewards`, `InitialRewardsRateCalculation`, `RewardsCalculationFix`, `UnifyInnerTxIDs`, `UnfundedSenders`, `EnablePrecheckECDSACurve`, `AppForbidLowResources`, `StateProofTopVoters`) | [#759](https://github.com/xarmian/algod-rust/pull/759) (`74a8914`) | `crates/core/algo-types/src/consensus.rs`: all 8 fields added, version-gated per-protocol-version test coverage in `consensus.rs`'s own test module. `StateProofTopVoters` had no code path to wire into yet — moved to #758; two verification-depth gaps moved to #760. |
| [#758](https://github.com/xarmian/algod-rust/issues/758) state-proof independent voter-set formation/verification (`StateProofTopVoters` had no code path) | [#781](https://github.com/xarmian/algod-rust/pull/781) (`36e0538`) | `TopOnlineAccounts`-equivalent voter-set selection + commitment implemented from scratch in `crates/core/algo-ledger`, ported against go's `ledger/ledgercore/votersForRound.go`. |
| [#780](https://github.com/xarmian/algod-rust/issues/780) wire voter-set selection into block production/validation (votersTracker + onlineTotalsEx) | [#782](https://github.com/xarmian/algod-rust/pull/782) (`084b51a`), [#783](https://github.com/xarmian/algod-rust/pull/783) (`cd57f63`) | #782 wires #758's voter-set selection into real block production/validation; #783 closes live/byte-level voters-commitment gaps found during that work. |
| [#752](https://github.com/xarmian/algod-rust/issues/752) remaining missing `ConsensusParams` fields (`LogicSigMsig`/`LogicSigLMsig`, `EnableBareBudgetError`, `StateProofMaxRecoveryIntervals`, `CatchpointLookback`, `EnableLedgerDataUpdateRound`, `StateProofUseTrackerVerification`) | [#765](https://github.com/xarmian/algod-rust/pull/765) (`accb9ed`) | `consensus.rs`: all remaining fields added with version-gated defaults matching `config/consensus.go`. |
| [#760](https://github.com/xarmian/algod-rust/issues/760) close verification-depth gaps from #747 (live mixed-cluster + oracle fixtures) | [#784](https://github.com/xarmian/algod-rust/pull/784) (`0f61e49`) | Live mixed-cluster/oracle-fixture test coverage added for #747's 8 fields, closing gaps in the original PR's verification depth. |
| [#766](https://github.com/xarmian/algod-rust/issues/766) catchpoint V6 file-format producer/consumer support | [#787](https://github.com/xarmian/algod-rust/pull/787) (`33a5fd4`) | `catchpoint::writer`/`catchpoint::parser`: V6 export path (no SP-verification blob, `make_catchpoint_label_v6`) and V6 header parsing added. |
| [#786](https://github.com/xarmian/algod-rust/issues/786) catchpoint writer: V7 export label used the V8 label maker, not V7's | same PR [#787](https://github.com/xarmian/algod-rust/pull/787) (`33a5fd4`) | Found while restructuring #766's label-construction code: `export_catchpoint_file` now dispatches to the version-appropriate label maker (`make_catchpoint_label_v6`/`_v7`/`_v8`) instead of always calling the V8 maker. Fixed inline in the same PR; issue filed and closed for the record. |

### Group B — consensus.json mechanism

| Sub-issue | PR / commit | Evidence |
|---|---|---|
| [#750](https://github.com/xarmian/algod-rust/issues/750) implement custom consensus.json load/merge/save (`LoadConfigurableConsensusProtocols` equivalent) | [#761](https://github.com/xarmian/algod-rust/pull/761) (`b2c93c7`) | New consensus.json load/merge/save mechanism parses and applies `docker/config/vfuture-consensus.json`-shaped overrides; round-trip tests. |
| [#762](https://github.com/xarmian/algod-rust/issues/762) thread custom consensus.json overrides through `consensus_params_for_version` (previously only one startup call site was affected) | [#763](https://github.com/xarmian/algod-rust/pull/763) (`10d8643`) | All call sites of `consensus_params_for_version` now honor loaded overrides, not just the one startup path; self-review follow-up commit (`d98e39b`) pinned dangling `approved_upgrade` pruning through the override registry. |
| [#764](https://github.com/xarmian/algod-rust/issues/764) live-node verification that consensus.json overrides are enforced over the wire | [#785](https://github.com/xarmian/algod-rust/pull/785) (`9ba90b7`) | Live-node test confirms a custom consensus.json override is actually honored end-to-end (not just parsed), closing #750/#762's remaining verification gap. |

### Group C — config.json plumbing (foundational)

| Sub-issue | PR / commit | Evidence |
|---|---|---|
| [#754](https://github.com/xarmian/algod-rust/issues/754) implement config.json loading and version migration (`config.Local` equivalent) | [#767](https://github.com/xarmian/algod-rust/pull/767) (`d404b52`) | New `crates/node/algo-config` crate: version-tagged defaults, partial-overlay `config.json` loading, migration logic mirroring `config.Local`. Foundational — every per-area config issue below (`#748`, `#749`, `#751`, `#753`, `#755`, `#756`, `#757`) depends on it. |

### Group D — per-area config gaps

| Sub-issue | PR / commit | Evidence |
|---|---|---|
| [#748](https://github.com/xarmian/algod-rust/issues/748) networking config.json field gaps (`GossipFanout`, `NetAddress` unification, connection limits, P2P hybrid validation, etc.) | [#769](https://github.com/xarmian/algod-rust/pull/769) (`db985d4`) | Networking fields wired into `algo-network`/`algo-rest-api`; connection-limit/rate-limit/TLS fields, `DisableAPIAuth`, gossip-service toggles, and a real conformance bug fix (WS listener incorrectly gated bind on `ForceRelayMessages` instead of `NetAddress` alone). |
| [#749](https://github.com/xarmian/algod-rust/issues/749) storage/data-directory config.json field gaps (`HotDataDir`/`ColdDataDir`/etc., catchpoint interval/tracking, sync modes) | [#771](https://github.com/xarmian/algod-rust/pull/771) (`8944616`) | Storage/data-dir fields wired into `algo-ledger`; `CatchpointInterval`/`CatchpointFileHistoryLength`/`CatchpointTracking` added as config-surface fields (feature-gap follow-up moved to #770). |
| [#751](https://github.com/xarmian/algod-rust/issues/751) REST/API config.json field gaps (`EndpointAddress` default-on behavior, timeouts, connection limits, dev/experimental API gating) | [#772](https://github.com/xarmian/algod-rust/pull/772) (`7e52cb6`) | REST/API config gaps closed in `algo-rest-api`, including the `EndpointAddress` default-on divergence flagged in the epic. |
| [#753](https://github.com/xarmian/algod-rust/issues/753) catchup/sync config.json field gaps (parallelism, timeouts, retry attempts, tx-sync protocol) | [#773](https://github.com/xarmian/algod-rust/pull/773) (`843d1217`) | Catchup/sync config fields wired in; discovered while working this issue that the tx-sync loop never ran at all — moved to #774. |
| [#755](https://github.com/xarmian/algod-rust/issues/755) agreement-protocol config.json field gaps (queue lengths, `MaxAcctLookback`, reporting toggles) | [#775](https://github.com/xarmian/algod-rust/pull/775) (`c48f680`) | Agreement-protocol config fields wired into `algo-agreement`/`algo-ledger`; also fixed 2 live bugs found along the way (stale queue-length constants, delta-cache lookback window 80x too large). |
| [#756](https://github.com/xarmian/algod-rust/issues/756) telemetry/metrics/logging config.json field audit | [#777](https://github.com/xarmian/algod-rust/pull/777) (`7b3b367`) | Remote telemetry formally dispositioned as a deliberate non-goal (privacy/trust reasons); Prometheus `/metrics` always-on behavior confirmed **not** a bug (matches go-algorand's own unconditional route). `EnableRuntimeMetrics`/`EnableNetDevMetrics` moved to #776 since no counters existed yet to gate. |
| [#757](https://github.com/xarmian/algod-rust/issues/757) wire up or remove the decorative `docker/localnet-rust/data/config.json` | [#778](https://github.com/xarmian/algod-rust/pull/778) (`1684b20`) | Node start now genuinely reads and applies `config.json` at startup rather than treating it as decorative dead weight. |
| [#776](https://github.com/xarmian/algod-rust/issues/776) add Go-runtime and network-interface metrics counters to gate with `EnableRuntimeMetrics`/`EnableNetDevMetrics` | [#795](https://github.com/xarmian/algod-rust/pull/795) (`394ad42`) | Go-runtime and network-interface counters added to `/metrics`, gated by the two previously-inert config fields split off from #756. |
| [#779](https://github.com/xarmian/algod-rust/issues/779) `DNSBootstrapID` (config.json) has no peer-discovery consumer | [#796](https://github.com/xarmian/algod-rust/pull/796) (`02514bf`) | Formally dispositioned as out of scope by design (documented judgment call, not silently dropped) — see PR #796's rationale in `crates/node/algo-config` module docs. |

### Group E — networking/catchpoint follow-on chain

This chain emerged organically: #768 (closing #748's deferred networking
fields) → #789 (wiring the `MessageFilter` config #768 added) → #798
(broadcast-side notification #789's wiring exposed as missing) → #803
(per-connection state bug found while implementing #798) → #794
(catchpoint shutdown/atomicity, chained off #770/#749 instead). A
parallel chain ran through tx-sync: #774 (wire `TxSyncer` into the live
node) → #792 (real Bloom-filter wire protocol) → #801 (misbehaving-peer
defense gap found while implementing #792's protocol).

| Sub-issue | PR / commit | Evidence |
|---|---|---|
| [#768](https://github.com/xarmian/algod-rust/issues/768) close remaining networking config.json field gaps (PublicAddress/hybrid validation, message filters, DNS security, Relay config.json loading, etc.) | [#790](https://github.com/xarmian/algod-rust/pull/790) (`7a8ee2b`) | Follow-up to #748: relay gets its own config.json loading; `IncomingMessageFilterBucketCount`/`Size` and outgoing equivalents wired into `algo-network`'s `MessageFilter` bucket construction. |
| [#788](https://github.com/xarmian/algod-rust/issues/788) full `enrichNetworkingConfig`-style `NetAddress` unification (relay `--bind-address` / participate `--listen-address`) | [#799](https://github.com/xarmian/algod-rust/pull/799) (`c233feec`) | Split off from #768 as a larger architectural item; `enrichNetworkingConfig`'s `GossipFanout` bump for listen servers implemented for both `relay`/`participate`. |
| [#789](https://github.com/xarmian/algod-rust/issues/789) wire `MessageFilter` into real peer connections (`incoming_filter`/`outgoing_filter` never populated) | [#797](https://github.com/xarmian/algod-rust/pull/797) (`e15e367`) | Discovered while implementing #768: `WsPeerConfig`'s filter slots were never populated by `WebsocketNetwork`. Now wired through to real connections. |
| [#792](https://github.com/xarmian/algod-rust/issues/792) TxSyncer HTTP pull protocol doesn't match go-algorand's Bloom-filter wire format (go-algorand v1.0.23-stable) | [#800](https://github.com/xarmian/algod-rust/pull/800) (`544ac77`) | Real `bloom.rs`/`tx_sync_service.rs`/`tx_sync_client.rs` port of go's Bloom-filter-over-HTTP protocol (`rpcs/txService.go`/`rpcs/httpTxSync.go`), replacing #774's deliberate simplification. |
| [#798](https://github.com/xarmian/algod-rust/issues/798) send `MsgDigestSkip` notifications to peers (outgoing filter's broadcast-side notification is unwired) | [#802](https://github.com/xarmian/algod-rust/pull/802) (`80fda67`) | Discovered while implementing #789: go-algorand broadcasts `MsgDigestSkipTag` to other peers after processing a large (≥5000 byte) dedup-safe (`AV`/`TX`) message (`network/wsNetwork.go`); now ported. |
| [#801](https://github.com/xarmian/algod-rust/issues/801) TxSyncer never checks whether a peer's returned group was entirely already in our Bloom filter | [#805](https://github.com/xarmian/algod-rust/pull/805) (`5065202`) | Follow-up from #792/PR #800: the misbehaving-peer defense in go's `TxSyncer.syncFromClient` (post-decode, pre-handler check) was scoped out of #800; now ported. |
| [#803](https://github.com/xarmian/algod-rust/issues/803) `outgoing_message_filter` shared across all peer connections instead of per-peer, causing over-suppression | [#804](https://github.com/xarmian/algod-rust/pull/804) (`449b902`) | Discovered while implementing #798: go's `wsPeer` owns its own `outgoingMsgFilter` per connection; algod-rust shared one network-wide instance, over-suppressing broadcasts. Now per-connection. |
| [#770](https://github.com/xarmian/algod-rust/issues/770) wire automatic catchpoint generation into the live apply loop (`CatchpointInterval`/`CatchpointTracking`) | [#793](https://github.com/xarmian/algod-rust/pull/793) (`3cd3f2a`) | Follow-up from #749: `SqliteLedger::commit_block` now spawns an automatic, fire-and-forget catchpoint export every `CatchpointInterval` rounds, gated by `CatchpointTracking`. |
| [#774](https://github.com/xarmian/algod-rust/issues/774) wire TxSyncer into the live node (transaction sync loop never runs) | [#791](https://github.com/xarmian/algod-rust/pull/791) (`c9f6f97`) | Follow-up from #753: real `PeerSource`/`PendingTxAggregate`/`SolicitedTxHandler` implementations wired into `relay`/`participate`'s startup, pulling missing transactions from peers. |
| [#794](https://github.com/xarmian/algod-rust/issues/794) automatic catchpoint export needs graceful-shutdown wait and atomic file write | [#806](https://github.com/xarmian/algod-rust/pull/806) (`34632fd`) | Follow-up from #770: `wait_for_pending_catchpoint_export()` now called from `relay`/`participate`'s shutdown path (no killed-mid-write corruption); `export_catchpoint_file` writes to a temp file + atomic rename instead of writing the destination path directly. |

## Full gate on `main`

Re-run at close-out (2026-08-30) via the pinned MSVC/cargo invocation:

- `cargo fmt --all -- --check` — one pre-existing diff in
  `crates/core/algo-avm/src/assembler.rs` (a `format!` call's line-wrap
  choice), the same rustfmt-version-drift issue already documented in
  `docs/PHASE15_VALIDATION.md`'s full-gate run — confirmed unrelated to
  any Phase 16 change (no Phase 16 PR touches `assembler.rs`).
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo test --workspace` — every crate green except the pre-existing,
  documented `algo-network` doctest flake (CLAUDE.md's known
  local-environment noexec-tempdir issue) — the sole acceptable failure
  per this repo's stated policy.

## Outcome

All 12 originally-scoped sub-issues plus 18 follow-up issues filed and
worked during implementation are merged. No sub-issue was disposed as
unreachable or deferred — every real gap that surfaced, including
several discovered only while implementing an adjacent fix, was
implemented and merged. `gh issue list --label "phase:16" --state open`
returns only the epic issue itself, confirmed immediately before this
document was written.

algod-rust now has: a real `config.json` loading/migration mechanism
(`config.Local` equivalent) with per-area field parity across
networking, storage, REST/API, catchup/sync, agreement, and
telemetry/metrics; a custom consensus.json load/merge/save mechanism
threaded through every `consensus_params_for_version` call site and
live-verified over the wire; the 23 previously-missing
`ConsensusParams` fields (including independent state-proof voter-set
formation, a feature that had no code path at all before this phase);
and a fully wired transaction-sync loop and automatic catchpoint
generation, both with go-algorand-matching wire/file-format fidelity
and graceful-shutdown/atomicity guarantees.
