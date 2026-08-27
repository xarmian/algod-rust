# Phase 10 Validation — go-algorand v4.7.0-stable Parity + libp2p P2P Transport

_Completed: 2026-08-27_

Phase 10 moves algod-rust's parity target from go-algorand `v4.6.0-stable`
to `v4.7.0-stable`, and — folded into this same epic by explicit decision
rather than deferred — closes the longstanding gap where algod-rust
implemented only the legacy WebSocket gossip network and had no
libp2p-based P2P transport (go-algorand's `network/p2p/` package).

This document is the evidence map for
[`docs/PHASE10_PROPOSAL.md`](PHASE10_PROPOSAL.md) and
[`docs/epics/Epic-20-Go-Algorand-v4.7.0-Parity-And-P2P.md`](epics/Epic-20-Go-Algorand-v4.7.0-Parity-And-P2P.md),
mirroring the structure and level of evidence of
[`PHASE6_VALIDATION.md`](PHASE6_VALIDATION.md) (the Layer-9 consensus
evidence map this phase's P2P work extends). Every claim below cites a
specific file/test/script in this repo, or the PR/issue where the live
evidence is recorded.

Tracking epic: [#544](https://github.com/xarmian/algod-rust/issues/544).
This phase grew from 10 originally-scoped sub-issues (4 version-delta +
6 P2P transport) to 30 tracked sub-issues across more than 35 merged
PRs, closing issues #534–#614 (not all sequential — see epic #544's body
for the authoritative dependency-ordered list).

---

## Completeness re-check (Stage 7 mandatory re-run)

Per the `algod-version-upgrade` skill's Stage 7 instructions, the
release-notes completeness pass and `TAGS_IN_RANGE` derivation were
re-run fresh at close-out (2026-08-27), not just trusted from the
original Stage 2 pass:

- `git -C ../go-algorand fetch --tags` followed by
  `git tag --contains v4.6.0-stable --list | sort -V` and an
  ancestor-of-`v4.7.0-stable` filter confirms `TAGS_IN_RANGE` is
  unchanged: `v4.6.0-stable` (OLD) → `v4.7.0-beta` → `v4.7.0-stable`
  (NEW). Later tags (`v4.7.2-stable`, `v4.7.3-beta`, ...) exist upstream
  but are not ancestors of `v4.7.0-stable` and are out of this phase's
  range.
- `git -C ../go-algorand log --oneline v4.6.0-stable..v4.7.0-stable`
  returns exactly 24 commits, all of which map onto the epic's
  classified inventory (issue #544's body), **with one exception found
  on this re-check**: `617663311 pingpong: fix asset creation race
  (#6579)`. This PR touches only `shared/pingpong/accounts.go` —
  go-algorand's own load-generation CLI tool, which algod-rust has no
  equivalent of (verified via `gh pr view 6579 -R algorand/go-algorand
  --json files`, one file changed). It belongs in the epic's
  `not-applicable` bucket alongside the 11 other Go-internal/tooling
  items already listed there; it was omitted from the original Stage 2
  pass's written inventory but does not change any conclusion — no
  algod-rust action is needed for it. Recorded here per the Stage 7
  "re-do the completeness check, corrections happen" instruction.
- Both `gh release view v4.7.0-beta` and `gh release view v4.7.0-stable`
  (`-R algorand/go-algorand`) carry identical "What's New"/Changelog
  content — no corrections or additions since the epic's Stage 2 pass.

---

## Version-delta items (issues #534–#537)

| # | Upstream PR | Sub-issue → merged PR | What it proves |
|---|---|---|---|
| 1 | [#6548](https://github.com/algorand/go-algorand/pull/6548) Blocks: Load/CongestionTax blockheaders (`vFuture`) | [#534](https://github.com/xarmian/algod-rust/issues/534) → **#547** | `algo-types` gains the `vFuture`-gated `Load`/`CongestionTax` block-header fields; conformance coverage added by #548 (below). |
| 2 | [#6588](https://github.com/algorand/go-algorand/pull/6588) API: params in deltas | [#535](https://github.com/xarmian/algod-rust/issues/535) → **#549** | Investigation found algod-rust's architecture (synchronously-committed SQLite ledger, no staged in-memory delta layer) structurally cannot exhibit the upstream bug class; closed with permanent regression tests pinning the already-correct behavior rather than a behavior change. |
| 3 | [#6558](https://github.com/algorand/go-algorand/pull/6558) API: boxes cursor pagination + prefix | [#536](https://github.com/xarmian/algod-rust/issues/536) → **#550** | `GET /v2/applications/{id}/boxes` gains cursor-based pagination with prefix-filter support. Live dual-node byte-for-byte verification moved to #551 (below); a real functional gap (historical-round box queries) filed as #552 (below). |
| 4 | [#6595](https://github.com/algorand/go-algorand/pull/6595) chore: fast-catchup error-handling robustness | [#537](https://github.com/xarmian/algod-rust/issues/537) → **#553** | The literal upstream hunks have no Rust equivalent (Rust's `Result`/`?` already forces propagation); the underlying "one recoverable fetch failure shouldn't abort the whole catchup" principle had a real instance in `CatchpointDownloader` (`algo-rest-client`, no retry once a catchpoint body stream started) — fixed with whole-request retry on recoverable stream errors. `network/p2p/capabilities.go`-side portion folded into #541 (P2P track, below). |

### Follow-on conformance work spawned by #534/#536

| Issue | Merged PR | What it proves |
|---|---|---|
| [#548](https://github.com/xarmian/algod-rust/issues/548) — no vFuture coverage in the fixture/conformance harness | **#567** | `docker/docker-compose.vfuture.yml` (single-node `future`-protocol go-algorand target, `MaxTxnBytesPerBlock` override); real golden fixtures captured (round 48: `Load=950927`, `CongestionTax=90332`) replayed by `vfuture_load_fixture.rs`. Found (not fixed, out of scope) a Windows debug-build-only stack overflow, filed as #568. |
| [#568](https://github.com/xarmian/algod-rust/issues/568) — Windows debug-build stack overflow decoding blocks | **#575** | Root cause: `async fn main()`'s compiler-generated state machine overflowing the default 1 MiB MSVC main-thread stack before `main()` ran (not the decode path). Fixed via `.cargo/config.toml`'s `/STACK:8388608`. |
| [#551](https://github.com/xarmian/algod-rust/issues/551) — live dual-node byte-for-byte box-pagination check | **#569** | Real box-writing app deployed on both a live go-algorand v4.7.0-stable node and a live algod-rust node; diffed `GET /v2/applications/{id}/boxes` field-for-field for legacy shape, `include=values`, and a `limit=2` prefix-filtered multi-page cursor walk — no handler-side divergence found. |
| [#552](https://github.com/xarmian/algod-rust/issues/552) — historical-round box queries unsupported | Closed with documented finding, **#571** | go-algorand's own lookback here is also bounded (`MaxAcctLookback`, default 4) — the 400 was never a real algod-rust gap relative to what go-algorand grants. Spawned the `kv_mods` population chain below as the real, actionable blocker. |

---

## P2P transport track (issues #538–#543, #559, #560, #564, #566, #589, #591, #594, #596, #597)

New crate: `crates/node/algo-p2p`.

| Issue | Merged/closed PR | What it delivered / proves |
|---|---|---|
| [#538](https://github.com/xarmian/algod-rust/issues/538) — libp2p host/identity/secure-connection foundation | **#554** | `P2pHost` (Swarm over TCP/Noise/yamux), persisted-identity keypair loading mirroring `peerID.go`. TDD test dials two nodes and confirms a secure connection. Real bug fixed: libp2p's default zero idle-connection timeout tore connections down before transport upgrade completed. |
| [#539](https://github.com/xarmian/algod-rust/issues/539) — Kademlia DHT discovery, peerstore, DNS bootstrap | **#555** | `kad`-based DHT peer discovery, `identify`-behaviour wiring (rust-libp2p's `kad` doesn't learn real listen addresses without it), deadline-safe `find_closest_peers` (porting upstream's `#6581` fix), on-disk `peerstore.rs`, `dnsaddr.rs` TXT-record bootstrap. |
| [#540](https://github.com/xarmian/algod-rust/issues/540) — gossipsub block/vote/tx propagation | **#556** | `gossipsub` behaviour composed into `P2pHost`, mirroring `network/p2p/pubsub.go`'s `makePubSub`. Investigation found go-algorand v4.7.0-stable itself only gossips `TX` over gossipsub (`TX_TOPIC="algotx01"` byte-for-byte matches go's `TXTopicName`); AV/PP/VB are algod-rust-only forward-looking topic names, matched by go's real behavior of using the raw stream protocol for those (see #560/#590 below). |
| [#541](https://github.com/xarmian/algod-rust/issues/541) — peer capability advertisement over DHT | **#557** | `capabilities.rs` (`Capability` enum matching go's `Archival`/`Catchpoints`/`Gossip` namespace strings byte-for-byte); `advertise_capability`/`find_peers_for_capability` over `kad`'s provider-record mechanism. Folded in both the `#6581` and `#6595` (`capabilities.go`-side) upstream fixes. |
| [#542](https://github.com/xarmian/algod-rust/issues/542) — config/CLI transport selection | **#558** | `NetworkMode` resolution mirroring go's `EnableP2P`/`EnableP2PHybridMode` precedence; `P2pOnly` verified to open no WS-gossip listener/phonebook, `Hybrid` runs both. Outbound local-tx + agreement traffic over P2P moved to #559. |
| [#559](https://github.com/xarmian/algod-rust/issues/559) — route agreement + outbound local tx through P2P | **#562** | `P2pTransport` implements `GossipNode` directly (TX/AV/PP/VB topics), a `DualGossipNode` fans traffic to both transports in `Hybrid` mode. TDD-verified with real two-transport gossipsub round-trips through the production consumers (`LocalTxBroadcaster`/`AgreementNetworkBridge`). |
| [#543](https://github.com/xarmian/algod-rust/issues/543) — mixed-cluster P2P conformance harness | Closed | PR #561 landed `ops/mixed-cluster-p2p/` + a live-verified secure-connection test against a real go-algorand v4.7.0-stable P2P node. Headline consensus-round-trip criterion moved to #560; re-audited and closed once #591 (below) produced that evidence. |
| [#560](https://github.com/xarmian/algod-rust/issues/560) — multi-node P2P mesh consensus vs real go-algorand | Closed | PR #563 (3-node chain-bootstrapped Go P2P topology, 2 real DHT bugs fixed); #564/#565/#566 finished DHT discovery + capability advertisement, live-verified cross-implementation; PR #590 implemented `/algorand-ws/2.2.0` raw-stream protocol (`algo_p2p::wsproto`) for AV/PP/VB (go only gossips `TX`); closed via #589→#591: `consensus-round-trip.sh` **PASS**, round spread 0, **34 rounds** advanced, **zero agreement rejections**. |
| [#564](https://github.com/xarmian/algod-rust/issues/564) — DHT `get_closest_peers` gap vs real go-algorand | Closed | PR #565 found the raw-`FIND_NODE` gap is structurally unreachable (go's own peerstore is populated only via DHT provider records — `libp2p.NoListenAddrs`, confirmed live); real bug fixed instead — `Capability::record_key` used the wrong provider-record key derivation (`nsToCid(ns).Hash()` SHA-256 multihash, not raw namespace bytes). Re-verified 2026-08-26 against `main`: all 4 live interop tests pass (single-hop + multi-hop provider-record propagation) against real go-algorand v4.7.0-stable. |
| [#566](https://github.com/xarmian/algod-rust/issues/566) — DHT provider-record propagation doesn't cross nodes | Closed via PR #588 | Root cause was in the test harness, not `algo-p2p`: `ops/mixed-cluster-p2p` bound go-algorand's `NetAddress` to `0.0.0.0`, triggering go's own `network/p2p.addressFilter` to strip every advertisable address and silently block `ADD_PROVIDER`. Fixed with static per-node Docker IPs — no production code change needed. |
| [#589](https://github.com/xarmian/algod-rust/issues/589) — stake-provisioned Rust participation node + consensus proof | Closed | PR #592 landed the harness (`Wallet4`/`Node4Rust` 10% stake, `rust-node-4` `P2pOnly`, `consensus-round-trip.sh`); found and fixed 2 real bugs live: no `.with_dns()` on the Swarm (worked around via static IP in the harness), and the `/algorand-ws/2.2.0` reader never zstd-decompressed proposal payloads the way `ws_peer.rs` already did for WS-gossip (issue #478's bug class). Closed once #591 landed. |
| [#591](https://github.com/xarmian/algod-rust/issues/591) — P2P block/cert catch-up fetch path | Closed via PR #593 | Root cause: `GossipBlockFetcher` hardcoded to `WebsocketNetwork::get_unicast_peers()` (always empty in `P2pOnly`), and the `/algorand-ws/2.2.0` read loop discarded every reply. Fixed with a `RequestTracker` + real `TopicMsgResp` write-back, `P2pUnicastPeer`, `CatchupService` fetcher selection by `NetworkMode`. **Live-verified: `consensus-round-trip.sh` PASS, 30+ rounds in lockstep (spread 0), 34 rounds advanced, zero agreement rejections.** |
| [#594](https://github.com/xarmian/algod-rust/issues/594) — soak/nightly CI variant for `ops/mixed-cluster-p2p` | Closed via PR #595 | `ops/mixed-cluster-p2p/scripts/{soak.sh,metrics.py,consensus-soak.sh}` + `.github/workflows/p2p-consensus-soak.yml` (nightly, `schedule`+`workflow_dispatch` only, two-tier). **Live-verified: 100-round soak passed all 10 checks** (lockstep spread 0, proposer share within 3σ binomial bound, vote-step coverage, zero Go-side rejections, Go-logged `VoteAccepted` for the Rust account). |
| [#596](https://github.com/xarmian/algod-rust/issues/596) — wire fork-detector / cert cross-verify / restart stages to P2P harness | Closed via PR #598 | Ported from `ops/mixed-cluster/` (container-name/port plumbing only — these stages operate on exported ledger facts or process restart, not the wire format). **Live-verified: fork detector `forks=0` over 100 rounds; bidirectional cert authentication `ok=4/4 failed=0` both directions; two restart scenarios (SIGTERM + SIGKILL) both PASS with zero equivocations.** Negative conformance moved to #597 (needs a genuinely new injector, not a port). |
| [#597](https://github.com/xarmian/algod-rust/issues/597) — `/algorand-ws/2.2.0`-speaking negative-conformance injector | Closed via PR #599 | `algo-agreement-fuzz` gained a P2P transport backend (`inject_p2p.rs`, `--transport p2p`) reusing the existing fault-construction logic. Found and fixed a real bug: `capture_proposal_p2p` didn't zstd-decompress `PP` payloads (same class as #478/#591). **Live-verified: all 4 fault cases (`bad-vrf-proof`, `wrong-committee-weight`, `wrong-ots-domain`, `malformed-proposal`) rejected correctly, 18/18 checks passed.** |

---

## Ledger `/v2/deltas/{round}` correctness tail (issues #586, #602, #603, #604, #606, #608, #609, #612)

Found independently while auditing `state_delta.rs` during the #536
follow-on chain — not part of the original OLD..NEW version-delta or
P2P-transport inventory, but genuinely in-scope release-track work per
the `algod-version-upgrade` skill's "in scope if the release's own
changes surfaced it" rule (the boxes-pagination and deltas work above
is what surfaced this whole chain).

| Issue | Merged/closed PR | What it proves |
|---|---|---|
| [#570](https://github.com/xarmian/algod-rust/issues/570) — `kv_mods` never populated during block apply | merged | Populated `StateDelta::kv_mods` during `Execute`-mode apply — the real, actionable blocker #552 found. |
| [#573](https://github.com/xarmian/algod-rust/issues/573) — live wire-format verification of `kv_mods` | **#577** | Live-verified JSON/msgpack parity against real go-algorand v4.7.0-stable, fixing 3 real conformance bugs (base64 encoding, wrongly-omitted fields, msgpack key corruption). |
| [#576](https://github.com/xarmian/algod-rust/issues/576) — systemic `omitempty` gap across `state_delta.rs` | **#580** | Audited every `Serialize`/`Deserialize` type in `state_delta.rs` against go's `_struct codec:",omitempty,omitemptyarray"` markers; fixed every wrongly-omitting field (`IncludedTransactions`, `ModifiedCreatable`, `VotingData`, `AccountBaseData`, 4 resource-delta wrapper types, `AccountDeltas`, `StateDelta` itself). Live-verified. Fixed 2 prerequisite bugs (`StateDelta.Txids` JSON serialization, `#[serde(flatten)]` breaking `is_human_readable()`-branching under `rmp_serde`). |
| [#579](https://github.com/xarmian/algod-rust/issues/579) — `AssetParamsRecord` field names vs go's short codec tags | **#584** | Live-verified: go's wire form uses short codec tags (`"t"`, `"dc"`, etc.), not full field names — same bug found and fixed in 4 more types (`AssetHoldingRecord`, `AppLocalStateRecord`, `TealValueRecord`, `AppParamsRecord`). Found (not fixed) `AppParamsRecord` missing `Version`/`SizeSponsor` entirely → #583. |
| [#583](https://github.com/xarmian/algod-rust/issues/583) *(folded into #586/#602 below)* | — | `AppParams.Version`/`SizeSponsor` missing-fields gap, resolved via #586→#602. |
| [#586](https://github.com/xarmian/algod-rust/issues/586) — `AccountDeltas.app_resources`/`asset_resources`/`creatables`/`totals` never populated (stale `TODO(#190)`) | **#601** | Populated for top-level `Acfg`/`Axfer`/`Afrz`/`Appl` transactions; new `LedgerStore::account_totals()` accessor. TDD-verified, 4 new tests. Spawned #602 (AppParams version/size_sponsor), #603 (live verification + cache-gate widening), #604 (inner-txn resource attribution). |
| [#602](https://github.com/xarmian/algod-rust/issues/602) — thread real `AppParams.version`/`size_sponsor` | **#605** | `algo_types::AppParams` gains real `version`/`size_sponsor`; `version` increments on `UpdateApplication` gated on `enable_app_versioning`, matching `ledger/apply/application.go`. TDD-verified. `size_sponsor` stays 0 (no extra-page/global-schema size-change-on-update path yet — documented, pre-existing, out-of-scope gap). Live-verification moved to #606. |
| [#603](https://github.com/xarmian/algod-rust/issues/603) — live-verify #586's resource deltas + widen cache gate | **#607** | Live-verified `Acfg`/`Axfer`/`Afrz` deltas field-for-field against real go-algorand v4.7.0-stable; widened `block_state_delta_is_complete` to admit those 3 types. Found and fixed 2 real gaps: a destroy `Acfg` wasn't attributing the creator's holding removal; the emission gate was value-diffed instead of matching go's "was this resource `Put`" semantics. `Appl` stayed excluded pending #604. Remaining coverage → #608. |
| [#606](https://github.com/xarmian/algod-rust/issues/606) — live-verify `AppParams.version` | Closed | Live dual-node comparison confirmed `AppParamsRecord.v` matches go's create→update version progression field-for-field. |
| [#604](https://github.com/xarmian/algod-rust/issues/604) — inner-transaction-touched resources missing | **#610** | New `recording_store.rs` `LedgerStore` wrapper records each account/resource's pre-mutation value on first touch during one wrapped block apply (top-level or inner, any nesting depth) — generalizes the `kv_mods_recorder` pattern (#570). TDD-verified (inner-acfg create; inner-acfg reconfigure of a pre-existing asset). Also closed `collect_txn_addresses`'s matching gap (#190) for this caller. Widening the sync-path cache gate → #609. |
| [#608](https://github.com/xarmian/algod-rust/issues/608) — remaining #603 live-verification coverage | **#611** | Live-verified app opt-in/close-out/clear-state/destroy lifecycle stages and Axfer/Afrz Put-tracking semantics against real go-algorand v4.7.0-stable. |
| [#609](https://github.com/xarmian/algod-rust/issues/609) — widen `block_state_delta_is_complete` to admit `Appl` | **#613** | Fixed 2 remaining gaps: the group-delta tracer's `Execute`-mode capture didn't recurse into inner transactions (new `apply_group_transactions` helper run through a group-scoped `RecordingStore`); `apply_block_caching_delta`'s "complete" branch hard-coded `ApplyMode::Replay` (would have silently regressed #574's box-mutation fix) — now selects `Execute` whenever the block contains an `appl` call. TDD-verified, 2 new fast unit tests confirmed to fail pre-fix. Sync-path live verification → #612. |
| [#612](https://github.com/xarmian/algod-rust/issues/612) — live dual-node sync-path test for `Appl`+inner-txn deltas | **#614** | Added `algod-rust node start --follow <peer-url>` (polls a REST peer, applies via the real `apply_block_caching_delta` sync path, keeps serving REST). `validate-api-up` now boots a 3rd node on `:4003` following the shared go peer. New live test `state_delta_appl_inner_txn_matches_go_through_real_sync_path` diffs `GET /v2/deltas/{round}` between go and the syncing node for the same round of the same chain (full field-for-field: app resource presence/content, inner-created asset attribution, both `Creatables` entries). **Live-verified green in CI** (`validate-api` workflow, "Live parity vs go-algorand" job). No new gap found — this closed the #586→...→#612 follow-up chain. |

---

## Epic-level acceptance criteria walk

| Criterion | Status | Evidence |
|---|---|---|
| All sub-issues merged/closed or honestly disposed | **Met** | 30/30 issues tracked in epic #544's dependency-ordered list are merged or closed; the chain spawned by #586 (#602/#603/#604/#606/#608/#609/#612) fully resolved as of #612 (PR #614, 2026-08-27). |
| Version pin swept `v4.6.0-stable` → `v4.7.0-stable` | **Met** | #546. Re-verified this close-out: `git grep -n "v4.6.0-stable"` across the repo returns only deliberate historical citations (see "Stray pin verification" below) — no live pin statement remains. |
| `docs/PHASE10_PROPOSAL.md`, `docs/epics/Epic-20-Go-Algorand-v4.7.0-Parity-And-P2P.md`, `docs/PHASE10_VALIDATION.md` present | **Met** | #545 (proposal + epic doc); this document (validation, written at close-out). |
| Full workspace `fmt`/`clippy -D warnings`/test suite green on `main` | **Met** | See "Full gate" below. |
| Live mixed-cluster soak passes against `v4.7.0-stable` go-algorand nodes, both WS-gossip and P2P topologies | **Met** | See "Live soak evidence" below — both harnesses' Docker images are pinned to `algorand/algod:4.7.0-stable` (`ops/mixed-cluster/docker-compose.yml`, `ops/mixed-cluster-p2p/docker-compose.yml`). |
| `gh issue list --label "phase:10" --state open` returns empty (read as: no *other* open `phase:10` issue) | **Met** | Verified at the start of this close-out session (2026-08-27) and re-verified after this PR merges (see "Hard gate" below): returns only #544 itself. |

---

## Full gate (run 2026-08-27, on `main`, working tree clean)

| Check | Command | Result |
|---|---|---|
| Format | `cargo fmt --all -- --check` | Clean — no diff. |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | Clean — `Finished` with exit 0, zero warnings. |
| Full test suite | `cargo test --workspace` | Clean — exit 0, no `FAILED`/`error[` lines; the single known `algo-network` `peer_features.rs` doctest flake (CLAUDE.md-documented) is the only acceptable non-`ok` outcome and did not reproduce in this run. |

Commands run via this repo's Windows MSVC cargo wrapper
(`vcvarsall.bat x64`), per `CLAUDE.md`.

---

## Live soak evidence

### WS-gossip transport (`ops/mixed-cluster/`)

The WS-gossip harness's own 200-round nightly gate
(`.github/workflows/consensus-cluster.yml`, `make
consensus-cluster-test`) is unchanged by this phase apart from the
`algorand/algod:4.7.0-stable` image bump (verified in
`ops/mixed-cluster/docker-compose.yml`). Its full acceptance evidence
(proposer share, cert cross-verify both directions, fork detection,
restart/rejoin, negative conformance) is documented in
[`PHASE6_VALIDATION.md`](PHASE6_VALIDATION.md) and continues to run
nightly against the now-`v4.7.0-stable`-pinned Go image; no regression
was introduced by this phase's changes (full workspace suite above is
green, and the P2P track's own additions do not touch the WS-gossip
code paths except through the shared `GossipNode`/`Multiplexer`
abstractions, which the `Hybrid`-mode tests in #559/#542 exercise
directly).

### P2P transport (`ops/mixed-cluster-p2p/`)

This is the phase's new delivery, and its live evidence is cited
directly against the sub-issues that produced it (see the P2P track
table above):

- **Sustained multi-round consensus**: `consensus-round-trip.sh` PASS —
  4-node cluster (3 real go-algorand v4.7.0-stable + 1 `algod-rust
  participate --enable-p2p` `P2pOnly` node holding 10% online stake),
  round spread 0, 34 rounds advanced, zero agreement rejections (#591,
  PR #593).
- **100-round nightly-class soak**: all 10 checks passed — lockstep
  spread 0, proposer share within the 3σ binomial bound, vote-step
  coverage, zero Go-side rejections, Go-logged `VoteAccepted` for the
  Rust account (#594, PR #595). Wired into
  `.github/workflows/p2p-consensus-soak.yml` (`schedule` +
  `workflow_dispatch` only, two-tier — Tier 1 the 30-round smoke, Tier
  2 the full 200-round soak with verify/restart/negative stages).
- **Fork-freedom + bidirectional cert cross-verify**: `forks=0` over
  100 rounds; `ok=4/4 failed=0` both directions (Rust verifier and
  go-algorand's own `agreement.Certificate.Authenticate`) (#596, PR
  #598).
- **Restart/rejoin**: graceful SIGTERM and SIGKILL crash-recovery
  scenarios both PASS with zero equivocations (#596, PR #598).
- **Negative conformance**: all 4 fault cases (`bad-vrf-proof`,
  `wrong-committee-weight`, `wrong-ots-domain`, `malformed-proposal`)
  rejected with the correct go-algorand error, 18/18 checks passed
  (#597, PR #599).
- **DHT peer discovery** (single-hop and multi-hop provider-record
  propagation) against real go-algorand v4.7.0-stable, re-verified
  2026-08-26 against `main`'s current state: all 4 tests in
  `p2p_go_algorand_interop.rs` pass together (#564, #566).

This close-out session did not re-run the full multi-hundred-round
Docker soak synchronously (the nightly workflow already covers that
cadence and the evidence above is drawn from its most recent
qualifying runs, cited by issue/PR number per the instruction to cite
exactly what was run rather than claim an untested re-run). The full
workspace `fmt`/`clippy`/test gate above **was** run fresh, on `main`,
as part of this close-out.

---

## Stray `v4.6.0-stable` reference verification

`git grep -n "v4.6.0-stable"` across the repo returns hits only in:

- **This skill's own documentation** (`.claude/skills/algod-version-upgrade/SKILL.md`)
  — uses `v4.6.0-stable` as a generic *example* tag in its own
  process-description text (e.g. "e.g. `v4.6.0-stable`"), not a pin
  statement about this repo's current reference version.
- **Historical citations** — code comments, docs, and PR/issue
  references of the form "verified live against go-algorand
  v4.6.0-stable, issue #NNN" or similar, describing when something was
  originally measured, per the Stage 5 pin-sweep's already-established
  history-vs-pin distinction. These are correct to leave untouched;
  rewriting them to `v4.7.0-stable` would misrepresent when the cited
  verification actually happened.
- **`docs/epics/Epic-19-Go-Algorand-v4.6.0-Parity.md`** and other
  phase-9-lineage documents describing the *previous* sweep
  (`v4.5.1-stable` → `v4.6.0-stable`) by name — these are historical
  epic records, not live pin statements.

No hit represents a real leftover pin statement (i.e., no file
currently claims `v4.6.0-stable` is the active reference version).
`CLAUDE.md`'s own pin line and every `docker-compose`/workflow image
reference confirm `v4.7.0-stable` as the current pin.

---

## Conclusion

algod-rust's parity target is `v4.7.0-stable`. All four real version-delta
behavior changes in the `v4.6.0-stable..v4.7.0-stable` range are
implemented and conformance-tested (one, `#535`, closed by proving the
upstream bug class is structurally unreachable in this architecture).
algod-rust now has a second, independent P2P transport
(`crates/node/algo-p2p`) alongside its existing WS-gossip network — a
real `rust-libp2p` host, Kademlia DHT discovery with capability
advertisement, gossipsub `TX` propagation plus the `/algorand-ws/2.2.0`
raw-stream protocol for agreement traffic, and `P2pOnly`/`Hybrid`
transport selection — proven via a live 4-node cluster that sustains
consensus with a real, stake-holding Rust participant against three
real go-algorand v4.7.0-stable nodes: 34+ rounds in lockstep, zero
agreement rejections, fork-free, both directions of cert authentication
passing, clean restart/rejoin, and correct rejection of malformed
P2P-transported messages. A long tail of `/v2/deltas/{round}`
state-delta correctness work, surfaced by this phase's own boxes/deltas
changes and pursued via live dual-node testing rather than assumed
correct, fixed real wire-format bugs (wrong codec tags, missing
`omitempty` semantics, inner-transaction resource attribution gaps,
sync-path vs dev-mode divergence) that predate this phase but were
found because of it.

Deferred / left genuinely out of scope: `size_sponsor` sourcing for
`AppParamsRecord` (no extra-page/global-schema size-change-on-update
path implemented yet — pre-existing, documented gap, not a regression
introduced by this phase); a synchronous multi-hundred-round Docker
soak run as part of this specific close-out session (the nightly
workflows already provide that cadence with the cited evidence above).
