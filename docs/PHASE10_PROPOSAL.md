# Phase 10: go-algorand v4.7.0-stable Parity + libp2p P2P Transport

## Goal

Move algod-rust's parity target from go-algorand `v4.6.0-stable` to `v4.7.0-stable`, closing every behavioral gap the release introduces and re-pinning the reference checkout — and, folded into this same phase by explicit decision rather than deferred, close the longstanding gap where algod-rust implements only the legacy WebSocket gossip network and has no libp2p-based P2P transport (go-algorand's `network/p2p/` package).

## Scope

`TAGS_IN_RANGE` for the version delta: `v4.6.0-stable` (OLD) → `v4.7.0-beta` → `v4.7.0-stable` (NEW). Every version-delta change in range originates from `v4.7.0-beta`.

**Version-delta items** (`v4.6.0-stable..v4.7.0-stable`):

- A new `vFuture`-gated consensus param, `LoadTracking`, plus new block-header field(s) tracking recent-block "fullness" and a derived congestion-tax fee adjustment. Not yet active on MainNet/TestNet, but tracked for private-network/conformance parity alongside algod-rust's other already-tracked `vFuture` params.
- A ledger correctness fix so account/asset/app "params" REST lookups see values that exist only in an uncommitted in-memory delta, not just what has been flushed to storage.
- Cursor-based pagination with prefix filtering added to the application-boxes list REST endpoint, backed by new tracker-db range-query support.
- A robustness fix to fast-catchup error handling so specific recoverable errors during catchpoint fetch/apply no longer abort the node process.

**New-scope P2P transport work** (not part of the OLD..NEW diff — go-algorand's `network/p2p/` package predates this version range; building a Rust equivalent is included in this phase per explicit user decision that a version-upgrade checkpoint is also the right time to close this parity gap):

- A libp2p host/identity/secure-connection foundation (`rust-libp2p`, Noise transport, multistream-select).
- Kademlia DHT peer discovery, persistent peerstore, and DNS-based bootstrap — folding in the `v4.7.0-beta` fix that stops a DHT context-deadline from being treated as a hard error.
- Gossipsub-based propagation of blocks, votes, and transactions over the new P2P transport, wired into the existing broadcast/consume interfaces already used by the WS-gossip stack.
- Peer capability advertisement over the DHT (e.g. archival, catchpoint-source), folding in the remaining piece of the `v4.7.0-beta` fast-catchup error-handling fix that touches `network/p2p/capabilities.go`.
- Config/CLI surface to enable P2P-only or hybrid (WS-gossip + P2P simultaneously) transport mode.
- A P2P-topology extension to the mixed-cluster conformance harness, verifying interop with real go-algorand P2P nodes.

## Non-Goals (explicitly out of scope this phase)

See epic #544 for the full classified inventory with per-item justification. In summary, of the remaining upstream `v4.6.0-stable..v4.7.0-stable` PRs:

- One assembler change (`optimizeConstants` single-pass rewrite) is verified byte-for-byte-output-identical — pure performance refactor, no behavioral delta.
- One `goal --rekey-to` CLI flag targets go-algorand's `goal` binary; algod-rust's planned `goal-rust` operator CLI does not exist yet in this repo — a pre-existing, unrelated gap, not this phase's concern.
- Six items are Go-internal build/CI/test/logging-library fixes with no Rust equivalent surface (dependabot bump, copyright header, CI Slack webhook config, logrus atomic-accessor race fix, a pure log-output double-logging fix, two Go test-flakiness fixes, a macOS SDK build fix, a Go SDK codegen script update).
- The upstream `libp2p` Go-dependency version bump (`#6564`) has no direct porting step — the new Rust P2P stack (in scope above) is built fresh on current `rust-libp2p`, which starts from current dependency versions rather than needing an "upgrade."

## Conformance Standard

Byte-level/behavioral parity with go-algorand `v4.7.0-stable` for every in-scope version-delta item, verified against real go-algorand `v4.7.0-stable` binaries (`../go-algorand`, re-pinned as part of this phase) via this repo's conformance harness. For the P2P work, wire-level interop with real go-algorand P2P nodes (DHT discovery, gossipsub message format, capability records) via an extended mixed-cluster harness.

## Issue Table

| Sub-issue | Title | Issue | Effort | Dependencies |
|---|---|---|---|---|
| 1 | consensus: vFuture LoadTracking block-header and congestion-tax support | [#534](https://github.com/xarmian/algod-rust/issues/534) | Large | None |
| 2 | ledger+api: correct account/asset/app params from uncommitted deltas | [#535](https://github.com/xarmian/algod-rust/issues/535) | Medium | None |
| 3 | api: cursor-based pagination with prefix support for application boxes | [#536](https://github.com/xarmian/algod-rust/issues/536) | Medium | None |
| 4 | sync: improve error-handling robustness in fast-catchup mode | [#537](https://github.com/xarmian/algod-rust/issues/537) | Small | None |
| 5 | network(p2p): libp2p host, identity, and secure peer-connection foundation | [#538](https://github.com/xarmian/algod-rust/issues/538) | Large | None |
| 6 | network(p2p): Kademlia DHT peer discovery, peerstore, and DNS bootstrap | [#539](https://github.com/xarmian/algod-rust/issues/539) | Large | #538 |
| 7 | network(p2p): gossipsub-based block/vote/tx propagation over P2P | [#540](https://github.com/xarmian/algod-rust/issues/540) | Large | #538 (sequenced after #539) |
| 8 | network(p2p): peer capability advertisement over DHT | [#541](https://github.com/xarmian/algod-rust/issues/541) | Medium | #539 |
| 9 | network(p2p): config/CLI surface and WS-gossip/P2P/hybrid transport selection | [#542](https://github.com/xarmian/algod-rust/issues/542) | Medium | #538, #539, #540, #541 |
| 10 | network(p2p): mixed-cluster conformance harness for P2P interop with go-algorand | [#543](https://github.com/xarmian/algod-rust/issues/543) | Large | #538, #539, #540, #541, #542 |

## Dependency Graph

```
#534, #535, #536, #537 — all independent of each other and of the P2P track
#538 → #539 → #541
   \-> #540 (after #539 for discovery, though only #538 is a hard dependency)
#538, #539, #540, #541 → #542 → #543
```

## Critical Path

`#538 → #539 → #540/#541 → #542 → #543` for the P2P track (six sequential large/medium issues). The version-delta issues (`#534`-`#537`) are independent and worked first per the "consensus params/encoding first" convention, unblocking the version-pin sweep early; the P2P track proceeds after.

## Success Criteria

See epic #544's acceptance criteria: all ten sub-issues merged (or honestly disposed), the version-pin sweep completed across the repo, this doc plus `docs/epics/Epic-20-Go-Algorand-v4.7.0-Parity-And-P2P.md` and `docs/PHASE10_VALIDATION.md` written, `docs/PROJECT_SCOPE.md` updated, and the full gate (fmt/clippy/tests/conformance) green on `main` with the reference pinned to `v4.7.0-stable`, including a live mixed-cluster soak against `v4.7.0-stable` go-algorand nodes covering both WS-gossip and the new P2P topology.
