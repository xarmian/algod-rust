# Epic 20: go-algorand v4.7.0-stable Parity + libp2p P2P Transport

Tracking issue: [#544](https://github.com/xarmian/algod-rust/issues/544)
Phase: [Phase 10](../PHASE10_PROPOSAL.md)

## Summary

Move algod-rust's parity target from go-algorand `v4.6.0-stable` (`0915527b4c462381d9afeabcd697703c9fbf61f9`) to `v4.7.0-stable` (`6927d906446d404705e46dcb8ecd759b642374c2`). No consensus/protocol version upgrade is contained in this release (the one new consensus param, `LoadTracking`, is `vFuture`-gated only). `TAGS_IN_RANGE`: `v4.6.0-stable` (OLD) → `v4.7.0-beta` → `v4.7.0-stable` (NEW); every version-delta change originates from `v4.7.0-beta`.

Folded into this same epic, per explicit decision made while scoping this upgrade rather than deferred to a separate phase: closing the longstanding gap where algod-rust implements only the legacy WebSocket gossip network and has no libp2p-based P2P transport (go-algorand's `network/p2p/` package). Three prior phases (5, 9, and the v4.6.0 epic) had each independently and deliberately scoped libp2p out; this epic reverses that decision.

## Classified Inventory

### consensus-critical

| Upstream PR | Change | Sub-issue |
|---|---|---|
| [#6548](https://github.com/algorand/go-algorand/pull/6548) | Blocks: Add support for Load and CongestionTax blockheaders (`vFuture`-gated) | [#534](https://github.com/xarmian/algod-rust/issues/534) |

### ledger / api

| Upstream PR | Change | Sub-issue |
|---|---|---|
| [#6588](https://github.com/algorand/go-algorand/pull/6588) | API: Deal with params that are in deltas | [#535](https://github.com/xarmian/algod-rust/issues/535) |
| [#6558](https://github.com/algorand/go-algorand/pull/6558) | API: Add cursor-based pagination with prefix support to application boxes | [#536](https://github.com/xarmian/algod-rust/issues/536) |

### behavioral-other (sync)

| Upstream PR | Change | Sub-issue |
|---|---|---|
| [#6595](https://github.com/algorand/go-algorand/pull/6595) | chore: better error handling in fast catchup mode | [#537](https://github.com/xarmian/algod-rust/issues/537) (catchup-service side), [#541](https://github.com/xarmian/algod-rust/issues/541) (network/p2p/capabilities.go side, folded into P2P work) |

### network (P2P transport — folded-in new scope + version-delta fixes)

| Upstream PR / item | Change | Sub-issue |
|---|---|---|
| [#6564](https://github.com/algorand/go-algorand/pull/6564) | network: upgrade libp2p ecosystem to fix dependabot security alerts | No direct porting step — the new Rust P2P stack is built fresh on current `rust-libp2p`, superseding the need to "upgrade" from an old baseline |
| [#6581](https://github.com/algorand/go-algorand/pull/6581) | dht: do not err on context deadline | Folded into [#539](https://github.com/xarmian/algod-rust/issues/539) and [#541](https://github.com/xarmian/algod-rust/issues/541) as acceptance criteria |
| *(new scope, not from OLD..NEW diff)* | libp2p host, identity, secure connections | [#538](https://github.com/xarmian/algod-rust/issues/538) |
| *(new scope)* | Kademlia DHT peer discovery, peerstore, DNS bootstrap | [#539](https://github.com/xarmian/algod-rust/issues/539) |
| *(new scope)* | gossipsub block/vote/tx propagation | [#540](https://github.com/xarmian/algod-rust/issues/540) |
| *(new scope)* | peer capability advertisement over DHT | [#541](https://github.com/xarmian/algod-rust/issues/541) |
| *(new scope)* | config/CLI surface, WS-gossip/P2P/hybrid selection | [#542](https://github.com/xarmian/algod-rust/issues/542) |
| *(new scope)* | mixed-cluster P2P conformance harness | [#543](https://github.com/xarmian/algod-rust/issues/543) |

### not-applicable (justified)

| Upstream PR | Change | Why not applicable |
|---|---|---|
| [#6598](https://github.com/algorand/go-algorand/pull/6598) | assembler: single-pass optimizeConstants using cumulative delta array | Verified byte-for-byte-identical bytecode output via full diff read — pure performance refactor (O(n²) shift-per-change → single cumulative-delta pass), zero behavioral change |
| [#6571](https://github.com/algorand/go-algorand/pull/6571) | Goal: Add --rekey-to flag for calling applications | Targets go-algorand's `goal` CLI; algod-rust's planned `goal-rust` operator CLI does not exist yet in this repo — pre-existing, unrelated gap |
| [#6610](https://github.com/algorand/go-algorand/pull/6610) | build: combine dependabot dependency upgrades (April 2026) | Go dependency bumps, no Rust equivalent |
| [#6611](https://github.com/algorand/go-algorand/pull/6611) | Legal: Update copyright to the Foundation | Copyright header text only |
| [#6597](https://github.com/algorand/go-algorand/pull/6597) | CICD: update actions to use SLACK_WEBHOOK_URL | go-algorand's own CI notification config |
| [#6599](https://github.com/algorand/go-algorand/pull/6599) | logging: use atomic logrus level accessors to prevent data races | Go-internal logging-library race fix; algod-rust does not use logrus, no observable behavior change |
| [#6583](https://github.com/algorand/go-algorand/pull/6583) | network: fix double logging with elevated level | Pure log-output fix, no wire/protocol/API behavior change |
| [#6593](https://github.com/algorand/go-algorand/pull/6593) | tests: fix data race in catchpoint tests | go-algorand's own Go test-suite flakiness fix |
| [#6591](https://github.com/algorand/go-algorand/pull/6591) | tests: fix TestDiscardUnrequestedBlockResponse race | go-algorand's own Go test-suite flakiness fix |
| [#6589](https://github.com/algorand/go-algorand/pull/6589) | build: fix MacOS 14 SDK and XCode 16.x issue | Go build tooling for macOS |
| [#6584](https://github.com/algorand/go-algorand/pull/6584) | scripts: update go sdk type exporter | Go SDK codegen tooling, unrelated to algod-rust's own type generation |

## Dependency Order

1. [#534](https://github.com/xarmian/algod-rust/issues/534) — vFuture LoadTracking/congestion-tax
2. [#535](https://github.com/xarmian/algod-rust/issues/535) — ledger delta-params correctness fix
3. [#536](https://github.com/xarmian/algod-rust/issues/536) — boxes cursor pagination + prefix
4. [#537](https://github.com/xarmian/algod-rust/issues/537) — fast-catchup error-handling robustness
5. [#538](https://github.com/xarmian/algod-rust/issues/538) — P2P host/identity foundation
6. [#539](https://github.com/xarmian/algod-rust/issues/539) — P2P DHT/peerstore/bootstrap (depends on #538)
7. [#540](https://github.com/xarmian/algod-rust/issues/540) — P2P gossipsub propagation (depends on #538, sequenced after #539)
8. [#541](https://github.com/xarmian/algod-rust/issues/541) — P2P capability advertisement (depends on #539)
9. [#542](https://github.com/xarmian/algod-rust/issues/542) — P2P config/CLI/hybrid selection (depends on #538-#541)
10. [#543](https://github.com/xarmian/algod-rust/issues/543) — P2P mixed-cluster harness (depends on #538-#542)

Items 1-4 are independent of each other and of the P2P track (5-10), and are worked first to unblock the version-pin sweep early.

## Acceptance Criteria

- [ ] All ten sub-issues (#534-#543) merged, or honestly disposed per this repo's issue-disposition rules
- [ ] Version-pin sweep completed (`CLAUDE.md`, docs, CI workflows, `tools/cert-authenticate`, `Makefile`, `ops/mixed-cluster*/`, code comments)
- [ ] `docs/PHASE10_PROPOSAL.md` (this epic's parent) and this doc committed
- [ ] `docs/PROJECT_SCOPE.md` updated to mention Phase 10 and the new P2P transport
- [ ] `docs/PHASE10_VALIDATION.md` written at close-out citing evidence per criterion
- [ ] Full gate green on `main`: fmt, clippy, full workspace suite, conformance suite, reference pinned to `v4.7.0-stable`
- [ ] Live mixed-cluster soak passes against `v4.7.0-stable` go-algorand nodes, both WS-gossip and (new) P2P topologies
- [ ] No stray `v4.6.0-stable` references remain outside deliberate history
