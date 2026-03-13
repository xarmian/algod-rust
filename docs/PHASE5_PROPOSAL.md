# Phase 5: Networking Integration

Replace REST-based block ingestion with real P2P gossip networking. The Rust node becomes a full network participant: both observer (passive gossip receiver) and relay (accepting connections, serving blocks, forwarding messages).

## Goal

Implement go-algorand's WebSocket gossip protocol in Rust with 100% wire-format conformance, enabling the Rust node to participate in the Algorand P2P network alongside Go nodes without any protocol-level differences.

## Scope

- Gossip wire format: all 12 protocol tags, message framing, compression
- WebSocket peer connectivity: handshake, identity challenge, keepalive
- Peer discovery: DNS SRV records, phonebook management
- Message handling: tag-based dispatch, dedup, request/response correlation
- Block service: HTTP and WS unicast block fetching, sync integration
- Observer mode: multi-peer mesh, passive block receipt, ledger application
- Relay mode: incoming connections, block serving, message forwarding
- Mixed-cluster conformance testing (Conformance Layer 8)

## Epic Index

| Epic | Title | Issue | Effort | Dependencies |
|------|-------|-------|--------|--------------|
| 30 | Gossip Message Types and Protocol Wire Format | [#78](https://github.com/xarmian/algod-rust/issues/78) | Medium | None |
| 31 | WebSocket Peer Connectivity | [#79](https://github.com/xarmian/algod-rust/issues/79) | Large | #78 |
| 32 | Peer Discovery and Phonebook | [#80](https://github.com/xarmian/algod-rust/issues/80) | Medium | #78 |
| 33a | Message Handler Framework | [#81](https://github.com/xarmian/algod-rust/issues/81) | Medium | #79 |
| 33b | Block Service Client and Sync Integration | [#82](https://github.com/xarmian/algod-rust/issues/82) | Medium | #81 |
| 34 | Gossip Network Observer and Mesh Management | [#83](https://github.com/xarmian/algod-rust/issues/83) | Large | #80, #82 |
| 35 | Relay Node — Incoming Connections and Message Forwarding | [#84](https://github.com/xarmian/algod-rust/issues/84) | Large | #83 |
| 36 | Mixed-Cluster Conformance Testing | [#85](https://github.com/xarmian/algod-rust/issues/85) | Medium | #83, #84 |

## Critical Path

```
Epic 30 --> Epic 31 --> Epic 33a --> Epic 33b --> Epic 34 --> Epic 35 --> Epic 36
Epic 30 --> Epic 32 --------------------------------^
```

Epics 31 and 32 can proceed in parallel after Epic 30. The critical path runs through 30 -> 31 -> 33a -> 33b -> 34 -> 35 -> 36.

## New Infrastructure

- **New crate:** `crates/node/algo-network` — gossip protocol, WebSocket peers, mesh management, relay
- **New dependencies:** `tokio-tungstenite` (WebSocket), `hickory-resolver` (DNS SRV), `zstd` (compression), `futures-util` (async streams)
- **Docker:** Mixed Go+Rust cluster compose config for conformance testing

## Success Criteria

1. Rust connects to Go relay via WebSocket, completes full handshake including identity challenge
2. Rust discovers peers via DNS SRV records
3. Rust receives/deserializes all 12 gossip message tag types
4. Rust receives block proposals via gossip and applies to ledger
5. Rust fetches blocks from peers via block service (HTTP + WS unicast)
6. Rust maintains stable multi-peer connections with reconnect and mesh management
7. Rust relay accepts incoming connections from Go nodes
8. Rust relay serves blocks to Go nodes via BlockService
9. Rust relay correctly forwards/relays messages
10. Mixed Go+Rust cluster runs 1000+ rounds with identical ledger state
11. Standalone catchpoint export produces valid snapshot file
12. Conformance Layer 8 documented and passing
13. All existing tests pass
14. Zero clippy warnings
15. Graceful degradation: peer disconnect does not halt forward sync

## Risks

- **WebSocket handshake complexity:** go-algorand's handshake involves many headers and an identity challenge. Any mismatch causes connection rejection. Mitigated by wire fixture capture and step-by-step conformance testing.
- **Relay performance:** Message forwarding under load requires careful queue management and backpressure. Mitigated by matching go-algorand's broadcast thread design exactly.
- **DNS SRV reliability:** Bootstrap DNS may have availability issues. Mitigated by config-file fallback peer lists.
- **Protocol version evolution:** Future go-algorand versions may change the wire protocol. Mitigated by pinning to v4.5.1-stable and version negotiation support.

## Reference

All implementation guided by go-algorand source at `../go-algorand` (v4.5.1-stable). Key reference files:
- `protocol/tags.go` — protocol tags and max sizes
- `network/wsNetwork.go` — WebSocket network, handshake, mesh management, relay
- `network/wsPeer.go` — per-peer read/write loops
- `network/gossipNode.go` — GossipNode interface, message handlers
- `network/phonebook.go` — peer discovery and phonebook
- `network/identityTracker.go` — identity challenge protocol
- `network/msgOfInterest.go` — message interest negotiation
- `rpcs/blockService.go` — block serving (HTTP + WS)
- `config/local_defaults.go` — network configuration defaults
