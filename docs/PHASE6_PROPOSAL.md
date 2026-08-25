# Phase 6: Consensus Participation

## Goal

Transform algod-rust from a follower/relay node into a full participation node capable of proposing blocks and voting in Algorand's consensus protocol alongside Go nodes.

## Scope

Implement the complete consensus participation stack:
- VRF proof generation and sortition for committee selection
- One-time signature (OTS) key management with forward-secure deletion
- Agreement protocol types, verification, and state machine
- Service integration wiring the state machine to network, ledger, and key manager
- Mixed-cluster conformance testing proving interoperability with Go nodes

## Conformance Standard

100% protocol conformance with go-algorand. The Go reference implementation (`../go-algorand`, pinned to `v4.7.0-stable`) is the source of truth for all protocol behavior, field values, algorithm implementations, domain separation strings, consensus parameters, and edge cases.

## Issue Table

| Epic | Title | Issue | Effort | Dependencies |
|------|-------|-------|--------|--------------|
| 37 | Cryptographic Primitives and Agreement Params | [#101](https://github.com/xarmian/algod-rust/issues/101) | Large | None |
| 38 | Participation Key Loading and Signing | [#102](https://github.com/xarmian/algod-rust/issues/102) | Medium | #101 |
| 39 | Agreement Types, Selectors, and Verification | [#103](https://github.com/xarmian/algod-rust/issues/103) | Large | #101 |
| 41a | Agreement Service Interfaces | [#104](https://github.com/xarmian/algod-rust/issues/104) | Small | #101 |
| 40 | Agreement State Machine | [#105](https://github.com/xarmian/algod-rust/issues/105) | Large | #103, #104 |
| 41b | Agreement Service Integration | [#106](https://github.com/xarmian/algod-rust/issues/106) | Large | #102, #105, #104 |
| 42 | Mixed-Cluster Consensus Conformance Testing | [#107](https://github.com/xarmian/algod-rust/issues/107) | Medium | #106 |

## Dependency Graph

```
Epic 37 (#101) Crypto + Params
  |         \            \
  v          v            v
Epic 38    Epic 39      Epic 41a
(#102)     (#103)       (#104) Interfaces
  |           |           |       \
  |           v           v        |
  |         Epic 40 (#105)         |
  |           State Machine        |
  |            |                   |
  v            v                   v
  +--------> Epic 41b (#106) <----+
              Integration
                |
                v
              Epic 42 (#107)
              Conformance
```

## Critical Path

```
Epic 37 -> Epic 39 -> Epic 40 -> Epic 41b -> Epic 42
```

Epic 38 (key loading) and Epic 41a (interfaces) can proceed in parallel with Epic 39, but Epic 40 blocks on both Epic 39 and Epic 41a, and Epic 41b blocks on all three of Epics 38, 40, and 41a.

## New Infrastructure

### Crates
- `crates/core/algo-consensus-crypto` — VRF proof generation, sortition, OTS keygen/signing
- `crates/core/algo-agreement` — agreement types, selectors, verification, state machine, service

### Dependencies
- Possibly `libsodium-sys` for VRF proof generation (Go uses a libsodium fork)
- Pure Rust binomial CDF for sortition (`num-bigint` already in workspace)

## Success Criteria

1. VRF sortition produces identical committee membership decisions as Go (test vectors)
2. Rust votes accepted/verified by Go nodes in mixed cluster
3. Rust proposes blocks accepted by Go nodes
4. Rust correctly verifies Go votes
5. 200+ rounds in mixed 4-node cluster (3 Go + 1 Rust) with active participation
6. No forks; normal block cadence
7. Certificates with Rust votes verifiable by Go nodes during catchup

## Risks

| # | Risk | Severity | Mitigation |
|---|------|----------|------------|
| 1 | Lookback-state access — incorrect historical seed/stake snapshot | Highest | Extensive test vectors against Go output; careful `balanceRound`/`seedRound` implementation |
| 2 | VRF proof fidelity — must match Go's libsodium fork exactly | High | May need to link same libsodium; byte-level proof comparison tests |
| 3 | Sortition precision — Go uses big.Float/C++ binomial CDF | High | Extended precision arithmetic; exhaustive input comparison against Go |
| 4 | OTS domain separation — hash IDs must match exactly | Medium | Domain separation string constants verified against Go source |
| 5 | State machine behavioral equivalence — timing-dependent behavior | High | Deterministic replay tests; event sequence comparison against Go |
| 6 | Valid block assembly — even empty blocks must be protocol-valid | Medium | Cross-validate assembled blocks with Go validation |
