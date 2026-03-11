# Phase 4 — Catchup and Sync

_Created: 2026-03-10_

## Goal

Add fast synchronization via catchpoint files and sequential block replay. Rust nodes can sync from a catchpoint to current state. This covers Conformance Layer 7: ensure the Rust node reconstructs the ledger identically to Go.

## Scope

**In scope:**
- Catchpoint file parsing (tar + Snappy + msgpack, Go `msgp` inner-blob compatibility)
- Catchpoint import with atomic staging-table cutover
- Catchpoint verification via Merkle trie rebuild
- Block header history store (bounded circular buffer for lookback queries)
- Parallel block fetcher with configurable concurrency
- Sequential sync from genesis or any starting round
- NormalizedOnlineBalance calculation matching Go
- Heartbeat transaction replay semantics
- Post-catchpoint block replay to current round
- Resume support for interrupted imports and syncs
- CLI `sync` and `sync --catchpoint` subcommands

**Out of scope:**
- Standalone snapshot export (Phase 5)
- Networking / gossip / peer discovery (Phase 5)
- Consensus participation (Phase 6)

**Scope clarification:** "Snapshots" = catchpoint files (Go's catchpoint files ARE the snapshot mechanism). Standalone snapshot export deferred to Phase 5.

## Epic Issues

| Epic | Title | Issue | Effort | Dependencies |
|------|-------|-------|--------|--------------|
| 25a | Block Header History Store | [#59](https://github.com/xarmian/algod-rust/issues/59) | Medium | — |
| 25b | Parallel Block Fetcher and Sequential Sync | [#63](https://github.com/xarmian/algod-rust/issues/63) | Medium | #59 |
| 26a | Catchpoint File Parser and Fixtures | [#60](https://github.com/xarmian/algod-rust/issues/60) | Medium | — |
| 26b | Catchpoint Importer and Atomic Cutover | [#64](https://github.com/xarmian/algod-rust/issues/64) | Large | #60, #59 |
| 28a | NormalizedOnlineBalance | [#61](https://github.com/xarmian/algod-rust/issues/61) | Small | — |
| 28b | Heartbeat Transaction Replay Semantics | [#62](https://github.com/xarmian/algod-rust/issues/62) | Small | — |
| 27 | Catchpoint Download, Verification, and Lookback Warmup | [#65](https://github.com/xarmian/algod-rust/issues/65) | Large | #64, #61, #59 |
| 29 | Sync Orchestrator and CLI Integration | [#66](https://github.com/xarmian/algod-rust/issues/66) | Large | All previous |

## Critical Path

**25a → 25b → 29** (header store → parallel fetch → orchestrator)

**26a → 26b → 27 → 29** (parser → importer → verify → orchestrator)

**28a → 27** (normalized balance → trie verification)

Longest path: **26a → 26b → 27 → 29**

## Dependency Graph

```
Track A: 25a (header store) -------> 25b (parallel fetch + CLI sync)
Track B: 26a (parser + fixtures) --> 26b (importer + atomic cutover)
Track C: 28a (normalized balance) -- gates Epic 27
Track D: 28b (heartbeat) ----------- independent until Epic 29

Convergence:
  25a + 26b + 28a --> 27 (download + verify + lookback warmup)
  All -------------> 29 (orchestrator + CLI + conformance)
```

## New Dependencies

- `snap = "1"` — Snappy decompression
- `tar = "0.4"` — tar archive streaming
- `flate2 = "1"` — gzip decompression

## Success Criteria

1. Fast sync from catchpoint file to valid ledger state
2. State root equality with Go node after catchpoint import + block replay
3. Non-hash metadata equality: `acctrounds`, `accounttotals`, `normalizedonlinebalance`, online round params, `catchpointstate`
4. Sequential sync from genesis with parallel downloads
5. `normalizedonlinebalance` matches Go calculation
6. Heartbeat transactions replayed correctly
7. CLI `algod-rust sync --catchpoint <label>` end-to-end
8. Resume support for interrupted catchpoint imports
9. 1000-round lookback history reconstructed post-catchpoint
10. Lease table correctly rebuilt from lookback headers

## Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Go `msgp` inner-blob encoding differs from standard msgpack | High | Build golden fixtures early (26a), test against real catchpoint data |
| Catchpoint files 500MB+ | Medium | Streaming parser, chunk-ordinal checkpointing |
| SQLite write contention | Medium | WAL mode, batch transactions |
| Atomic staging swap must include ALL tables | Medium | Enumerate complete table list from Go trackerdb |
| State proof verification context | Low | Deferred initially |
