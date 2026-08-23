# Epic 19: go-algorand v4.6.0-stable Parity

Tracking issue: [#503](https://github.com/xarmian/algod-rust/issues/503)
Phase: [Phase 9](../PHASE9_PROPOSAL.md)

## Summary

Move algod-rust's parity target from go-algorand `v4.5.1-stable` (`a8c16ecc2324cc10acb75de367c0b5dad4b0a5a3`) to `v4.6.0-stable` (`0915527b4c462381d9afeabcd697703c9fbf61f9`). No consensus/protocol version upgrade is contained in this release.

## Classified Inventory

### api (REST surface)

| Upstream PR | Change | Sub-issue |
|---|---|---|
| [#6577](https://github.com/algorand/go-algorand/pull/6577) | ledger: fix lookupAssetResources/lookupApplicationResources delta-merge bugs | [#504](https://github.com/xarmian/algod-rust/issues/504) |
| [#6552](https://github.com/algorand/go-algorand/pull/6552) | API: new pagination endpoint for applications | [#505](https://github.com/xarmian/algod-rust/issues/505) |
| [#6559](https://github.com/algorand/go-algorand/pull/6559) | API: incorporate deltas in paginated assets/applications, remove experimental gate | [#505](https://github.com/xarmian/algod-rust/issues/505) (apps half), [#506](https://github.com/xarmian/algod-rust/issues/506) (assets half) |
| [#6547](https://github.com/algorand/go-algorand/pull/6547) | API: conditionally exclude app/asset params on /v2/accounts | [#507](https://github.com/xarmian/algod-rust/issues/507) |
| [#6322](https://github.com/algorand/go-algorand/pull/6322) | API: add OnlineCirculation (online-stake) to GetSupply | [#508](https://github.com/xarmian/algod-rust/issues/508) |

### infrastructure

| Upstream PR | Change | Sub-issue |
|---|---|---|
| [#6556](https://github.com/algorand/go-algorand/pull/6556) | Tools: fix stale DevNet genesis hash in algokey | [#509](https://github.com/xarmian/algod-rust/issues/509) |

### not-applicable (justified)

| Upstream PR | Change | Why not applicable |
|---|---|---|
| [#6551](https://github.com/algorand/go-algorand/pull/6551) | agreement: implement TODO in broadcast/relay actions | Pure internal Go refactor (typed action constructors replacing a type-switch); verified via full diff read — zero behavioral change |
| [#6495](https://github.com/algorand/go-algorand/pull/6495) | network: silently fall back if uncompressed vote received | Go-side log-noise suppression only; the fallback-to-raw-data behavior already existed |
| [#6576](https://github.com/algorand/go-algorand/pull/6576) | network: fix streamManager deadlock on P2P hybrid relays | Targets go-algorand's experimental libp2p P2P transport, not implemented in algod-rust |
| [#6568](https://github.com/algorand/go-algorand/pull/6568) | network: don't listen if IncomingConnectionsLimit == 0 | Same libp2p P2P transport, not implemented |
| [#6569](https://github.com/algorand/go-algorand/pull/6569) | network: adjust pubsub params | Same libp2p P2P transport, not implemented |
| [#6555](https://github.com/algorand/go-algorand/pull/6555) | Eval: Prefetch better | Internal Go I/O-scheduling optimization; no effect on eval/apply semantics or results |
| [#6565](https://github.com/algorand/go-algorand/pull/6565) | Kmd: fix macOS HID failures | kmd is out of algod-rust's current scope (Phase 8) |
| [#6557](https://github.com/algorand/go-algorand/pull/6557) | Node: collect goroutine stacks before SIGKILL | Go-runtime-specific ops diagnostics, no protocol/API-visible behavior |
| [#6544](https://github.com/algorand/go-algorand/pull/6544) | Network: use specific error assertions in tests | go-algorand's own test-suite hygiene, not a behavior change |
| [#6549](https://github.com/algorand/go-algorand/pull/6549) | Build: add golangci-lint format into make fmt | Go build tooling, not applicable to a Rust codebase |

## Dependency Order

1. [#504](https://github.com/xarmian/algod-rust/issues/504) — ledger delta-merge fix (foundation for #505, #506)
2. [#505](https://github.com/xarmian/algod-rust/issues/505) — new paginated applications endpoint
3. [#506](https://github.com/xarmian/algod-rust/issues/506) — assets pagination delta-awareness
4. [#507](https://github.com/xarmian/algod-rust/issues/507) — exclude parameter verification
5. [#508](https://github.com/xarmian/algod-rust/issues/508) — GetSupply online-stake field
6. [#509](https://github.com/xarmian/algod-rust/issues/509) — devnet genesis hash fix

(#507–#509 are independent and may be worked in any order relative to the #504→#505/#506 chain.)

## Acceptance Criteria

- [ ] All six sub-issues merged, or honestly disposed per this repo's issue-disposition rules
- [ ] Version-pin sweep completed (`CLAUDE.md`, docs, CI workflows, `tools/cert-authenticate`, `Makefile`, `ops/mixed-cluster*/`, code comments)
- [ ] `docs/PHASE9_PROPOSAL.md` (this epic's parent) and this doc committed
- [ ] `docs/PROJECT_SCOPE.md` updated to mention Phase 9
- [ ] `docs/PHASE9_VALIDATION.md` written at close-out citing evidence per criterion
- [ ] Full gate green on `main`: fmt, clippy, full workspace suite, conformance suite, reference pinned to `v4.6.0-stable`
- [ ] No stray `v4.5.1-stable` references remain outside deliberate history
