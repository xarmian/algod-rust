# Phase 9: go-algorand v4.6.0-stable Parity

## Goal

Move algod-rust's parity target from go-algorand `v4.5.1-stable` to `v4.6.0-stable`, closing every behavioral gap the release introduces and re-pinning the reference checkout.

## Scope

`v4.6.0-stable` carries **no consensus/protocol version upgrade** (confirmed in go-algorand's own release notes). The delta is entirely REST-surface and one infrastructure constant:

- A ledger-crate correctness fix underlying paginated resource lookups (delta-merge bugs: undercounted deletions, phantom holdings, an empty-page edge case).
- A new paginated `GET /v2/accounts/{address}/applications` endpoint, mirroring the existing assets pagination.
- Real-time delta-awareness added to the existing paginated assets endpoint (and removal of any experimental gating).
- Verification that `/v2/accounts`'s `exclude` query parameter semantics match go-algorand's expanded set.
- A new `online-stake` field on `GET /v2/ledger/supply`, computed via the existing sortition lookback machinery.
- A stale `devnet` genesis-hash constant algod-rust inherited from go-algorand, now corrected upstream.

## Non-Goals (explicitly out of scope this phase)

Ten of the sixteen upstream PRs in the `v4.5.1-stable..v4.6.0-stable` range are deliberately **not** ported — see the epic issue (#503) for the full classified inventory with per-item justification. In summary:

- One `agreement/` change is a pure internal Go refactor (typed action constructors replacing a type-switch) with zero behavioral delta.
- Five network/P2P changes (`streamManager` deadlock fix, listen-limit fix, pubsub param tuning, an uncompressed-vote log-noise fix, a test-assertion cleanup) target go-algorand's experimental libp2p-based P2P transport, which algod-rust does not implement (only the classic WS gossip network).
- One Eval/ledger change is an internal Go I/O-scheduling optimization (prefetcher rewrite) with no effect on eval results.
- One `kmd` fix is out of scope — algod-rust has no `kmd-rust` yet (Phase 8 territory).
- Two are Go build/ops tooling with no Rust equivalent surface (goroutine-stack-dump-on-SIGKILL, golangci-lint-in-make-fmt).

## Conformance Standard

Byte-level/behavioral parity with go-algorand `v4.6.0-stable` for every in-scope item, verified against real go-algorand `v4.6.0-stable` binaries (`../go-algorand`, re-pinned as part of this phase) via this repo's conformance harness.

## Issue Table

| Sub-issue | Title | Issue | Effort | Dependencies |
|---|---|---|---|---|
| 1 | ledger: fix lookupAssetResources/lookupApplicationResources delta-merge bugs | [#504](https://github.com/xarmian/algod-rust/issues/504) | Small | None |
| 2 | rest-api: add paginated GET /v2/accounts/{address}/applications endpoint | [#505](https://github.com/xarmian/algod-rust/issues/505) | Medium | #504 |
| 3 | rest-api: incorporate uncommitted deltas into paginated GET /v2/accounts/{address}/assets | [#506](https://github.com/xarmian/algod-rust/issues/506) | Small | #504 |
| 4 | rest-api: verify /v2/accounts exclude parameter semantics | [#507](https://github.com/xarmian/algod-rust/issues/507) | Small | None |
| 5 | rest-api: add online-stake (OnlineCirculation) field to GET /v2/ledger/supply | [#508](https://github.com/xarmian/algod-rust/issues/508) | Small | None |
| 6 | infrastructure: fix stale devnet genesis hash constant | [#509](https://github.com/xarmian/algod-rust/issues/509) | Small | None |

## Dependency Graph

```
#504 (ledger delta-merge fix)
  |         \
  v          v
#505        #506
(new apps   (assets delta
 pagination)  awareness)

#507, #508, #509 — independent, no dependencies on the above or each other
```

## Critical Path

```
#504 -> #505
```

Everything else may proceed in parallel once #504 lands. Per this repo's `algod-issue-fix`/`algod-version-upgrade` workflow, sub-issues are still worked **sequentially** (one merged before the next begins) to avoid conflicts on shared surfaces — the graph above informs ordering, not parallel execution.

## Success Criteria

See epic #503's acceptance criteria: all six sub-issues merged (or honestly disposed), the version-pin sweep completed across the repo, this doc plus `docs/epics/Epic-19-Go-Algorand-v4.6.0-Parity.md` and `docs/PHASE9_VALIDATION.md` written, `docs/PROJECT_SCOPE.md` updated, and the full gate (fmt/clippy/tests/conformance) green on `main` with the reference pinned to `v4.6.0-stable`.
