# Phase 9: go-algorand v4.6.0-stable Parity

## Goal

Move algod-rust's parity target from go-algorand `v4.5.1-stable` to `v4.6.0-stable`, closing every behavioral gap the release introduces and re-pinning the reference checkout.

## Scope

`v4.6.0-stable` carries **no consensus/protocol version upgrade** (confirmed in go-algorand's own release notes). The delta is entirely REST-surface and one infrastructure constant:

- A new paginated `GET /v2/accounts/{address}/applications` endpoint, mirroring the existing assets pagination, and incorporating a correctness fix upstream made to the delta-merge logic underlying paginated resource lookups (undercounted deletions, phantom holdings, an empty-page edge case) since algod-rust has no such layer yet to patch separately.
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
| ~~1~~ | ~~ledger: fix lookupAssetResources/lookupApplicationResources delta-merge bugs~~ | [#504](https://github.com/xarmian/algod-rust/issues/504) (closed, superseded) | — | — |
| 2 | rest-api: add paginated GET /v2/accounts/{address}/applications endpoint (now includes #504's correctness rules) | [#505](https://github.com/xarmian/algod-rust/issues/505) | Medium | None |
| 3 | rest-api: incorporate uncommitted deltas into paginated GET /v2/accounts/{address}/assets (now includes #504's correctness rules + experimental-gate removal) | [#506](https://github.com/xarmian/algod-rust/issues/506) | Small | None |
| 4 | rest-api: verify /v2/accounts exclude parameter semantics | [#507](https://github.com/xarmian/algod-rust/issues/507) | Small | None |
| 5 | rest-api: add online-stake (OnlineCirculation) field to GET /v2/ledger/supply | [#508](https://github.com/xarmian/algod-rust/issues/508) | Small | None |
| 6 | infrastructure: fix stale devnet genesis hash constant | [#509](https://github.com/xarmian/algod-rust/issues/509) | Small | None |

**#504 closed as superseded during stage-6 investigation**: algod-rust has no delta-merge layer for paginated resource lookups at all (`lookup_assets` reads only the committed `SqliteLedger`), so there was no standalone code for #504's fix to patch. Its three correctness rules (deletion-counting, no phantom holdings, round-0 edge case) were folded directly into #505 and #506 — the two issues that actually build such a layer for the first time.

## Dependency Graph

```
#505, #506, #507, #508, #509 — all independent, no dependencies on each other
```

## Critical Path

None — all five remaining sub-issues are independent. Per this repo's `algod-issue-fix`/`algod-version-upgrade` workflow, they are still worked **sequentially** (one merged before the next begins) to avoid conflicts on shared surfaces, but ordering among them is a scheduling choice, not a dependency requirement.

## Success Criteria

See epic #503's acceptance criteria: #504 honestly disposed (done) and all five remaining sub-issues merged (or honestly disposed), the version-pin sweep completed across the repo (done), this doc plus `docs/epics/Epic-19-Go-Algorand-v4.6.0-Parity.md` and `docs/PHASE9_VALIDATION.md` written, `docs/PROJECT_SCOPE.md` updated, and the full gate (fmt/clippy/tests/conformance) green on `main` with the reference pinned to `v4.6.0-stable`.
