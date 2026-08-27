# Phase 12: go-algorand v4.7.3-stable Parity

## Goal

Move algod-rust's parity target from go-algorand `v4.7.2-stable` to `v4.7.3-stable`, closing every behavioral gap the release introduces and re-pinning the reference checkout.

## Scope

`TAGS_IN_RANGE` for the version delta: `v4.7.2-stable` (OLD) → `v4.7.3-stable` (NEW). A `v4.7.3-beta` tag exists but is confirmed to be a re-publish of the exact same `v4.7.3-stable` content plus one extra empty merge-wrapper commit, tagged 5 days *later* than `v4.7.3-stable` (`v4.7.3-stable` is an ancestor of `v4.7.3-beta`, not the reverse) — its own release notes say "This is a backport of v4.7.3-stable" and list both v4.7.2's and v4.7.3's changes together. Excluded from `TAGS_IN_RANGE`.

This is a small, security/robustness-focused patch release ("This release improves safety and durability of node operation" / "Improved error handling and validation for transactions and transaction groups"). It contains no consensus version bump, no new AVM opcodes, and no new REST API surface — only 4 first-parent commits in range.

**Version-delta items** (`v4.7.2-stable..v4.7.3-stable`):

- `MaxDecompressedMessageSize` (the anti-zip-bomb bound on decompressed gossip message size) tightened from a flat 20 MiB to `protocol.ProposalPayloadTagMaxSize` (0x501e3a ≈ 5.01 MiB) — the actual maximum size a legitimate compressed gossip message can decompress to.
- The entire block-evaluation/verification pipeline wrapped in Go's `recover()`, converting a panic on malformed/malicious block content into a typed `EvalPanicError` instead of crashing the process, with a poison-flag preventing a corrupted evaluator from silently continuing to accept other, innocent transaction groups.

## Non-Goals (explicitly out of scope this phase)

See epic #643 for the full classified inventory with per-item justification. Of the 4 real upstream commits surveyed, 2 required no algod-rust action because the Rust port is already structurally immune or parity-correct:

- **`eval: call WellFormed for entire group`**: go-algorand moved its per-transaction well-formedness check from being interleaved with per-transaction application to an upfront, whole-group check before any transaction in the group is applied. algod-rust already structurally separates validation (`algo-validate::validate_block`, which touches no ledger state) from application (`algo-ledger::apply_block_impl`, never called until validation passes cleanly) — the atomicity property this go-algorand commit was retrofitting already holds in algod-rust's design.
- **`txn: handle failures better in txnGroupBatchPrep`**: fixes a real go-algorand bug where a transaction group failing signature-prep partway left its already-enqueued signatures in a shared batch verifier, risking cross-group failure-attribution misalignment. algod-rust has no shared/deferred batch-verifier object for transaction-group signatures — each transaction's signature is verified synchronously and immediately — structurally immune to this bug class.

The remaining 2 commits (a CI-runner update, a build-number bump) are Go-internal tooling with no Rust-facing behavior.

## Conformance Standard

Byte-level/behavioral parity with go-algorand `v4.7.3-stable` for every in-scope version-delta item, verified against real go-algorand `v4.7.3-stable` binaries (`../go-algorand`, re-pinned as part of this phase) via this repo's conformance harness.

## Issue Table

| Sub-issue | Title | Issue | Effort | Dependencies |
|---|---|---|---|---|
| 1 | network: tighten MaxDecompressedMessageSize to ProposalPayloadTagMaxSize | [#641](https://github.com/xarmian/algod-rust/issues/641) | Small | None |
| 2 | ledger+avm: harden block-evaluation pipeline against panics on malformed/malicious input | [#642](https://github.com/xarmian/algod-rust/issues/642) | Medium | None |

## Dependency Graph

```
#641, #642 — independent, no ordering constraints
```

## Critical Path

None — both sub-issues are independent. Implementation loop order: #641 (small, self-contained) → #642 (broader audit, larger surface).

## Success Criteria

See epic #643's acceptance criteria: both sub-issues merged (or honestly disposed), the version-pin sweep completed across the repo, this doc plus `docs/epics/Epic-22-Go-Algorand-v4.7.3-Parity.md` and `docs/PHASE12_VALIDATION.md` written, `docs/PROJECT_SCOPE.md` updated, and the full gate (fmt/clippy/tests/conformance) green on `main` with the reference pinned to `v4.7.3-stable`.
