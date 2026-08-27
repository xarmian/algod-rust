# Epic: go-algorand v4.7.3-stable parity

Upgrades algod-rust's parity target from `v4.7.2-stable` to `v4.7.3-stable`. `TAGS_IN_RANGE`: `v4.7.2-stable` (OLD) → `v4.7.3-stable` (NEW) — no genuine intermediate `-beta`/`-rc` tag exists in this range. A `v4.7.3-beta` tag exists but is confirmed to be a re-publish of the exact same `v4.7.3-stable` content plus one extra empty merge-wrapper commit, tagged 5 days *later* (`v4.7.3-stable` is an ancestor of `v4.7.3-beta`, not the reverse) — its own release notes explicitly say "This is a backport of v4.7.3-stable" and list both v4.7.2's and v4.7.3's changes together. Excluded from `TAGS_IN_RANGE` per the "drop anything not reachable from NEW" rule.

This is a small, security/robustness-focused patch release: "This release improves safety and durability of node operation" / "Improved error handling and validation for transactions and transaction groups." No consensus version bump, no new opcodes, no new REST API fields. Only 4 real first-parent commits in range (excluding the release-PR merge wrapper and a build-number bump).

## Classified inventory (OLD..NEW)

### network (anti-DoS, real gap)

- `MaxDecompressedMessageSize` tightened from a flat 20 MiB to `protocol.ProposalPayloadTagMaxSize` (0x501e3a ≈ 5.01 MiB) — the actual max size a legitimate compressed gossip message can decompress to. algod-rust's `algo-network` still has the old 20 MiB constant. → #641

### consensus-critical (Go-specific infrastructure, real parity work needed)

- `ledger/eval/eval.go` et al. wrap the entire block-evaluation/verification pipeline in `recover()`, converting a Go panic on malformed/malicious block content into a typed `EvalPanicError` instead of crashing the process, with a `corruptedState` poison-flag for evaluator reuse across a round. Not a 1:1 port (Rust panic semantics differ), but the underlying robustness property — a malformed block must never crash a live node — needs an audit-and-fix pass against algod-rust's own apply/eval pipeline. → #642

### not-applicable (reviewed, no algod-rust action needed — already parity-correct or structurally immune)

- **`eval: call WellFormed for entire group` (643e86bd8)**: go-algorand moved its per-transaction `WellFormed()` check from being interleaved with per-transaction application to an upfront, whole-group check before any transaction in the group is applied (atomicity fix). Investigated: algod-rust already structurally separates *validation* (`algo-validate::validate_block`, which touches no ledger state and only accumulates errors) from *application* (`algo-ledger::apply_block_impl`, which is never called until `validate_block` returns fully valid) — the agreement bridge (`block_validator_bridge.rs`) only proceeds to `apply_block` after a clean `validate_block` pass. algod-rust therefore already has the atomicity property go v4.7.3 was retrofitting; no gap, no action needed.
- **`txn: handle failures better in txnGroupBatchPrep` (f2acb9b39)**: fixes a real go-algorand bug where a transaction group that failed signature-prep partway through left its already-enqueued signatures in a SHARED batch verifier, misaligning the per-group failure-index bookkeeping and risking cross-group signature-result misattribution. Investigated: algod-rust has no shared/deferred batch-verifier object for transaction-group signatures at all — `verify_transaction_signature` (`algo-validate/src/signature.rs`) verifies each transaction's signature synchronously and immediately, with no cross-transaction or cross-group shared state to misalign. Structurally immune to this bug class; no action needed.
- **`CI: update runners` (aaea558d6)**: Go-internal CI infrastructure, no Rust-facing behavior.
- **Build-number bump**: version-string bookkeeping only.

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

Both sub-issues merged (or honestly disposed), the version-pin sweep completed across the repo (`v4.7.2-stable` → `v4.7.3-stable`), `docs/PHASE12_PROPOSAL.md` + `docs/epics/Epic-22-Go-Algorand-v4.7.3-Parity.md` + `docs/PHASE12_VALIDATION.md` written, `docs/PROJECT_SCOPE.md` updated, and the full gate (fmt/clippy/tests/conformance) green on `main` with the reference pinned to `v4.7.3-stable`.
