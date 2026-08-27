# Phase 11: go-algorand v4.7.2-stable Parity

## Goal

Move algod-rust's parity target from go-algorand `v4.7.0-stable` to `v4.7.2-stable`, closing every behavioral gap the release introduces and re-pinning the reference checkout.

## Scope

`TAGS_IN_RANGE` for the version delta: `v4.7.0-stable` (OLD) → `v4.7.2-stable` (NEW). No intermediate `-beta`/`-rc` tags exist in this range — no `v4.7.1-*` tag was ever published upstream (a `4.7.1-stable` release PR was merged internally but folded directly into the `v4.7.2-stable` tag rather than shipped as its own release).

This is a small, security/bounds-check-focused patch release ("This release contains improvements to improve stability" / "Added better bound checks to transaction evaluation code"). It contains no consensus version bump, no new AVM opcodes, and no new REST API surface — only 2 first-parent commits in range, both hardening malformed/adversarial-input handling across transaction validation, agreement message ingestion, and cryptographic proof verification.

**Version-delta items** (`v4.7.0-stable..v4.7.2-stable`):

- A new group-level `CheckTxnGroup`/`CheckPayset` pre-signature-verification screen bundling five rejection rules (heartbeat-missing-fields, heartbeat-grouped-with-resource-trigger txn, state-proof-reveal signature/tree-depth/path-length bounds, application-box-index-exceeds-foreign-apps, unknown-txn-type), wired into both the standard signed-txn-group verification path and agreement proposal ingestion (malformed proposals are silently dropped, not disconnect-worthy).
- Codec-level `required` struct-tag enforcement on five fields (`Transaction.Type`, `Header.Sender`, `MultisigSig.{Version,Threshold,Subsigs}`, `stateproof.Reveal.Part`, `basics.Participant.PK`) — decode now rejects these fields when absent/zero instead of silently defaulting.
- A defense-in-depth `TreeDepth` bound guard in state-proof committable-signature-slot construction, duplicating part of the group screen's own check but reachable via a different call path.
- A global msgpack decode nesting-depth cap (255) as an anti-DoS measure against maliciously deep/recursive payloads.

## Non-Goals (explicitly out of scope this phase)

See epic #621 for the full classified inventory with per-item justification. In summary, of the 9 upstream behavior-relevant changes surveyed, 5 required no algod-rust action because the Rust port was already parity-correct or more conservative than the Go fix:

- HeartbeatTxnFields is already modeled as `Option<T>` in algod-rust with nil-checks at every access site — the Go pointer-nilability fix has no Rust-side gap.
- The `Access` field decode allocbound tightening (64 → `bounds.MaxAppAccess`=16) is already dominated by algod-rust's generic vector-preallocation cap (1024) and its already-correct `max_app_access=16` consensus param.
- Falcon signature short-length bounds checking, `merklearray.SingleLeafProof` index-out-of-bounds guards, and the `universalFetcher` short-bytes guard were all already present and correct in algod-rust before this survey.
- Go's `protocol/codec_tester.go` changes are internal fuzz/fixture-generation test tooling with no Rust-facing behavior.

## Conformance Standard

Byte-level/behavioral parity with go-algorand `v4.7.2-stable` for every in-scope version-delta item, verified against real go-algorand `v4.7.2-stable` binaries (`../go-algorand`, re-pinned as part of this phase) via this repo's conformance harness, including live mixed-cluster verification for the consensus-critical items.

## Issue Table

| Sub-issue | Title | Issue | Effort | Dependencies |
|---|---|---|---|---|
| 1 | validate+agreement: group-level CheckTxnGroup/CheckPayset transaction screen | [#617](https://github.com/xarmian/algod-rust/issues/617) | Medium | None |
| 2 | codec: enforce required-field decode rejection | [#618](https://github.com/xarmian/algod-rust/issues/618) | Medium | None |
| 3 | crypto: guard state-proof TreeDepth bound in Signature::verify_bytes | [#619](https://github.com/xarmian/algod-rust/issues/619) | Small | None |
| 4 | codec: cap msgpack decode nesting depth at 255 | [#620](https://github.com/xarmian/algod-rust/issues/620) | Small | None |

## Dependency Graph

```
#617, #618, #619, #620 — all independent, no ordering constraints
```

## Critical Path

None — all four sub-issues are independent. Implementation loop order: #618 (codec/encoding foundation) → #620 (codec depth cap, same crate) → #619 (crypto) → #617 (validate/agreement, broadest surface, last).

## Success Criteria

See epic #621's acceptance criteria: all four sub-issues merged (or honestly disposed), the version-pin sweep completed across the repo, this doc plus `docs/epics/Epic-21-Go-Algorand-v4.7.2-Parity.md` and `docs/PHASE11_VALIDATION.md` written, `docs/PROJECT_SCOPE.md` updated, and the full gate (fmt/clippy/tests/conformance) green on `main` with the reference pinned to `v4.7.2-stable`, including a live mixed-cluster soak against `v4.7.2-stable` go-algorand nodes.
