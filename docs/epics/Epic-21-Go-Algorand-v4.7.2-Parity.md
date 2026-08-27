# Epic: go-algorand v4.7.2-stable parity

Upgrades algod-rust's parity target from `v4.7.0-stable` to `v4.7.2-stable`. `TAGS_IN_RANGE`: `v4.7.0-stable` (OLD) → `v4.7.2-stable` (NEW) — no intermediate `-beta`/`-rc` tags exist in this range (no `v4.7.1-*` tag was published upstream; a `4.7.1-stable` release PR was merged internally but folded directly into the `v4.7.2-stable` tag). This is a small, security/bounds-check-focused patch release: "This release contains improvements to improve stability" / "Added better bound checks to transaction evaluation code." No consensus version bump, no new opcodes, no new REST API fields.

Only 2 first-parent commits in range: `2fd42e446` ("transactions: updates for bound checks") and `219edc42a` ("transactions: catch bogus type in group with computeAvailability").

## Classified inventory (OLD..NEW)

### consensus-critical

- New group-level `CheckTxnGroup`/`CheckPayset` pre-signature-verification screen (`data/transactions/checks.go`, new file) bundling five rejection rules: heartbeat-missing-fields, heartbeat-grouped-with-resource-trigger, state-proof-reveal signature/tree-depth/path-length bounds, application-box-index-exceeds-foreign-apps, and unknown-txn-type. Wired into both `verify/txn.go` (pre-signature) and `agreement/message.go`/`demux.go` (proposal ingestion, silent-drop semantics) → #617
- Codec-level `required` struct tags added to `Transaction.Type`, `Header.Sender`, `MultisigSig.{Version,Threshold,Subsigs}`, `stateproof.Reveal.Part`, `basics.Participant.PK` — decode now rejects these fields when absent/zero instead of silently defaulting → #618
- `buildCommittableSignature` TreeDepth bound guard (`crypto/stateproof/committableSignatureSlot.go`), defense-in-depth alongside the group-screen's own TreeDepth check, reachable via a different call path (direct state-proof signature verification, not just group screening) → #619

### behavioral-other (infrastructure / anti-DoS)

- `protocol/codec.go` sets `msgp.DefaultUnmarshalState.AllowableDepth = 255`, capping msgpack decode nesting depth globally → #620

### not-applicable (reviewed, no algod-rust action needed — already parity-correct)

- **HeartbeatTxnFields nilable pointer** (`data/transactions/transaction.go`, `ledger/eval/eval.go`, `ledger/eval/prefetcher/prefetcher.go`): algod-rust already models `heartbeat: Option<HeartbeatTxnFields>` (`crates/core/algo-types/src/transaction.rs:467`) with nil-checks at every access site (`algo-validate/src/rules.rs:153-190`, `algo-ledger/src/apply.rs:3960-3963`). No panic-on-nil risk ever existed in the Rust port.
- **`Access` field decode allocbound** (`data/transactions/application.go`, `encodedMaxAccess=64` → `bounds.MaxAppAccess`, currently 16): algod-rust's generic vector-preallocation helper (`algo-types/src/rmp_decode.rs:563-566`) caps all vec preallocation at `len.min(1024)` — already conservative relative to both the old (64) and new (16) Go bounds, and `max_app_access=16` is already correctly set in `algo-types/src/consensus.rs` for V41. No hardcoded constant to update.
- **Falcon signature `len(signature) < 2` bounds check** (`crypto/falconWrapper.go`): `algo_falcon::falcon_verify` (`crates/core/algo-falcon/src/lib.rs:99-100`) already rejects `sig.len() < 2` before any indexing.
- **`merklearray.SingleLeafProof` index-out-of-bounds fixes** (`crypto/merklearray/proof.go`): `crates/core/algo-consensus-crypto/src/merklearray.rs:238-274` already bounds-checks `i < path.len()` before indexing in both `get_fixed_length_hashable_representation` and `get_concatenated_proof`. (Note: the *rejection* semantics upstream now also applies at the group-screen layer — that's covered by #617's state-proof-reveal bounds check, not a separate item here.)
- **`universalFetcher` short "latest round" bytes guard** (`catchup/universalFetcher.go`): `crates/node/algo-rest-client/src/gossip_block_source.rs:207-215`'s `parse_latest_round` already requires exactly 8 bytes before decoding, with existing test coverage.
- **Test-harness-only changes** (`protocol/codec_tester.go`'s `isRequiredField`/randomization updates): Go-internal fixture-generation/fuzz-test tooling with no Rust-facing behavior.

## Issue Table

| Sub-issue | Title | Issue | Effort | Dependencies |
|---|---|---|---|---|
| 1 | validate+agreement: group-level CheckTxnGroup/CheckPayset transaction screen | [#617](https://github.com/xarmian/algod-rust/issues/617) | Medium | None |
| 2 | codec: enforce required-field decode rejection | [#618](https://github.com/xarmian/algod-rust/issues/618) | Medium | None |
| 3 | crypto: guard state-proof TreeDepth bound in Signature::verify_bytes | [#619](https://github.com/xarmian/algod-rust/issues/619) | Small | None (references #617 for shared context, not a hard dependency) |
| 4 | codec: cap msgpack decode nesting depth at 255 | [#620](https://github.com/xarmian/algod-rust/issues/620) | Small | None |

## Dependency Graph

```
#617, #618, #619, #620 — all independent, no ordering constraints
```

## Critical Path

None — all four sub-issues are independent and can be worked in any order. Implementation loop order: #618 (codec/encoding foundation) → #620 (codec depth cap, same crate) → #619 (crypto) → #617 (validate/agreement, broadest surface, last).

## Success Criteria

All four sub-issues merged (or honestly disposed), the version-pin sweep completed across the repo (`v4.7.0-stable` → `v4.7.2-stable`), `docs/PHASE11_PROPOSAL.md` + `docs/epics/Epic-21-Go-Algorand-v4.7.2-Parity.md` + `docs/PHASE11_VALIDATION.md` written, `docs/PROJECT_SCOPE.md` updated, and the full gate (fmt/clippy/tests/conformance) green on `main` with the reference pinned to `v4.7.2-stable`, including a live mixed-cluster soak against `v4.7.2-stable` go-algorand nodes.
