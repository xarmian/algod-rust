# Phase 11 Validation — go-algorand v4.7.2-stable Parity

_Completed: 2026-08-27_

Phase 11 moves algod-rust's parity target from go-algorand `v4.7.0-stable`
to `v4.7.2-stable`. This is a small, security/bounds-check-focused patch
release with no consensus version bump, no new AVM opcodes, and no new
REST API surface.

This document is the evidence map for
[`docs/PHASE11_PROPOSAL.md`](PHASE11_PROPOSAL.md) and
[`docs/epics/Epic-21-Go-Algorand-v4.7.2-Parity.md`](epics/Epic-21-Go-Algorand-v4.7.2-Parity.md),
mirroring the structure of [`PHASE10_VALIDATION.md`](PHASE10_VALIDATION.md)
and [`PHASE6_VALIDATION.md`](PHASE6_VALIDATION.md). Every claim below cites
a specific file/test/tool in this repo, or the PR/issue where the evidence
is recorded.

Tracking epic: [#621](https://github.com/xarmian/algod-rust/issues/621).

---

## Completeness re-check (Stage 7 mandatory re-run)

Per the `algod-version-upgrade` skill's Stage 7 instructions, the
release-notes completeness pass and `TAGS_IN_RANGE` derivation were
re-run fresh at close-out (2026-08-27), not just trusted from the
original Stage 2 pass:

- `git -C ../go-algorand tag --contains v4.7.0-stable --list | sort -V`
  confirms `TAGS_IN_RANGE` is unchanged: `v4.7.0-stable` (OLD) →
  `v4.7.2-stable` (NEW), with no intermediate `-beta`/`-rc` tag — no
  `v4.7.1-*` tag exists upstream (its release PR merged directly into
  `v4.7.2-stable` rather than shipping standalone). Later tags
  (`v4.7.3-*`, `v4.7.4-*`, `v5.0.0-*`) exist but are out of this
  phase's range.
- `git -C ../go-algorand log --first-parent --oneline v4.7.0-stable..v4.7.2-stable`
  returns exactly 2 merge commits (`b247a77aa`, `6d3120ae1`), consistent
  with the original Stage 2 pass's `2fd42e446`/`219edc42a` commit
  citations (the two named commits are the underlying feature commits
  squashed/merged by these two merge PRs).
- `gh release view v4.7.2-stable -R algorand/go-algorand` still lists
  exactly the same two Changelog/Enhancements bullets the epic's Stage 2
  pass classified: "transactions: updates for bound checks" and
  "transactions: catch bogus type in group with computeAvailability" —
  no corrections or additions since the original survey. Both map onto
  the `consensus-critical`/`behavioral-other` inventory in epic #621's
  body; no re-check finding, no missed item.

## Sub-issue disposition

| Sub-issue | Outcome | Evidence |
|---|---|---|
| [#617](https://github.com/xarmian/algod-rust/issues/617) — group-level `CheckTxnGroup`/`CheckPayset` screen | Merged (PR [#627](https://github.com/xarmian/algod-rust/pull/627)) | `crates/core/algo-validate/src/checks.rs` (~30 unit tests, all five rejection rules); wired into `algo-validate/src/block.rs` and `algo-agreement/src/demux.rs` (`demux_raw_proposal_with_malformed_payset_is_dropped_not_disconnected` proves silent-drop-not-disconnect semantics); `tools/checktxngroup-oracle` — 18 scenarios run against go-algorand v4.7.2-stable's real `CheckTxnGroup`, all match, several drawn verbatim from go-algorand's own `checks_test.go` |
| [#618](https://github.com/xarmian/algod-rust/issues/618) — codec `required`-field decode enforcement | Merged (PR #624) | `crates/core/algo-types/src/transaction.rs`'s `required_field_decode_tests` (16 tests); `tools/required-field-decode-oracle` — byte-level oracle against go-algorand's real generated `UnmarshalMsg` decoders |
| [#619](https://github.com/xarmian/algod-rust/issues/619) — state-proof `TreeDepth` guard in `Signature::verify_bytes` | Closed not-planned, superseded by [#626](https://github.com/xarmian/algod-rust/issues/626) | Investigation found the guessed target location (`Signature::verify_bytes`) doesn't exist in algod-rust's call graph the way it does in go-algorand; the real gap is structurally larger — algod-rust applies `stpf` transactions with **zero** cryptographic verification (`algo-ledger/src/apply.rs` ~line 2265 short-circuits to `Ok(ApplyData::default())`), so a `TreeDepth` guard on a verification path that doesn't exist yet is moot. Filed as #626 (deliberately unlabeled `phase:11` — it predates and is broader than this patch release, see disposition below) |
| [#620](https://github.com/xarmian/algod-rust/issues/620) — msgpack decode nesting-depth cap | Merged (PR #625) | Depth-cap test in `algo-types`'s `rmp_decode` skip-value path, matching go-algorand's `AllowableDepth = 255` |

**Follow-up filed during #617's PR audit, not blocking:** [#628](https://github.com/xarmian/algod-rust/issues/628)
(ledger: box-ref index resolution silently skips invalid refs on
sync/replay/simulate paths, not gated by `CheckTxnGroup`) — surfaced by
an investigation agent tracing every caller of `avm_context.rs`'s
`ensure_boxes_initialized`. Structurally independent of the two
documented go-algorand call sites #617 targets (consensus/agreement
block-apply, which *is* gated); a defense-in-depth question about
trust boundaries on sync/replay/catchpoint-restore/simulate paths that
predates this patch release's actual scope.

## Non-goals confirmed (no algod-rust action needed)

Per epic #621's classified inventory, 5 of the 9 upstream items required
no change because the Rust port was already parity-correct or more
conservative than the Go fix — re-confirmed unchanged at close-out:
`HeartbeatTxnFields` already modeled as `Option<T>` with nil-checks at
every access site; the `Access` allocbound tightening is already
dominated by algod-rust's generic 1024-cap preallocation guard and its
already-correct `max_app_access=16` consensus param; Falcon short-signature
bounds checking, `merklearray.SingleLeafProof` index guards, and the
`universalFetcher` short-bytes guard were already present; go's
`protocol/codec_tester.go` changes are internal Go fuzz-tooling with no
Rust-facing surface.

## Version-pin sweep

64 files swept from `v4.7.0-stable` to `v4.7.2-stable` (PR #623):
`CLAUDE.md`, `README.md`, CI workflows, Docker compose files, capture
tools' pin constants, `ops/mixed-cluster/*` scripts, etc. Remaining
`v4.7.0-stable` references in the tree (checked at close-out via
`grep -rln "v4\.7\.0-stable"`) are exclusively: historical validation
docs describing the *prior* phase (`PHASE10_VALIDATION.md`, `Epic-20`),
Phase 5/6 proposal docs predating this pin entirely, and code comments
citing "live-verified against a real go-algorand v4.7.0-stable node"
for evidence that was gathered under that pin and remains historically
accurate — none of these are the *current* pin statement.

## Full gate on `main`

Re-run at close-out after PR #627 merged (2026-08-27):

- `cargo fmt --all --check` — clean.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo test --workspace` — every crate green except the pre-existing,
  documented `algo-network` `peer_features.rs` doctest flake
  (`decode_peer_features`/`encode_peer_features`, CLAUDE.md's known
  local-environment issue) — the sole acceptable failure per this
  repo's stated policy.

## Live mixed-cluster verification

Not run for this phase. Disposition recorded on issue #617 (the one
sub-issue whose acceptance criteria named it as consensus-critical):
every new rejection path in this release triggers only on deliberately
malformed input (unknown transaction types, missing heartbeat fields,
out-of-bounds box indices, malformed state-proof reveals) that a
healthy consensus network never produces in normal traffic. A live
mixed-cluster soak under normal conditions would exercise none of the
new code paths; injecting adversarial input into a live cluster to
exercise them is a disproportionately larger effort than this small
patch release's scope, and is superseded in evidentiary value by the
byte-level go-algorand oracle (`tools/checktxngroup-oracle`, calling
go-algorand v4.7.2-stable's real `CheckTxnGroup` directly) plus the
~30 unit tests already covering every rejection rule.

## Outcome

All four originally-scoped sub-issues are resolved (three merged, one
closed-superseded with a properly filed and more-precisely-scoped
replacement). The reference pin, docs, and code are consistent at
`v4.7.2-stable`. One structurally-separate follow-up (#628) was
surfaced during review and filed as its own tracked issue rather than
folded into this phase's scope or left undocumented.
