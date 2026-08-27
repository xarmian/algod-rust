# Phase 12 Validation — go-algorand v4.7.3-stable Parity

_Completed: 2026-08-28_

Phase 12 moves algod-rust's parity target from go-algorand `v4.7.2-stable`
to `v4.7.3-stable`, a small security/robustness-focused patch release.

This document is the evidence map for
[`docs/PHASE12_PROPOSAL.md`](PHASE12_PROPOSAL.md) and
[`docs/epics/Epic-22-Go-Algorand-v4.7.3-Parity.md`](epics/Epic-22-Go-Algorand-v4.7.3-Parity.md),
mirroring the structure of [`PHASE11_VALIDATION.md`](PHASE11_VALIDATION.md).
Every claim below cites a specific file/test/tool in this repo.

Tracking epic: [#643](https://github.com/xarmian/algod-rust/issues/643).

---

## Completeness re-check (Stage 7 mandatory re-run)

Per the `algod-version-upgrade` skill's Stage 7 instructions, the
release-notes completeness pass and `TAGS_IN_RANGE` derivation were
re-run fresh at close-out (2026-08-28), not just trusted from the
original Stage 2 pass:

- `git -C ../go-algorand fetch --tags` followed by
  `git tag --contains v4.7.2-stable --list | sort -V` confirms
  `TAGS_IN_RANGE` is unchanged: `v4.7.2-stable` (OLD) → `v4.7.3-stable`
  (NEW). `v4.7.3-beta` remains correctly excluded — re-verified as a
  re-publish of the exact same `v4.7.3-stable` content plus one extra
  empty merge-wrapper commit, tagged 5 days later (`v4.7.3-stable` is
  an ancestor of `v4.7.3-beta`, not the reverse).
- `gh release view v4.7.3-stable -R algorand/go-algorand` returns the
  identical four Changelog/Enhancements bullets the original Stage 2
  pass classified — no corrections or additions since the original
  survey. All four map onto the epic #643 inventory below; no missed
  item.

## Sub-issue disposition

| Sub-issue | Outcome | Evidence |
|---|---|---|
| [#641](https://github.com/xarmian/algod-rust/issues/641) — tighten `MaxDecompressedMessageSize` to `ProposalPayloadTagMaxSize` | Merged (PR [#646](https://github.com/xarmian/algod-rust/pull/646)) | `crates/node/algo-network/src/compression.rs`'s `MAX_DECOMPRESSED_MESSAGE_SIZE` set to `0x501e3a` exactly; `decompress_between_old_and_new_bound_now_rejected` confirmed failing against the pre-fix constant before the change |
| [#642](https://github.com/xarmian/algod-rust/issues/642) — harden block-evaluation pipeline against panics on malformed/malicious input | Merged (PR [#647](https://github.com/xarmian/algod-rust/pull/647)) | Full audit of every non-test `.unwrap()`/`.expect()`/`panic!()`/`unreachable!()` call site reachable from received block/transaction content across `algo-ledger`, `algo-avm` (including a deep-dive on EC opcode field-element inversions vs. go-algorand's `pairing.go`/gnark-crypto reference), `algo-validate`, `algo-types`, `algo-codec` — zero genuine panics found. Two boundary-condition regression tests added (`read_u64_truncated_after_marker_does_not_panic`/`read_i64_truncated_after_marker_does_not_panic`). `catch_unwind` deliberately not added, with reasoned justification in the PR body. |

## Non-goals confirmed (no algod-rust action needed)

Per epic #643's classified inventory, 2 of the 4 real upstream commits
required no algod-rust action because the Rust port is already
structurally correct or immune — re-confirmed unchanged at close-out:

- **`eval: call WellFormed for entire group`**: algod-rust already
  structurally separates validation (`algo-validate::validate_block`,
  touches no ledger state) from application
  (`algo-ledger::apply_block_impl`, never called until validation
  passes cleanly) — the atomicity property go v4.7.3 was retrofitting
  already holds.
- **`txn: handle failures better in txnGroupBatchPrep`**: algod-rust
  has no shared/deferred batch-verifier object for transaction-group
  signatures — each signature is verified synchronously and
  immediately, structurally immune to the cross-group misattribution
  bug this go-algorand commit fixed.

The remaining 2 items (a CI-runner update, a build-number bump) are
Go-internal tooling with no Rust-facing behavior.

## Version-pin sweep

68 files swept from `v4.7.2-stable` to `v4.7.3-stable` (PR #645):
`CLAUDE.md`, `README.md`, `Makefile` help text, all `*-capture`/`*-oracle`
tool pin constants and `go.mod` comments, `ops/mixed-cluster{,-p2p,-3rust}`
docker-compose images and scripts, `docker/docker-compose.*.yml` and
`docker/scripts/*.sh`, `.github/workflows/*.yml` `GO_ALGORAND_REV`
values, and docs narrating the current live setup. Deliberately left
untouched: historical version-delta citations, genuine captured-fixture
provenance, `PHASE10/11_VALIDATION.md` and `PHASE11_PROPOSAL.md` and
Epic-21's own historical range descriptions, and
`DEV_WORKFLOW.md`'s illustrative `v4.5.1-stable → v4.7.0-stable`
pin-bump example. The sweep itself caught and hand-fixed one real
mistake: an earlier, overly-broad substitution attempt would have
silently corrupted `CLAUDE.md`'s own historical
"`v4.7.0-stable → v4.7.2-stable`" range description into
"`v4.7.0-stable → v4.7.3-stable`" — rewritten by hand instead.

Live-parity CI on the pin-sweep PR itself (`Live parity vs go-algorand`,
`algokey-rust e2e`, `Crypto + Codec Parity Suite`) ran green against
real go-algorand v4.7.3-stable nodes with no carve-outs needed —
neither #641's tightened decompression bound nor #642's (ultimately
empty) panic-hardening audit surfaced as an observable live-parity
regression, confirming Stage 2's analysis was complete.

## Full gate on `main`

Re-run at close-out after PR #647 merged (2026-08-28):

- `cargo fmt --all --check` — clean.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo test --workspace` — every crate green except the pre-existing,
  documented `algo-network` `peer_features.rs` doctest flake
  (CLAUDE.md's known local-environment issue) — the sole acceptable
  failure per this repo's stated policy.

## Live mixed-cluster verification

Not separately re-run as a dedicated soak for this phase — #642's
acceptance criteria explicitly struck the live-mixed-cluster criterion
since the audit found zero behavioral changes to verify (no fix
altered any rejection/acceptance behavior), and #641's live-parity
coverage already ran clean as part of the pin-sweep PR's own CI
(see above), which is the meaningful live-verification signal for a
tightened anti-DoS bound that isn't exercised by normal conformance
traffic in the first place.

## Outcome

Both sub-issues resolved (merged). The reference pin, docs, and code
are consistent at `v4.7.3-stable`. Unlike prior phases, this sweep's
"consensus-critical" item (#642) resolved to a documented null result
rather than a code fix — a legitimate, evidenced outcome of the audit,
not a shortcut.
