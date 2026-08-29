# Phase 14 Validation — go-algorand v5.0.0-stable Parity

_Completed: 2026-08-29_

Phase 14 moves algod-rust's parity target from go-algorand `v4.7.4-stable`
to `v5.0.0-stable`, a consensus-upgrade release (V41 → V42) bringing native
post-quantum (Falcon-1024) account signatures, big-transaction size
pricing, AVM v13, a new `SelectF128` 128-bit-software-float sortition
algorithm, a new `GET /v2/node/peers` endpoint, and removal of the
`dryrun` REST endpoint.

This document is the evidence map for
[`docs/PHASE14_PROPOSAL.md`](PHASE14_PROPOSAL.md) and
[`docs/epics/Epic-24-Go-Algorand-v5.0.0-Parity.md`](epics/Epic-24-Go-Algorand-v5.0.0-Parity.md),
mirroring the structure of [`PHASE13_VALIDATION.md`](PHASE13_VALIDATION.md).
Every claim below cites a specific file/test/tool in this repo.

Tracking epic: [#678](https://github.com/xarmian/algod-rust/issues/678).

---

## Completeness re-check (Stage 7 mandatory re-run)

Re-run fresh at close-out (2026-08-29), not just trusted from the original
Stage 1-2 pass:

- `git -C ../go-algorand fetch --tags` followed by
  `git tag --contains v4.7.4-stable --list | sort -V` confirms
  `TAGS_IN_RANGE` is unchanged: `v4.7.4-beta`, `v5.0.0-beta`,
  `v5.0.0-stable`. No new pre-release tag landed upstream since Stage 1.
- `gh release view v5.0.0-stable -R algorand/go-algorand` returns the
  identical changelog (New Features / Enhancements / Bugfixes) the
  original Stage 2 pass classified — every bullet still maps to a merged
  sub-issue or a justified not-applicable entry in
  `docs/PHASE14_PROPOSAL.md`. No corrections or additions since the
  original survey.

## Sub-issue disposition

All 21 sub-issues from the original Stage 3 inventory, plus 14 follow-up
issues filed and worked during Stage 6 (per this repo's "every open topic
becomes a worked sub-issue" rule), are merged. None were disposed as
unreachable/deferred — every item that surfaced was implemented.

### Original Stage 3 inventory (21)

| Sub-issue | PR | Evidence |
|---|---|---|
| [#658](https://github.com/xarmian/algod-rust/issues/658) consensus v42 parameter sweep | [#682](https://github.com/xarmian/algod-rust/pull/682) | `crates/core/algo-types/src/consensus.rs`: `CONSENSUS_V42` + all 11 upstream-changed params; `test_consensus_v42_params`/`test_consensus_v42_spec_url`. |
| [#663](https://github.com/xarmian/algod-rust/issues/663) Falcon-1024 seed size + sign convention | [#683](https://github.com/xarmian/algod-rust/pull/683) | `FALCON_SEED_SIZE` 48→32 in `crates/core/algo-falcon`; traced every sign/verify call site, confirmed the double-hash bug never applied to algod-rust's byte-level API. |
| [#669](https://github.com/xarmian/algod-rust/issues/669) sha512/sumhash512 cost bugfix | [#684](https://github.com/xarmian/algod-rust/pull/684) | `ops/crypto.rs` cost formulas corrected, pinned against go's own `TestHashCosts` vectors. |
| [#670](https://github.com/xarmian/algod-rust/issues/670) gload nil-pastScratch fix | [#685](https://github.com/xarmian/algod-rust/pull/685) | `avm_context.rs::gload` ports go's check order via new `GroupInfo::ran_program`; real 2-txn-group regression test through `apply_transaction_with_budget`. |
| [#672](https://github.com/xarmian/algod-rust/issues/672) assembler match-type-tracking + deadcode disassembly | [#687](https://github.com/xarmian/algod-rust/pull/687) | `disassembler.rs::collect_labels` now labels every `proto`, including dead subroutines; `test_roundtrip_dead_subroutine` ported from go's own test. |
| [#666](https://github.com/xarmian/algod-rust/issues/666) byte-constant size limit + falcon_verify audit | [#688](https://github.com/xarmian/algod-rust/pull/688) | `MAX_STRING_SIZE` enforced in `bytecode.rs` (v13+) and all 4 assembler sites; falcon_verify confirmed already correct (regression test added). |
| [#665](https://github.com/xarmian/algod-rust/issues/665) poseidon2 opcode | [#689](https://github.com/xarmian/algod-rust/pull/689) | Hand-ported gnark-crypto v0.18.1 algorithm; byte-identical against go's `TestPoseidon2` vectors for both curve configs. |
| [#661](https://github.com/xarmian/algod-rust/issues/661) varint branch encoding | [#690](https://github.com/xarmian/algod-rust/pull/690) | Interpreter + assembler (`findBranchSizes` port) + disassembler, all three layers; 10 oracle tests against go's exact algorithm. Live-verified (see #691 below). |
| [#664](https://github.com/xarmian/algod-rust/issues/664) auto-salt TEAL v13 programs | [#692](https://github.com/xarmian/algod-rust/pull/692) | `program_hash_is_edwards25519_point` + 128-candidate salt search port; vectors independently generated from a standalone Go program using go-algorand's own curve library. |
| [#694](https://github.com/xarmian/algod-rust/issues/694) fix flaky varint-branch test (found during #659) | [#696](https://github.com/xarmian/algod-rust/pull/696) | `#pragma autosalt false` added to the test's fixed source, restoring deterministic layout. |
| [#659](https://github.com/xarmian/algod-rust/issues/659) app_params_set + multi-byte dispatch | [#695](https://github.com/xarmian/algod-rust/pull/695) | New `OpSpec.sub_ops`/`opcode::resolve` two-byte dispatch; `AppParams.foreign_box_reads`/`family_box_access` threaded through codec/trackerdb/catchpoint. |
| [#662](https://github.com/xarmian/algod-rust/issues/662) nine foreign-box opcodes | [#697](https://github.com/xarmian/algod-rust/pull/697) | `authorize_box_access`/`check_family_reentrancy` port go's read/write/family-reentrancy rules exactly, with adversarial test cases. |
| [#667](https://github.com/xarmian/algod-rust/issues/667) SelectF128 sortition port (**highest risk**) | [#699](https://github.com/xarmian/algod-rust/pull/699) | Bit-for-bit `f128.rs` port; 221 end-to-end vectors generated by driving the real unmodified `sortition@v1.1.1` Go source; upstream's own named frozen-tail regression tests ported verbatim; **live 4-node mixed-cluster soak, 30 rounds, zero agreement-level rejections**. |
| [#675](https://github.com/xarmian/algod-rust/issues/675) application-update LocalStateSchema check | [#700](https://github.com/xarmian/algod-rust/pull/700) | `validate_application_call_wellformed` implemented from scratch with the local-schema-always-immutable rule correct from day one. |
| [#657](https://github.com/xarmian/algod-rust/issues/657) big-transaction size pricing | [#702](https://github.com/xarmian/algod-rust/pull/702) | `algo-validate::fee` module: `fee_for_usage`/`MulInt`/contribution primitives; caught and fixed a real u128-overflow bug in self-review before merge. |
| [#677](https://github.com/xarmian/algod-rust/issues/677) AVM inner-txn fee-residue threading | [#704](https://github.com/xarmian/algod-rust/pull/704) | `fee_residue` threaded through `LedgerAvmContext`/`ApplyContext`/simulation, inherit-down/copy-back matching go's pattern. |
| [#668](https://github.com/xarmian/algod-rust/issues/668) heartbeat HbChallengeDiscount field | [#705](https://github.com/xarmian/algod-rust/pull/705) | Version-gated flag + fixed a real bug where the pre-v42 fee-inference path applied unconditionally regardless of protocol version. |
| [#660](https://github.com/xarmian/algod-rust/issues/660) post-quantum Falcon-1024 account signatures | [#706](https://github.com/xarmian/algod-rust/pull/706) | `PQSig`/`PQAddress`/`PQDelegatedProgram` wire types + verification wiring; fixed an attacker-controlled-key-size self-review finding before merge. |
| [#671](https://github.com/xarmian/algod-rust/issues/671) simulate API fee-usage reporting | [#708](https://github.com/xarmian/algod-rust/pull/708) | `fees-paid`/`group-usage`/`group-fees-paid` wired through `Simulator::simulate`, recursive-inner-txn integration test. |
| [#674](https://github.com/xarmian/algod-rust/issues/674) remove dryrun REST endpoint | [#709](https://github.com/xarmian/algod-rust/pull/709) | Full removal (route/handler/models/OAS schema/tests), plus dead-code cleanup beyond the issue's literal scope (goal-rust CLI leaves, `AlgodClient` methods). |
| [#673](https://github.com/xarmian/algod-rust/issues/673) GET /v2/node/peers + POST /v2/node/shutdown | [#710](https://github.com/xarmian/algod-rust/pull/710) | Real `NodeInterface::get_peers()` backed by `algo-network`/`algo-p2p` connection state (not a stub); admin-token access-control verified with dedicated 401 tests. |
| [#676](https://github.com/xarmian/algod-rust/issues/676) FNet consensus version table entries | [#711](https://github.com/xarmian/algod-rust/pull/711) | `CONSENSUS_VFNET1..4` added; regression tests confirming graceful degradation on unknown protocol strings. |

### Follow-up issues filed and worked during Stage 6 (14)

| Sub-issue | PR | Why it exists / evidence |
|---|---|---|
| [#681](https://github.com/xarmian/algod-rust/issues/681) block production never proposes/votes for protocol upgrades | [#712](https://github.com/xarmian/algod-rust/pull/712) | Found during Stage 5's pin sweep: the first pin bump where `ConsensusCurrentVersion` itself advances past genesis, breaking a documented "no upgrade ever in flight" assumption. Full propose/vote/switch lifecycle ported; **live-verified in CI** (`Live parity vs go-algorand` — `get_produced_block_msgpack_matches` passing byte-identical against a real go-algorand v5.0.0-stable node, carve-out from PR #680 removed). |
| [#686](https://github.com/xarmian/algod-rust/issues/686) gload must return sibling's real scratch value | [#713](https://github.com/xarmian/algod-rust/pull/713) | Found during #670: the ledger-apply path silently returned a zero placeholder instead of a sibling's real scratch write. `AvmResult::scratch` added; real integration test through `apply_transaction_with_budget`. |
| [#698](https://github.com/xarmian/algod-rust/issues/698) machine.rs cost-charging bypasses sub-opcode resolution | [#715](https://github.com/xarmian/algod-rust/pull/715) | Found during #662: static cost charging used prefix-byte-only lookup instead of resolving the real sub-opcode; harmless today (uniform costs) but latent. |
| [#701](https://github.com/xarmian/algod-rust/issues/701) remaining ApplicationCallTxnFields.wellFormed sub-checks | [#716](https://github.com/xarmian/algod-rust/pull/716) | Found during #675: OnCompletion/RejectVersion/program-version/arg/reference-count bounds, ~50 adversarial tests, fixed 3 pre-existing test fixtures that had been passing only because the check didn't exist. |
| [#693](https://github.com/xarmian/algod-rust/issues/693) assembler warnings channel | [#717](https://github.com/xarmian/algod-rust/pull/717) | Deferred from #664: go's `shouldAutoSalt` diagnostics had no algod-rust warnings mechanism; minimal channel added, backfilled with the two autosalt warnings. |
| [#714](https://github.com/xarmian/algod-rust/issues/714) gload unconditionally errors inside an inner-transaction group | [#718](https://github.com/xarmian/algod-rust/pull/718) | Found during #686: `execute_inner_appl` always built a single-element AVM group; generalized the `GroupInfo` pattern to inner groups. |
| [#691](https://github.com/xarmian/algod-rust/issues/691) live/binary-diff verification of v13 varint branches | [#719](https://github.com/xarmian/algod-rust/pull/719) + closed after [#721](https://github.com/xarmian/algod-rust/pull/721) | Deferred from #661: live byte-for-byte assembler diff against a real go-algorand v5.0.0-stable node, **confirmed passing in CI**; the mixed-branch execution-trace criterion was initially blocked (see #720) and confirmed passing once unblocked. |
| [#720](https://github.com/xarmian/algod-rust/issues/720) shared test genesis lagging at consensus V41 | [#721](https://github.com/xarmian/algod-rust/pull/721) | Found during #691: `docker/localnet-rust/data/genesis.json` was never bumped through phases 9-14, blocking live verification of **every** AVM v13 feature. Bumped to V42; full blast-radius audit of all 10+ dependent live test files found no hardcoded genesis-hash assumptions needing changes. **Live-verified**: real `Live parity vs go-algorand` CI run confirmed the previously-blocked test now passes. |
| [#703](https://github.com/xarmian/algod-rust/issues/703) live fixture/oracle tests for big-transaction size-pricing | [#722](https://github.com/xarmian/algod-rust/pull/722) | Deferred from #657: 5 live dual-node boundary tests. **Found and fixed two real production bugs**: (1) canonical encoder used the wrong omitempty rule for `Note []byte`, silently dropping a non-empty all-zero note from the signed encoding; (2) group-fee validation skipped every ungrouped (size-1) transaction entirely, letting an underpaid oversized-LogicSig transaction through. |
| [#723](https://github.com/xarmian/algod-rust/issues/723) gate oversized app-program writes behind box I/O budget | [#724](https://github.com/xarmian/algod-rust/pull/724) | Found during #703's live testing: go's `considerBudgetProgramWrites` wasn't ported. `consider_budget_program_writes` added, live-verified against a real go-algorand v5.0.0-stable node. |
| [#707](https://github.com/xarmian/algod-rust/issues/707) live PQSig msgpack fixture | [#728](https://github.com/xarmian/algod-rust/pull/728) | Deferred from #660: replaced the hand-computed oracle with a genuinely live-captured one — built `algokey` from the pinned go-algorand checkout in Docker, used real `algokey pq generate/sign/sign-program` to produce a real PQSig-signed transaction and PQ-delegated LogicSig; both decoded and re-encoded byte-identical through algod-rust's existing canonical encoder on the first try. |
| [#725](https://github.com/xarmian/algod-rust/issues/725) box read-I/O-budget check only ever lazily triggered | [#726](https://github.com/xarmian/algod-rust/pull/726) | Found during #723: go's read-budget check runs unconditionally at the start of every top-level app call; algod-rust only checked it lazily on first box-opcode use. Fixed with a real correctness regression test (not just a missing-test gap). |
| [#727](https://github.com/xarmian/algod-rust/issues/727) box budget state not shared across sibling top-level app calls | [#729](https://github.com/xarmian/algod-rust/pull/729) | Found during #725: go shares one `EvalParams` (and its I/O-budget state) by pointer across a whole txn group; algod-rust rebuilt a fresh context per top-level app call. Generalized the group-scoped `BoxBudgetState` carrier already used for parent/child inner-call propagation. |

## Version-pin sweep

69 files swept from `v4.7.4-stable` to `v5.0.0-stable` (PR #680):
`CLAUDE.md`, `README.md`, CI workflows, `Makefile`, oracle/capture tools
(`tools/*`, `crates/tools/*`), `docker/*` compose files, and
`ops/mixed-cluster{,-p2p,-3rust}` harness docs/scripts/compose files.
Went beyond the directed hot-spot list: found and fixed the
`algorand/algod:4.7.3-stable` Docker image tag lagging one patch release
behind the git pin since the Phase 13 sweep. Deliberately left untouched:
historical version-delta citations (`PHASE9`-`PHASE13*`,
`docs/epics/Epic-19`-`22-*`).

The pin bump legitimately surfaced one real gap during CI
(`get_produced_block_msgpack_matches`: algod-rust's block header was
missing every `next*`/`upgrade*` field entirely) — this is the first pin
bump in the repo's history where go-algorand's `ConsensusCurrentVersion`
itself advances, so it was the first time an active default upgrade
proposal appeared in the live-parity harness. Filed as #681 (see above)
rather than papering over it with a permanent carve-out; the narrow
7-field carve-out added to unblock the pin-sweep PR was removed when #681
landed.

## Full gate on `main`

Re-run at close-out after PR #729 merged (2026-08-29):

- `cargo fmt --all --check` — clean.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo test --workspace` — every crate green except the pre-existing,
  documented `algo-network` `peer_features.rs` doctest flake (CLAUDE.md's
  known local-environment issue) — the sole acceptable failure per this
  repo's stated policy.

## Live mixed-cluster / dual-node verification

Live verification for this phase is unusually extensive because several
sub-issues (#681, #691, #703, #720, #723) specifically targeted live
dual-node/mixed-cluster confirmation, each confirmed via real GitHub
Actions job logs rather than assumption:

- **SelectF128 sortition (#667)**: 4-node mixed cluster (3 real
  go-algorand v5.0.0-stable relays + 1 algod-rust participant, genesis
  inheriting v42's `EnableSelectF128=true`), 30 rounds in lockstep, zero
  agreement-level rejections, Rust votes accepted, a block proposed.
- **Protocol upgrade voting (#681)**: `Live parity vs go-algorand`
  workflow — algod-rust's own produced block at round 1 matches a real
  go-algorand v5.0.0-stable node's `nextbefore`/`nextproto`/`nextswitch`/
  `nextyes`/`upgradedelay`/`upgradeprop`/`upgradeyes` fields byte-for-byte.
- **Varint branch encoding (#661/#691)**: live assembler byte-diff against
  a real go-algorand v5.0.0-stable node's `POST /v2/teal/compile`, plus a
  mixed forward/back branch execution-trace test, both confirmed passing
  in CI once the shared test genesis was bumped to V42 (#720).
- **Big-transaction size pricing (#657/#703)**: 5 live dual-node boundary
  tests at the note/app-arg/app-program/logicsig-program size limits,
  which caught the two real production bugs described above.
- **Program-write budget gate (#723)**: live-verified reject-decision
  parity against a real go-algorand v5.0.0-stable node.

## Outcome

All 21 original sub-issues plus 14 follow-up issues filed during Stage 6
are merged. `gh issue list --label "phase:14" --state open` returns only
the epic issue itself (verified immediately before this document was
written). The reference pin, docs, and code are consistent at
`v5.0.0-stable`. No sub-issue was disposed as unreachable or deferred —
every item that surfaced, including several discovered only through live
dual-node testing, was implemented and merged.
