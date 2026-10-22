# Phase 22 Validation — go-algorand v5.0.4-stable Parity

_Completed: 2026-10-22_

Phase 22 moved algod-rust's parity target from go-algorand `v5.0.3-stable`
to `v5.0.4-stable`, a minimum-balance patch release that ships a protocol
upgrade: consensus **v43** (`CloseRequiresBaseMinBalance`), a generate-only
close-out guard, and zstd decode support for agreement crash-recovery
snapshots.

Evidence map for [`docs/PHASE22_PROPOSAL.md`](PHASE22_PROPOSAL.md) and
[`docs/epics/Epic-32-Go-Algorand-v5.0.4-Parity.md`](epics/Epic-32-Go-Algorand-v5.0.4-Parity.md).
Tracking epic: [#2025](https://github.com/xarmian/algod-rust/issues/2025).

## Completeness re-check (Stage 7)

- `git -C ../go-algorand fetch --tags`; `TAGS_IN_RANGE` = `{v5.0.4-stable}`
  (`v5.0.4-beta` only merges the stable branch back). Unchanged since Stage 1.
- `gh release view v5.0.4-stable -R algorand/go-algorand`: three "Bug Fixes"
  bullets — close-out guard (#2023), consensus v43 (#2022), zstd snapshots
  (#2024) — plus the "Protocol Upgrade" notice (v43, #2022). All mapped;
  `buildnumber.dat`, `ci-pr.yml` and the e2e shell scripts' expected error
  strings are the `not-applicable` remainder of the diff.
- `gh issue list --label phase:22 --state open`: only the epic #2025.

## Criteria and evidence

| Criterion | Evidence |
|---|---|
| Consensus v43 / `CloseRequiresBaseMinBalance` (#2022) | PR #2030: `CONSENSUS_V43` (spec hash `73c43b4a…`), v42→v43 upgrade edge 208000, v43 current, vFuture from v43, `close_requires_base_min_balance` param (+ `consensus.json` override field). `apply_pay` enforces the base-MBR rule with go's exact message for outer and inner payments; `legacy_close_checks` keeps pre-v43 replay byte-identical. Tests: `consensus.rs::test_v43_is_v42_plus_close_requires_base_min_balance` / `test_v42_approves_v43_upgrade` / `test_v43_is_current_and_future_derives_from_it`, `block_header.rs::v42_proposes_v43_by_default`, `apply_test.rs::test_v43_*`, and the end-to-end port of `TestSponsorCannotClose` (`app_call_lifecycle_test.rs::sponsor_cannot_close_v43_but_can_pre_v43`, `sponsor_can_close_after_app_delete_releases_mbr_v43`). Lookback parity fixture regenerated from v5.0.4-stable (`tools/lookback-vector-capture` now lists V43). |
| Generate-only close-out guard (#2023) | PR #2031: `ProbeRequest::generate` → `ApplyContext::generate` → `LedgerAvmContext::generate` (inherited by nested inner calls), set only by `evaluate_group` (pool), `evaluate_payset` / proposer scratch payset (assembly) and the simulator; `closing_record` + `check_close_min_balance` after `apply_pay` in both the top-level and inner paths. `close_min_balance_policy_test.rs` is a 1:1 port of `TestCloseMinBalancePolicy` over v42/v43 (generating via `evaluate_group`, validating via a block, inner update/close through a closer app); verified to fail with the guard disabled. |
| zstd crash-recovery snapshots (#2024) | PR #2032: `decode` transparently decompresses a zstd frame (magic `28 b5 2f fd`), `encode` stays uncompressed (`COMPRESS_SNAPSHOTS = false`), `compress_snapshot` is the level-3 compressor; `persistence.rs::agreement_snapshot_compression` mirrors `TestAgreementSnapshotCompression` (round trip, same decoded state, through the SQLite crash table, truncated frame → `Corrupt`). |
| Pin swept | PR #2028: ~95 files from `v5.0.3-stable` to `v5.0.4-stable` (CLAUDE.md, workflows, docker/ops compose + scripts, Go oracle/capture tool pins, both `algod-rust/5.0.4` User-Agent prefixes); history-citing files (Phase 19/20/21 docs, epic docs) untouched. The one live-parity carve-out it needed (v43 upgrade-proposal header fields, `live_msgpack_parity.rs`) was removed again by PR #2030, and the Dual-Node REST Conformance job has run green since against `algorand/algod:5.0.4-stable`. |
| Test parity | `docs/phase22/test_parity_delta.md`: 3 added / 0 removed / 0 moved / 3 body-changed. `TestSponsorCannotClose` → `matched-1:many`, `TestCloseMinBalancePolicy` → `matched-1:1`, `TestAgreementSnapshotCompression` → `matched-1:1`; `TestExtraPagesUpdate`, `TestRandomizedEncodingFullDiskState` re-verified (hunks are only the adjacent new tests); `TestCowChildReflect` re-verified (new `generate` field carried and inherited; stays `out-of-scope` as a reflect field-list net). |
| Parity map gate | `python3 scripts/phase17_parity_delta.py check --tag v5.0.4-stable --go-algorand ../go-algorand --allow-partial 3` → `OK - parity map is pinned, complete, and gap-free` (pin v5.0.4-stable; rows 3193 = inventory 3193; matched-1:1 1212, matched-1:many 956, matched-many:1 286, partial 3, out-of-scope 736; `not-implemented` = `missing-test` = `unclassified` = 0). |
| Live mixed-cluster vs v5.0.4 Go nodes | Local `consensus-conformance.sh` ROUNDS=200 WORKLOAD=rich on 3×`algorand/algod:5.0.4-stable` + 1×algod-rust (`ops/mixed-cluster/conformance-20261022-094858`, working tree = main + every Phase 22 PR): 200 rounds byte-identical on 4 nodes (96 with txns, 72 non-payment; pay/acfg/axfer/afrz/appl incl. 27 inner-txn and 8 box-ref txns), fork-free, 0 Go-side agreement rejections, 744 `VoteAccepted` records with the Rust account as sender, proposer share 16/200 (z=−0.94, 3σ bound), soft+cert+next* vote steps seen, rich workload steps=108 confirmed=96 rejected=12 go/rust admission divergences=0, cadence and lockstep within bounds. The two cert cross-verify checks failed for the known harness reason only (tip 333 > `BalanceLookback` 320, so every sampled cert's balance round is beyond the online-account retention and OTS key lookup fails on *both* verifiers — #1854 / #1892, same as the Phase 20 run); the exported certs decode cleanly (3 votes each, `snd`/`cred`/`sig`, `rnd`/`step` set).  Authoritative CI evidence: the Nightly Consensus Cluster run [39743853594](https://github.com/xarmian/algod-rust/actions/runs/39743853594) on `main` @ `24949416` (v43 + the generate-only guard merged) against `algorand/algod:5.0.4-stable` concluded **success** on 2026-10-22 — every gate including both cert cross-verify directions (2026-10-22T08:23:33.9126153Z cert-authenticate (go-algorand v5.0.4-stable): rounds=11 ok=11 failed=0 rust_vote_rounds=0). |

## Known limitations / sign-offs

- **3 `partial` rows** (`docs/phase17/parity_agreement.md`) remain, each needing a
  live multi-node `Fuzzer`+`Service`+`TopologyFilter` harness; carried
  forward under the standing `--allow-partial 3` sign-off (Phases 18–20).
- Snapshot **compression on encode** stays off, as upstream this release;
  flipping `COMPRESS_SNAPSHOTS` is a future-release decision, not a gap.
