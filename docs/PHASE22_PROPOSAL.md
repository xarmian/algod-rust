# Phase 22 Proposal — go-algorand v5.0.4-stable parity

Phase 22 moves algod-rust's parity target from go-algorand `v5.0.3-stable`
to `v5.0.4-stable`, per the `algod-version-upgrade` skill.

Tracking epic: [#2025](https://github.com/xarmian/algod-rust/issues/2025) (`docs/epics/Epic-32-Go-Algorand-v5.0.4-Parity.md`).

## Motivation

`v5.0.4-stable` (published 2026-10-20) addresses minimum-balance handling
inconsistencies and **contains a protocol upgrade**: consensus version v43.
`AppSizeUpdates` (v42) lets an account be an app's SizeSponsor, holding MBR
for global state and extra pages of apps it neither created nor opted into;
the legacy per-counter close-out checks miss that, so an account could be
closed while still owing MBR. v43 replaces them with a single base-MBR check.

## Scope

`OLD` = `v5.0.3-stable` (`2dc9524e9e9b7f4cd9234659d45ac42b283c4ae3`)
`NEW` = `v5.0.4-stable` (`927ae0863cbb4cf29c6845c088a4ea4c439b10bb`)

`TAGS_IN_RANGE` = `{v5.0.4-stable}`. `v5.0.4-beta` (`02a411567`) only merges the
stable branch into the beta line; no separate pre-release behavior.

### Classified inventory

| Upstream commit | Classification | Sub-issue |
|---|---|---|
| `0ed1007d8` — Consensus: add v43 with `CloseRequiresBaseMinBalance` (+ `apply/payment.go` rewrite, `legacyCloseChecks`) | `consensus-critical` | #2022 |
| `4aaa58fa0` — eval: refuse to assemble a close-out that still requires a minimum balance (generate-only) | `behavioral-other` | #2023 |
| `e5a1da05d` — agreement: restore zstd-compressed crash recovery snapshots (decode only; `compressSnapshots = false`) | `behavioral-other` | #2024 |
| `3de5f9828` — ledger: reconcile tests | tests of the above | #2022 / #2023 |
| `6edbfe05c` — Bump buildnumber.dat; `ci-pr.yml` tweak; e2e script error strings | `not-applicable` | Build/CI metadata only. |

The release notes list exactly the three bug-fix bullets above; all accounted for.

### Test parity (Pass C)

`docs/phase22/test_parity_delta.md`: 3 added (`TestAgreementSnapshotCompression`,
`TestSponsorCannotClose`, `TestCloseMinBalancePolicy`), 0 removed, 0 moved,
3 body changed (`TestRandomizedEncodingFullDiskState`, `TestExtraPagesUpdate`,
`TestCowChildReflect`), each owned by a sub-issue above.

## Success criteria

- [ ] #2022, #2023, #2024 closed.
- [ ] Pin swept from `v5.0.3-stable` to `v5.0.4-stable` across the repo.
- [ ] `python3 scripts/phase17_parity_delta.py check --tag v5.0.4-stable --go-algorand ../go-algorand` exits 0 (`not-implemented` = `missing-test` = `partial` = `unclassified` = 0).
- [ ] Full gate green on `main` (fmt, clippy, workspace tests) and a live mixed-cluster run against v5.0.4-stable Go nodes.
- [ ] `docs/PHASE22_VALIDATION.md` evidence map written at close-out.
- [ ] `gh issue list --label "phase:22" --state open` empty before the epic closes.

## Non-goals

- Build metadata (`buildnumber.dat`), `ci-pr.yml`, go e2e shell scripts.
- Enabling snapshot compression on encode (upstream keeps it off this release).
