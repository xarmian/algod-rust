# Epic: go-algorand v4.7.4-stable parity

Tracks moving algod-rust's parity target from go-algorand `v4.7.3-stable` to
`v4.7.4-stable`, per the `algod-version-upgrade` skill.

## Stage 1 — Tags in range

- `OLD` = `v4.7.3-stable` (`4d11e2e9c3e5b056fdfa08053dcef79d2d6422df`)
- `NEW` = `v4.7.4-stable` (`91cbddcd37d4fe7cbece5f631158a6710e5666fd`)
- `TAGS_IN_RANGE` = `v4.7.3-stable`, `v4.7.4-stable` only.
  `v4.7.4-beta` exists upstream but is **excluded**: it is chronologically
  *after* `v4.7.4-stable` (2026-07-21 vs. 2026-07-14) and contains 3 commits
  not reachable from `v4.7.4-stable`
  (`git merge-base --is-ancestor v4.7.4-beta v4.7.4-stable` → false;
  the reverse holds true) — it is a preview of later work, not a
  pre-release of this stable tag.

## Stage 2 — Classified inventory

`git log --oneline v4.7.3-stable..v4.7.4-stable` (4 commits, 1 merge):

| Commit | Classification | Disposition |
|---|---|---|
| `b07049dfb` "checks: recompute group IDs" | **consensus-critical** | Real gap found in algod-rust's early proposal screen — see #649 |
| `5fe110422` "makefile: bump msgp 1.1.63" | not-applicable | Go build-tooling dependency bump, zero behavior change |
| `6c99119ef` "Bump buildnumber.dat" | not-applicable | Go-internal build-number bookkeeping, no Rust-facing behavior |
| `91cbddcd3` merge commit | not-applicable | Merge wrapper, no content |

Upstream release notes (`gh release view v4.7.4-stable -R algorand/go-algorand`)
confirm this is the complete surface: "This release improves safety and
durability of node operation... Improved error handling and validation for
transactions and transaction groups," with the single Enhancements bullet
"checks: recompute group IDs" — matching the commit-log analysis above
exactly. No protocol upgrade in this release.

### `b07049dfb` — checks: recompute group IDs

Closes a real gap in go-algorand's early block-proposal screen
(`agreement.proposalCarriesInvalidTxn`): previously it only checked
transaction-group **boundaries** (`CheckPayset`, comparing adjacent `.Group`
field values), never cryptographically verifying that the claimed `Group`
digest actually commits to (hashes) the transactions claimed to be in it.
Now `Block.PaysetGroups()` + `transactions.CheckPaysetGroup` recompute the
canonical group hash and enforce `MaxTxGroupSize` per group before a
proposal is accepted/relayed.

A background investigation (Explore agent) found algod-rust's **deep**
validation path (`algo-validate::rules::validate_transaction_group`,
run inside `validate_block`) already does the strong, correct check —
but algod-rust's **early** pre-acceptance proposal screen
(`algo-agreement::demux::handle_raw_proposal`, the direct analogue of
`proposalCarriesInvalidTxn`) still uses the old weak boundary-only check
(`algo_validate::check_payset` / `detect_validation_groups`), with no
max-group-size bound either. Tracked as #649.

## Stage 6 — Sub-issues (dependency order)

- [ ] #649 — agreement: enforce cryptographic group-ID recomputation in
      early proposal screen

## Epic-level acceptance criteria

- [ ] All sub-issues above closed (merged or honestly disposed).
- [ ] `docs/PHASE13_PROPOSAL.md`, `docs/epics/Epic-23-Go-Algorand-v4.7.4-Parity.md`,
      `docs/PROJECT_SCOPE.md` updated.
- [ ] Version pin swept from `v4.7.3-stable` to `v4.7.4-stable` across the
      repo (CLAUDE.md, workflows, docker compose, docs).
- [ ] Full gate green on `main` (fmt, clippy, full workspace suite).
- [ ] `docs/PHASE13_VALIDATION.md` evidence map written at close-out.
- [ ] Hard gate: `gh issue list --label "phase:13" --state open` empty
      before this epic closes.
