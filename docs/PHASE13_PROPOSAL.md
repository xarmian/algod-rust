# Phase 13 Proposal — go-algorand v4.7.4-stable Parity

Phase 13 moves algod-rust's parity target from go-algorand `v4.7.3-stable`
to `v4.7.4-stable`, a small safety/durability-focused patch release.

Tracking epic: [#650](https://github.com/xarmian/algod-rust/issues/650).

## Scope

`TAGS_IN_RANGE` = `v4.7.3-stable` (OLD) → `v4.7.4-stable` (NEW) only.
`v4.7.4-beta` exists upstream but is excluded: it is chronologically
*after* `v4.7.4-stable` and contains commits not reachable from it
(`git merge-base --is-ancestor v4.7.4-beta v4.7.4-stable` is false; the
reverse holds) — it previews later work, not a pre-release of this tag.

`git log --oneline v4.7.3-stable..v4.7.4-stable` has 4 commits (1 merge).
Upstream release notes ("This release improves safety and durability of
node operation... Improved error handling and validation for transactions
and transaction groups") list exactly one Enhancements bullet: "checks:
recompute group IDs" — matching the commit-log analysis below with no gaps.
No protocol upgrade in this release.

### Classified inventory

| Commit | Classification | Disposition |
|---|---|---|
| `b07049dfb` "checks: recompute group IDs" | consensus-critical | Real gap in algod-rust's early proposal screen — issue [#649](https://github.com/xarmian/algod-rust/issues/649) |
| `5fe110422` "makefile: bump msgp 1.1.63" | not-applicable | Go build-tooling dependency bump, zero behavior change |
| `6c99119ef` "Bump buildnumber.dat" | not-applicable | Go-internal build-number bookkeeping, no Rust-facing behavior |
| `91cbddcd3` merge commit | not-applicable | Merge wrapper, no content |

### `b07049dfb` — checks: recompute group IDs

Before this commit, go-algorand's early block-proposal screen
(`agreement.proposalCarriesInvalidTxn`, called before accepting/relaying a
gossiped proposal) only checked transaction-group *boundaries*
(`CheckPayset`, comparing adjacent `.Group` field values) — it never
cryptographically verified that the claimed `Group` digest actually commits
to (hashes) the transactions claimed to be in it, in the given order. The
commit replaces this with `Block.PaysetGroups()` (which also now enforces
`bounds.MaxTxGroupSize` per group) and a reworked
`transactions.checkTxnGroupID`/`CheckPaysetGroup`, which recomputes the
canonical group hash from the transactions (each with its own `.Group`
zeroed) and rejects a mismatch, an inconsistent per-txn `Group` value
within a claimed group, or a `n>1` group with a zero `Group`. A lone
transaction (`n==1`, zero group) remains exempt.

A background investigation (Explore agent, this session) found algod-rust's
**deep** validation path (`algo-validate::rules::validate_transaction_group`,
run inside `validate_block`) already performs the strong, correct
hash-recomputation check, including the `n==1` exemption and the
max-group-size bound. The gap is in algod-rust's **early**
pre-acceptance/pre-relay proposal screen
(`algo-agreement::demux::handle_raw_proposal`, the direct analogue of
`proposalCarriesInvalidTxn`), which still calls the weak, boundary-only
`algo_validate::check_payset`/`detect_validation_groups` with no
max-group-size bound — exactly the check go-algorand replaced. Tracked as
issue #649.

## Non-goals

- `makefile: bump msgp 1.1.63` — Go build-tooling change with no runtime
  behavior; algod-rust does not depend on go-algorand's `msgp` codegen
  toolchain.
- `Bump buildnumber.dat` — Go-internal release bookkeeping, no observable
  behavior.

## Success criteria

- Issue [#649](https://github.com/xarmian/algod-rust/issues/649) merged
  (or honestly disposed per this repo's issue-disposition rules).
- Version pin swept to `v4.7.4-stable` across the repo.
- Full gate green on `main`; live mixed-cluster verification against
  go-algorand v4.7.4-stable Go nodes for the consensus-critical fix.
- `docs/PHASE13_VALIDATION.md` written at close-out.
