# Phase 13 Validation — go-algorand v4.7.4-stable Parity

_Completed: 2026-08-28_

Phase 13 moves algod-rust's parity target from go-algorand `v4.7.3-stable`
to `v4.7.4-stable`, a small safety/durability-focused patch release.

This document is the evidence map for
[`docs/PHASE13_PROPOSAL.md`](PHASE13_PROPOSAL.md) and
[`docs/epics/Epic-23-Go-Algorand-v4.7.4-Parity.md`](epics/Epic-23-Go-Algorand-v4.7.4-Parity.md),
mirroring the structure of [`PHASE12_VALIDATION.md`](PHASE12_VALIDATION.md).
Every claim below cites a specific file/test/tool in this repo.

Tracking epic: [#650](https://github.com/xarmian/algod-rust/issues/650).

---

## Completeness re-check (Stage 7 mandatory re-run)

Per the `algod-version-upgrade` skill's Stage 7 instructions, the
release-notes completeness pass and `TAGS_IN_RANGE` derivation were
re-run fresh at close-out (2026-08-28), not just trusted from the
original Stage 1-2 pass:

- `git -C ../go-algorand fetch --tags` followed by
  `git tag --contains v4.7.3-stable --list | sort -V` confirms
  `TAGS_IN_RANGE` is unchanged: `v4.7.3-stable` (OLD) → `v4.7.4-stable`
  (NEW) only. `v4.7.4-beta` remains correctly excluded — re-verified as
  chronologically *after* `v4.7.4-stable` and not an ancestor of it
  (`git merge-base --is-ancestor v4.7.4-beta v4.7.4-stable` → false).
- `gh release view v4.7.4-stable -R algorand/go-algorand` returns the
  identical single Enhancements bullet ("checks: recompute group IDs")
  the original Stage 2 pass classified — no corrections or additions
  since the original survey.

## Sub-issue disposition

| Sub-issue | Outcome | Evidence |
|---|---|---|
| [#649](https://github.com/xarmian/algod-rust/issues/649) — enforce cryptographic group-ID recomputation in early proposal screen | Merged (PR [#653](https://github.com/xarmian/algod-rust/pull/653)) | `crates/core/algo-agreement/src/demux.rs`'s `handle_raw_proposal` now calls `algo_validate::validate_transaction_group` alongside `check_payset`. New test `demux_raw_proposal_with_group_id_mismatch_is_dropped_not_disconnected` confirmed FAILED against pre-fix code, passes after. Live-verified: `consensus-cluster.yml` smoke tier ([run 33153343847](https://github.com/xarmian/algod-rust/actions/runs/33153343847)) — 4-node mixed cluster (3 go-algorand v4.7.4-stable relays + 1 algod-rust participant) advanced 30 rounds in lockstep, no agreement-level rejection logged. |

### Spin-off: #654 (infra, not phase-13-blocking)

Working #649's live-verification acceptance criterion surfaced an
unrelated pre-existing bug: `ops/mixed-cluster/scripts/participation-smoke.sh`
had been git-mode `100644` (non-executable) since its introduction in PR
#481 (issue #469, phase 6) — `Makefile`'s `consensus-cluster-smoke` target
invokes it directly and needs the execute bit, so every nightly-scheduled
`consensus-cluster.yml` run had been failing with `Permission denied`
since at least 2026-08-24, unnoticed because the workflow never runs on
PRs. Filed and fixed as [#654](https://github.com/xarmian/algod-rust/issues/654)
(PR [#655](https://github.com/xarmian/algod-rust/pull/655), mode-only
change, verified working via a manual dispatch before merge) — not added
to this epic's blocking sub-issue list since it predates and is unrelated
to the v4.7.4-stable sweep, but noted in the epic per this repo's
open-topics rules since #649's own live verification depended on it.

## Non-goals confirmed (no algod-rust action needed)

Per epic #650's classified inventory, 2 of the 4 commits in the
`v4.7.3-stable..v4.7.4-stable` range required no algod-rust action:

- `5fe110422` "makefile: bump msgp 1.1.63" — Go build-tooling dependency
  bump; algod-rust does not depend on go-algorand's `msgp` codegen
  toolchain.
- `6c99119ef` "Bump buildnumber.dat" — Go-internal release bookkeeping,
  no observable behavior.

(The 4th commit, `91cbddcd3`, is the merge-wrapper commit itself, with
no content of its own.)

## Version-pin sweep

49 files swept from `v4.7.3-stable` to `v4.7.4-stable` (PR #652):
`CLAUDE.md`, `README.md`, CI workflows (`algokey-e2e.yml`,
`conformance-parity.yml`, `consensus-cluster.yml`, `p2p-consensus-soak.yml`,
`p2p-interop.yml`, `validate-api.yml`), `Makefile`, oracle/capture tools
(`tools/*`, `crates/tools/*`), `ops/mixed-cluster{,-p2p,-3rust}` harness
docs/scripts/compose files, and docs (`DEV_WORKFLOW.md`,
`CONFORMANCE_STRATEGY.md`, `MIXED_CLUSTER_HARNESS.md`,
`P2P_SOAK_METHODOLOGY.md`, `SOAK_METHODOLOGY.md`). Deliberately left
untouched: historical version-delta citations (`PHASE12*`,
`docs/epics/Epic-22-*`) and `DEV_WORKFLOW.md`'s illustrative
`v4.5.1-stable → v4.7.0-stable` pin-bump example. The sweep caught and
hand-fixed one real mistake: a blind substitution would have silently
collapsed `CLAUDE.md`'s historical
"`v4.7.2-stable → v4.7.3-stable`" Phase-12 range description into
"`v4.7.2-stable → v4.7.4-stable`" — rewritten by hand instead, along with
adding the missing Phase-13-in-progress note.

Live-parity CI on the pin-sweep PR itself (`Crypto + Codec Parity Suite`,
`Live parity vs go-algorand`, `algokey-rust e2e`) ran green against real
go-algorand v4.7.4-stable nodes with no carve-outs needed — #649's gap is
agreement/consensus-path only (requires a maliciously-crafted proposal to
trigger) and did not surface as an observable REST/algokey/general
conformance failure, confirming Stage 2's analysis was complete.

## Full gate on `main`

Re-run at close-out after PR #653 merged (2026-08-28):

- `cargo fmt --all --check` — clean.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo test --workspace` — every crate green except the pre-existing,
  documented `algo-network` `peer_features.rs` doctest flake (CLAUDE.md's
  known local-environment issue) — the sole acceptable failure per this
  repo's stated policy.

## Live mixed-cluster verification

Run explicitly for this phase (unlike Phase 12, where the sole
consensus-critical item resolved to a documented null result): a manually
dispatched `consensus-cluster.yml` smoke tier
([run 33153343847](https://github.com/xarmian/algod-rust/actions/runs/33153343847))
against the branch carrying #649's fix — 4-node mixed cluster (3
go-algorand v4.7.4-stable relays + 1 algod-rust online participant)
advanced 30 rounds in lockstep with no agreement-level rejection logged
by any Go node, confirming the new early-screen group-ID check does not
produce false-positive rejections against real, well-formed proposals in
normal cluster operation. Local Docker was unavailable in this session's
environment, so verification ran via CI dispatch rather than
`ops/mixed-cluster/` locally.

## Outcome

Sub-issue #649 resolved (merged, live-verified). One unrelated
pre-existing infra bug (#654) surfaced and fixed along the way, not
counted against this phase's scope. The reference pin, docs, and code are
consistent at `v4.7.4-stable`.
