# Epic: go-algorand v5.0.0-stable parity

Tracks moving algod-rust's parity target from go-algorand `v4.7.4-stable` to
`v5.0.0-stable`, per the `algod-version-upgrade` skill. GitHub epic issue:
[#678](https://github.com/xarmian/algod-rust/issues/678).

## Stage 1 — Tags in range

- `OLD` = `v4.7.4-stable` (`91cbddcd37d4fe7cbece5f631158a6710e5666fd`)
- `NEW` = `v5.0.0-stable` (`da5946a14568c0cbaa2c9daf4241882de12f3c16`)
- `TAGS_IN_RANGE` = `v4.7.4-beta`, `v5.0.0-beta`, `v5.0.0-stable`.
  `v4.7.4-beta`'s sole change ("checks: recompute group IDs") was already
  implemented in Phase 13 (#649). `v5.0.0-beta` and `v5.0.0-stable` carry
  identical changelogs — every feature below originates at `v5.0.0-beta`.

## Stage 2 — Classified inventory

See `docs/PHASE14_PROPOSAL.md` for the full classified inventory (this
epic mirrors it) — consensus-critical, api, and behavioral-other buckets,
plus the reviewed not-applicable list with justifications. Consensus goes
from V41 to **V42** (`config/consensus.go` commit `88fe542f3`).

Headline items, by consensus risk:

1. **SelectF128 sortition** (#667) — replaces the hardware-double
   binomial-CDF committee-selection weight function with a bit-identical
   128-bit software-float implementation. Highest risk in this epic: a
   non-bit-identical port causes algod-rust to disagree with the network
   on committee membership once v42 activates.
2. **Post-quantum Falcon-1024 accounts** (#660, #663) — new wire types and
   verification wiring reusing algod-rust's existing Falcon-1024/det1024
   primitive (already used for state-proof keys), plus two real primitive
   bugfixes (seed size, sign-message convention) that affect existing
   state-proof signing too.
3. **Big-transaction size pricing** (#657, #677, #668, #671) — new fee
   surcharge and residue-rounding scheme threaded through outer and inner
   transaction fee checks.
4. **AVM v13 opcodes and encoding changes** (#659, #661, #662, #664, #665,
   #666, #669, #670, #672) — new opcodes (poseidon2, app_params_set, nine
   foreign-box opcodes), a new multi-byte opcode dispatch mechanism,
   varint branch encoding, assembler auto-salting, and several small
   correctness bugfixes.
5. **API surface** (#673, #674) and **application-update validation**
   (#675) — lower risk, no consensus-agreement exposure.

## Stage 6 — Sub-issues (dependency order)

- [x] #658 — consensus v42 parameter sweep (**foundation**) — merged, PR #682
- [x] #663 — Falcon-1024 seed size + sign-message convention fix — merged, PR #683
- [x] #669 — sha512/sumhash512 opcode cost formula bugfix — merged, PR #684
- [x] #670 — gload/gloads nil-pastScratch fix — merged, PR #685
- [x] #686 — gload/gloads must return sibling's real scratch value, not a zero placeholder (found during #670; depends on #670) — merged, PR #713
- [x] #672 — assembler match-opcode type tracking + deadcode disassembly fix — merged, PR #687
- [x] #666 — byte-constant size-limit enforcement + falcon_verify audit — merged, PR #688
- [x] #665 — poseidon2 opcode — merged, PR #689
- [x] #661 — variable-length (varint) branch encoding — merged, PR #690
- [x] #664 — auto-salt TEAL v13 programs — merged, PR #692
- [x] #694 — fix flaky varint-branch test broken by auto-salt (found during #659) — merged, PR #696
- [x] #659 — app_params_set + multi-byte opcode dispatch + ForeignBoxReads/FamilyBoxAccess fields — merged, PR #695
- [x] #662 — nine app_box_* foreign-box opcodes (depends on #659) — merged, PR #697
- [x] #667 — SelectF128 sortition port (**highest risk**) — merged, PR #699
- [x] #675 — application-update LocalStateSchema immutability check — merged, PR #700
- [x] #657 — big-transaction size pricing — merged, PR #702
- [x] #677 — AVM inner-txn fee-residue threading + fee-shortfall message (depends on #657) — merged, PR #704
- [x] #668 — heartbeat explicit HbChallengeDiscount field (depends on #657) — merged, PR #705
- [x] #660 — post-quantum Falcon-1024 account signatures (depends on #663) — merged, PR #706
- [x] #671 — simulate API fee-usage reporting (depends on #657, #677) — merged, PR #708
- [x] #674 — remove dryrun REST endpoint — merged, PR #709
- [x] #673 — GET /v2/node/peers + POST /v2/node/shutdown canonical route — merged, PR #710
- [x] #676 — FNet consensus version table entries — merged, PR #711
- [x] #681 — algod-rust block production never proposes/votes for protocol upgrades (found during Stage 5's pin sweep — see PR #680; the first pin bump in this repo's history where `ConsensusCurrentVersion` itself advances, surfacing a previously-unreachable gap) — merged, PR #712
- [x] #691 — live byte-for-byte assembler verification + mixed-cluster check for #661 — merged, PR #719; both criteria confirmed live-verified after #720 landed
- [x] #693 — assembler warnings channel (deferred from #664; upstream's two `shouldAutoSalt` diagnostics have no algod-rust warnings mechanism to attach to yet) — merged, PR #717
- [x] #698 — machine.rs cost-charging gap for multi-byte opcodes (found during #662, currently harmless) — merged, PR #715
- [x] #701 — remaining ApplicationCallTxnFields.wellFormed sub-checks (found during #675; OnCompletion validity, RejectVersion, program/arg/reference-count bounds, etc.) — merged, PR #716
- [x] #714 — gload unconditionally errors inside an inner-transaction group (found during #686) — merged, PR #718
- [x] #720 — shared test genesis lagging at consensus V41, blocking every AVM v13 live-verification test (found during #691) — merged, PR #721
- [x] #703 — live fixture/oracle parity tests for big-transaction size-pricing boundaries (found during #657, unblocked by #720) — merged, PR #722; found and fixed two real production bugs (canonical Note-field omitempty rule, group-fee check skipping ungrouped txns)
- [x] #723 — gate oversized app-program writes behind the box I/O write budget (found during #703) — merged, PR #724
- [x] #707 — upgrade #660's hand-computed msgpack byte-oracle test to a live go-algorand-captured fixture — merged, PR #728
- [x] #725 — box read-I/O-budget check only ever lazily triggered (found during #723) — merged, PR #726
- [x] #727 — box budget state not shared across sibling top-level app calls in a group (found during #725) — merged, PR #729

## Epic-level acceptance criteria

- [x] All sub-issues above closed (merged; none required honest disposition — every item surfaced was implemented).
- [x] `docs/PHASE14_PROPOSAL.md`, `docs/epics/Epic-24-Go-Algorand-v5.0.0-Parity.md`,
      `docs/PROJECT_SCOPE.md` updated.
- [x] Version pin swept from `v4.7.4-stable` to `v5.0.0-stable` across the
      repo (CLAUDE.md, workflows, docker compose, docs) — PR #680.
- [x] Full gate green on `main` (fmt, clippy, full workspace suite) —
      re-verified 2026-08-29, only the documented `algo-network` doctest
      flake present.
- [x] Live mixed-cluster soak against `v5.0.0-stable` Go nodes, with
      particular attention to `SelectF128` committee-selection agreement —
      30-round soak, zero rejections (PR #699); plus live dual-node
      verification for #681, #691, #703, #723.
- [x] `docs/PHASE14_VALIDATION.md` evidence map written at close-out.
- [x] Hard gate: `gh issue list --label "phase:14" --state open` empty
      before this epic closes — confirmed 2026-08-29 (only the epic issue
      itself remained).
