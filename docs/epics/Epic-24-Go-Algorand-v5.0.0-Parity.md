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
- [ ] #686 — gload/gloads must return sibling's real scratch value, not a zero placeholder (found during #670; depends on #670)
- [ ] #672 — assembler match-opcode type tracking + deadcode disassembly fix
- [ ] #666 — byte-constant size-limit enforcement + falcon_verify audit
- [ ] #665 — poseidon2 opcode
- [ ] #661 — variable-length (varint) branch encoding
- [ ] #664 — auto-salt TEAL v13 programs
- [ ] #659 — app_params_set + multi-byte opcode dispatch + ForeignBoxReads/FamilyBoxAccess fields
- [ ] #662 — nine app_box_* foreign-box opcodes (depends on #659)
- [ ] #667 — SelectF128 sortition port (**highest risk**)
- [ ] #675 — application-update LocalStateSchema immutability check
- [ ] #657 — big-transaction size pricing
- [ ] #677 — AVM inner-txn fee-residue threading + fee-shortfall message (depends on #657)
- [ ] #668 — heartbeat explicit HbChallengeDiscount field (depends on #657)
- [ ] #660 — post-quantum Falcon-1024 account signatures (depends on #663)
- [ ] #671 — simulate API fee-usage reporting (depends on #657, #677)
- [x] #674 — remove dryrun REST endpoint
- [ ] #673 — GET /v2/node/peers + POST /v2/node/shutdown canonical route
- [ ] #676 — FNet consensus version table entries
- [ ] #681 — algod-rust block production never proposes/votes for protocol upgrades (found during Stage 5's pin sweep — see PR #680; the first pin bump in this repo's history where `ConsensusCurrentVersion` itself advances, surfacing a previously-unreachable gap)

## Epic-level acceptance criteria

- [ ] All sub-issues above closed (merged or honestly disposed).
- [ ] `docs/PHASE14_PROPOSAL.md`, `docs/epics/Epic-24-Go-Algorand-v5.0.0-Parity.md`,
      `docs/PROJECT_SCOPE.md` updated.
- [ ] Version pin swept from `v4.7.4-stable` to `v5.0.0-stable` across the
      repo (CLAUDE.md, workflows, docker compose, docs).
- [ ] Full gate green on `main` (fmt, clippy, full workspace suite).
- [ ] Live mixed-cluster soak against `v5.0.0-stable` Go nodes, with
      particular attention to `SelectF128` committee-selection agreement.
- [ ] `docs/PHASE14_VALIDATION.md` evidence map written at close-out.
- [ ] Hard gate: `gh issue list --label "phase:14" --state open` empty
      before this epic closes.
