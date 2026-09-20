# Epic: go-algorand v5.0.1-stable parity

Tracks moving algod-rust's parity target from go-algorand `v5.0.0-stable` to
`v5.0.1-stable`, per the `algod-version-upgrade` skill. GitHub epic issue:
[#1537](https://github.com/xarmian/algod-rust/issues/1537).

## Stage 1 — Tags in range

- `OLD` = `v5.0.0-stable` (`da5946a14568c0cbaa2c9daf4241882de12f3c16`)
- `NEW` = `v5.0.1-stable` (`e763fb0d849f1263c72726b9e2dfc240accc926f`)
- `TAGS_IN_RANGE` = `v5.0.1-beta`, `v5.0.1-stable`. `v5.0.1-beta` is not an
  ancestor of `v5.0.1-stable` (divergent pre-release track) and is excluded;
  every change in scope originates at `v5.0.1-stable` itself.

## Stage 2 — Classified inventory

See `docs/PHASE18_PROPOSAL.md` for the full classified inventory (this
epic mirrors it). One `consensus-critical` change, two `not-applicable`
(test-only / build-metadata).

1. **StateProof verifier hash-algorithm/digest-size validation** (#1538) —
   go-algorand now pins state proof Merkle proofs to the protocol-fixed
   hash algorithm and rejects wrong-sized path elements instead of
   silently padding/truncating them; a code audit confirmed algod-rust has
   the identical gap. Highest (and only) risk item in this epic.

## Stage 6 — Sub-issues (dependency order)

- [ ] #1538 — StateProof verification must reject mismatched/wrong-size
      hash algorithms

## Epic-level acceptance criteria

- [ ] #1538 closed (merged, or honestly disposed).
- [ ] `docs/PHASE18_PROPOSAL.md`, `docs/epics/Epic-28-Go-Algorand-v5.0.1-Parity.md`,
      `docs/PROJECT_SCOPE.md` updated.
- [ ] Version pin swept from `v5.0.0-stable` to `v5.0.1-stable` across the
      repo (CLAUDE.md, workflows, docker compose, docs).
- [ ] Full gate green on `main` (fmt, clippy, full workspace suite).
- [ ] Live mixed-cluster verification of the new reject behavior.
- [ ] `docs/PHASE18_VALIDATION.md` evidence map written at close-out.
- [ ] Hard gate: `gh issue list --label "phase:18" --state open` empty
      before this epic closes.
