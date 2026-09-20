# Epic: go-algorand v5.0.2-stable parity

Tracks moving algod-rust's parity target from go-algorand `v5.0.1-stable` to
`v5.0.2-stable`, per the `algod-version-upgrade` skill. GitHub epic issue:
[#1547](https://github.com/xarmian/algod-rust/issues/1547).

## Stage 1 — Tags in range

- `OLD` = `v5.0.1-stable` (`e763fb0d849f1263c72726b9e2dfc240accc926f`)
- `NEW` = `v5.0.2-stable` (`fe1308bd3c669c806facfd34e5eb2873e6c4aa93`)
- `TAGS_IN_RANGE` = `{v5.0.2-stable}` only. `v5.0.1-beta` and `v5.0.2-beta`
  both exist but neither is an ancestor of `v5.0.2-stable` (each sits on a
  separate post-release branch) and are excluded; every change in scope
  originates at `v5.0.2-stable` itself.

## Stage 2 — Classified inventory

See `docs/PHASE19_PROPOSAL.md` for the full classified inventory (this
epic mirrors it). Three `consensus-critical` changes, one `not-applicable`
(build-metadata).

1. **Reject step above `down` at decode/verify time** (#1543) — a
   stateless `wellFormed()` bound check on votes/bundles/proposals.
2. **Isolate bundle-verification crypto contexts from untrusted periods**
   (#1544) — bundle contexts become round-scoped only, never keyed by the
   bundle's own unauthenticated claimed period.
3. **Discard stale cert bundles per spec bundle relay rule** (#1545) —
   removes the `cert`-step exemption from bundle freshness checking.
4. **Pre-existing test-parity tracking gap** (#1546) — 5 Go tests that
   predate `v5.0.2-stable` and are already matched by existing Rust code,
   but were missing a row in the tracking docs before this sweep.
   Docs-only, no `algod:<tag>` label (not a `v5.0.2-stable` behavior
   change).

## Stage 6 — Sub-issues (dependency order)

- [ ] #1543 — agreement: reject votes/bundles/proposals with step above
      `down` at decode/verify time
- [ ] #1544 — agreement: isolate bundle-verification crypto contexts from
      untrusted periods
- [ ] #1545 — agreement: discard stale cert bundles per spec bundle relay
      rule
- [ ] #1546 — test-parity: close pre-existing untracked-test gaps
      surfaced by the v5.0.2-stable sweep (after the pin-sweep PR's
      `repin` step creates the `unclassified` placeholders)

## Epic-level acceptance criteria

- [ ] #1543, #1544, #1545, #1546 all closed (merged, or honestly
      disposed).
- [ ] `docs/PHASE19_PROPOSAL.md`, `docs/epics/Epic-29-Go-Algorand-v5.0.2-Parity.md`,
      `docs/PROJECT_SCOPE.md` updated.
- [ ] Version pin swept from `v5.0.1-stable` to `v5.0.2-stable` across the
      repo (CLAUDE.md, workflows, docker compose, docs).
- [ ] `python3 scripts/phase17_parity_delta.py check --tag v5.0.2-stable
      --go-algorand ../go-algorand` exits 0.
- [ ] Full gate green on `main` (fmt, clippy, full workspace suite).
- [ ] Live mixed-cluster verification of the new reject/isolation/discard
      behaviors.
- [ ] `docs/PHASE19_VALIDATION.md` evidence map written at close-out.
- [ ] Hard gate: `gh issue list --label "phase:19" --state open` empty
      before this epic closes.
