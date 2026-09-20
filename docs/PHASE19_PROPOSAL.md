# Phase 19 Proposal — go-algorand v5.0.2-stable parity

Phase 19 moves algod-rust's parity target from go-algorand `v5.0.1-stable`
to `v5.0.2-stable`, per the `algod-version-upgrade` skill.

Tracking epic: [#1547](https://github.com/xarmian/algod-rust/issues/1547).

## Motivation

`v5.0.2-stable` is a small safety/durability patch release: "This release
improves safety and durability of node operation" / "Strengthen handling
around agreement verifications to improve stability." All three
behavioral changes harden the agreement layer's bundle/vote admission
path against untrusted, unauthenticated network input — closing gaps
that could let a malicious peer inject an out-of-range step, exhaust
per-period verification state with bogus future periods, or relay a
stale cert bundle past its freshness window.

## Scope

`OLD` = `v5.0.1-stable` (`e763fb0d849f1263c72726b9e2dfc240accc926f`)
`NEW` = `v5.0.2-stable` (`fe1308bd3c669c806facfd34e5eb2873e6c4aa93`)

`TAGS_IN_RANGE` = `{v5.0.2-stable}` only. `v5.0.1-beta` and `v5.0.2-beta`
both exist in the repo's tag list but neither is an ancestor of
`v5.0.2-stable` — each sits on a separate post-release branch
(`git merge-base --is-ancestor <beta-tag> v5.0.2-stable` fails for both),
so no intermediate pre-release is in scope. Every change below originates
at `v5.0.2-stable` itself.

### Classified inventory

| Upstream commit | Classification | Sub-issue |
|---|---|---|
| `a3865cbf5` — "agreement: add bound check on step" | `consensus-critical` | #1543 |
| `6a0ce18fc` — "agreement: isolate bundle verification from untrusted periods" | `consensus-critical` | #1544 |
| `39563dba8` — "agreement: discard stale cert bundles per spec bundle relay rule" | `consensus-critical` | #1545 |
| `bb55d0b32` — "Bump buildnumber.dat" | `not-applicable` | Build/version metadata only. |

Release notes (`gh release view v5.0.2-stable -R algorand/go-algorand`)
list exactly these 3 agreement commits as the complete "Enhancements"
changelog; the completeness check found no other bullet to account for.

### The changes, in detail

1. **`a3865cbf5`** — `unauthenticatedVote`/`unauthenticatedBundle` gain a
   stateless `wellFormed()` check rejecting any `Step` above `down` (the
   largest step defined by the protocol). Called at decode time
   (`decodeVote`/`decodeBundle`/`decodeProposal`) and again inside
   `verify()`, as defense in depth. Previously an absurdly large step
   value (e.g. `math.MaxUint64`) could be decoded and would only be
   rejected later in the pipeline, if at all.
2. **`6a0ce18fc`** — bundle crypto-verification contexts are now
   round-scoped only, never keyed by the bundle's own (unauthenticated)
   claimed period. Previously a bundle claiming a far-future period could
   allocate unbounded per-period state and its `clearStaleContexts` call
   could cancel unrelated, legitimate vote/payload verification for that
   round using an attacker-controlled period. The old `certify`-only
   sentinel (special-cased for cert bundles) is generalized to `bundle`,
   covering every step.
3. **`39563dba8`** — `bundleFresh` no longer exempts `cert`-step bundles
   from the period-freshness check. Previously a cert bundle bypassed
   freshness entirely; now a stale cert (period more than one behind the
   player's current period) is discarded like any other bundle, and the
   corresponding block is recovered through catchup instead.

## Non-goals

Nothing beyond the three sub-issues above is in scope for this phase —
the release contains no API, AVM, network wire-format, or other
behavioral changes outside `agreement/**`.

### Pre-existing test-parity tracking gap (not a `v5.0.2-stable` change)

The Pass C delta (`docs/phase19/test_parity_delta.md`) flagged 5 Go tests
as "added" that in fact already existed at (or before) `v5.0.1-stable`
and are already matched by existing Rust tests — they were simply
missing a row in `docs/phase17/go_tests.tsv`/the `parity_*.md` files
before this sweep (one of them, `TestProposalCarriesMalformedStateProofPath`,
was left behind by Phase 18's own PR #1541). Closing this gap is
docs-only bookkeeping, tracked as #1546, not a `v5.0.2-stable` behavior
change.

## Success criteria

- [ ] Issues #1543, #1544, #1545 merged with TDD tests mirroring
      go-algorand's new coverage.
- [ ] Issue #1546 merged, closing the pre-existing test-parity tracking
      gap.
- [ ] Version pin swept from `v5.0.1-stable` to `v5.0.2-stable`.
- [ ] `python3 scripts/phase17_parity_delta.py check --tag v5.0.2-stable
      --go-algorand ../go-algorand` exits 0 (map pinned to
      `v5.0.2-stable`, complete, `not-implemented` = `missing-test` =
      `partial` = `unclassified` = 0).
- [ ] Full workspace gate green on `main`.
- [ ] Live mixed-cluster verification of the new reject/isolation/discard
      behaviors.
- [ ] `docs/PHASE19_VALIDATION.md` written at close-out.
