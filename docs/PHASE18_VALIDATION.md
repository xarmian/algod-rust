# Phase 18 Validation — go-algorand v5.0.1-stable Parity

_Completed: 2026-09-20_

Phase 18 moved algod-rust's parity target from go-algorand
`v5.0.0-stable` to `v5.0.1-stable`, a small security/safety patch
release with a single behavioral change: the state proof verifier now
pins Merkle proofs to the protocol-fixed hash algorithm and rejects
wrong-sized proof-path elements instead of silently zero-padding/
truncating them.

This document is the evidence map for
[`docs/PHASE18_PROPOSAL.md`](PHASE18_PROPOSAL.md) and
[`docs/epics/Epic-28-Go-Algorand-v5.0.1-Parity.md`](epics/Epic-28-Go-Algorand-v5.0.1-Parity.md).

Tracking epic: [#1537](https://github.com/xarmian/algod-rust/issues/1537).

---

## Completeness re-check (Stage 7 mandatory re-run)

Re-run fresh on 2026-09-20, immediately before writing this document:

- `git -C ../go-algorand fetch --tags` then re-derived `TAGS_IN_RANGE`:
  `v5.0.0-stable`, `v5.0.1-beta`, `v5.0.1-stable`, `v5.0.2-beta`,
  `v5.0.2-stable` are all tags reachable from `v5.0.0-stable`; of these,
  only `v5.0.0-stable` (=`OLD`) and `v5.0.1-stable` (=`NEW`) are
  ancestors of `NEW` (`git merge-base --is-ancestor <tag> v5.0.1-stable`).
  `v5.0.1-beta` sits on a divergent pre-release track and is not an
  ancestor of `v5.0.1-stable` — excluded, unchanged from Stage 1's
  original finding.
- `gh release view v5.0.1-stable -R algorand/go-algorand` re-read: still
  exactly one Changelog/Enhancements bullet ("stateproof: reject
  mismatched hash type"), unchanged since the epic began — no corrected
  or expanded release notes.
- `gh issue list --repo xarmian/algod-rust --label "phase:18" --state open`
  returns **only** the epic issue [#1537](https://github.com/xarmian/algod-rust/issues/1537)
  itself — no missed sub-issue exists under the label.

## Classified inventory

| Upstream commit | Classification | Disposition |
|---|---|---|
| `9d20718f9` — "stateproof: reject mismatched hash type" | `consensus-critical` | Closed by issue #1538 / PR #1541 |
| `c40e73d9b` — "testing: fix stateproof e2e test" | `not-applicable` | Test-only change to go-algorand's own e2e test, no production code touched |
| `40af46d23` — "Bump buildnumber.dat" | `not-applicable` | Build/version metadata only |

## Sub-issue disposition

One sub-issue in scope, closed via a single merged PR — no follow-ups
surfaced during implementation:

- [x] **#1538** — StateProof verification must reject mismatched/
  wrong-size hash algorithms — merged, PR
  [#1541](https://github.com/xarmian/algod-rust/pull/1541).

## Evidence per criterion

| Criterion | Evidence |
|---|---|
| Issue #1538 merged with TDD tests mirroring go-algorand's new coverage | PR #1541: `verify_rejects_oversized_path_element` (go: `TestVerifyRejectsOversizedPathElement`), `pair_to_be_hashed_does_not_erase_sibling` (go: `TestToBeHashedDoesNotEraseSibling`), `verify_state_proof_algorithms_*` suite (go: `TestVerifyStateProofAlgorithms`), `state_proof_basic_suite_*` (go: `TestCheckTxnGroupStateProofBasicSuite`), plus `apply_stateproof.rs` wire-conversion propagation tests. All written first and confirmed to fail against pre-fix code. |
| Fix mirrors go-algorand exactly (same fields, same order, same rejection semantics) | `Verifier::verify()` now calls `verify_state_proof_algorithms()` first (matching go's `verifyStateProofAlgorithms` position in `Verify`); `verify_path()` rejects non-empty wrong-sized path elements via `PathElementSizeMismatch` (matching `ErrPathElementSizeMismatch`) instead of `partial_layer_up`'s prior silent zero-pad/truncate; `pair_to_be_hashed()` copies each child into its own fixed digest-sized slot (matching go's `layer.go` fix); `checks.rs`'s `check_basic_state_proof_path`/`check_basic_state_proof`/`check_state_proof` mirror go's `checkBasicStateProofPath`/`checkBasicStateProof`/`checkStateProof` dispatch, including the unsupported-`StateProofType` rejection. |
| Version pin swept from `v5.0.0-stable` to `v5.0.1-stable` | PR #1539 (docs/proposal, merged first) + PR #1540 (repo-wide pin sweep — 97 files: `CLAUDE.md`, `README.md`, CI workflows, `ops/mixed-cluster*`, `tools/*/run-in-docker.sh`, Go oracle-tool `expectedGoAlgorandPin` constants across 11 `.go` files caught in a follow-up commit, and the `rewards_innertxid/oracle.json` fixture's `go_algorand_pin` provenance label re-verified live against the bumped pin by CI's own regenerate-and-diff step). |
| Full workspace gate green on `main` | Re-verified 2026-09-20 after PR #1541 merged: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` — all clean, zero failures (including the usually-present `algo-network` doctest flake, which did not reproduce this run). |
| Live mixed-cluster verification of the new reject behavior | The repo has no live Fuzzer+Service+TopologyFilter test infrastructure to carry a malformed `StateProof` through the agreement layer end-to-end — the same documented gap behind Phase 17's four remaining `partial` rows (`docs/phase17/parity_agreement.md`). PR #1540's live-parity CI (`Live parity vs go-algorand`, shared-genesis dual-node conformance against real `v5.0.1-stable` go-algorand nodes) passed green without needing a carve-out, since that scenario doesn't exercise a malformed state proof. The transaction-well-formedness-time rejection in `checks.rs` — which runs before a malformed proof could ever reach agreement — is exercised by PR #1541's unit tests instead, matching the closest verification go-algorand's own new `TestProposalCarriesMalformedStateProofPath` provides without equivalent live infrastructure on this side. |
| Hard gate: no open `phase:18` issues before close | Re-confirmed 2026-09-20 (see Completeness re-check above) — only the epic issue itself. |

## Not-applicable items (reviewed, justified)

- `c40e73d9b` ("testing: fix stateproof e2e test") — touches only
  `test/e2e-go/features/stateproofs/stateproofs_test.go`, go-algorand's
  own e2e test harness. No algod-rust equivalent exists or is needed;
  algod-rust's parity claim is about production behavior, not
  go-algorand's internal test tooling.
- `40af46d23` ("Bump buildnumber.dat") — build/version metadata file,
  no behavioral content.

## Conclusion

Phase 18 is complete. The one behavioral change in `v5.0.0-stable` →
`v5.0.1-stable` is closed with a faithful, test-covered port; the
version pin is swept repo-wide; the full workspace gate is green; and
the hard gate confirms no outstanding work under this phase's label.
