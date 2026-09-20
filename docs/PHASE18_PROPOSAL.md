# Phase 18 Proposal — go-algorand v5.0.1-stable parity

Phase 18 moves algod-rust's parity target from go-algorand `v5.0.0-stable`
to `v5.0.1-stable`, per the `algod-version-upgrade` skill.

Tracking epic: [#1537](https://github.com/xarmian/algod-rust/issues/1537).

## Motivation

`v5.0.1-stable` is a small security/safety patch release. It fixes a real
gap in state proof verification: go-algorand previously trusted the
wire-provided hash algorithm/digest size on a `StateProof`'s Merkle proofs
without pinning them to the protocol-fixed algorithm, and silently
zero-padded/truncated wrong-sized Merkle path elements instead of
rejecting them. A code audit confirmed algod-rust has the identical gap
today, so this phase closes it to restore byte-for-byte-equivalent
rejection behavior with the network.

## Scope

`OLD` = `v5.0.0-stable` (`da5946a14568c0cbaa2c9daf4241882de12f3c16`)
`NEW` = `v5.0.1-stable` (`e763fb0d849f1263c72726b9e2dfc240accc926f`)

`TAGS_IN_RANGE` = `v5.0.1-beta`, `v5.0.1-stable`. `v5.0.1-beta` is
**not** an ancestor of `v5.0.1-stable`
(`git merge-base --is-ancestor v5.0.1-beta v5.0.1-stable` fails) — it sits
on a divergent pre-release track and its changes are not part of this
pin's history, so it is excluded from the classified inventory below.
Every change in scope originates at `v5.0.1-stable` itself.

### Classified inventory

| Upstream commit | Classification | Notes |
|---|---|---|
| `9d20718f9` — "stateproof: reject mismatched hash type" | `consensus-critical` | Sole behavioral change. See issue #1538. |
| `c40e73d9b` — "testing: fix stateproof e2e test" | `not-applicable` | Test-only change to go-algorand's own e2e test; no production code touched. |
| `40af46d23` — "Bump buildnumber.dat" | `not-applicable` | Build/version metadata only. |

### The `9d20718f9` change, in detail

1. `crypto/stateproof/verifier.go` gained `verifyStateProofAlgorithms()`,
   run first inside `Verifier.Verify()`. Rejects a `StateProof` whose
   `SigProofs`/`PartProofs` hash factory isn't the protocol-fixed
   `stateproof.HashType` (Sumhash), whose `SigCommit` isn't exactly
   `HashSize` bytes, or whose per-reveal Merkle signature proof doesn't
   use `merklesignature.MerkleSignatureSchemeHashFunction`.
2. `crypto/merklearray/merkle.go`'s `verifyPath` now rejects any
   non-empty `proof.Path` element whose length doesn't exactly match the
   hash factory's digest size (previously implicitly zero-padded/
   truncated) — new `ErrPathElementSizeMismatch`.
3. `data/transactions/checks.go` gained `checkBasicStateProof`/
   `checkBasicStateProofPath`, invoked from `StateProofTxnFields.wellFormed`
   via a new `checkStateProof(spType, ...)` dispatch that also rejects
   unsupported `StateProofType` values — so malformed proofs are now
   rejected at transaction well-formedness time, before reaching the
   agreement layer's proposal-validity check.
4. `crypto/merklearray/layer.go`'s `pair.ToBeHashed()` was fixed to copy
   child digests into fixed digest-sized slots instead of variable-offset
   slices, closing a related bug where an oversized left child could
   silently overwrite the right child's bytes in the hash input.

## Non-goals

Nothing beyond the single sub-issue below is in scope for this phase —
the release contains no API, AVM, network, or other behavioral changes.

## Success criteria

- [ ] Issue #1538 merged with TDD tests mirroring go-algorand's new
      coverage.
- [ ] Version pin swept from `v5.0.0-stable` to `v5.0.1-stable`.
- [ ] Full workspace gate green on `main`.
- [ ] Live mixed-cluster verification of the new reject behavior.
- [ ] `docs/PHASE18_VALIDATION.md` written at close-out.
