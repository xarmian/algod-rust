# Phase 20 Proposal — go-algorand v5.0.3-stable parity

Phase 20 moves algod-rust's parity target from go-algorand `v5.0.2-stable`
to `v5.0.3-stable`, per the `algod-version-upgrade` skill.

Tracking epic: [#1864](https://github.com/xarmian/algod-rust/issues/1864) (`docs/epics/Epic-30-Go-Algorand-v5.0.3-Parity.md`).

## Motivation

`v5.0.3-stable` (published 2026-10-12) is a one-change patch release: it adds
the IANA root KSK-2024 trust anchor (key tag 38696) to go-algorand's
DNSSEC root anchor set (`tools/network/dnssec/anchor.go`), ahead of the root
key rollover that starts signing with KSK-2024. Without it a validating
resolver cannot validate the root DNSKEY RRset and DNSSEC-validated SRV
bootstrap fails.

## Scope

`OLD` = `v5.0.2-stable` (`fe1308bd3c669c806facfd34e5eb2873e6c4aa93`)
`NEW` = `v5.0.3-stable` (`2dc9524e9e9b7f4cd9234659d45ac42b283c4ae3`)

`TAGS_IN_RANGE` = `{v5.0.3-stable}`. `v5.0.3-beta` exists (`544a0267e`) but is a
merge of the stable branch back into the beta line (`53783e9de` is the only
functional commit and it is in `v5.0.3-stable`), so no separate pre-release
behavior is in scope.

### Classified inventory

| Upstream commit | Classification | Sub-issue |
|---|---|---|
| `53783e9de` — "dnssec: add root KSK-2024 trust anchor (#6764)" | `network` / `behavioral-other` | #1863 |
| `a8e1ec34c` — "Bump buildnumber.dat" | `not-applicable` | Build/version metadata only. |

The release notes list no other bullet; the completeness check found nothing
else to account for. `git diff v5.0.2-stable v5.0.3-stable --stat` touches four
files: `buildnumber.dat`, `tools/network/dnssec/anchor.go`, and the two tests
that assert the anchor count (`anchor_test.go`, `trustedchain_test.go`).

### The change, in detail

`rootAnchorXML` gains a third `KeyDigest` (id `Kmyv6jo`, valid from
2024-07-18): key tag 38696, algorithm 8, digest type 2, digest
`683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16`, plus the
public keys/flags for the existing 20326 and the new 38696 entry.

algod-rust delegates DNSSEC validation to `hickory-resolver` (0.25.2, built-in
root anchors `dnssec/roots/20326.rsa` and `38696.rsa`), so the expected
outcome is "already at parity, now proven and guarded" (#1863).

### Test parity (Pass C)

`docs/phase20/test_parity_delta.md`: 0 added, 0 removed, 0 moved, 2 body
changed (`TestParseRootTrustAnchor`, `TestQueryWrapper`), both owned by #1863.

## Success criteria

- [ ] #1863 closed (anchor-set parity test + live validation check).
- [ ] Pin swept from `v5.0.2-stable` to `v5.0.3-stable` across the repo.
- [ ] `python3 scripts/phase17_parity_delta.py check --tag v5.0.3-stable --go-algorand ../go-algorand` exits 0 (`not-implemented` = `missing-test` = `partial` = `unclassified` = 0).
- [ ] Full gate green on `main` (fmt, clippy, workspace tests) and a live mixed-cluster run against v5.0.3-stable Go nodes.
- [ ] `docs/PHASE20_VALIDATION.md` evidence map written at close-out.
- [ ] `gh issue list --label "phase:20" --state open` empty before the epic closes.

## Non-goals

- Build metadata (`buildnumber.dat`).
