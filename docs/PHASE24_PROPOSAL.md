# Phase 24 Proposal — go-algorand v5.0.5-stable parity

Phase 24 moves algod-rust's parity target from go-algorand `v5.0.4-stable`
to `v5.0.5-stable`, per the `algod-version-upgrade` skill.

Tracking epic: [#2308](https://github.com/xarmian/algod-rust/issues/2308) (`docs/epics/Epic-33-Go-Algorand-v5.0.5-Parity.md`).

## Motivation

`v5.0.5-stable` (published 2026-10-28) is a small hardening release,
"Stricter checks around decoding", with **no protocol upgrade**. When a node
assembles a block it now re-decodes each transaction it just encoded, so it
never proposes a block containing a transaction its peers cannot decode.

## Scope

`OLD` = `v5.0.4-stable` (`927ae0863cbb4cf29c6845c088a4ea4c439b10bb`)
`NEW` = `v5.0.5-stable` (`31186e99a69e74483ad95e9ce872903b74758abf`)

`TAGS_IN_RANGE` = `{v5.0.5-beta, v5.0.5-stable}`. `v5.0.5-beta` (`3a15530c3`)
is a separate release-branch merge of the identical change; the diff between
the two tags is empty. Release notes of both list one bullet, "eval: check
decoding while generating".

### Classified inventory

| Upstream commit | Classification | Sub-issue |
|---|---|---|
| `45da7e5c6` — eval: check decoding while generating (`SignedTxnInBlock.GetEncodedLength(decode)`, `BlockEvaluator.TransactionGroup` in the `eval.validate` branch calls it with `eval.generate`; `TransactionPool.AssembleBlock` adapts to the signature) | `behavioral-other` (generate-only; never run when validating received blocks) | #2309 |
| `a099fafa8` — Bump buildnumber.dat | `not-applicable` | Build metadata only. |

Pass B surfaces touched: `data/transactions/*.go`, `ledger/**`, `data/pools/**`;
no consensus params, opcodes, REST, network or crypto changes.
`docs/DIVERGENCES.md` was consulted: DIV-004 (Rust struct readers are map-form
only) is adjacent to the decode check; #2309 must re-verify rather than re-port.

### Test parity (Pass C)

`docs/phase24/test_parity_delta.md`: 1 added (`TestGetEncodedLengthDecode`),
0 removed, 0 moved, 1 body changed
(`TestSignedTxnFeeFactorPQSignatureContribution`, adjacent hunk only: the new
test is appended after it; re-verified cosmetic). Both owned by #2309.
`ledger/ledger_test.go` changes are helper-signature adaptations only.

## Success criteria

- [ ] #2309 closed.
- [ ] Pin swept from `v5.0.4-stable` to `v5.0.5-stable` across the repo.
- [ ] `python3 scripts/phase17_parity_delta.py check --tag v5.0.5-stable --go-algorand ../go-algorand` exits 0 (`not-implemented` = `missing-test` = `partial` = `unclassified` = 0).
- [ ] Full gate green on `main` (fmt, clippy, workspace tests) and a live mixed-cluster run against v5.0.5-stable Go nodes.
- [ ] `docs/PHASE24_VALIDATION.md` evidence map written at close-out.
- [ ] `gh issue list --label "phase:24" --state open` empty before the epic closes.

## Non-goals

- Build metadata (`buildnumber.dat`).
