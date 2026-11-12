# Phase 24 Validation — go-algorand v5.0.5-stable Parity

_Completed: 2026-11-12_

Phase 24 moved algod-rust's parity target from go-algorand `v5.0.4-stable`
to `v5.0.5-stable`, a hardening release with no protocol upgrade: when a node
generates a block it now re-decodes each transaction it encoded ("Stricter
checks around decoding").

Evidence map for [`docs/PHASE24_PROPOSAL.md`](PHASE24_PROPOSAL.md) and
[`docs/epics/Epic-33-Go-Algorand-v5.0.5-Parity.md`](epics/Epic-33-Go-Algorand-v5.0.5-Parity.md).
Tracking epic: [#2308](https://github.com/xarmian/algod-rust/issues/2308).

## Completeness re-check (Stage 7)

- `git -C ../go-algorand fetch --tags` re-run on 2026-11-12. `TAGS_IN_RANGE` =
  `{v5.0.5-beta, v5.0.5-stable}`, unchanged since Stage 1. The only newer tag,
  `v5.1.0-beta` (2026-11-06), is a later release line, outside `OLD..NEW`, and
  is not part of this phase.
- `gh release view v5.0.5-stable` and `v5.0.5-beta` re-read against the
  current releases page: identical notes, one "Bug Fixes" bullet ("eval: check
  decoding while generating", mapped to #2309) and "This release does not
  contain a protocol upgrade". `buildnumber.dat` is the `not-applicable`
  remainder of the diff. `git diff v5.0.5-beta v5.0.5-stable` is empty.
- `gh issue list --label phase:24 --state open`: only the epic #2308 (closed
  with this PR's merge).

## Criteria and evidence

| Criterion | Evidence |
|---|---|
| Generate-only decode-after-encode check (#2309) | PR #2312: `algo_codec::signed_txn_in_block_encoded_len(stx, decode)` (go `SignedTxnInBlock.GetEncodedLength(decode)`), called with `decode = true` from `SimpleBlockEvaluator::transaction_group` (`bin/algod-rust/src/commands/participate.rs`), the only generating evaluator (pool admission, proposal assembly). Failure reads `transaction <txid>: <decode error>` like go's `TransactionGroup`. Received blocks never take the check (go: only under `eval.generate`). Test: `canonical::tests::signed_txn_in_block_encoded_len_checks_decode_like_go` (port of `TestGetEncodedLengthDecode`). The stateless checks reject a zero-sender transaction first, as in go, so the evaluator-level check is defense in depth. |
| DIV-004 considered | `docs/DIVERGENCES.md` DIV-004 (map-form-only struct readers, replace-on-duplicate-key) concerns non-canonical input only; the check decodes algod-rust's own canonical encoding, whose required-field rejection (`missing required field 'snd'` / `'type'`) is go-parity. No new divergence was introduced (`scripts/check_divergences.py` ok). |
| Pin swept (PR #2311) | `v5.0.4-stable` -> `v5.0.5-stable` across CLAUDE.md, README, workflows, Go oracle/capture tools, bench pin, compose files, both User-Agent prefixes (`algod-rust/5.0.5 (`). Its first CI run caught two real follow-ups, fixed in the same PR: `tools/simulate-rewards-oracle/blockdup.go` adapted to `GetEncodedLength(decode)`, and the `small`/`small-catchpoint` bench corpus manifests refreshed for the new go tag/commit (blocks byte-identical). Final CI: 31 pass, 4 skipped. No live-parity carve-outs were needed. |
| Test-parity map complete at the new pin | Verbatim `python3 scripts/phase17_parity_delta.py check --tag v5.0.5-stable --go-algorand ../go-algorand --allow-partial 3`: see below. `TestGetEncodedLengthDecode` is `matched-1:1`; `TestSignedTxnFeeFactorPQSignatureContribution` (body changed only by the adjacent addition) carries a re-verification note. |
| Full gate green on `main` | PR CI for #2310, #2311, #2312 green (fmt, clippy, workspace tests, conformance, oracle regeneration); local `algo-codec` test and `cargo test -p algod-rust --bin algod-rust participate` (330 passed). |
| Live mixed-cluster against v5.0.5-stable Go nodes | `Nightly Consensus Cluster` dispatched from `main` (`96542ca2`, includes #2312) with `tier=full`, `rounds=200`, `workload=rich` against the `algorand/algod:5.0.5-stable` Go nodes: run [43257488783](https://github.com/xarmian/algod-rust/actions/runs/43257488783), **success** (both tiers, rich workload and cross-implementation block comparison). |
| Dual-Node REST Conformance on `main` | `Dual-Node REST Conformance` push run on `main` `96542ca2` (v5.0.5-stable Go node): [43257439170](https://github.com/xarmian/algod-rust/actions/runs/43257439170), **success**. The pin-sweep merge run [43251562714](https://github.com/xarmian/algod-rust/actions/runs/43251562714) was also green. |
| No `phase:24` issue open at close | checked 2026-11-12 (see re-check above). |

### `check` output

```
pin: v5.0.5-stable; rows: 3194; inventory: 3194
  matched-1:1: 1214
  matched-1:many: 956
  matched-many:1: 286
  partial: 3
  out-of-scope: 735

OK - parity map is pinned, complete, and gap-free
```

The 3 `partial` rows are the standing rows in `docs/phase17/parity_agreement.md`
(live multi-node `Fuzzer`+`Service`+`TopologyFilter` infrastructure), signed
off previously and recorded in `CLAUDE.md`'s Phase 17 summary; hence
`--allow-partial 3`. `not-implemented` = `missing-test` = `unclassified` = 0.

### Aggregate totals (`docs/PHASE17_TEST_PARITY.md`)

| status | count |
|---|---|
| `matched-1:1` | 1,216 |
| `matched-1:many` | 958 |
| `out-of-scope` | 735 |
| `matched-many:1` | 286 |
| `partial` | 3 |
| `not-implemented` | 0 |
| `missing-test` | 0 |
| total | 3,198 |

(The aggregate table counts rows per area file, including a few multi-row
entries; `check` counts one row per go test, 3,194 at `v5.0.5-stable`.)
