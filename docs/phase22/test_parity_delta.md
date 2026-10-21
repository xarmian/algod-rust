# Test-parity delta: go-algorand `v5.0.3-stable` → `v5.0.4-stable`

_Generated 2026-10-21 by `scripts/phase17_parity_delta.py report`._

| metric | count |
|---|---:|
| Go tests in `v5.0.3-stable` | 3190 |
| Go tests in `v5.0.4-stable` | 3193 |
| added | 3 |
| removed | 0 |
| moved (file rename, same name) | 0 |
| body changed (existing rows to re-verify) | 3 |

## Added in `v5.0.4-stable` (3)

Each needs a new row in the listed `parity_<area>.md` with an honest status. A `missing-test`/`not-implemented`/`partial` classification is a sub-issue of the upgrade epic, not a resting state.

| go-algorand test | package | area file |
|---|---|---|
| [TestAgreementSnapshotCompression](https://github.com/algorand/go-algorand/blob/v5.0.4-stable/agreement/persistence_test.go#L238) | `agreement` | `parity_agreement.md` |
| [TestSponsorCannotClose](https://github.com/algorand/go-algorand/blob/v5.0.4-stable/ledger/applications_test.go#L1793) | `ledger` | `parity_ledger_core.md` |
| [TestCloseMinBalancePolicy](https://github.com/algorand/go-algorand/blob/v5.0.4-stable/ledger/close_test.go#L37) | `ledger` | `parity_ledger_core.md` |

## Removed in `v5.0.4-stable` (0)

Delete each row (the go test no longer exists at the pin). If the matched Rust test proved behavior go-algorand deliberately dropped, that is an upstream behavior change — make sure a Stage 2/3 issue covers it.

_none_

## Moved (0)

`repin` rewrites these links automatically; listed for the record.

_none_

## Body changed — re-verify the mapped Rust test(s) (3)

For each: read `git -C ../go-algorand diff OLD NEW -- <file>` around the function. If go-algorand added/changed an assertion, the mapped Rust test must gain the same assertion (or the row honestly drops to `partial` and becomes a sub-issue). Update the row's notes with what was re-checked.

| go-algorand test | current status | row |
|---|---|---|
| [TestRandomizedEncodingFullDiskState](https://github.com/algorand/go-algorand/blob/v5.0.4-stable/agreement/persistence_test.go#L209) | matched-1:1 | `docs/phase17/parity_agreement.md:166` |
| [TestExtraPagesUpdate](https://github.com/algorand/go-algorand/blob/v5.0.4-stable/ledger/applications_test.go#L1699) | matched-1:many | `docs/phase17/parity_ledger_core.md:114` |
| [TestCowChildReflect](https://github.com/algorand/go-algorand/blob/v5.0.4-stable/ledger/eval/cow_test.go#L301) | out-of-scope | `docs/phase17/parity_ledger_core.md:239` |

