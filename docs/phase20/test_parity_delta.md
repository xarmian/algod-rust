# Test-parity delta: go-algorand `v5.0.2-stable` → `v5.0.3-stable`

_Generated 2026-10-12 by `scripts/phase17_parity_delta.py report`._

| metric | count |
|---|---:|
| Go tests in `v5.0.2-stable` | 3190 |
| Go tests in `v5.0.3-stable` | 3190 |
| added | 0 |
| removed | 0 |
| moved (file rename, same name) | 0 |
| body changed (existing rows to re-verify) | 2 |

## Added in `v5.0.3-stable` (0)

Each needs a new row in the listed `parity_<area>.md` with an honest status. A `missing-test`/`not-implemented`/`partial` classification is a sub-issue of the upgrade epic, not a resting state.

_none_

## Removed in `v5.0.3-stable` (0)

Delete each row (the go test no longer exists at the pin). If the matched Rust test proved behavior go-algorand deliberately dropped, that is an upstream behavior change — make sure a Stage 2/3 issue covers it.

_none_

## Moved (0)

`repin` rewrites these links automatically; listed for the record.

_none_

## Body changed — re-verify the mapped Rust test(s) (2)

For each: read `git -C ../go-algorand diff OLD NEW -- <file>` around the function. If go-algorand added/changed an assertion, the mapped Rust test must gain the same assertion (or the row honestly drops to `partial` and becomes a sub-issue). Update the row's notes with what was re-checked.

| go-algorand test | current status | row |
|---|---|---|
| [TestParseRootTrustAnchor](https://github.com/algorand/go-algorand/blob/v5.0.3-stable/tools/network/dnssec/anchor_test.go#L27) | out-of-scope | `docs/phase17/parity_tools_cmd.md:123` |
| [TestQueryWrapper](https://github.com/algorand/go-algorand/blob/v5.0.3-stable/tools/network/dnssec/trustedchain_test.go#L388) | out-of-scope | `docs/phase17/parity_tools_cmd.md:143` |

