# Phase 17 Test Parity Map — go-algorand ↔ algod-rust

_Generated 2026-09-20 against go-algorand `v5.0.2-stable` (detached HEAD,
`../go-algorand`) and algod-rust `main`._

This document is the test-level evidence map for
[`docs/PHASE17_PROPOSAL.md`](PHASE17_PROPOSAL.md). It answers, for every
`func TestXxx` in the pinned go-algorand checkout: does algod-rust have a
test proving the same behavior, and if not, why not.

Tracking epic: [#830](https://github.com/xarmian/algod-rust/issues/830).

## How this was built

1. [`scripts/list_go_tests.sh`](../scripts/list_go_tests.sh) walks the
   go-algorand checkout and emits every `_test.go` `Test*` function as a
   TSV (`package`, `test_name`, `file`, `line`).
2. [`scripts/list_rust_tests.sh`](../scripts/list_rust_tests.sh) walks
   this repo and emits every `#[test]`/`#[tokio::test]` function the same
   way (`crate`, `test_name`, `file`, `line`).
3. The go-algorand test list was split by package area into
   [`docs/phase17/batches/`](phase17/batches/), and for each area a
   mapping pass produced one `docs/phase17/parity_<area>.md` file: one
   row per go-algorand test, linked to its exact GitHub blob at
   `v5.0.0-stable`, cross-referenced against the full Rust test list by
   keyword/behavior, and classified into a status (below).
4. Both scripts are safe to re-run at any time — after the next
   go-algorand version bump, or periodically — to regenerate this map
   from scratch. They are intentionally dumb (no state, no caching) so
   the output is always a true reflection of the current two trees.

Raw generated inputs (kept for reproducibility, not hand-edited):
[`docs/phase17/go_tests.tsv`](phase17/go_tests.tsv) (3,177 go-algorand
tests), [`docs/phase17/rust_tests.tsv`](phase17/rust_tests.tsv) (6,644
algod-rust tests), [`docs/phase17/batches/`](phase17/batches/) (the
per-area split of the former).

## Keeping this map current across version upgrades

This map is a live invariant, not a point-in-time audit: at the current
pin, every `func Test*` in `../go-algorand` has exactly one row pinned to
that tag, and `not-implemented`, `missing-test` and `partial` are all zero.
[`scripts/phase17_parity_delta.py`](../scripts/phase17_parity_delta.py)
keeps it that way across go-algorand version bumps, and the
`algod-version-upgrade` skill runs it at fixed points:

1. `report --old-tag OLD --new-tag NEW --old-tsv <OLD go_tests.tsv> --go-algorand ../go-algorand --out docs/phase<N>/test_parity_delta.md`
   (upgrade analysis, before the pin moves) — lists Go tests **added**,
   **removed**, **moved** and **body-changed** between the two tags, each
   with the `parity_<area>.md` row it affects. Every added/body-changed
   test becomes an acceptance criterion of an upgrade sub-issue.
2. `repin --old-tag OLD --new-tag NEW --go-algorand ../go-algorand`
   (the pin-sweep PR) — rewrites every row link to `NEW` with `NEW`'s line
   numbers, regenerates `go_tests.tsv` and `batches/`, and appends an
   `unclassified` placeholder row per added test so nothing can be skipped
   silently.
3. `check --tag NEW --go-algorand ../go-algorand` (every sub-issue PR as
   a progress gauge; the epic's close-out as a hard gate) — exits non-zero
   on any stale/unpinned link, any Go test without a row, any row without
   a Go test, or any `unclassified` / `not-implemented` / `missing-test` /
   `partial` row.

Between upgrades, any PR that adds a Rust test proving parity with a Go
test named here updates that row in the same PR and re-runs
[`scripts/update_phase17_summary.py`](../scripts/update_phase17_summary.py)
so the tables below never drift from what `main` actually covers.

## Status legend

| status | meaning |
|---|---|
| `matched-1:1` | one go test ↔ one rust test, equivalent behavior |
| `matched-1:many` | one go test's behavior is covered by several, finer-grained rust tests |
| `matched-many:1` | several go tests collapse onto one broader rust test |
| `partial` | related rust coverage exists but is narrower/weaker than the go test |
| `missing-test` | the feature **is** implemented in algod-rust, but this specific behavior has no test — a fixable test gap |
| `not-implemented` | the underlying feature/opcode/mechanism does not exist in algod-rust at all — a real functionality gap, not just a test gap |
| `out-of-scope` | genuinely not applicable to algod-rust (Go-runtime specifics, CLI tooling with no Rust equivalent concept, structural differences that make the go test meaningless in Rust) |
| `unclassified` | **transient only** — placeholder inserted by `scripts/phase17_parity_delta.py repin` for a test a go-algorand version bump added, pending classification by the upgrade epic's sub-issues; never a valid final state, and the summary tables below cannot be regenerated while any remain |

## Aggregate totals (3,194 go-algorand tests)

| status | count | share |
|---|---|---|
| `matched-1:1` | 1,215 | 38% |
| `matched-1:many` | 953 | 30% |
| `out-of-scope` | 737 | 23% |
| `matched-many:1` | 286 | 9% |
| `partial` | 3 | 0% |
| `not-implemented` | 0 | 0% |
| `missing-test` | 0 | 0% |

**0 rows (`not-implemented` + `missing-test`, 0%) are real, actionable
gaps** — either a behavior algod-rust doesn't implement yet, or one it
implements but never tests. `partial` (3, 0%) is coverage that exists
but is weaker than go-algorand's; some of these are worth strengthening,
most are diminishing-returns edge cases. See
[`docs/PHASE17_PROPOSAL.md`](PHASE17_PROPOSAL.md) for how the real gaps
were triaged into tracked issues.

## Per-area breakdown

| area | file | total | 1:1 | 1:many | many:1 | partial | not-impl | missing-test | out-of-scope |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| AVM/TEAL opcodes (`data/transactions/logic`) | [parity_txn_logic.md](phase17/parity_txn_logic.md) | 449 | 147 | 255 | 6 | 0 | 0 | 0 | 41 |
| Transactions core (`data/transactions`) | [parity_txn_core.md](phase17/parity_txn_core.md) | 176 | 77 | 48 | 32 | 0 | 0 | 0 | 19 |
| Ledger core (`ledger`, `ledger/eval`, `ledger/apply`, `ledger/ledgercore`, `ledger/store`, `ledger/encoded`) | [parity_ledger_core.md](phase17/parity_ledger_core.md) | 503 | 78 | 152 | 62 | 0 | 0 | 0 | 211 |
| Ledger simulation (`ledger/simulation`) | [parity_ledger_sim.md](phase17/parity_ledger_sim.md) | 68 | 37 | 30 | 0 | 0 | 0 | 0 | 1 |
| Agreement protocol (`agreement`) | [parity_agreement.md](phase17/parity_agreement.md) | 335 | 166 | 67 | 89 | 3 | 0 | 0 | 10 |
| e2e integration (`test/e2e-go`) | [parity_e2e.md](phase17/parity_e2e.md) | 195 | 80 | 45 | 3 | 0 | 0 | 0 | 67 |
| Networking (`network`, `network/p2p`, ...) | [parity_network.md](phase17/parity_network.md) | 263 | 115 | 94 | 12 | 0 | 0 | 0 | 42 |
| Crypto (`crypto`, `crypto/stateproof`, ...) | [parity_crypto.md](phase17/parity_crypto.md) | 279 | 165 | 43 | 26 | 0 | 0 | 0 | 45 |
| Daemon/node/rpcs (`daemon/algod`, `node`, `rpcs`) | [parity_daemon_node.md](phase17/parity_daemon_node.md) | 144 | 62 | 70 | 1 | 0 | 0 | 0 | 11 |
| Data structures (`data/basics`, `data/bookkeeping`, ...) | [parity_data_misc.md](phase17/parity_data_misc.md) | 274 | 145 | 42 | 48 | 0 | 0 | 0 | 39 |
| Config/stateproof/protocol | [parity_config_proto_sp.md](phase17/parity_config_proto_sp.md) | 119 | 32 | 41 | 0 | 0 | 0 | 0 | 46 |
| Util (`util/*`) | [parity_util.md](phase17/parity_util.md) | 118 | 34 | 14 | 0 | 0 | 0 | 0 | 70 |
| Tools/CLI (`tools/*`, `cmd/*`, ...) | [parity_tools_cmd.md](phase17/parity_tools_cmd.md) | 173 | 46 | 30 | 7 | 0 | 0 | 0 | 90 |
| Logging (`logging/*`) | [parity_logging.md](phase17/parity_logging.md) | 41 | 0 | 0 | 0 | 0 | 0 | 0 | 41 |
| Catchup (`catchup`) | [parity_catchup.md](phase17/parity_catchup.md) | 57 | 31 | 22 | 0 | 0 | 0 | 0 | 4 |
| **Total** | | **3,194** | **1215** | **953** | **286** | **3** | **0** | **0** | **737** |

