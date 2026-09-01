# Phase 17 Test Parity Map — go-algorand ↔ algod-rust

_Generated 2026-09-01 against go-algorand `v5.0.0-stable` (detached HEAD,
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

## Aggregate totals (3,177 go-algorand tests)

| status | count | share |
|---|---|---|
| `partial` | 714 | 22% |
| `not-implemented` | 555 | 17% |
| `matched-1:1` | 484 | 15% |
| `matched-1:many` | 461 | 15% |
| `missing-test` | 430 | 14% |
| `out-of-scope` | 333 | 10% |
| `matched-many:1` | 200 | 6% |

**985 rows (`not-implemented` + `missing-test`, 31%) are real, actionable
gaps** — either a behavior algod-rust doesn't implement yet, or one it
implements but never tests. `partial` (714, 22%) is coverage that exists
but is weaker than go-algorand's; some of these are worth strengthening,
most are diminishing-returns edge cases. See
[`docs/PHASE17_PROPOSAL.md`](PHASE17_PROPOSAL.md) for how the real gaps
were triaged into tracked issues.

## Per-area breakdown

| area | file | total | 1:1 | 1:many | many:1 | partial | not-impl | missing-test | out-of-scope |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| AVM/TEAL opcodes (`data/transactions/logic`) | [parity_txn_logic.md](phase17/parity_txn_logic.md) | 449 | 52 | 132 | 6 | 121 | 29 | 86 | 23 |
| Transactions core (`data/transactions`) | [parity_txn_core.md](phase17/parity_txn_core.md) | 173 | 31 | 32 | 0 | 68 | 31 | 10 | 1 |
| Ledger core (`ledger`, `ledger/eval`, `ledger/apply`, `ledger/ledgercore`, `ledger/store`, `ledger/encoded`) | [parity_ledger_core.md](phase17/parity_ledger_core.md) | 503 | 34 | 85 | 39 | 132 | 41 | 54 | 118 |
| Ledger simulation (`ledger/simulation`) | [parity_ledger_sim.md](phase17/parity_ledger_sim.md) | 68 | 6 | 15 | 0 | 19 | 10 | 17 | 1 |
| Agreement protocol (`agreement`) | [parity_agreement.md](phase17/parity_agreement.md) | 326 | 99 | 28 | 77 | 47 | 6 | 66 | 3 |
| e2e integration (`test/e2e-go`) | [parity_e2e.md](phase17/parity_e2e.md) | 195 | 28 | 14 | 0 | 61 | 0 | 66 | 26 |
| Networking (`network`, `network/p2p`, ...) | [parity_network.md](phase17/parity_network.md) | 263 | 44 | 44 | 11 | 59 | 85 | 19 | 1 |
| Crypto (`crypto`, `crypto/stateproof`, ...) | [parity_crypto.md](phase17/parity_crypto.md) | 276 | 56 | 25 | 15 | 62 | 47 | 49 | 22 |
| Daemon/node/rpcs (`daemon/algod`, `node`, `rpcs`) | [parity_daemon_node.md](phase17/parity_daemon_node.md) | 144 | 33 | 43 | 0 | 15 | 18 | 25 | 10 |
| Data structures (`data/basics`, `data/bookkeeping`, ...) | [parity_data_misc.md](phase17/parity_data_misc.md) | 274 | 75 | 15 | 45 | 67 | 40 | 25 | 7 |
| Config/stateproof/protocol | [parity_config_proto_sp.md](phase17/parity_config_proto_sp.md) | 119 | 15 | 17 | 0 | 18 | 59 | 6 | 4 |
| Util (`util/*`) | [parity_util.md](phase17/parity_util.md) | 118 | 5 | 2 | 0 | 19 | 59 | 0 | 33 |
| Tools/CLI (`tools/*`, `cmd/*`, ...) | [parity_tools_cmd.md](phase17/parity_tools_cmd.md) | 173 | 4 | 2 | 7 | 13 | 102 | 3 | 42 |
| Logging (`logging/*`) | [parity_logging.md](phase17/parity_logging.md) | 41 | 0 | 0 | 0 | 0 | 0 | 0 | 41 |
| Catchup (`catchup`) | [parity_catchup.md](phase17/parity_catchup.md) | 55 | 2 | 7 | 0 | 13 | 28 | 4 | 1 |
| **Total** | | **3,177** | **484** | **461** | **200** | **714** | **555** | **430** | **333** |

