# Mainnet regression corpus

Real mainnet blocks that once exposed a divergence between algod-rust and
go-algorand (issue #1675), each with the minimal pre-state needed to apply it
and go's own post-state for everything the block wrote. Replayed in
`ApplyMode::Execute` by `crates/core/algo-ledger/tests/mainnet_corpus_test.rs`.

Per entry (`<round>` = mainnet round):

| File | Content |
| --- | --- |
| `<round>.msgpack` | The block exactly as served by `GET /v2/blocks/<round>?format=msgpack` (the block's recorded ApplyData is the oracle). |
| `<round>.state.msgpack` | `{meta, prev_hdr, extra_hdrs, pre, post}`; see below. |

`state.msgpack` is a msgpack map in go's own record shapes (the field names of
go's `ledgercore.StateDelta`):

* `prev_hdr` / `extra_hdrs`: block headers of rounds R-1 and R-2..R-17 (rewards
  state, txn counter, protocol, genesis, `global LatestTimestamp`, the `block`
  opcode).
* `pre`: `Accts`, `AppResources`, `AssetResources` and `KvMods` (boxes) records
  for every account, resource and box the block touches or references, as they
  stood at the end of round R-1.
* `post`: the same record kinds copied verbatim from go's state delta of round R
  (`GET /v2/deltas/<R>?format=msgpack`), i.e. what go wrote.
* `meta`: provenance (URLs, capture date) and the honesty lists below.

The test builds an in-memory `LedgerState` from `pre`, applies the block in
Execute mode and asserts (1) no error, (2) the ApplyData Execute computed for
every transaction equals the one recorded in the block
(`shadow_execute::compare_recorded_apply_data`), (3) every account, asset
holding/params, app params/local state and box in `post` equals the resulting
state.

## How the pre-state is obtained (and its limits)

The free public endpoints cannot rewind state (the indexer rejects `round=`,
algod only serves the tip). `scripts/capture_mainnet_corpus.py` therefore
reconstructs the state at R-1 from go's per-round state deltas
(`/v2/deltas/<round>`, served by algonode for old rounds): for each key it takes
the record from the most recent delta before R that carried it, using the
indexer to find the rounds in which the account / asset / application was
involved. Box pre-values come from `KvMods.OldData` of round R where the box is
written. Keys the block writes are always resolved exactly this way.

Keys the block only *references* (read-only) whose last write is more than 150
candidate rounds back are taken from the chain tip instead (balances of dormant
helper accounts, unchanged app code, ...). Those are listed in
`meta.tip_approximated_accounts` / `meta.tip_approximated_resource_parts`.
Accounts that could not be found in any delta are treated as non-existent
(`meta.unresolved_accounts`). Whether a reconstructed pre-state is complete
enough is proven by the entry itself: it must reproduce every recorded
ApplyData and every written post record.

## Regenerate

```
pip install msgpack requests
python3 scripts/capture_mainnet_corpus.py <round> [<round> ...]
cargo test -p algo-ledger --test mainnet_corpus_test
```

Network responses are cached under `$CORPUS_CACHE` (default
`<tmp>/algod-corpus-cache`). The files are public chain data, binary-pinned by
`.gitattributes` (`*.msgpack binary`); never let autocrlf touch them.
Adding an entry also needs one `corpus_entry!` line and the round in the
`wired` list of the test.

## Entries

| Round | Block / state (bytes) | Guards |
| --- | --- | --- |
| 65549710 | 79964 / 73344 | listed in #1675 |
| 65549861 | 68403 / 126689 | listed in #1675 |
| 65560513 | 98057 / 91414 | listed in #1675 |
| 65561121 | 84720 / 69163 | listed in #1675 |
| 65582745 | 82104 / 85198 | listed in #1675 |
| 65589704 | 84466 / 134697 | inner close-out leaving a zeroed account (#1665, #1669 class) |
| 65595332 | 90578 / 90242 | app account box totals / min balance (#1664, #1665) |
| 65596480 | 71913 / 36959 | listed in #1675 |
| 65668288 | 39492 / 82724 | account go zeroes must not stay a non-empty record (#1669) |
| 65689687 | 84342 / 91692 | inner transaction group IDs (#1699, #1710) |
| 65703970 | 61148 / 51737 | DeltaAction numbering SetBytes=1 / SetUint=2 (#1698, #1708) |
| 65723764 | 100975 / 117217 | zero-amount close into a new account stamps rewards_base (#1729, #1730) |
| 65723784 | 88258 / 119428 | first spend from that account: sender_rewards must be 0 (#1729) |

Not captured (tracked as follow-ups of #1675): 65743637 (heavy app-call block of
#1757) is ~530 KB, over the 200 KB per-fixture budget; 53000003 (#1742) needs
state from ~12M rounds back, where the deleted apps and closed-out local states
it references cannot be reconstructed cheaply (its `itx` bytes already exist as
`../mainnet_53000003_txn3_itx.hex`).
