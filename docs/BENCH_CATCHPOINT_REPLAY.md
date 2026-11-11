# Catchpoint-start replay corpus (issue #2146)

Part of the benchmark epic #2101; follow-up of #2119 (`testnet-head`). Built by
#2294 (plan), #2291 (go harness), #2292 (Rust harness) and #2293 (fetch, gates,
tier wiring).

## Why

`testnet-head` replays rounds 0..20000 of the public testnet from genesis. That
range holds 425 transactions: no applications, no boxes, no proposer payouts, no
state proofs (they arrived in later consensus versions). A node cannot start
at a later round without a snapshot, so a corpus that exercises those features
has to start from a **catchpoint**: the ledger state at a catchpoint round,
authenticated by the catchpoint label `<round>#<hash>`, followed by the real
blocks and certificates of the rounds after it.

## The corpora

| name | what | where |
|---|---|---|
| `testnet-catchpoint` | the public testnet's catchpoint of round 69 120 000 and rounds 69 120 001..=69 120 200 with real certificates | fetched once into `benchmarks/corpus/testnet-catchpoint` (git-ignored) |
| `small-catchpoint` | the committed `small` corpus cut at the catchpoint go generated at its round 1500 | `benchmarks/corpus/small-catchpoint` (committed, 3.7 MB) |

A catchpoint corpus is an ordinary corpus directory (`blocks.bin` in the
`ACRPBLK1` layout, `genesis.json`, `node-config.json`, `corpus.json`,
`MANIFEST.sha256`) with two differences: `corpus.json` has `rounds.first > 0` and
a `start` object (`catchpoint`: the label, `file`: `catchpoint.tar`, `round`,
`coverage`), and `blocks.bin` holds the rounds `first..=last`, that is the
lookback before the catchpoint round (go's `processStageBlocksDownload`:
`MaxTxnLife + DeeperBlockHeaderHistory + CatchpointLookback = 1321`, or what a
pending state proof needs, trimmed to `round - 1`) and then the rounds to replay.
Both harnesses read `start` from `corpus.json`: no extra argument.

`testnet-catchpoint` is pinned by `benchmarks/corpus/testnet-catchpoint.ref`
(endpoint, relay, catchpoint label, round count, genesis hash, and
`final_state=benchmarks/corpus/testnet-catchpoint.final.json`). It is not pinned
by a manifest hash: a relay's tar file is not byte-stable, and the label (the hash
of the whole state) is the pin, which both harnesses check against the restored
state.

## What the range exercises

Scanned at fetch time and gated (`fetch-catchpoint` refuses a range without
them, `--allow-uncovered` skips the gate): the 200 replayed blocks hold a
proposer payout in every block, a state proof transaction (round 69 120 131) and
257 application calls; the catchpoint itself holds 2 245 701 accounts and
18 057 002 boxes. `testnet-head` holds none of these.

## Running it

```bash
# once: the corpus (the endpoint serves the blocks, a relay the catchpoint file)
python3 scripts/bench/corpus/fetch_testnet.py fetch-catchpoint
# the comparison: both sides start from the catchpoint, replay 200 blocks with
# certificate verification, and must reach the same final state
make bench-compare TIERS=replay CORPUS=testnet-catchpoint RUNS=3
```

`make bench-compare ... CORPUS=small-catchpoint` runs the same on the committed
small corpus (seconds). Each side's result records `from_catchpoint` and
`catchpoint_restore_s`; the timed section (blocks/s, txns/s, CPU, I/O) starts
after the catchpoint start, and the work counts cover only the replayed rounds.

Making a new range: `fetch_testnet.py plan-catchpoint [--rounds N]` writes the
ref (latest catchpoint of the channel, checked against the endpoint),
`fetch-catchpoint` builds a provisional corpus (attested round, hash and txn
counter only), a go replay of it gives the full state, `finalize` turns that into
the final-state file, and `final_state=` in the ref makes the next fetch final.
Rerun `fetch-catchpoint` after that.

## How the start works

- **go** (`benchmarks/go-replay`, `catchpoint.go`): go's catchpoint catchup with
  the corpus as the network: `CatchpointCatchupAccessor` stages the file's chunks,
  builds the trie, `VerifyCatchpoint` checks it against the catchpoint block (and so
  the label), the block and its lookback are stored from the corpus,
  `CompleteCatchup` switches the databases. It runs as a non-archival node (an
  archival ledger resets itself when its blocks database does not start at
  round 0).
- **algod-rust** (`bench replay-corpus`): the production `SyncOrchestrator`
  (import, verify, lookback blocks, window replay) with a corpus-backed
  `SyncBackend`, stopped at the catchpoint round.
- Then both replay the later rounds through their catchup path (certificate
  authentication, payset checks, apply, commit) and compute the same canonical
  final state: the whole ledger (every account and box), not a sample.

## Measured (this machine, one run each, not a benchmark)

| step | value |
|---|---|
| catchpoint file | 2 583 MB (2.4 GiB) from a relay at about 11 MB/s: about 4 minutes |
| blocks (1 522 incl. lookback) | seconds, from the archival endpoint |
| go: catchpoint restore | 1 002 s; whole run 26 min wall, 15.5 GB peak RSS, 8.5 GB database |
| go: replay of 200 blocks (319 txns) | 0.67 s |
| algod-rust: catchpoint restore | 365 s (Windows, release); whole run 32 min (the final-state read of 2.2 M accounts and 18 M boxes dominates), 8.7 GB database |
| algod-rust: replay of 200 blocks | 1.65 s |
| final state | identical on both sides: block hash `blk-PIV736MTN7...` (the endpoint's), txn counter 775 694 114, 2 245 701 accounts, 18 057 002 boxes, same digests |

The replay itself is tiny next to the restore: this corpus tests that both nodes
reach the same state and handle payouts, state proofs and apps correctly, and its
timings are most useful as the restore cost. Use more rounds (`--rounds`) for a
longer replay.

## Limits

- The restore needs 10+ GB of RAM on go (15.5 GB peak seen) and 9+ GB of disk per
  side.
- The final-state digest streams the box digest on the go side (millions of
  boxes up to 32 KB do not fit in a buffer); `-dump-state` keeps the lines in
  memory and is only for the small corpora.
- go's `LookupKeysByPrefix(maxKeyNum = 0)` is not "all keys": it stops at once
  when the in-memory deltas hold no box set and then reports a stale database
  round; the harness passes `MaxUint64`.
