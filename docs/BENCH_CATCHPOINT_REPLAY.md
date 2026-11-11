# Catchpoint-start replay corpus (issue #2146)

Part of the benchmark epic #2101; follow-up of #2119 (`testnet-head`).

## Why

`testnet-head` replays rounds 0..20000 of the public testnet from genesis. That
range holds 425 transactions: no applications, no boxes, no proposer payouts, no
state proofs (they arrived in later consensus versions). A node cannot start
at a later round without a snapshot, so a corpus that exercises those features
has to start from a **catchpoint**: the ledger state at a catchpoint round,
authenticated by the catchpoint label `<round>#<hash>`, followed by the real
blocks and certificates of the rounds after it.

## The range

`benchmarks/corpus/testnet-catchpoint.ref` pins one such range (written by
`scripts/bench/corpus/fetch_testnet.py plan-catchpoint`):

| | |
|---|---|
| network | public testnet (genesis hash pinned in the ref) |
| catchpoint | `69120000#HV3VUPYHFFFV5DQ4KAJ7UL7KU7SB5TV2W4TMITNE65XTR7IKBKLQ` (the channel's latest at the time of writing) |
| replayed rounds | 69 120 001 ..= 69 120 200 (200 rounds) |
| source of the blocks | an archival algod, `GET /v2/blocks/{r}?format=msgpack` (certificate included), as for `testnet-head` |

Scanned for this issue (`GET /v2/blocks/{r}` for each round of the range): every
block carries a proposer payout (`prp`), round 69 120 131 holds a state proof
transaction (`stpf`), and 257 application calls are spread over the range. So the
range exercises exactly what `testnet-head` cannot.

`plan-catchpoint` resolves the label (the channel's `latest.catchpoint`, or
`--label`), checks it (positive round on a 10 000-round boundary, 52 base32
characters of hash), checks that the endpoint is on the pinned network and
serves the first and the last block of the range with certificates, and writes
the ref. It touches no ledger. `scripts/bench/test_testnet_corpus.py`
(`PlanCatchpointTests`) covers it against a local endpoint.

## What is not built yet, and why

Both harnesses start from genesis today (`benchmarks/go-replay`,
`bin/algod-rust/src/commands/bench_replay.rs`, `scripts/bench/tiers/replay.py`).
The tier cannot run on this range until:

1. **A pinned catchpoint file** is fetched and cached (like `testnet-head`, outside git, never
   published from CI). A testnet catchpoint is the whole ledger state at round
   69 120 000; its size was not measured here and is expected to be in the
   gigabytes, so the fetch is a deliberate, cached, manual step. It comes from a
   relay (`_algobootstrap._tcp.testnet.algorand.network`), not from the algod REST API.
2. **Each harness starts from it.** The Rust side has catchpoint apply
   (`algo_ledger::catchpoint`); `bench_replay` has to open a ledger from it and
   replay the range with certificate verification on. The Rust side is done
   (#2292): `algod-rust bench replay-corpus --from-catchpoint FILE
   --catchpoint-label L` runs the production `SyncOrchestrator` (import, verify,
   lookback blocks, window replay) with the corpus as its backend, stopped at the
   catchpoint round, then replays the rest through the same catchup path as the
   genesis replay (certificates, apply, commit); the timed section starts after
   the catchpoint start. `bench_replay::tests::small_corpus_catchpoint_start_reaches_the_go_final_state`
   starts from the catchpoint go generated at round 1000 of the small corpus
   (`benchmarks/go-replay/testdata/small-catchpoint-1000.{tar,label}`, 14 KB) and
   reaches the recorded go final state; a wrong label is refused. The go side is
   done (#2291): `benchmarks/go-replay -from-catchpoint FILE -catchpoint-label L`
   runs go's catchpoint catchup (`CatchpointCatchupAccessor`: stage the file's
   chunks, build the trie, `VerifyCatchpoint` against the catchpoint block, store
   that block and the lookback before it from the corpus, `CompleteCatchup`) and
   replays only the rounds after the catchpoint round, as a non-archival node
   (an archival ledger resets itself when its blocks database does not start at
   round 0). `-export-catchpoint FILE` writes the newest catchpoint go generated
   during a replay (set `CatchpointInterval` in the config). Proven on a small
   generated catchpoint: `TestCatchpointStartMatchesStraightReplay` replays rounds
   1..1200 of the small corpus with a catchpoint every 500 rounds, exports the
   round-1000 catchpoint, starts a fresh ledger from it, replays 1001..2000 and
   reaches exactly `corpus.json`'s and the recorded full final state;
   `TestCatchpointStartRefusesAWrongLabel` shows the label authenticates the
   file. The testnet catchpoint (GBs) was not fetched here.
3. **A final-state definition** for the range: the corpus's `final_state`
   (round, block hash, txn counter, totals, account digest) derived by the go
   replay and attested by the endpoint, as `finalize` does for `testnet-head`.
   The start state needs no separate gate: the catchpoint label's hash pins it,
   and both sides must accept the same label.
4. **Corpus coverage gate**: the range must keep its payouts and state proof
   (a re-planned range with none fails the build).

Items 1 to 3 are GB-scale downloads and hours of catchpoint apply on each side,
and the go side needs the go-algorand build (libsodium) the WSL/CI environments
provide; they are tracked as follow-up issues of #2146 rather than done in one
change.

## Cost

Planning is 3 small requests. The replay itself is 200 blocks; the dominant cost
is the one-off catchpoint download and apply (not measured here), cached
outside git like `testnet-head`.
