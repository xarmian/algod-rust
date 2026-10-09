# Mixed-cluster runbook: go-algorand and algod-rust agreement under a rich workload

Issue #1674. How to run, on demand, a soak in which three go-algorand v5.0.2-stable
nodes and one `algod-rust participate` node (30/30/30/10 online stake) stay in
agreement over many rounds while the chain carries boxes, inner transactions,
asset create / opt-in / transfer / close-out, application create / call / delete,
app-account closes, atomic groups, and minimum-balance edge cases.

Why it exists: the Execute-mode follow path (#1665) and the stricter minimum-balance
sweep (#1660) are consensus-critical, but the plain soak (`soak.sh` without a
workload) submits nothing, so every block it observes is empty. Empty blocks cannot
disagree about ApplyData.

## What runs

| Piece | File | Role |
| --- | --- | --- |
| Cluster | `ops/mixed-cluster/scripts/start.sh` | 3 Go relays + 1 Rust participant, fresh genesis |
| Workload | `ops/mixed-cluster/scripts/workload.py` | Seeded transaction driver (goal CLI inside `phase6-go-node-1`) |
| TEAL | `ops/mixed-cluster/workload/rich_app.teal`, `rich_clear.teal` | One v10 app that drives every box and inner-txn op |
| Comparator | `ops/mixed-cluster/scripts/blockcompare.py` | Raw block bytes of all 4 nodes, every round |
| Analyzer | `ops/mixed-cluster/scripts/analyze.py --workload --blockcompare` | Verdict |
| Wrapper | `soak.sh --workload rich`, `consensus-conformance.sh WORKLOAD=rich` | Wiring |
| CI | `.github/workflows/consensus-cluster.yml` | Nightly plain, weekly rich, on-demand dispatch |

`WORKLOAD` defaults to `plain`, which is the historical behaviour (nothing is
submitted). Nothing changes unless you ask for `rich`.

## Run it locally

Needs Docker, `python3`, and (for the full suite) a Rust toolchain.

```bash
# Quick agreement check on a cluster you start yourself (a few minutes):
ops/mixed-cluster/scripts/start.sh
ops/mixed-cluster/scripts/soak.sh --workload rich --rounds 60 --out /tmp/soak/soak.jsonl
ops/mixed-cluster/scripts/analyze.py /tmp/soak/soak.jsonl \
    --workload /tmp/soak/workload.jsonl --blockcompare /tmp/soak/blockcompare.jsonl
ops/mixed-cluster/scripts/stop.sh --purge

# The whole conformance suite (up, soak, verify, down) with the rich workload:
make consensus-cluster-test ROUNDS=200 WORKLOAD=rich
# add RESTART_SCENARIOS=1 NEGATIVE_CASES=1 for the restart and negative stages.
```

Notes:

* `soak.sh` writes `workload.jsonl` and `blockcompare.jsonl` next to `--out`.
* The schedule is a pure function of the seed (`WORKLOAD_SEED`, default 1674).
  `workload.py --print-plan 30 --seed 7` prints the scenario order without a cluster.
  Account keys come from kmd, so txids differ between runs; the schedule does not.
* `workload.py --scenarios app_inner,group` restricts the mix (useful when
  reproducing one finding). Scenarios: `pay min_balance asset app_boxes app_inner
  app_local group account_close app_close_delete`. The first pass runs each once in
  that order, then a weighted random mix.
* A 60-round run reaches about the first four scenarios; a full first pass is about
  150 rounds.
* Start from a fresh genesis. `consensus-conformance.sh` purges `netroot/` unless
  `REUSE_NETROOT=1`.
* `consensus-conformance.sh` with `WORKLOAD=rich` sets `PHASE6_GO_ARCHIVAL=1`, so the
  Go nodes keep every block. Without it a non-archival go-algorand node prunes blocks
  older than about 1000 rounds and the post-hoc fork detector degrades on long runs.
  When you drive `start.sh` yourself for a long run, set it yourself.
* Native Windows Python cannot take MSYS `C:/...` output paths from Git Bash; pass an
  absolute `/c/...` path to `--out`.

## Run it in CI

`Nightly Consensus Cluster` (`consensus-cluster.yml`):

* Nightly (02:41 UTC): plain, 200 rounds, 120 min stop. Unchanged.
* Weekly (Sunday 04:17 UTC): rich, 1000 rounds, 240 min stop.
* Dispatch: `gh workflow run consensus-cluster.yml --ref <branch> -f tier=full -f workload=rich -f rounds=2700 -f seed=1674`.

A small `plan` job turns the inputs into `workload`, `rounds` and the job timeout.
At roughly 3 s per round plus about 75 minutes of build, Tier 1, restart, negative and
verify stages, 2700 rounds needs about 210 minutes, which the 240-minute stop covers.
Any run over 400 rounds or any rich run gets at least 240 minutes; a request that
cannot fit in 350 minutes is refused by `plan`. Only one cluster runs at a time
(`concurrency: consensus-cluster`).

Artifacts (`consensus-cluster-<run id>`): `summary.json`, `soak.jsonl`,
`workload.jsonl`, `blockcompare.jsonl`, `analyze.summary.json`, `analyze.log`,
`verify.log`, per-node logs.

## Reading the result

`summary.json` lists named checks; the rich-specific ones are:

* `cross_impl_blocks_identical`: every compared round had byte-identical `block`
  values on all four nodes. The comparison slices the `block` entry out of
  `GET /v2/blocks/{r}?format=msgpack` (the `cert` next to it legitimately differs per
  node). Equal bytes means equal block hash, per-round txn count and ApplyData for
  every transaction. On a mismatch the failure names the round, the node, and the
  first differing msgpack paths (for example `$.txns[3].dt.itx[0]...`).
* `rich_workload`: the run proved something. It fails if: any round differs; a block
  hash differs; a negative transaction was admitted by one implementation and rejected
  by the other (`workload_divergence`); the workload recorded no steps; no
  non-payment round was compared; `pay`, `axfer`, `acfg`, `appl` never appeared on
  chain; no block carried inner transactions (`dt.itx`) or box references (`apbx`); a
  confirmed step points at an empty round; too many rounds could not be fetched from
  all nodes.
* `blockcompare_recheck`: `verify-soak.sh --blockcompare-jsonl` re-read the file clean.
* the existing checks (fork-free, certs both ways, proposer share, cadence, lockstep).

`analyze.py` also prints `note:` lines that do not fail the run: workload steps whose
outcome on go differed from what `workload.py` expected (a harness model problem, not
a divergence), scenario aborts, and a missing `workload_summary` (workload killed).

`workload.jsonl` records: `workload_meta`, one `workload_step` per transaction
(`scenario`, `op`, `txids`, `round`, `outcome`, `expect`, `ok`, and for must-reject
transactions the HTTP status each node returned), `workload_divergence`,
`workload_abort`, `workload_summary`.

Triage of a red run:

1. `analyze.log` first. A byte mismatch is a consensus finding: take the round and node
   from the failure, `GET /v2/blocks/<round>?format=msgpack` on each node, and diff.
2. `workload_divergence` means `POST /v2/transactions` gave different verdicts on
   go-node-1 and rust-node-4 for the same signed transaction.
3. Coverage failures mean the workload did not run (check `workload.log`, container
   `goal` errors, kmd permissions).
4. File each finding as its own issue (labels `bug`, `consensus`, `conformance`;
   "Part of epic #1680") with the run link.

## Add a workload op

1. If it needs program behaviour, add a branch to `workload/rich_app.teal` (the `match`
   cases, a label, and the handler), keep it TEAL v10 or lower-compatible, and check
   with `goal clerk compile`. Inner transactions must set `Fee 0`; the caller pays with
   `--fee`.
2. Add steps to a scenario in `workload.py` (`sc_*` methods) through `self.run(op, "<goal
   args>", expect=..., must=...)`. Use `expect="rejected"` for a transaction go must
   refuse, or `self.negative(op, build_cmd, out_file)` to build a signed file in the
   container and submit it to go-node-1 and rust-node-4 over REST (both must reject).
3. A new scenario goes in `SCENARIO_ORDER`, `SCENARIO_WEIGHTS` and `Workload.SCENARIOS`.
4. Extend `FakeEnv` coverage in `workload_test.py`; run
   `make consensus-cluster-analyzer` (no Docker).
5. Run the new scenario alone against a live cluster:
   `workload.py --out /tmp/w.jsonl --scenarios <name> --rounds 80`.

## Known limits

* Cert cross-verify covers only blocks the Rust ledger retains (#1777). A non-archival node (go and algod-rust alike) keeps ~1001 blocks (`MaxTxnLife + DeeperBlockHeaderHistory`). `PHASE6_GO_ARCHIVAL=1` (implied by `WORKLOAD=rich`) now makes the Rust node archival too (`Archival` in its config.json, written by `start.sh`), so the whole range is verified. Without it, `verify-soak.sh` derives the start of the cert pass from the snapshot's lowest block round (`cert_window.py`, `CERT_RETAIN_MARGIN` default 100 rounds for the seed lookback). `CERT_WINDOW=N` (opt-in, default off) additionally restricts it to the last N rounds. A clamp is never silent: `verify.log` carries `CERT_WINDOW_CLAMPED=1` and `summary.json` a `cert_window_clamped` WARN row. The fork detector and the live block comparison always cover every round.
* The comparison is strict by design (a harness that can pass vacuously is worthless): a round where any of the 4 nodes (or its block hash) could not be fetched is `incomplete` and fails the run, as does a soak where fewer than 90% of the rounds were compared (`--min-compare-coverage`), a Rust node absent from a compared round, no committed close-to / inner-txn / box-ref / axfer / appl, a missing `workload_summary`, any `workload_abort` (setup included), and any workload step whose outcome differed from its expectation. `--allow-missing` (blockcompare and analyze) is the explicit opt-out for missing nodes.

* The workload is single-threaded (one `goal` call at a time), so blocks carry a few
  transactions each, not a stress load. Throughput testing is `docker/scripts/bench-stress.sh`.
* Accounts, apps and assets are generated by kmd at run time; there is no rekey
  coverage.
* The Rust node is submitted to directly only for must-reject transactions; positive
  transactions reach it by gossip from the Go relays.

## Pool admission and block assembly evaluate with the real apply (#1773, #1774, #1776)

go's pool admits a group by running it through the pending block evaluator
(`data/pools/transactionPool.go` `ingest` -> `pendingBlockEvaluator.TransactionGroup`),
and its `GenerateBlock` only ever emits what that evaluator applied. algod-rust does the same:

* Admission (`SimpleBlockEvaluator::transaction_group`, `bin/algod-rust/src/commands/participate.rs`)
  runs the group through the real apply with AVM execution on a copy-on-write overlay of the
  pending state (`algo_ledger::pending_overlay`, `algo_ledger::proposal_eval::evaluate_group`).
  A failing group is rejected with go's text, `TransactionPool.Remember: transaction <txid>: <reason>`,
  HTTP 400. Cost is proportional to the group, not to the pool: earlier pending groups live in the
  overlay, only keys they did not touch are read from the ledger. A per-evaluator budget
  (`EXEC_ADMISSION_BUDGET`, 10 s) bounds re-evaluating a huge pool after a block; once spent, groups
  are admitted on the cheap checks and policed by assembly.
* Assembly (`SimpleBlockEvaluator::generate_block`) re-evaluates the whole candidate payset against
  the ledger in a rolled-back scratch apply (`algo_ledger::shadow_execute::scratch_execute_payset`),
  drops every group that fails (one extra pass per dropped group), and writes the resulting
  ApplyData (closing amounts, rewards, created ids, eval deltas) and the final transaction counter
  (inner transactions included) into the proposal. The ledger mutex is held for that pass.
