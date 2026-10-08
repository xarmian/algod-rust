<!--
Copyright (c) 2026 Algod DAO
SPDX-License-Identifier: MIT
See the LICENSE-MIT file in the repository root for the full license text.
-->

# Nightly Mainnet Node Soak (issue #1598)

`.github/workflows/mainnet-node-soak.yml` runs a single `algod-rust
participate --network mainnet` process on the GitHub-hosted runner every
night — configured exactly as an operator would run a participation node,
bootstrapped with fast catchup against a real mainnet relay/archival
endpoint — and answers two questions no other workflow in this repo does:

1. How long does fast catchup actually take on a real network?
2. Does the node ever go quiet — mid-catchup, or after it reaches the tip
   — for longer than a genuine hang would ever take?

This is a **standalone** workflow. It shares no state, harness, or trigger
with `consensus-cluster.yml`, `p2p-consensus-soak.yml`, `validate-api.yml`,
or `nightly-fuzz.yml`.

## What runs

1. Release-build `algod-rust`; self-test `ops/mainnet-soak/monitor.py` and
   `file_issue.py` before trusting either.
2. Start the node: real mainnet genesis (`crates/core/algo-ledger/tests/
   fixtures/mainnet-genesis.json`, the same fixture `make
   replay-mainnet*` already uses), a fresh empty participation-key store
   (zero stake — this soak proves the node runs and catches up, not that
   it votes), DNS-discovered mainnet relays, REST on `127.0.0.1:8180`.
3. Read the catchup peer's `/v2/status` `last-catchpoint` and `POST
   /v2/catchup/{label}` on the node — the fast-catchup clock starts here.
4. Poll both `/v2/status` endpoints every 10s for the run's budget
   (default 240 minutes cap, ending 120 minutes after the tip is first reached; see below) via `monitor.py collect`.
5. Tear down, write the job summary, upload artifacts, and — only on a
   halt — file or comment on a GitHub issue.

## What counts as "halted"

The node reports a **progress signature** every poll:

- **catchup phase** (`/v2/status` `catchpoint` is non-empty): the tuple of
  `catchpoint-acquired-blocks` / `-processed-accounts` / `-processed-kvs`
  / `-verified-accounts` / `-verified-kvs`. Frozen means the
  download/import/verify pipeline stopped moving, even before `last-round`
  is expected to advance.
- **follow phase** (no `catchpoint`): `last-round`.

If that signature is unchanged for `halt_minutes` (default 5) **and** the
catchup peer's own `last-round` kept advancing during the same window, the
node is genuinely stuck — a real halt, worth an issue.

**Exception — the verify phase (issue #1623):** algod-rust's
`run_verify_ledger` (`crates/core/algo-ledger/src/sync/mod.rs`) rebuilds
the Merkle trie and compares the catchpoint label in one single,
non-incremental step, unlike go-algorand's incremental
`updateVerifiedCounts`. That step has been observed to take 900+ seconds
on a real mainnet-sized catchpoint (~22.47M accounts) with the catchup
counters completely frozen the whole time — legitimate work, not a stall.
`monitor.py`'s `is_verifying_signature()` recognizes this specific window
(import counters fully caught up to their totals, verify counters not
yet) from fields already in `/v2/status`, and gives it its own, longer
`verify_halt_minutes` allowance (default 45) instead of the steady-state
`halt_minutes` — still finite, so a genuine deadlock in the trie rebuild
is caught eventually, just not mistaken for a stall at 5 minutes in.

**Post-verify window (issue #1663).** Once import *and* verify counters are
both complete, the node still downloads the lookback blocks (~4 min on
mainnet), replays the go-catchpoint 320-block window (~4 min) and
checkpoints the WAL, and none of that moves a `catchpoint-*` counter.
`is_post_verify_signature()` recognizes that state and gives it a
`post_verify_halt_minutes` allowance (default 30, `--post-verify-halt-minutes`)
instead of the 5-minute rule, so a healthy nightly is no longer classified
`stuck` ~303 s into the replay. It is still finite: a node wedged there is
caught after 30 minutes, and the workflow's `halt_minutes` default (5) is
unchanged for every other phase (mid-import freezes, the follow phase).

If the peer was
*also* frozen, or unreachable, there's no way to tell node staleness from
network staleness, so it's classified a **source outage** — a warning,
never an issue. If the node process exits or its REST stops answering
(and never recovers before the stream ends), that's a **node failure**,
reported at the last round observed.

**Exception — a still-alive node's REST going briefly unreachable (issue
#1623, live-dispatch follow-up):** a live run (36204923591) showed the
verify phase can starve the node's REST responder under CI-runner CPU
contention badly enough that individual `/v2/status` polls time out
outright, not just return frozen counters. `collect()`'s live loop gives
a single unreachable poll (the child process still running per
`process_alive()`) a grace window before treating it as a real
`node_failure` — `unreachable_grace_minutes` (default 3) normally, or the
longer `verify_halt_minutes` if the last known-good sample looked like
the verify window. A confirmed-dead process (`process_alive()` returns
`False`) is never given this grace — that failure is real and immediate.

A node that's still catching up when the time budget runs out, having
made continuous progress the whole time, is **not** a halt — "didn't
finish within the budget" and "got stuck" are different claims, and
`monitor.py` never conflates them.

Five minutes was chosen because it comfortably exceeds this repo's own
`ActivityMonitor`-class stall budgets (see issue #1595) while still being
short enough that a genuine per-block/import stall is caught the same
night, not days later.

## Detailed catchup phases (`phase_seconds_detailed`)

`summary.json`'s `phase_seconds` only attributes time while a `/v2/status`
catchup counter moves, which left ~2500 s of a ~3850 s catchup as
`unattributed`. Those keys are unchanged; `phase_seconds_detailed` adds a
timeline derived from `node.log` (ANSI stripped) by
`ops/mainnet-soak/nodelog.py` (`parse_phase_log`). Every segment is the
difference of two adjacent log timestamps (or an `elapsed_s=` the node
logged itself), so the segments sum to `catchup_log_total_s`:

| key | from -> to |
| --- | --- |
| `startup_s` | node's first log line -> catchup request (outside the catchup clock) |
| `earlier_attempts_s` | first request -> start of the final sync attempt (0 unless it restarted) |
| `download_s` | `Downloading ledger snapshot` -> `Importing ledger into database` |
| `import_s` | import -> `Verifying ledger integrity` (includes the catchpoint cutover) |
| `verify_s` | verify -> `Downloading lookback blocks`, split into `verify_staging_s`, `verify_indexing_s`, `verify_trie_build_s` (the node's `trie rebuild ... elapsed_s=` markers) and `verify_tail_s` (the rest) |
| `lookback_download_s` | lookback download -> `Replaying blocks` |
| `replay_s` | replay start -> first post-sync WAL checkpoint |
| `post_sync_wal_checkpoint_s` | first -> last post-sync WAL checkpoint |
| `invariant_validation_s` | last post-sync checkpoint -> `Sync complete` (ledger invariant validation) |
| `final_wal_checkpoint_s` | `Sync complete` -> end of the contiguous `WAL checkpoint:` chain (the ~270 s checkpoint) |

`catchup_wall_s` is the status-polling `fast_catchup_seconds`;
`unaccounted_s` is the difference (poll latency, a few seconds). A line the
log did not contain yields `null` for the affected segments; it never fails
the run. Run 37217724082 for reference: download 95, import 1059, verify
1722 (staging 547, indexing 355, trie build 739, tail 81), lookback 379,
replay 214, post-sync WAL 16, invariant validation 97, final WAL checkpoint
272 -> 3852 s of 3857 s wall.

## Follow window and broken-state scan

`follow_minutes` (dispatch input; scheduled default 120): once the monitor
first sees the node at the tip it keeps collecting for `follow_minutes`,
then ends `ok`. `duration_minutes` (scheduled default 240 = catchup 60-75
min + 120 min follow + margin) stays the **hard cap** on total poll time, so
the monitor ends at `min(duration, first_tip + follow)`; `follow_minutes=0`
is the previous behaviour exactly. `duration_minutes` is clamped to 315 so
the 320-minute monitor-step and 350-minute job timeouts (GitHub-hosted
limit: 360) always fit. The stall rules keep applying during the follow
window, and `summary.json` gains `follow` (`requested_s`, `observed_s`,
`time_to_tip_s`, `completed`) alongside the unchanged `lag_rounds`, which
covers every sample from the first tip sighting, i.e. the follow window.
`lag_rounds` carries `mean`/`p50`/`p95`/`p99`/`max`.

**Lag versus the terminal stall window (issue #1759).** When the verdict is a
halt (`stuck`, `source_outage` or `invalid_block_stall`) the trailing frozen-node
window would otherwise dominate the lag numbers (run 37207786702: healthy
part mean 0.26 / p95 1 / max 3, but 31 frozen samples lifted the headline to
mean 4.37 / p95 34 / max 114). `summary.json` therefore carries both:
`lag_rounds` (every sample since the first tip sighting, unchanged for
compatibility) and `lag_rounds_before_stall` (same stats over the samples up
to and including the one where the signature froze), plus `stall_window`
(`start_ts`, `seconds`; `null` when there is no halt, in which case the two
lag blocks are equal). The step summary prints both lag rows and the window.

**Invalid-block stall (issue #1715).** Each poll reads the additive
`stalled-on-invalid-block` object of `GET /v2/status` (`round`, `error`,
`consecutive-failures`, `since-unix-secs`); when `/v2/status` does not answer
the monitor falls back to the gauge `algod_rust_sync_stalled_on_invalid_block`
on `/metrics` (`algod_rust_sync_stalled_block_round` gives the round), read at
most once per 30 s and only while the status is unavailable. If the latest
sample says the node is stalled, the verdict is `invalid_block_stall` (exit 1, the
run ends at once, the issue is filed): the message carries round, error and
consecutive failures, and `summary.json` keeps the status payload under
`invalid_block_stall` (also in the step summary and the auto-filed issue
body; node-supplied text is stripped of backticks and newlines, `|` is
replaced in table cells, and it is truncated to 500 characters). A stall that
cleared (a valid block committed and later samples are healthy) does not fail the
run: it is reported as `invalid_block_stall_cleared` (round, error, first and
last time seen) and as a warning row in the step summary; an unreachable node at
the end of the stream stays a `node_failure`. The log scan has a matching hard signature, `stalled_on_invalid_block`
(the node's `stalled on invalid block` ERROR line). A healthy node is
unaffected: the field is absent from its status and the gauge is only read
while the status is unavailable.

**Per-block follow-path timing (issue #1678).** The node's `/metrics` always
exposes fixed-bucket histograms `algod_rust_follow_block_{apply,avm,commit,
wal_checkpoint,ensure_block}_seconds` (buckets 1 ms ... 30 s plus `+Inf`):
block apply (includes AVM), top-level AVM program evaluation (only blocks that
ran programs, so its count is smaller), the SQLite commit, each WAL checkpoint
run on the committing thread (the ledger connection's auto-checkpoint, timed),
and the successful `ensure_block` attempt (ledger-lock wait plus commit,
excluding earlier failed attempts and retry sleeps). Failures are visible
separately: `..._apply_failed_seconds`, `..._commit_failed_seconds` (a failed
SQLite commit), `..._ensure_block_failed_seconds` (also observes the early
return of a poisoned ledger lock; the routine "block ahead of the ledger, needs
catchup" skip is only counted by `..._ensure_block_skipped_ahead_total`),
`..._ensure_block_retries_total` and `..._ensure_block_already_committed_total`.
Once the node is out of catchup, `status.jsonl` samples carry the parsed
cumulative histograms (`follow_timing`), scraped at most every 30 s with a 1 s
timeout so the poll cadence is unaffected (a persistent scrape failure is
logged once to stderr; the first sample at the tip is always scraped, so the
delta window starts exactly at the tip transition rather than up to 30 s
later). `summary.json` gains `follow_block_timing` (all eight series above,
failed-path ones included; the step-summary rows print `baseline` and
`restarted` too): per
metric `count`, `mean_s`, `p50_s`, `p95_s`, `max_s`, plus `baseline` and
`restarted`. `baseline` is `"delta"` (last scrape minus the first scrape at
the tip, i.e. the follow window) or `"absolute"` (no earlier scrape to subtract,
or the node restarted between the scrapes: a counter or bucket went backwards,
buckets are non-monotonic; then `restarted` is `true` and the post-restart
absolute values are reported). A restart that processed more blocks than the
baseline leaves every counter larger, so it is also detected by the node's
`algod_rust_process_start_time_seconds` gauge (Unix seconds at process start,
scraped with the histograms; float Unix seconds with millisecond resolution,
captured as the first statement of `main`, compared for exact equality): a
different value between the baseline and the last scrape marks the series
`restarted`. The post-restart absolute values are reported, and
`pre_tip_included: true` flags that the first post-restart scrape was taken
before the node was at the tip, i.e. the values include catchup-era timings (older nodes without the gauge fall
back to the counter checks). `/metrics` itself cannot 404 on the production
adapter (the follow series and the start-time gauge are always exposed); the
404 contract only remains for `NodeInterface` implementations with nothing to
report. Percentiles and `max_s` are **bucket upper
bounds** (the `+Inf` bucket reports 30, i.e. "at least 30 s"). Use these next
to `lag_rounds` to tell a slow apply from a slow commit or checkpoint when lag
spikes.

After teardown the job scans `node.log` (`monitor.py scan-log`, merged into
`summary.json` as `log_scan`, rendered in the step summary):

- **hard** (fail the job): `permanent error writing block`,
  `stalled on invalid block` (issue #1715),
  `apply_block failed`, `panicked`, `invariant check: error`,
  `Resource temporarily unavailable`, three or more
  `ensure_block ... did not advance`, and `below minimum balance` /
  `insufficient balance` on any line that is not from the gossip tx path
  (`tx_tag_handler`, `tx_syncer`, `tx_sync_pool_adapter`,
  `PoolSolicitedTxHandler`, `TxSyncer`, `TransactionPool`).
- **warn** (counted, shown, not failing): invariant-check warnings,
  `group ID mismatch` proposal drops (with the number of distinct
  proposals), agreement persistence write failures/timeouts, slow
  `ensure_block`.
- **noise** (counted only): the `hickory_proto` DNSSEC `exceeded max
  validation depth` ERROR flood (issue #1676), gossip tx rejections, `WS
  block fetch failed`.

`group ID mismatch` is kept at warn rather than excluded: on run
37217724082 it fired for 1740 distinct proposals in 86 minutes, i.e. about
every round, while mainnet proposals are valid, so it is not normal noise;
it is not yet a hard failure so the nightly is not red for a known open
defect. A scan failure does not file an issue: `file_issue.py` is keyed on
halt verdicts (round/phase), a scan hit has neither, and the evidence is in
the job summary, `summary.json` and `node.log`.

## Shadow-execute differential check (issue #1673)

Dispatch with `-f shadow_execute=true` to set `ALGOD_SHADOW_EXECUTE=1` on the
soak node. While it follows the chain, every Replay-applied block is also
evaluated in Execute mode on a rolled-back scratch apply and the results are
compared, and every app-call block's computed ApplyData/EvalDelta is compared
with the recorded one. Any difference is logged as `shadow_execute_mismatch`
(a hard-tier finding). The check costs follow-path CPU: use
`-f shadow_execute_sample_every=N` (`ALGOD_SHADOW_EXECUTE_SAMPLE_EVERY`,
default 1) to check only every Nth Replay-applied block. Watch the
`shadow_execute_progress` log line (checked / mismatched /
`state_skipped_unsupported_store` / suppressed-line counters); a non-zero
skipped count means the store could not roll back and nothing was verified:
the log scan treats `shadow_execute_unsupported_store`, and a progress line
that shows zero checked blocks and zero app-call compares, as hard failures so
such a soak never reports clean. `shadow_execute_sample_every` accepts at most
9 digits (longer values are clamped to 999999999 with a workflow warning;
non-numeric or 0 means 1). The workflow passes every dispatch input to the
run-parameters script through `env:` rather than interpolating it into the
shell text.

## Auto-filed issues

Only a `stuck` or `node_failure` verdict files anything
(`ops/mainnet-soak/file_issue.py`). It first searches open issues labelled
`mainnet-soak` for a `<!-- mainnet-soak:round=N -->` marker matching the
halted round; if found, it comments with the new run's link instead of
opening a duplicate. Otherwise it creates one from
`ops/mainnet-soak/issue_template.md`, labelled `bug`, `sync`,
`conformance`, `mainnet-soak`, `algod:v5.0.2-stable`, `effort:medium`,
with the offline reproduction command
(`algod-rust replay --network mainnet --start <N-1> --end <N> --compare`)
and links to the run and its artifacts.

`workflow_dispatch`'s `dry_run_issues` input (default `true`) prints the
exact would-be issue/comment to the log and step summary instead of
calling `gh`, so the whole path is testable without touching the tracker.
Scheduled (nightly) runs always file for real.

## Reading the artifacts

Every run uploads `mainnet-node-soak-<run-id>`:

- `node.log` — the participation node's full stdout/stderr.
- `status.jsonl` — one record per poll: `ts`, the node's and peer's
  `/v2/status` fields, and (out of catchup) the parsed `follow_timing`
  histograms from the node's `/metrics`.
- `summary.json` — `monitor.py`'s verdict + timing/lag metrics (the same
  object the step summary table is built from).
- On a halt: `block-<round>.msgpack` / `block-<round>.json` — the halted
  round fetched from the peer, for offline reproduction without re-running
  a soak.

## Known constraint: runner disk/bandwidth

A full mainnet catchpoint import is large; a GitHub-hosted runner's local
disk and network bandwidth may not be enough to reach the tip inside the
default 60-minute budget, or at all. That's expected signal, not a bug in
the workflow — the summary records `reached_tip: false` and whatever
`fast_catchup_seconds`/phase timing was possible, and (per the halt
definition above) this alone is never classified as a halt as long as the
node kept making progress.

## Baseline

First live full-budget baseline, recorded per issue #1598's acceptance
criteria. Every dispatch below ran a real `algod-rust participate
--network mainnet` node against real mainnet — no simulated data.

[Run 36246996407](https://github.com/xarmian/algod-rust/actions/runs/36246996407)
(60-minute poll budget, `dry_run_issues=true`, default `halt_minutes=5`)
was the first fully clean end-to-end dispatch of this workflow: catchpoint
`65410000` (~22.47M accounts/resources/kvs) downloaded, imported, and
Merkle-trie-verified with zero errors, reaching `balances_round`
`65409680`. Verdict `ok — no stall observed` — the halt detector
correctly stayed silent through the whole run. Per-phase timing from that
run's `summary.json` (`phase_seconds`): **import-accounts 910.5s**
(~15.2 min), **import-kvs 5.1s**, and **2684.5s (~44.7 min) unattributed**
(covers the download step, the non-incremental verify-trie rebuild —
issue #1623 documents this as a legitimate 900s+ single step — and the
start of post-verify block replay). That totals almost exactly the full
60-minute poll budget, which is why `reached_tip` was `false` and
`fast_catchup_seconds` was not recorded: the import+verify pipeline alone
consumes the entire default budget on this catchpoint's real size, before
the node has caught up the ~65,410,000→tip block gap that remains after
verify finishes.

To get a genuine `fast_catchup_seconds` measurement, a second dispatch
raised the poll budget past the ~60 minutes import+verify alone consumes:
[run 36251668578](https://github.com/xarmian/algod-rust/actions/runs/36251668578)
(`duration_minutes=75`, chosen to stay under the job's 90-minute hard
`timeout-minutes` once ~8 minutes of build/setup and ~2 minutes of
teardown are accounted for). This run processed the **same** catchpoint
(round `65410000`) — `catchpoint_processed_accounts`/`_kvs` both reached
their totals (import phase: **accounts 743.4s, kvs 5.1s** this time) —
but `catchpoint_verified_accounts`/`_kvs` never moved off `0` for the
entire remaining 2822.6s (~47 min), so `monitor.py` classified it
`stuck` (past `DEFAULT_VERIFY_HALT_MINUTES = 45.0`) and correctly did
**not** file a real issue (`dry_run_issues` defaulted `true`). Since the
*prior* run completed verify for the identical catchpoint well inside a
similar window, this looks like either CI-runner timing variance in the
non-incremental trie rebuild or a real, run-dependent regression in the
chunked rebuild path — filed for its own investigation as
[issue #1631](https://github.com/xarmian/algod-rust/issues/1631) rather
than guessed at here.

| run | catchpoint round | fast-catchup time | reached tip | lag at tip (mean/p95/max) |
| --- | --- | --- | --- | --- |
| [36246996407](https://github.com/xarmian/algod-rust/actions/runs/36246996407) (60 min budget) | 65410000 | not recorded — import (915.6s) + verify consumed the full budget; verify itself completed (node reached `balances_round` 65409680 with zero errors) but the run ended before catching up to the live tip | false | n/a (0 follow samples) |
| [36251668578](https://github.com/xarmian/algod-rust/actions/runs/36251668578) (75 min budget) | 65410000 | not recorded — verify (Merkle trie rebuild) had not completed after 47+ minutes; classified `stuck`, see issue #1631 | false | n/a (0 follow samples) |
| [36433896069](https://github.com/xarmian/algod-rust/actions/runs/36433896069) (45 min budget, dispatched on `main` after issue #1636's fix) | 65469680 | **2676.1s (~44.6 min)** — first confirmed, completed measurement: import (922.1s) + verify (1368.3s Merkle trie rebuild over 76,944,826 elements, `total_elements_added` matches staged row count exactly) + cutover finalized, node reached `phase: follow` | false | n/a (0 follow samples; node was 8,727 rounds behind the peer, `lag_rounds.n=0`, when the 45-minute poll budget ended — `monitor.py` only starts recording lag samples once `reached_tip` first becomes true) |
| [36975813534](https://github.com/xarmian/algod-rust/actions/runs/36975813534) (dispatched on the #1655 branch) | 65590000 | **2948.7s (~49.1 min)** | **true** | n=544, mean 1.72, p95 3, max 69 rounds (stopped later at block 65596480 on a frozen zero-unit holding close-out, fixed in the same PR) |
| [36990771406](https://github.com/xarmian/algod-rust/actions/runs/36990771406) (150 min budget, #1655 head) | 65590000 | **3141.3s (~52.4 min)** | **true** | n=482, mean 0.37, p95 2, max 3 rounds; node 65600081 == peer 65600081, verdict `ok` |

**A confirmed, completed `fast_catchup_seconds` number is now
available**: **2676.1s (~44.6 min)** for a real mainnet catchpoint
(round 65469680, 22,498,654 accounts, 739,051 kvs, 45,411 chunks) —
run 36433896069 above, dispatched specifically as issue #1636's live
fix-confirmation run. Verdict `ok — no stall observed`; zero
catchpoint-related errors. Issue #1631's verify-duration variance
question is now moot for this baseline purpose: this run's verify
(1368.3s) landed well inside both prior runs' range (900s–2822s+), so
no `verify_halt_minutes` widening was needed to get a clean completion
here.

The remaining gap against the *original* "≈15 min short budget:
catchup to the tip" framing (see the next section — already documented
as no longer achievable at mainnet's current scale) is `reached_tip`:
the node was still 8,727 rounds behind the peer when this run's
45-minute poll budget ended, so no lag-at-tip sample was ever taken.
Closing that fully would need either a follow-up dispatch with a
budget large enough for post-verify block replay to close an
~8,700-round gap (replay speed once caught up should be well above
mainnet's real-time round production rate, but this hasn't been
directly measured yet), or accepting `fast_catchup_seconds` alone
(now confirmed) as satisfying this criterion's core intent, per the
already-documented position in the next section that a short budget
reaching the live tip is no longer realistic at mainnet's real
~22.5M-account scale.

**`reached_tip: true` is now confirmed (issue #1598's remaining bar).** Runs 36975813534 and 36990771406, dispatched on the branch merged as PR #1655, reached the live tip and stayed there: the second followed 65590000 -> 65600081 with a mean lag of 0.37 rounds. Getting there took the stale-catchpoint-state fix (#1654: a go-produced catchpoint holds state at `balances_round` and the stored window up to `blocks_round` must be replayed), a series of replay-parity fixes each found from a real mainnet block, a thread-per-round fix (#1652) and a WAL checkpoint moved off the ledger lock. Use a 150-minute dispatch budget to see tip-following; the default 60-minute budget cannot reach the tip at mainnet's current scale.

### On the issue's original "≈15 min short budget" criterion

Issue #1598 originally asked for one short (~15 min) dispatch reaching the
tip plus a few minutes of live follow, alongside the full 60-minute run.
At mainnet's current real scale (~22.47M accounts in the live catchpoint),
that is no longer achievable: the measured import-accounts phase alone
(910.5s ≈ 15.2 min) already exceeds a 15-minute total budget before the
download step, the verify-trie rebuild, or any post-verify block replay
even start. A 15-minute dispatch today can only ever exercise
startup/discovery/download-start, never "reach the tip" — that part of
the original criterion was written before this workflow had ever
completed an import against full mainnet-scale data, and is now
superseded by the real, measured phase breakdown above. See the
"Known constraint: runner disk/bandwidth" section above, which already
anticipated exactly this outcome.

## Dry-run demonstrations (issue #1598 acceptance criteria)

Both of these use `monitor.py analyze` — a pure function over an
already-collected JSONL (`_cmd_analyze`, see the module's own doc
comment: "verdict over an existing JSONL (dry runs, tests)") — the
mechanism this repo already ships for exercising `classify()`'s verdict
logic without needing a live node. No node code changes were involved.

**Halt path + title/labels/body template match + dedup**: a synthetic
JSONL with the node's `last_round` frozen at `65409680` for 390s (peer
advancing from the same round) produces:

```
{
  "status": "stuck", "phase": "follow", "round": 65409680,
  "message": "node made no progress for 390s during follow while the peer kept advancing",
  ...
}
```

exit code `1`. Feeding that verdict through `file_issue.py --dry-run`
with no pre-existing issue printed the exact would-be title
(`sync: mainnet participation node halted at round 65409680 — nightly
mainnet soak 2026-09-26`), the full label set
(`bug, sync, conformance, mainnet-soak, algod:v5.0.2-stable,
effort:medium`), and a body rendered from `issue_template.md` with the
round/phase/stalled-minutes/log-excerpt fields correctly substituted —
`{"action": "dry_run_create", ...}`.

A real, throwaway issue
([#1630](https://github.com/xarmian/algod-rust/issues/1630), closed
immediately after) was then created with the same
`<!-- mainnet-soak:round=65409680 -->` marker `file_issue.py` searches
for. Re-running the identical `file_issue.py --dry-run` call against that
now-open issue correctly found it via `gh issue list --search` and
switched to `{"action": "dry_run_comment", "number": 1630, ...}` instead
of creating a duplicate — dedup confirmed working end to end.

**Source-outage classification**: a synthetic JSONL with the node's
`last_round` frozen and the peer reporting `"ok": false` throughout
produces:

```
{"status": "source_outage", "phase": "follow", "round": 65409680, ...}
```

exit code `2`. `source_outage` is one of only two verdicts (`ok` is the
other) that `mainnet-node-soak.yml` never passes to `file_issue.py` at
all (only `stuck`/`node_failure`, exit code `1`, reach that step) — so an
unreachable `algod_url` in a real dispatch structurally cannot file or
comment on an issue, by construction of the workflow, not just by
`file_issue.py`'s own logic.

This same real-dispatch behavior was independently confirmed live in
[run 36251668578](https://github.com/xarmian/algod-rust/actions/runs/36251668578)
(see the Baseline section above): its verdict was `stuck` (not
`source_outage` — the peer was reachable and advancing throughout), and
with `dry_run_issues` at its default `true`, the "File (or comment on) an
issue for a halt" step ran `file_issue.py --dry-run` and printed the
would-be issue to the log rather than calling `gh issue create` — the
exact same dry-run path demonstrated synthetically above, now also
proven against a genuine live halt.
