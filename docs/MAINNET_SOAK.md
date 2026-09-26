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
   (default 60 minutes) via `monitor.py collect`.
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
  `/v2/status` fields.
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

**A confirmed, completed `fast_catchup_seconds` number is still not
available** — both live attempts in this close-out session got real,
meaningful distance into the pipeline (one completed verify but ran out
of poll budget before reaching the tip; the other's verify did not finish
within an even larger budget) without ever landing in the
`catchpoint empty AND last-round within 2 rounds of peer` state
`monitor.py`'s `summarize()` requires to compute it. Getting that number
requires resolving issue #1631's investigation first — either widening
`verify_halt_minutes` with justified data, or fixing a genuine
verify-path regression — then a dispatch with a budget sized to that
confirmed verify duration plus enough follow time to reach the tip.

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
