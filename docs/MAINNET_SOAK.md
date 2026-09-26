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

_First live baseline recorded here once `workflow_dispatch` runs (a short
budget, then a full 60-minute run) complete — see issue #1598's
acceptance criteria._

| run | catchpoint round | fast-catchup time | reached tip | lag at tip (mean/p95/max) |
| --- | --- | --- | --- | --- |
| _pending_ | | | | |
